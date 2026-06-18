# Api.ps1 — part of the ARTCA Artifactory TUI (see StartTui.ps1).
#
# This file holds function and $script:-state definitions only; nothing here runs
# on its own. It is loaded two ways:
#   · dot-sourced automatically by StartTui.ps1 when the tool is run as a file, or
#   · pasted directly into the PowerShell console (paste the component files first,
#     then StartTui.ps1 last) to run the tool without executing the .ps1 files.
# Load order among the component files does not matter.
# Turn a caught web-request ErrorRecord into a readable message. Artifactory
# returns a JSON body like {"errors":[{"status":404,"message":"..."}]} that
# explains *why* (e.g. a repo is blacked out) — far more useful than the bare
# "(404) Not Found" in the exception. We read the response body and prefer its
# message(s), falling back to the raw body, then the exception text.
function Get-HttpErrorDetail($err) {
    $ex   = $err.Exception
    $code = 0
    try { if ($ex.Response) { $code = [int]$ex.Response.StatusCode } } catch { }
    $body = ''
    try {
        if ($ex.Response) {
            $body = [System.IO.StreamReader]::new($ex.Response.GetResponseStream()).ReadToEnd()
        }
    } catch { }
    $msg = ''
    if ($body) {
        try {
            $j = $body | ConvertFrom-Json
            if ($j.PSObject.Properties['errors'] -and $j.errors) {
                $msg = (@($j.errors | ForEach-Object { "$($_.message)" }) -join '; ')
            } elseif ($j.PSObject.Properties['message']) {
                $msg = "$($j.message)"
            }
        } catch { }
        if (-not $msg) { $msg = $body.Trim() }
    }
    if (-not $msg) { $msg = $ex.Message }
    if ($code -gt 0) { return "HTTP $code - $msg" }
    return $msg
}

# ── AUTH ──────────────────────────────────────────────────────────────────────

function Get-AuthHeaders {
    $h = @{}
    if     ($ApiKey) { $h['X-JFrog-Art-Api'] = $ApiKey }
    elseif ($Token)  { $h['Authorization']   = "Bearer $Token" }
    elseif ($Basic)  {
        $bytes = [Text.Encoding]::ASCII.GetBytes($Basic)
        $h['Authorization'] = "Basic $([Convert]::ToBase64String($bytes))"
    }
    return $h
}

# Build the artifactory REST base, tolerating URLs that already include /artifactory.
function Get-ArtBase {
    if ($BaseUrl -match '/artifactory/?$') { return $BaseUrl.TrimEnd('/') }
    return "$BaseUrl/artifactory"
}

# ── REPO METADATA ─────────────────────────────────────────────────────────────
# /api/repositories gives rclass (LOCAL/REMOTE/VIRTUAL) + packageType per repo.
# Fetched once; remote-cache repos (<key>-cache) inherit from their base repo.

$script:RepoMap       = @{}
$script:RepoMapLoaded = $false
$script:MetaCache     = [hashtable]::Synchronized(@{})   # written by background prefetch threads

# ── RATE-LIMIT / PARTIAL-RESULT DETECTION ─────────────────────────────────────
# We don't throttle; we just watch for trouble and tell the user. $Alert is a
# notice surfaced in the UI: set by any worker on HTTP 429/503, and by the search
# when it returns far fewer results than we've previously seen for the same query.
# $QueryMax remembers the largest result count seen per query this session — the
# baseline for the partial-result heuristic. ($Alert is synchronized because the
# background workers write to it from other threads.)
$script:Alert    = [hashtable]::Synchronized(@{ Message = ''; At = [DateTime]::MinValue })
$script:QueryMax = @{}

# $Flash is a transient, neutral one-shot notice shown on the results page (e.g.
# a download confirmation after returning from the item view). Main-thread only.
$script:Flash = @{ Message = ''; At = [DateTime]::MinValue }

function Initialize-RepoMap {
    if ($script:RepoMapLoaded) { return }
    $script:RepoMapLoaded = $true   # only attempt once, even if it fails
    $script:RepoMap = @{}
    try {
        $repos = Invoke-RestMethod -Uri "$(Get-ArtBase)/api/repositories" `
                     -Headers (Get-AuthHeaders) -ErrorAction Stop
        foreach ($r in $repos) {
            $script:RepoMap[$r.key] = [PSCustomObject]@{
                Type        = "$($r.type)"
                PackageType = "$($r.packageType)"
            }
        }
    } catch { }   # anonymous instances may deny this; columns degrade to '?'
}

function Resolve-Repo([string]$repo) {
    if ($script:RepoMap.ContainsKey($repo)) { return $script:RepoMap[$repo] }
    if ($repo -match '^(.*)-cache$' -and $script:RepoMap.ContainsKey($Matches[1])) {
        $base = $script:RepoMap[$Matches[1]]
        return [PSCustomObject]@{ Type = 'CACHE'; PackageType = $base.PackageType }
    }
    return [PSCustomObject]@{ Type = '?'; PackageType = '?' }
}

# Copy any already-cached size/modified onto the items for display. This never
# touches the network — fetching is done entirely by the background prefetch
# pool below, so rows simply populate as their entries land in the cache.
# Cheap; safe to call on every redraw.
function Apply-Meta([object[]]$Items) {
    if ($null -eq $Items) { return }
    foreach ($it in $Items) {
        if ($it -and $script:MetaCache.ContainsKey($it.Uri)) {
            $m = $script:MetaCache[$it.Uri]
            $it.Size = $m.Size; $it.Modified = $m.Modified
            if ($m.PSObject.Properties['Hash']) { $it.Hash = $m.Hash }
        }
    }
}

# How many of these items don't yet have cached detail.
function Get-MissingMeta([object[]]$Items) {
    if ($null -eq $Items) { return 0 }
    @($Items | Where-Object { $_ -and -not $script:MetaCache.ContainsKey($_.Uri) }).Count
}

# How many items are still genuinely in flight (uncached but queued in the
# pool). Used to decide whether to keep polling for fill-in: once nothing is
# in flight, a still-missing row is a failed/denied fetch, so we stop waiting
# rather than spin forever.
function Get-LoadingMeta([object[]]$Items) {
    if ($null -eq $Items) { return 0 }
    @($Items | Where-Object {
        $_ -and -not $script:MetaCache.ContainsKey($_.Uri) -and $script:PfQueued.ContainsKey($_.Uri)
    }).Count
}

# Block (up to $TimeoutMs) until every item has cached detail, retrying any
# straggler that isn't in flight. Used only on hosts without a real key buffer
# (ISE), where the non-blocking fill-in poll can't run; the items must already
# have been queued by the caller. Applies the results before returning.
function Wait-Meta([object[]]$Items, [int]$TimeoutMs) {
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    while ((Get-MissingMeta $Items) -gt 0 -and [DateTime]::UtcNow -lt $deadline) {
        Receive-Prefetch
        if ((Get-LoadingMeta $Items) -eq 0) { Start-Prefetch $Items }   # retry stragglers
        Start-Sleep -Milliseconds 60
    }
    Apply-Meta $Items
}


# ── SEARCH ────────────────────────────────────────────────────────────────────
# Parse a storage URI such as
#   https://host/artifactory/api/storage/<repo>/<dir>/<file>
# into repo / path / name, and resolve repo type + package type.

function Convert-UriToItem([string]$uri) {
    $marker = '/api/storage/'
    $idx    = $uri.IndexOf($marker)
    $rel    = if ($idx -ge 0) { $uri.Substring($idx + $marker.Length) } else { $uri }
    $rel    = $rel.TrimEnd('/')
    $parts  = $rel -split '/'
    $repo   = if ($parts.Count -ge 1) { $parts[0] } else { '?' }
    $name   = if ($parts.Count -ge 1) { $parts[-1] } else { '?' }
    $path   = if ($parts.Count -ge 3) { ($parts[1..($parts.Count - 2)] -join '/') }
              elseif ($parts.Count -eq 2) { '' }
              else { '' }
    return [PSCustomObject]@{
        Name     = $name
        Repo     = $repo
        Path     = $path
        Uri      = $uri
        FileType = Get-Ext $name
        Size     = ''           # size + modified + hash filled lazily from storage metadata
        Modified = ''
        Hash     = ''           # content identity as '<algo>:<hex>' (sha256/sha1/md5)
    }
}

function Search-Artifacts([string]$Query) {
    $uri = "$(Get-ArtBase)/api/search/artifact?name=$([Uri]::EscapeDataString($Query))"
    if ($Repos) { $uri += "&repos=$([Uri]::EscapeDataString($Repos))" }

    try {
        $resp  = Invoke-RestMethod -Uri $uri -Method Get -Headers (Get-AuthHeaders) -ErrorAction Stop
        $items = @()
        if ($resp.PSObject.Properties['results']) {
            $items = @($resp.results | ForEach-Object { Convert-UriToItem $_.uri })
        }
        $total = $items.Count

        # Partial-result detection: compare against the most results we've ever
        # seen for this exact query this session. A big drop means the server
        # returned a truncated set (load/throttling), not that matches vanished.
        $prev = if ($script:QueryMax.ContainsKey($Query)) { $script:QueryMax[$Query] } else { 0 }
        if ($prev -gt 0 -and $total -lt [int]($prev * 0.8)) {
            $script:Alert.Message = "Results may be incomplete: got $total, but saw $prev earlier for '$Query' - the server may be throttling. Press [s] to search again."
            $script:Alert.At      = [DateTime]::UtcNow
        } else {
            $script:Alert.Message = ''   # clear any stale notice on a clean result
        }
        if ($total -gt $prev) { $script:QueryMax[$Query] = $total }

        return [PSCustomObject]@{ Items = $items; Total = $total; Error = $null }
    }
    catch {
        return [PSCustomObject]@{ Items = @(); Total = 0; Error = (Get-HttpErrorDetail $_) }
    }
}

