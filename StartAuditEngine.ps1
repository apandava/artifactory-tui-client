#Requires -Version 5.1
<#
.SYNOPSIS
    Non-interactive (headless) credential/secret audit of a JFrog Artifactory
    instance — the third run-mode of the ARTCA tool, with no TUI.

.DESCRIPTION
    Drives the same audit engine the TUI uses (AuditEngine.ps1), but from the command
    line, producing the same CSV logs. Two verbs:

      scrape    Audit a scope and write scrape-log.csv (the would-be download set),
                WITHOUT downloading anything. The Hash and Timestamp columns are left
                blank (nothing was fetched).
      download  Audit a scope and DOWNLOAD the matching findings (dedup/rename/hash
                like the TUI's "download all"), writing download-log.csv. With
                -s/--scrape <file> it skips auditing entirely and just downloads every
                file listed in a scrape-log.csv, filling in the blank Hash/Timestamp.
      search    Run the public quick-search and, with -w/--walk-archives, also walk the
                instance's listable archives and add internal entries whose name matches
                the query, writing a results CSV. Reuses + grows the persistent local index
                (a per-instance directory of per-repo CSV shards) unless --no-index.

    Run as a script with unix-style flags:
      .\StartAuditEngine.ps1 scrape   -u https://art.example.com -q secrets -2 -v 3
      .\StartAuditEngine.ps1 download -u https://art.example.com -F -o out -v 2
      .\StartAuditEngine.ps1 download -u https://art.example.com -s scrape-log.csv

    Or paste Core.ps1, Api.ps1, AuditEngine.ps1 then this file into a console and call
    the entry functions with native parameters:
      Invoke-AuditScrape   -BaseUrl https://art.example.com -Query secrets -Tier2 -Verbosity 3
      Invoke-AuditDownload -BaseUrl https://art.example.com -Full -OutDir out
      Invoke-AuditDownload -BaseUrl https://art.example.com -FromScrape scrape-log.csv

    Flag <-> parameter map:
      -q/--query <name>   -Query          -F/--full            -Full
      -r/--repos <list>   -Repos          -2/--tier2           -Tier2
      -w/--walk-archives  -WalkArchives   -x/--exclude <globs> -Exclude
      --all-versions      -AllVersions    (search verb; default: skip duplicate archive versions)
      --offline <mode>    -Offline        (search verb only; 'index' or 'all')
      -s/--scrape <file>  -FromScrape     -o/--out <dir>       -OutDir
      -v/--verbose <0-5>  -Verbosity      --cap <bytes>        -Cap
      --workers <1-10>    -Workers        --delay <ms>         -DelayMs
      -u/--base-url <url> -BaseUrl        -t/--token <tok>     -Token
      -k/--api-key <key>  -ApiKey         -b/--basic <u:p>     -Basic

    Verbosity: 0 silent · 1 summary · 2 +milestones · 3 +per-finding · 4 +per-download
    · 5 +debug. Passive mode is TUI-only and not available here.

    Conventions: UTF-8 without BOM, LF endings; non-ASCII execution glyphs are numeric
    [char] escapes (literal Unicode only in comments).
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Allow many concurrent connections and ensure TLS 1.2 (matches StartTui.ps1).
[Net.ServicePointManager]::DefaultConnectionLimit = 256
[Net.ServicePointManager]::SecurityProtocol =
    [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# No-color, no-raw-key host: define the ANSI vars empty so any engine code path that
# interpolates them is StrictMode-safe, and disable the VT/raw-key capability flags.
$R = $BD = $DM = $CY = $MG = $YL = $RD = $HB = $SB = ''
$script:Vt = $false
$script:CanRawKey = $false
$script:ArcGlyph = '+'; $script:PreviewGlyph = [char]0x00B7; $script:Cut = [char]0x2026

# Shared config at script scope — read by the Core/Api helpers (Get-AuthHeaders reads
# $ApiKey/$Token/$Basic; Get-ArtBase/Get-UiHeaders/Get-TreeBrowseRequest read $BaseUrl;
# the dedup download reads $OutDir; the full walker reads $Repos). Populated per run.
$BaseUrl = ''; $ApiKey = ''; $Token = ''; $Basic = ''; $Repos = ''
$OutDir  = ''   # resolved per instance (output/<host>/downloads) unless -o/--out is given

# Verbosity level for this run (0..5); overridden by -Verbosity/-v.
$script:AuditVerbosity = 1

# ── LOAD COMPONENTS ───────────────────────────────────────────────────────────
# Headless run-mode loads only the headless layer: Core + Api + AuditEngine. Guarded
# so it runs only when executed as a file AND the engine isn't already present
# (Invoke-AuditPump is the sentinel). Paste-mode leaves $PSScriptRoot empty, so paste
# Core.ps1, Api.ps1, AuditEngine.ps1 first, then this file.
if ($PSScriptRoot -and -not (Get-Command Invoke-AuditPump -ErrorAction SilentlyContinue)) {
    foreach ($component in 'Core','Api','AuditEngine','Index') {
        . (Join-Path $PSScriptRoot "$component.ps1")
    }
}

# ── VERBOSITY OUTPUT ──────────────────────────────────────────────────────────
# Print $msg only when the run's verbosity is at least $level.
function Write-V([int]$level, [string]$msg) {
    if ($script:AuditVerbosity -ge $level) { Write-Host $msg }
}

# Route the shared bulk-download engine's progress lines to level-4 output (the TUI
# routes the same hook to Show-Popup instead).
$script:DownloadProgress = {
    param($lines)
    Write-V 4 ('  ' + ((@($lines) | Where-Object { "$_" -ne '' }) -join '  '))
}

# ── ARGV PARSING (unix-style CLI) ─────────────────────────────────────────────
# Turn the verb's remaining tokens into a splat hashtable keyed by parameter name.
# Value flags consume the following token; switches are set to $true.
function ConvertFrom-AuditArgv([string[]]$tokens) {
    $p = @{}
    # A zero-element array passed positionally arrives as $null (PowerShell unwraps empty
    # collections); guard so a verb with no further tokens (e.g. 'help') doesn't trip
    # StrictMode on $tokens.Count below.
    if ($null -eq $tokens) { return $p }
    $i = 0
    while ($i -lt $tokens.Count) {
        $t = $tokens[$i]
        switch -regex ($t) {
            '^(-q|--query)$'         { $p.Query        = $tokens[++$i] }
            '^(-F|--full)$'          { $p.Full         = $true }
            '^(-r|--repos)$'         { $p.Repos        = $tokens[++$i] }
            '^(-2|--tier2)$'         { $p.Tier2        = $true }
            '^(-w|--walk-archives)$' { $p.WalkArchives = $true }
            '^--all-versions$'       { $p.AllVersions  = $true }
            '^--skip-versions$'      { $p.AllVersions  = $false }   # affirms the default (no-op)
            '^(-x|--exclude)$'       { $p.Exclude      = $tokens[++$i] }
            '^(-s|--scrape)$'        { $p.FromScrape   = $tokens[++$i] }
            '^--index$'              { $p.IndexPath    = $tokens[++$i] }
            '^--no-index$'           { $p.NoIndex      = $true }
            '^--offline$'            { $p.Offline      = $tokens[++$i] }
            '^(-o|--out)$'           { $p.OutDir       = $tokens[++$i] }
            '^(-v|--verbose)$'       { $p.Verbosity    = [int]$tokens[++$i] }
            '^--cap$'                { $p.Cap          = [long]$tokens[++$i] }
            '^--workers$'            { $p.Workers      = [int]$tokens[++$i] }
            '^--delay$'              { $p.DelayMs      = [int]$tokens[++$i] }
            '^(-u|--base-url)$'      { $p.BaseUrl      = $tokens[++$i] }
            '^(-t|--token)$'         { $p.Token        = $tokens[++$i] }
            '^(-k|--api-key)$'       { $p.ApiKey       = $tokens[++$i] }
            '^(-b|--basic)$'         { $p.Basic        = $tokens[++$i] }
            default { throw "Unknown argument: $t" }
        }
        $i++
    }
    return $p
}

function Show-AuditEngineUsage {
    Write-Host @'
ARTCA headless audit

Usage:
  StartAuditEngine.ps1 scrape   <options>            audit + write scrape-log.csv (no download)
  StartAuditEngine.ps1 download <options>            audit + download + write download-log.csv
  StartAuditEngine.ps1 download -s scrape-log.csv    download a previous scrape (no audit)
  StartAuditEngine.ps1 search   <options>            quick-search (+ optional archive walk) to a CSV

Scope (one of):
  -q, --query <name>      audit/search the results of this artifact name search
  -F, --full              audit the entire instance (audit verbs only)
  -r, --repos <a,b>       restrict the scope to these repositories

Search options (search verb):
  -w, --walk-archives     also walk listable archives and add matching internal entries
      --all-versions      walk EVERY version of an archive (default: skip - walk only the
                          first version of each artifact, by version-normalized filename)
      --offline <mode>    don't query the server for search; use the local index as the catalogue.
                          'index' still fetches archive listings on demand; 'all' makes no
                          requests at all (matches come only from the index). search verb only.
      --index <path>      local index directory to use/update (default ./.artca-index/<host>/)
      --no-index          don't read or write the index
  -o, --out <file|dir>    results CSV (default search-results.csv under the out dir)

Audit options:
  -2, --tier2             also fetch file content and scan it (Tier 2; default Tier 1)
  -w, --walk-archives     expand listable archives and audit their entries
  -x, --exclude <globs>   comma/space globs to exclude from the set (e.g. "*.xml,*test*")
      --cap <bytes>       max file size to content-scan (default 2 MB)
      --workers <1-10>    parallel fetch workers (default 3)
      --delay <ms>        delay between request launches (default 150)

Output / auth:
  -o, --out <dir>         output folder (default ./output/<host>/downloads)
  -v, --verbose <0-5>     0 silent .. 5 debug (default 1)
  -u, --base-url <url>    Artifactory base URL (required)
  -t, --token <tok>       bearer token        -k, --api-key <key>   JFrog API key
  -b, --basic <user:pw>   basic auth
'@
}

# ── CONFIG / RUN ──────────────────────────────────────────────────────────────
# Resolve the per-instance output layout (downloads + audit dirs under output/<host>/) from
# the bound parameters. An explicit -o/--out (OutDir) is kept verbatim; otherwise downloads
# default under the instance root. Call after $BaseUrl is set. Shared by all verbs.
function Resolve-RunOutput([hashtable]$O) {
    if ($O.ContainsKey('OutDir') -and $O['OutDir']) {
        $script:OutDir = [string]$O['OutDir']; $script:OutDirExplicit = $true
    } else {
        $script:OutDirExplicit = $false
    }
    Resolve-OutputPaths
}

# Apply parsed options to script-scope config + engine settings. $O is the caller's
# bound parameters (only keys actually supplied are present).
function Initialize-AuditRunConfig([hashtable]$O) {
    if ($O.ContainsKey('Verbosity')) { $script:AuditVerbosity = [int]$O['Verbosity'] }
    if ($O.ContainsKey('BaseUrl'))   { $script:BaseUrl = [string]$O['BaseUrl'] }
    if ($O.ContainsKey('ApiKey'))    { $script:ApiKey  = [string]$O['ApiKey'] }
    if ($O.ContainsKey('Token'))     { $script:Token   = [string]$O['Token'] }
    if ($O.ContainsKey('Basic'))     { $script:Basic   = [string]$O['Basic'] }
    if ($O.ContainsKey('Repos'))     { $script:Repos   = [string]$O['Repos'] }
    if (-not $script:BaseUrl) { throw 'A base URL is required (-u/--base-url).' }
    $script:BaseUrl = $script:BaseUrl.TrimEnd('/')
    Resolve-RunOutput $O

    # Engine settings (Tier 1/2 + walk-archives persist across Reset-AuditEngine; cap
    # and throttle are read live by the dispatcher).
    $script:AuditTier2        = [bool]($O.ContainsKey('Tier2')        -and $O['Tier2'])
    $script:AuditWalkArchives = [bool]($O.ContainsKey('WalkArchives') -and $O['WalkArchives'])
    if ($O.ContainsKey('Cap') -and [long]$O['Cap'] -gt 0)        { $script:AuditCap = [long]$O['Cap'] }
    if ($O.ContainsKey('Workers') -and [int]$O['Workers'] -gt 0) { $script:AuditThrottle.MaxConcurrent = [Math]::Max(1, [Math]::Min(10, [int]$O['Workers'])) }
    if ($O.ContainsKey('DelayMs') -and [int]$O['DelayMs'] -ge 0) { $script:AuditThrottle.MinIntervalMs = [int]$O['DelayMs'] }
}

# Re-apply the exclude filter to every finding's Included flag (headless equivalent of
# the view's Update-AuditExclusions, without the preview-cache cleanup). Catches
# findings created before the filter was set as well as any added during the run.
function Update-AuditExcludedHeadless {
    foreach ($f in $script:AuditFindings) {
        if (Test-AuditExcluded ([string]$f.Name)) { $f.Included = $false }
    }
    $script:AuditSortDirty = $true
}

# Drive the engine to completion, emitting progress per verbosity.
function Invoke-AuditPumpToDone {
    if ($script:AuditState -eq 'paused') { $script:AuditState = 'running' }
    $printed  = 0
    $lastTick = [DateTime]::MinValue
    while ($script:AuditState -ne 'done' -and $script:AuditState -ne 'cancelled' -and $script:AuditState -ne 'idle') {
        Invoke-AuditPump
        if ($script:AuditVerbosity -ge 3) {
            while ($printed -lt $script:AuditFindings.Count) {
                $f = $script:AuditFindings[$printed]; $printed++
                $loc = (@($f.Repo, $f.Path, $f.Name) | Where-Object { "$_" -ne '' }) -join '/'
                Write-Host ("  [{0}] {1} - {2}" -f $f.Sev, $loc, $f.AllRules)
            }
        }
        if ($script:AuditVerbosity -ge 2 -and ([DateTime]::UtcNow - $lastTick).TotalSeconds -ge 1) {
            $walk = if (Test-AuditWalkActive) { ' (walking)' } else { '' }
            Write-Host ("  ...audited $($script:AuditDone)/$($script:AuditEnq), found $($script:AuditFindings.Count)$walk")
            if ($script:AuditVerbosity -ge 5) {
                Write-Host ("    queue=$($script:AuditQueue.Count) jobs=$($script:AuditJobs.Count) pending=$($script:AuditPendingNodes.Count) launched=$($script:AuditLaunched)")
            }
            $lastTick = [DateTime]::UtcNow
        }
        Start-Sleep -Milliseconds 100
    }
    if ($script:AuditVerbosity -ge 3) {
        while ($printed -lt $script:AuditFindings.Count) {
            $f = $script:AuditFindings[$printed]; $printed++
            $loc = (@($f.Repo, $f.Path, $f.Name) | Where-Object { "$_" -ne '' }) -join '/'
            Write-Host ("  [{0}] {1} - {2}" -f $f.Sev, $loc, $f.AllRules)
        }
    }
}

# Severity breakdown summary (level 1+).
function Write-AuditSummary {
    if ($script:AuditVerbosity -lt 1) { return }
    $counts = @{}
    foreach ($f in $script:AuditFindings) {
        $s = [string]$f.Sev
        $counts[$s] = 1 + $(if ($counts.ContainsKey($s)) { $counts[$s] } else { 0 })
    }
    $parts = @()
    foreach ($s in 'Critical','High','Medium','Low','Informational') {
        if ($counts.ContainsKey($s)) { $parts += "$s=$($counts[$s])" }
    }
    $brk = if ($parts.Count -gt 0) { ' [' + ($parts -join ' ') + ']' } else { '' }
    Write-Host ''
    Write-Host ("Audit complete: $($script:AuditFindings.Count) finding(s)$brk")
}

# Launch the chosen scope, run to completion, apply excludes.
function Invoke-HeadlessAudit([hashtable]$O) {
    Initialize-AuditRunConfig $O
    $full  = [bool]($O.ContainsKey('Full') -and $O['Full'])
    $query = if ($O.ContainsKey('Query')) { [string]$O['Query'] } else { '' }
    Write-V 5 ("Settings: tier=$(if ($script:AuditTier2) { '2' } else { '1' }) walkArchives=$script:AuditWalkArchives cap=$script:AuditCap workers=$($script:AuditThrottle.MaxConcurrent) delay=$($script:AuditThrottle.MinIntervalMs)ms out=$script:OutDir")

    if ($full) {
        Write-V 1 'Starting full-instance audit...'
        Start-AuditFull
    } elseif ($query) {
        Write-V 1 "Searching for '$query'..."
        $res = Search-Artifacts $query
        if ($res.Error) { throw "Search failed: $($res.Error)" }
        Write-V 2 "  $($res.Total) result(s) for '$query'"
        Start-AuditLocation "search: $query" $res.Items
    } else {
        throw 'Specify a scope: -q/--query <name> or -F/--full.'
    }

    # Excludes must be set AFTER the launch (Reset-AuditEngine clears them); the run
    # honours them for new findings and Update-AuditExcludedHeadless catches the rest.
    if ($O.ContainsKey('Exclude')) { Set-AuditExcludes ([string]$O['Exclude']) }

    Invoke-AuditPumpToDone
    Update-AuditExcludedHeadless
}

# Download every file listed in a scrape-log.csv, no auditing. Recomputes hashes (the
# scrape left them blank) and writes download-log.csv with Hash + Timestamp filled.
function Invoke-DownloadFromScrape([string]$file) {
    if (-not (Test-Path -LiteralPath $file)) { throw "Scrape file not found: $file" }
    $rows = @(Import-Csv -LiteralPath $file)
    $entries = @($rows | ForEach-Object {
        $sz = -1; if ("$($_.SizeBytes)" -match '^\d+$') { $sz = [long]$_.SizeBytes }
        [PSCustomObject]@{
            Ref = $null; Name = [string]$_.FileName; Url = [string]$_.DownloadUrl; KnownHash = ''
            Repo = [string]$_.Repository; Path = [string]$_.Path; Archive = [string]$_.Archive
            Size = $sz; Modified = [string]$_.Modified
            Sev = [string]$_.Severity; Rule = [string]$_.MatchedRule; VisitKey = [string]$_.DownloadUrl
        }
    })
    if ($entries.Count -eq 0) { Write-V 1 "No rows in $file."; return }
    Write-V 1 "Downloading $($entries.Count) file(s) listed in $file ..."
    $res = Invoke-DedupDownload $entries
    Write-V 1 (Get-DedupDoneLine $res)
    Write-V 1 ('Logged to ' + (Join-Path $script:OutDir 'download-log.csv'))
}

# ── ENTRY FUNCTIONS ───────────────────────────────────────────────────────────
function Invoke-AuditScrape {
    param(
        [string]$Query, [switch]$Full, [string]$Repos,
        [switch]$Tier2, [switch]$WalkArchives, [string]$Exclude,
        [long]$Cap, [int]$Workers, [int]$DelayMs,
        [string]$OutDir, [int]$Verbosity,
        [string]$BaseUrl, [string]$ApiKey, [string]$Token, [string]$Basic, [string]$Offline
    )
    if ("$Offline".Trim()) { throw '--offline is not supported for the scrape verb (auditing must fetch file content). Use it with the search verb, or the TUI.' }
    Invoke-HeadlessAudit $PSBoundParameters
    $cands = @(Get-AuditIncludedCandidates)
    foreach ($f in $cands) {
        $arch = if ($f.InArchive) { [string]$f.ArchiveName } else { '' }
        $sz   = if ($f.Size -ge 0) { [long]$f.Size } else { -1 }
        Write-DownloadLog $script:OutDir ([string]$f.Name) ([string]$f.Repo) ([string]$f.Path) $arch `
            $sz ([string]$f.Modified) ([string]$f.Url) ([string]$f.Sev) ([string]$f.AllRules) '' 'scrape-log.csv' -Scrape
    }
    Write-AuditSummary
    Write-V 1 ("Wrote $($cands.Count) finding(s) to " + (Join-Path $script:OutDir 'scrape-log.csv'))
}

function Invoke-AuditDownload {
    param(
        [string]$Query, [switch]$Full, [string]$Repos,
        [switch]$Tier2, [switch]$WalkArchives, [string]$Exclude,
        [long]$Cap, [int]$Workers, [int]$DelayMs,
        [string]$OutDir, [int]$Verbosity,
        [string]$BaseUrl, [string]$ApiKey, [string]$Token, [string]$Basic,
        [string]$FromScrape, [string]$Offline
    )
    if ("$Offline".Trim()) { throw '--offline is not supported for the download verb (downloading requires the server). Use it with the search verb, or the TUI.' }
    $O = $PSBoundParameters
    # Apply base config (base url, auth, out dir, verbosity) for both paths.
    if ($O.ContainsKey('Verbosity')) { $script:AuditVerbosity = [int]$O['Verbosity'] }
    if ($O.ContainsKey('BaseUrl'))   { $script:BaseUrl = ([string]$O['BaseUrl']).TrimEnd('/') }
    if ($O.ContainsKey('ApiKey'))    { $script:ApiKey  = [string]$O['ApiKey'] }
    if ($O.ContainsKey('Token'))     { $script:Token   = [string]$O['Token'] }
    if ($O.ContainsKey('Basic'))     { $script:Basic   = [string]$O['Basic'] }
    if ($O.ContainsKey('Repos'))     { $script:Repos   = [string]$O['Repos'] }
    if ($script:BaseUrl) { $script:BaseUrl = $script:BaseUrl.TrimEnd('/') }
    Resolve-RunOutput $O

    if ($O.ContainsKey('FromScrape') -and $O['FromScrape']) {
        Invoke-DownloadFromScrape ([string]$O['FromScrape'])
        return
    }
    Invoke-HeadlessAudit $O
    $cands = @(Get-AuditIncludedCandidates)
    Write-AuditSummary
    if ($cands.Count -eq 0) { Write-V 1 'No findings to download.'; return }
    $res = Invoke-AuditDownloadSet $cands
    Write-V 1 (Get-DedupDoneLine $res)
    Write-V 1 ('Logged to ' + (Join-Path $script:OutDir 'download-log.csv'))
}

# ── SEARCH (REST + optional archive walk) ─────────────────────────────────────
# Drive the archive-search walk to completion, emitting progress per verbosity.
function Invoke-ArcSearchPumpToDone {
    $lastTick = [DateTime]::MinValue
    while ($script:ArcSearchState -eq 'walking') {
        Invoke-ArcSearchPump
        if ($script:AuditVerbosity -ge 2 -and ([DateTime]::UtcNow - $lastTick).TotalSeconds -ge 1) {
            $walk = if (Test-ArcSearchWalkActive) { ' (walking)' } else { '' }
            Write-Host ("  ...indexed $($script:ArcIndexedArchives.Count) archive(s), $($script:ArcSearchResults.Count) match(es)$walk")
            if ($script:AuditVerbosity -ge 5) {
                Write-Host ("    queue=$($script:ArcQueue.Count) jobs=$($script:ArcJobs.Count) indexed=$($script:ArcIndexedArchives.Count)")
            }
            $lastTick = [DateTime]::UtcNow
        }
        Start-Sleep -Milliseconds 100
    }
}

# `search` verb: run the public quick-search and, with -w/--walk-archives, also walk the
# instance's listable archives in the background and add internal entries whose name
# matches the query. Writes the combined results to a CSV and (unless --no-index) caches
# walked archive contents to the index for reuse.
function Invoke-Search {
    param(
        [string]$Query, [string]$Repos, [switch]$WalkArchives, [switch]$AllVersions,
        [string]$IndexPath, [switch]$NoIndex, [string]$Offline,
        [long]$Cap, [int]$Workers, [int]$DelayMs,
        [string]$OutDir, [int]$Verbosity,
        [string]$BaseUrl, [string]$ApiKey, [string]$Token, [string]$Basic
    )
    $O = $PSBoundParameters
    if ($O.ContainsKey('Verbosity')) { $script:AuditVerbosity = [int]$O['Verbosity'] }
    # Offline: 'index'/'all' both skip the REST quick-search (Search-Artifacts self-gates to
    # empty); results come from the local index (Search-Index + indexed archive entries). 'all'
    # also skips the archive WALK (Start-ArcSearch gates it), so matches are index-only.
    if ($O.ContainsKey('Offline')) { Set-OfflineMode ([string]$O['Offline']) }
    if ($O.ContainsKey('BaseUrl'))   { $script:BaseUrl = ([string]$O['BaseUrl']).TrimEnd('/') }
    if ($O.ContainsKey('ApiKey'))    { $script:ApiKey  = [string]$O['ApiKey'] }
    if ($O.ContainsKey('Token'))     { $script:Token   = [string]$O['Token'] }
    if ($O.ContainsKey('Basic'))     { $script:Basic   = [string]$O['Basic'] }
    if ($O.ContainsKey('Repos'))     { $script:Repos   = [string]$O['Repos'] }
    if (-not $script:BaseUrl) { throw 'A base URL is required (-u/--base-url).' }
    if (-not $Query)          { throw 'Specify a query: -q/--query <name>.' }
    Resolve-RunOutput $O

    # Local index settings + throttle (read live by the dispatcher/writers).
    $script:IndexEnabled = -not ($O.ContainsKey('NoIndex') -and $O['NoIndex'])
    if ($O.ContainsKey('IndexPath') -and $O['IndexPath']) { Set-IndexPath ([string]$O['IndexPath']) }
    Resolve-IndexPath
    if ($O.ContainsKey('Workers') -and [int]$O['Workers'] -gt 0) { $script:ArcThrottle.MaxConcurrent = [Math]::Max(1, [Math]::Min(10, [int]$O['Workers'])) }
    if ($O.ContainsKey('DelayMs') -and [int]$O['DelayMs'] -ge 0) { $script:ArcThrottle.MinIntervalMs = [int]$O['DelayMs'] }
    # Skip-versions defaults on (set in Index.ps1); --all-versions/-AllVersions walks every
    # version of each archive. (--skip-versions passes AllVersions=$false, affirming the default.)
    if ($O.ContainsKey('AllVersions')) { $script:ArcSkipVersions = -not [bool]$O['AllVersions'] }
    $walk = [bool]($O.ContainsKey('WalkArchives') -and $O['WalkArchives'])

    # Reuse any prior index for this instance (serves local name-matches + skips re-walking
    # already-indexed archives).
    if ($script:IndexEnabled) {
        Import-Index $script:IndexPath
        Write-V 2 "  using index at $($script:IndexPath) (streamed on demand)"
    }

    Write-V 1 "Searching for '$Query'..."
    $res = Search-Artifacts $Query
    if ($res.Error) { throw "Search failed: $($res.Error)" }
    $restItems = @($res.Items)
    Write-V 2 "  $($res.Total) result(s) from the REST quick-search"
    $localHits = @(Search-Index $Query)
    if ($localHits.Count -gt 0) { Write-V 2 "  $($localHits.Count) local index match(es)" }

    $arcMatches = @()
    if ($walk) {
        Write-V 1 ("Walking listable archives" + $(if ($script:IndexEnabled) { " (index: $script:IndexPath)" } else { ' (indexing off)' }) + '...')
        Start-ArcSearch $Query $restItems
        Invoke-ArcSearchPumpToDone
        $arcMatches = @(Receive-ArcSearchResults)
        Write-V 1 "  $($arcMatches.Count) archive-entry match(es) across $($script:ArcIndexedArchives.Count) archive(s)"
    }

    # Merge: REST first, then local hits, then walk matches; dedup by .Uri.
    $all  = @($restItems)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($it in $all) { [void]$seen.Add([string]$it.Uri) }
    foreach ($it in (@($localHits) + @($arcMatches))) { if ($it -and $seen.Add([string]$it.Uri)) { $all += $it } }
    $all = @($all)

    $outFile = if ($O.ContainsKey('OutDir')) {
        if ([IO.Path]::GetExtension($script:OutDir)) { $script:OutDir } else { Join-Path $script:OutDir 'search-results.csv' }
    } else { Join-Path $script:OutDir 'search-results.csv' }
    Write-ArcSearchResults $outFile $all
    Stop-ArcSearch
    Write-V 1 "Wrote $($all.Count) result(s) to $outFile"
    if ($script:IndexEnabled) { Write-V 1 "Wrote $($script:IndexCount) new record(s) to the index this run ($($script:IndexPath))" }
}

# ── DISPATCH (script-file invocation) ─────────────────────────────────────────
# Skip when loaded only for testing, or pasted/dot-sourced with no verb.
if ($env:ARTCA_NOMAIN) { return }
if ($args.Count -eq 0) { Show-AuditEngineUsage; return }

$verb = [string]$args[0]
$rest = if ($args.Count -gt 1) { @($args[1..($args.Count - 1)]) } else { @() }
try {
    $splat = ConvertFrom-AuditArgv $rest
} catch {
    Write-Host "Error: $($_.Exception.Message)`n"
    Show-AuditEngineUsage
    return
}
switch ($verb.ToLower()) {
    'scrape'   { Invoke-AuditScrape @splat }
    'download' { Invoke-AuditDownload @splat }
    'search'   { Invoke-Search @splat }
    'help'     { Show-AuditEngineUsage }
    '-h'       { Show-AuditEngineUsage }
    '--help'   { Show-AuditEngineUsage }
    default    { Write-Host "Unknown verb: $verb`n"; Show-AuditEngineUsage }
}
