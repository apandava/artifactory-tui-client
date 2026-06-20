#Requires -Version 5.1
<#
.SYNOPSIS
    Non-interactive (headless) local-index BUILDER for a JFrog Artifactory instance —
    a run-mode of the ARTCA tool with no TUI.

.DESCRIPTION
    Walks the instance (or a search location) and writes the per-repo CSV shards of the
    local index (output/<host>/index/), so a later TUI session browses warm with no
    metadata requests. It uses only the public endpoints the rest of the tool relies on
    (anonymous-friendly): a recursive /api/storage walk to enumerate files, then a per-file
    /api/storage GET for size + lastModified. With -a/--archives it ALSO expands listable
    archives and indexes their internal entries (the same engine the [w] walk uses).

    Throughput: the walk runs as a POOL of --walkers discovery runspaces (parallel depth-first
    over a shared folder stack) feeding a POOL of --workers long-lived metadata-fetch loops; both
    are governed by an AIMD adaptive throttle that backs off on HTTP 429/503 and retries transient
    failures, so the aggressive defaults run hot but never hammer a server. --resume skips files
    already in the shards to finish an interrupted build. (Request COUNT is fixed - one GET per
    folder + one per file; the only batch alternative, ?list/AQL, needs a privileged Pro account
    and is unavailable anonymously - so the speedup is from safe concurrency, not fewer requests.)

    Scope (one of):
      -F, --full              index the entire instance
      -q, --query <name>      index the results of this artifact-name quick-search

    Run as a script with unix-style flags:
      .\StartIndex.ps1 -F -u https://art.example.com -v 2
      .\StartIndex.ps1 -F -a -u https://art.example.com -r repo1,repo2 -v 2
      .\StartIndex.ps1 -q secrets -a -u https://art.example.com

    Or paste Core.ps1, Api.ps1, Index.ps1 then this file into a console and call:
      Invoke-IndexBuild -BaseUrl https://art.example.com -Full -Archives -Verbosity 2
      Invoke-IndexBuild -BaseUrl https://art.example.com -Query secrets

    Flag <-> parameter map:
      -F/--full           -Full           -q/--query <name>    -Query
      -a/--archives       -Archives       -r/--repos <list>    -Repos
      --all-versions      -AllVersions    (default: skip duplicate archive versions)
      --resume            -Resume         (skip files already in the shards; no stale refresh)
      --index <dir>       -IndexPath      --workers <1-100>    -Workers
      --walkers <1-32>    -Walkers        --arc-workers <1-20> -ArcWorkers
      --delay <ms>        -DelayMs        -v/--verbose <0-5>   -Verbosity
      -u/--base-url <url> -BaseUrl        -t/--token <tok>     -Token
      -k/--api-key <key>  -ApiKey         -b/--basic <u:p>     -Basic

    Verbosity: 0 silent · 1 summary · 2 +periodic progress · 3 +scope/milestones
    · 4 +archive detail · 5 +debug counters.

    The index is append-only with last-wins reads; re-running appends, so run
    StartAuditEngine's index/compaction (Compress-Index) if shards grow dup-heavy.

    Conventions: UTF-8 without BOM, LF endings; non-ASCII execution glyphs are numeric
    [char] escapes (literal Unicode only in comments).
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Allow many concurrent connections and ensure TLS 1.2 (matches the other launchers).
[Net.ServicePointManager]::DefaultConnectionLimit = 256   # high enough for the aggressive worker + walker pools
[Net.ServicePointManager]::SecurityProtocol =
    [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# No-color, no-raw-key host: define the ANSI vars empty so any engine code path that
# interpolates them is StrictMode-safe, and disable the VT/raw-key capability flags.
$R = $BD = $DM = $CY = $MG = $YL = $RD = $HB = $SB = ''
$script:Vt = $false
$script:CanRawKey = $false
$script:ArcGlyph = '+'; $script:PreviewGlyph = [char]0x00B7; $script:Cut = [char]0x2026

# Shared config at script scope — read by the Core/Api/Index helpers (Get-AuthHeaders reads
# $ApiKey/$Token/$Basic; Get-ArtBase reads $BaseUrl; the walk reads $Repos). Populated per run.
$BaseUrl = ''; $ApiKey = ''; $Token = ''; $Basic = ''; $Repos = ''
$OutDir  = ''   # index build doesn't download; resolved for layout consistency only

# Verbosity level for this run (0..5); overridden by -Verbosity/-v.
$script:IndexVerbosity = 1

# Headless run-mode loads only the headless layer: Core + Api + Index. Guarded so it runs
# only when executed as a file AND the engine isn't already present (Invoke-IndexBuildPump is
# the sentinel). Paste-mode leaves $PSScriptRoot empty, so paste Core/Api/Index first.
if ($PSScriptRoot -and -not (Get-Command Invoke-IndexBuildPump -ErrorAction SilentlyContinue)) {
    foreach ($component in 'Core','Api','Index') {
        . (Join-Path $PSScriptRoot "$component.ps1")
    }
}

# ── VERBOSITY OUTPUT ──────────────────────────────────────────────────────────
function Write-V([int]$level, [string]$msg) {
    if ($script:IndexVerbosity -ge $level) { Write-Host $msg }
}

# Format a seconds count as M:SS (or H:MM:SS past an hour); '?' for unknown.
function Format-Eta([int]$seconds) {
    if ($seconds -lt 0) { return '?' }
    $ts = [TimeSpan]::FromSeconds($seconds)
    if ($ts.TotalHours -ge 1) { return ('{0}:{1:00}:{2:00}' -f [int][Math]::Floor($ts.TotalHours), $ts.Minutes, $ts.Seconds) }
    return ('{0}:{1:00}' -f $ts.Minutes, $ts.Seconds)
}

# ── ARGV PARSING (unix-style CLI) ─────────────────────────────────────────────
function ConvertFrom-IndexArgv([string[]]$tokens) {
    $p = @{}
    if ($null -eq $tokens) { return $p }
    $i = 0
    while ($i -lt $tokens.Count) {
        $t = $tokens[$i]
        switch -regex ($t) {
            '^(-F|--full)$'      { $p.Full      = $true }
            '^(-q|--query)$'     { $p.Query     = $tokens[++$i] }
            '^(-a|--archives)$'  { $p.Archives  = $true }
            '^--all-versions$'   { $p.AllVersions = $true }
            '^--skip-versions$'  { $p.AllVersions = $false }   # affirms the default (no-op)
            '^--resume$'         { $p.Resume    = $true }
            '^(-r|--repos)$'     { $p.Repos     = $tokens[++$i] }
            '^--index$'          { $p.IndexPath = $tokens[++$i] }
            '^--workers$'        { $p.Workers    = [int]$tokens[++$i] }
            '^--walkers$'        { $p.Walkers    = [int]$tokens[++$i] }
            '^--arc-workers$'    { $p.ArcWorkers = [int]$tokens[++$i] }
            '^--delay$'          { $p.DelayMs    = [int]$tokens[++$i] }
            '^(-v|--verbose)$'   { $p.Verbosity = [int]$tokens[++$i] }
            '^(-u|--base-url)$'  { $p.BaseUrl   = $tokens[++$i] }
            '^(-t|--token)$'     { $p.Token     = $tokens[++$i] }
            '^(-k|--api-key)$'   { $p.ApiKey    = $tokens[++$i] }
            '^(-b|--basic)$'     { $p.Basic     = $tokens[++$i] }
            '^(-h|--help|help)$' { $p.Help      = $true }
            default { throw "Unknown argument: $t" }
        }
        $i++
    }
    return $p
}

function Show-IndexUsage {
    Write-Host @'
ARTCA headless index builder

Usage:
  StartIndex.ps1 -F        <options>     index the entire instance
  StartIndex.ps1 -q <name> <options>     index the results of an artifact-name search

Scope (one of -F or -q is required):
  -F, --full              index the entire instance (recursive /api/storage walk)
  -q, --query <name>      index the results of this artifact-name quick-search
  -r, --repos <a,b>       restrict the scope to these repositories

Options:
  -a, --archives          also expand listable archives and index their internal entries
      --all-versions      expand EVERY version of an archive (default: skip - index only the
                          first version of each artifact, by version-normalized filename)
      --resume            skip files already present in the shards (finish/extend an interrupted
                          build). NOTE: does NOT refresh stale rows - the index is a point-in-time
                          snapshot; --resume only adds what's missing.
      --index <dir>       local index directory to write (default ./output/<host>/index)
      --workers <1-100>   parallel metadata-fetch workers (default 32; long-lived worker loops)
      --walkers <1-32>    parallel storage-walk discovery runspaces (default 8; feed the workers -
                          raise alongside --workers so discovery doesn't starve them)
      --arc-workers <1-20> parallel archive-expansion workers (default 6)
      --delay <ms>        per-request politeness delay (default 0; the adaptive throttle backs off
                          automatically on 429/503)
  -v, --verbose <0-5>     0 silent · 1 summary · 2 progress · 3 milestones · 4 detail · 5 debug (default 1)

Auth:
  -u, --base-url <url>    Artifactory base URL (required)
  -t, --token <tok>       bearer token        -k, --api-key <key>   JFrog API key
  -b, --basic <user:pw>   basic auth
'@
}

# ── ENTRY ─────────────────────────────────────────────────────────────────────
function Invoke-IndexBuild {
    param(
        [switch]$Full, [string]$Query, [switch]$Archives, [switch]$AllVersions, [switch]$Resume, [string]$Repos,
        [string]$IndexPath, [int]$Workers, [int]$Walkers, [int]$ArcWorkers, [int]$DelayMs, [int]$Verbosity,
        [string]$BaseUrl, [string]$ApiKey, [string]$Token, [string]$Basic
    )
    $O = $PSBoundParameters
    if ($O.ContainsKey('Verbosity')) { $script:IndexVerbosity = [int]$O['Verbosity'] }
    if ($O.ContainsKey('BaseUrl'))   { $script:BaseUrl = [string]$O['BaseUrl'] }
    if ($O.ContainsKey('ApiKey'))    { $script:ApiKey  = [string]$O['ApiKey'] }
    if ($O.ContainsKey('Token'))     { $script:Token   = [string]$O['Token'] }
    if ($O.ContainsKey('Basic'))     { $script:Basic   = [string]$O['Basic'] }
    if ($O.ContainsKey('Repos'))     { $script:Repos   = [string]$O['Repos'] }
    if (-not $script:BaseUrl) { throw 'A base URL is required (-u/--base-url).' }
    $script:BaseUrl = $script:BaseUrl.TrimEnd('/')

    $full     = [bool]($O.ContainsKey('Full') -and $O['Full'])
    $archives = [bool]($O.ContainsKey('Archives') -and $O['Archives'])
    $query    = if ($O.ContainsKey('Query')) { [string]$O['Query'] } else { '' }
    # Skip-versions defaults on (set in Index.ps1); --all-versions/-AllVersions turns it off so
    # every version of each archive is expanded. (--skip-versions passes AllVersions=$false.)
    if ($O.ContainsKey('AllVersions')) { $script:ArcSkipVersions = -not [bool]$O['AllVersions'] }
    if (-not $full -and -not $query) { throw 'Specify a scope: -F/--full or -q/--query <name>.' }
    if ($full -and $query)           { throw 'Choose one scope: -F/--full OR -q/--query, not both.' }

    # Output layout + index dir (output/<host>/index unless --index overrides).
    $script:OutDirExplicit = $false
    Resolve-OutputPaths
    if ($O.ContainsKey('IndexPath') -and $O['IndexPath']) { Set-IndexPath ([string]$O['IndexPath']) }
    Resolve-IndexPath
    $script:IndexEnabled = $true     # building the index is the whole point
    Import-Index $script:IndexPath   # migrations + archive skip-set

    # Throttle. --workers scales the metadata-fetch worker loops; --walkers scales the parallel
    # storage-walk discovery runspaces that feed them (raise together so discovery doesn't starve
    # the workers). --arc-workers scales archive expansion (each tree is now flattened in its
    # worker, so it's no longer the main-thread stall it once was). --delay is a per-request
    # politeness sleep; the adaptive throttle (B) also backs all pools off on 429/503.
    if ($O.ContainsKey('Workers') -and [int]$O['Workers'] -gt 0) {
        $script:IdxThrottle.MaxConcurrent = [Math]::Max(1, [Math]::Min(100, [int]$O['Workers']))
    }
    if ($O.ContainsKey('Walkers') -and [int]$O['Walkers'] -gt 0) {
        $script:IdxWalkConcurrency = [Math]::Max(1, [Math]::Min(32, [int]$O['Walkers']))
    }
    # Build-mode arc defaults: 6 workers, no pacing - safe now the per-archive tree is flattened in
    # the worker (not the main thread). The interactive [w] walk keeps its gentler 3/150ms defaults.
    $script:ArcThrottle.MaxConcurrent =
        if ($O.ContainsKey('ArcWorkers') -and [int]$O['ArcWorkers'] -gt 0) { [Math]::Max(1, [Math]::Min(20, [int]$O['ArcWorkers'])) }
        else { 6 }
    if ($O.ContainsKey('DelayMs') -and [int]$O['DelayMs'] -ge 0) {
        $script:IdxThrottle.MinIntervalMs = [int]$O['DelayMs']; $script:ArcThrottle.MinIntervalMs = [int]$O['DelayMs']
    } else {
        $script:ArcThrottle.MinIntervalMs = 0
    }
    $script:IdxResume = ($O.ContainsKey('Resume') -and [bool]$O['Resume'])   # (F) skip already-indexed files

    $scopeLabel = if ($full) { 'entire instance' } else { "search: $query" }
    $arcLabel   = if ($archives) { ' (+ listable archives)' } else { '' }
    Write-V 1 "Building index for $scopeLabel$arcLabel"
    Write-V 2 "  index dir: $($script:IndexPath)"
    Write-V 5 ("  settings: archives=$archives skip-versions=$($script:ArcSkipVersions) resume=$($script:IdxResume) workers=$($script:IdxThrottle.MaxConcurrent) walkers=$($script:IdxWalkConcurrency) arc-workers=$($script:ArcThrottle.MaxConcurrent) delay=$($script:IdxThrottle.MinIntervalMs)ms queue-cap=$($script:IdxQueueCap) repos='$($script:Repos)'")

    if ($full) {
        $walkRepos = @(Get-ArcSearchWalkRepos)
        if ($walkRepos.Count -eq 0) {
            Write-V 1 'Nothing to index: no readable repositories (anonymous access may be denied /api/repositories; try -r/--repos).'
            return
        }
        $repoPreview = (@($walkRepos | Select-Object -First 12) -join ', ')
        if ($walkRepos.Count -gt 12) { $repoPreview += ', ...' }
        Write-V 3 "  walking $($walkRepos.Count) repo(s): $repoPreview"
        if (-not (Start-IndexBuild $true $archives $null)) {
            Write-V 1 'Nothing to index.'
            return
        }
    } else {
        Write-V 1 "Searching for '$query'..."
        $res = Search-Artifacts $query
        if ($res.Error) { throw "Search failed: $($res.Error)" }
        Write-V 2 "  $($res.Total) result(s) from the REST quick-search"
        [void](Start-IndexBuild $false $archives $res.Items)
    }

    # Drive to completion, emitting progress per verbosity. Levels: 0 silent · 1 summary ·
    # 2 +periodic progress · 3 +scope/milestones · 4 +archive detail · 5 +debug counters.
    $start    = [DateTime]::UtcNow
    $lastTick = [DateTime]::MinValue
    $lastGc   = [DateTime]::UtcNow
    $lastFlush = [DateTime]::UtcNow
    $arcBase  = $script:ArcIndexedArchives.Count   # prior-run archives (skip-set); subtract for this run's archive progress
    while ($script:IdxBuildState -ne 'done') {
        Invoke-IndexBuildPump
        # Reclaim churn periodically: parsing thousands of archive trees + building entries +
        # CSV rows generates large transient garbage that .NET Framework is slow to return to
        # the OS, so the working set climbs even though nothing is logically retained. A forced
        # gen-2 collection on a cadence keeps it bounded over a long batch run.
        if (([DateTime]::UtcNow - $lastGc).TotalSeconds -ge 20) {
            [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers()
            $lastGc = [DateTime]::UtcNow
        }
        # Periodically flush buffered shard writes (D) so rows reach disk incrementally - a long
        # build then survives a kill with most progress persisted (and --resume can skip it).
        if (([DateTime]::UtcNow - $lastFlush).TotalSeconds -ge 5) {
            Flush-IndexWrites
            $lastFlush = [DateTime]::UtcNow
        }
        if ($script:IndexVerbosity -ge 2 -and ([DateTime]::UtcNow - $lastTick).TotalSeconds -ge 1) {
            # The headline fraction is the PER-FILE METADATA pipeline: $done = files whose
            # /api/storage metadata has been fetched + top-level row written; $denom = files the
            # storage walk has DISCOVERED so far ($IdxSeen). In location mode every file is seeded
            # up front, so $denom is the true total and the % is exact from the start. In full mode
            # the walk keeps discovering, so it's "of what's found so far" and only becomes the true
            # total once the walk finishes (no count is available up front - Artifactory gives none
            # without enumerating, and AQL is off the table). ETA is shown only when $denom is
            # stable (walk done); rate is files/sec overall. NOTE: archives are a SUBSET of these
            # files (counted here for their own metadata) AND are separately expanded into entries -
            # that work is tracked by the "archives=" count, not this fraction; "rows" is the index
            # rows written (top-level + every archive entry), which is why it far exceeds the file
            # count.
            # Resolved = fetched (IdxDone) + skipped-as-already-indexed (IdxSkipped, resume mode); both
            # are counted in $denom ($IdxSeen), so the fraction only reaches 100% when we add skips back.
            $done    = $script:IdxDone + $script:IdxSkipped
            $denom   = $script:IdxSeen.Count
            $walking = Test-IndexWalkActive
            $arcBusy = $archives -and ($script:ArcQueue.Count -gt 0 -or $script:ArcJobs.Count -gt 0)
            $elapsed = ([DateTime]::UtcNow - $start).TotalSeconds
            $rate    = if ($elapsed -gt 0) { $done / $elapsed } else { 0 }
            $pct     = if ($denom -gt 0) { [int][Math]::Floor($done * 100.0 / $denom) } else { 0 }
            # Archive-tail ETA: once the walk + files are done, no more archives are discovered,
            # so ArcQueue+ArcJobs IS the true remaining count and we have a completion rate -
            # the one phase where an archive ETA is honest (there's no upfront archive total).
            $status =
                if ($walking)                              { '(walking - discovered total still rising)' }
                elseif ($done -lt $denom -and $rate -gt 0) { 'ETA ' + (Format-Eta ([int][Math]::Ceiling(($denom - $done) / $rate))) }
                elseif ($arcBusy) {
                    $arcLeft  = $script:ArcQueue.Count + $script:ArcJobs.Count
                    $arcDone2 = $script:ArcIndexedArchives.Count - $arcBase
                    $arcRate  = if ($elapsed -gt 0) { $arcDone2 / $elapsed } else { 0 }
                    $arcEta   = if ($arcRate -gt 0) { ', ETA ' + (Format-Eta ([int][Math]::Ceiling($arcLeft / $arcRate))) } else { '' }
                    "(expanding archives $arcDone2/$($arcDone2 + $arcLeft)$arcEta)"
                }
                else { '' }
            $rateStr = if ($rate -gt 0) { ' | {0:0.0} files/s' -f $rate } else { '' }
            $arc  = if ($archives -and $script:IndexVerbosity -ge 4) { " | archives expanded=$($script:ArcIndexedArchives.Count)" } else { '' }
            $dbg  = if ($script:IndexVerbosity -ge 5) {
                $aq = if ($archives) { " | arc-expand queued=$($script:ArcQueue.Count) active=$($script:ArcJobs.Count)" } else { '' }
                "  [meta-fetch queued=$($script:IdxMetaQueue.Count) workers=$($script:IdxCtl.Target)/$($script:IdxWorkers.Count)$aq]"
            } else { '' }
            $skip = if ($script:IdxSkipped -gt 0) { " | $($script:IdxSkipped) already-indexed skipped" } else { '' }
            Write-Host ("  ...metadata fetched for $done/$denom discovered files ($pct%), $($script:IndexCount) index rows$rateStr$skip $status$arc$dbg".TrimEnd())
            $lastTick = [DateTime]::UtcNow
        }
        Start-Sleep -Milliseconds 100
    }
    Stop-IndexBuild

    $secs = [int]([DateTime]::UtcNow - $start).TotalSeconds
    $skipNote = if ($script:IdxSkipped -gt 0) { " ($($script:IdxSkipped) already-indexed file(s) skipped via --resume)" } else { '' }
    Write-V 1 ''
    Write-V 1 ("Index build complete in ${secs}s: metadata fetched for $($script:IdxDone) file(s)$skipNote, $($script:IndexCount) index row(s) written this run (top-level + archive entries).")
    if ($archives) { Write-V 1 ("  archives expanded (incl. prior runs): $($script:ArcIndexedArchives.Count)") }
    Write-V 2 "  index: $($script:IndexPath)"
}

# ── DISPATCH (script-file invocation) ─────────────────────────────────────────
if ($env:ARTCA_NOMAIN) { return }
if ($args.Count -eq 0) { Show-IndexUsage; return }
try {
    $splat = ConvertFrom-IndexArgv @($args)
} catch {
    Write-Host "Error: $($_.Exception.Message)`n"
    Show-IndexUsage
    return
}
if ($splat.ContainsKey('Help')) { Show-IndexUsage; return }
Invoke-IndexBuild @splat
