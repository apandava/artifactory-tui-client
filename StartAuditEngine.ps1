#Requires -Version 5.1
<#
.SYNOPSIS
    Non-interactive (headless) credential/secret audit of a JFrog Artifactory
    instance — the third run-mode of the ARTCA tool, with no TUI.

.DESCRIPTION
    Drives the same audit engine the TUI uses (AuditEngine.ps1), but from the command
    line. The audit sources its work ONLY from the local index (the per-repo CSV shards +
    archive buckets under output/<host>/index that StartIndex.ps1 builds) — it does NO
    searching or discovery of its own, so an index must already exist (a partial one is
    fine; it audits whatever rows are present). The index carries size/modified, so a
    Tier-1 audit fires ZERO requests; only Tier-2 content scanning (and downloading) hit
    the server. Two verbs:

      audit     Classify every indexed artifact (and indexed archive-internal entry) with
                the ruleset. By default it CATALOGUES matches to audit-log.csv (rule +
                severity, blank Hash/Timestamp) without downloading. With --download [all]
                it also DOWNLOADS the matching findings (dedup/rename/hash like the TUI's
                "download all") -> download-log.csv; --download <sev,...> (e.g. high,medium)
                downloads only those severities; --download count catalogues and prints the
                per-severity count + total size of the would-be download set (no download).
                With -s/--from-log <file> it
                skips auditing entirely and just downloads every file listed in a prior
                audit-log.csv. Per-repo matches are also written through to
                audit/<repo>-matches.csv as they are found.
                Tier-2 (content scanning) is a two-phase, resumable, worklist-driven flow:
                a Tier-1 pass writes tier2-pending.csv listing every file Tier-2 would
                content-inspect, then a pass content-scans it (resumable via a .progress
                cursor: pause/crash/cancel and re-run to continue). -2/--tier2 does both in
                one run; --defer-tier2 writes the worklist and stops; --tier2-resume <file>
                content-scans an existing worklist later.
      search    Run the public quick-search and, with -w/--walk-archives, also walk the
                instance's listable archives and add internal entries whose name matches
                the query, writing a results CSV. Reuses + grows the persistent local index
                (a per-instance directory of per-repo CSV shards) unless --no-index.

    Run as a script with unix-style flags:
      .\StartAuditEngine.ps1 audit -u https://art.example.com -2 -v 3
      .\StartAuditEngine.ps1 audit -u https://art.example.com --defer-tier2 -v 2
      .\StartAuditEngine.ps1 audit -u https://art.example.com --tier2-resume tier2-pending.csv -v 2
      .\StartAuditEngine.ps1 audit -u https://art.example.com -s audit-log.csv

    Or paste Core.ps1, Api.ps1, AuditEngine.ps1, Index.ps1 then this file into a console
    and call the entry functions with native parameters:
      Invoke-Audit -BaseUrl https://art.example.com -Tier2 -Verbosity 3
      Invoke-Audit -BaseUrl https://art.example.com -DeferTier2 -OutDir out
      Invoke-Audit -BaseUrl https://art.example.com -Tier2Resume tier2-pending.csv

    Flag <-> parameter map:
      -r/--repos <list>   -Repos          --repo-types <list>  -RepoTypes
      --all-repos         -RepoTypes all  -2/--tier2           -Tier2
      --defer-tier2       -DeferTier2     --tier2-resume <f>   -Tier2Resume
      --download [all|count|<sev,...>]    -Download  (default 'all'; omitted = catalogue only)
      -x/--exclude <globs>                -Exclude
      -s/--from-log <f>   -FromLog        --index <dir>        -IndexPath
      -o/--out <dir>      -OutDir         -v/--verbose <0-5>   -Verbosity
      --cap <bytes>       -Cap            --workers <1-10>     -Workers
      --delay <ms>        -DelayMs
      -u/--base-url <url> -BaseUrl        -t/--token <tok>     -Token
      -k/--api-key <key>  -ApiKey         -b/--basic <u:p>     -Basic
    (search verb also: -q/--query, -w/--walk-archives, --all-versions, --offline, --no-index.)

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

# Compact human duration for the ETA, coarsening as it grows: 45s / 3m 12s / 2h 14m / 1d 6h.
function Format-Duration([int]$secs) {
    if ($secs -lt 0) { $secs = 0 }
    if ($secs -lt 60)    { return "${secs}s" }
    if ($secs -lt 3600)  { return ('{0}m {1}s' -f [int][Math]::Floor($secs / 60), ($secs % 60)) }
    if ($secs -lt 86400) { return ('{0}h {1}m' -f [int][Math]::Floor($secs / 3600), [int][Math]::Floor(($secs % 3600) / 60)) }
    return ('{0}d {1}h' -f [int][Math]::Floor($secs / 86400), [int][Math]::Floor(($secs % 86400) / 3600))
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
            '^(-r|--repos)$'         { $p.Repos        = $tokens[++$i] }
            '^--repo-types$'         { $p.RepoTypes    = $tokens[++$i] }
            '^--all-repos$'          { $p.RepoTypes    = 'all' }
            '^(-2|--tier2)$'         { $p.Tier2        = $true }
            '^--defer-tier2$'        { $p.DeferTier2   = $true }
            '^--tier2-resume$'       { $p.Tier2Resume  = $tokens[++$i] }
            '^--download$'           {
                # Optional value: 'all' (default), 'count', or a severity list (e.g. high,medium).
                # Consume the next token only when it isn't another flag.
                $nxt = if (($i + 1) -lt $tokens.Count) { $tokens[$i + 1] } else { $null }
                if ($nxt -and ($nxt -notmatch '^-')) { $p.Download = $tokens[++$i] } else { $p.Download = 'all' }
            }
            '^(-w|--walk-archives)$' { $p.WalkArchives = $true }
            '^--all-versions$'       { $p.AllVersions  = $true }
            '^--skip-versions$'      { $p.AllVersions  = $false }   # affirms the default (no-op)
            '^(-x|--exclude)$'       { $p.Exclude      = $tokens[++$i] }
            '^(-s|--from-log)$'      { $p.FromLog      = $tokens[++$i] }
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
  StartAuditEngine.ps1 audit  <options>             Tier-1 audit of the index -> audit-log.csv
  StartAuditEngine.ps1 audit  -2 <options>          Tier-1 + Tier-2 content scan (one run)
  StartAuditEngine.ps1 audit  --defer-tier2 <opts>  Tier-1 + write a Tier-2 worklist, then stop
  StartAuditEngine.ps1 audit  --tier2-resume <file> content-scan a worklist (resumable)
  StartAuditEngine.ps1 audit  --download <options>  audit + download all matches -> download-log.csv
  StartAuditEngine.ps1 audit  --download count      audit + show the per-severity download breakdown
  StartAuditEngine.ps1 audit  --download high,medium   download only those severities
  StartAuditEngine.ps1 audit  -s audit-log.csv      download a previous audit-log (no audit)
  StartAuditEngine.ps1 search <options>             quick-search (+ optional archive walk) to a CSV

The audit reads ONLY the local index (no searching/discovery) - build one first with
StartIndex.ps1. It audits every indexed artifact AND indexed archive-internal entry. Tier-2 is a
two-phase flow: a Tier-1 pass writes a worklist of every file Tier-2 would content-inspect
(tier2-pending.csv), then a resumable pass content-scans it. `-2` does both in one run; split them
with --defer-tier2 (write the list) and --tier2-resume (scan it later, survives pause/crash/cancel).

Audit options (audit verb):
  -2, --tier2             Tier-2: also fetch file content and scan it (Tier-1 -> worklist -> scan)
      --defer-tier2       Tier-1 only, but write the Tier-2 worklist (tier2-pending.csv) and stop
      --tier2-resume <f>  content-scan an existing worklist; resumable via its .progress cursor
      --download [spec]   download matched findings (no flag = catalogue only). spec: 'all' (default),
                          a severity list e.g. 'high,medium' (critical/high/medium/low/informational,
                          short forms c/h/m/l/i ok), or 'count' = catalogue + print the per-severity
                          count and total size of the would-be download set without downloading
  -s, --from-log <file>   skip auditing; download every row of a prior audit-log.csv (fills hashes)
  -r, --repos <a,b>       restrict to these indexed repositories (bypasses the type filter)
      --repo-types <list> indexed repo rclasses to audit (default: local). e.g. local,remote or
                          'all' (every non-virtual repo). --all-repos is shorthand for 'all'.
  -x, --exclude <globs>   comma/space globs to exclude from the set (e.g. "*.xml,*test*")
      --index <dir>       local index directory to read (default ./output/<host>/index)
      --cap <bytes>       max file size to content-scan (default 2 MB)
      --workers <1-10>    parallel fetch workers (default 3)
      --delay <ms>        delay between request launches (default 150)

Search options (search verb):
  -q, --query <name>      the artifact name to search for
  -w, --walk-archives     also walk listable archives and add matching internal entries
      --all-versions      walk EVERY version of an archive (default: skip - walk only the
                          first version of each artifact, by version-normalized filename)
      --offline <mode>    don't query the server for search; use the local index as the catalogue.
                          'index' still fetches archive listings on demand; 'all' makes no
                          requests at all (matches come only from the index).
      --index <path>      local index directory to use/update (default ./output/<host>/index)
      --no-index          don't read or write the index
  -o, --out <file|dir>    results CSV (default search-results.csv under the out dir)

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
    # Repo-type scope: default LOCAL only (set in Api.ps1); --repo-types widens the auto-enumeration.
    if ($O.ContainsKey('RepoTypes')) { Set-RepoTypeScope ([string]$O['RepoTypes']) }
    if (-not $script:BaseUrl) { throw 'A base URL is required (-u/--base-url).' }
    $script:BaseUrl = $script:BaseUrl.TrimEnd('/')
    Resolve-RunOutput $O

    # Local index to read (the audit's only work source). An explicit --index wins; otherwise
    # the per-instance default (output/<host>/index). The index is read-only here (we don't grow
    # it), but $IndexEnabled gates a couple of read helpers, so leave it on.
    $script:IndexEnabled = $true
    if ($O.ContainsKey('IndexPath') -and $O['IndexPath']) { Set-IndexPath ([string]$O['IndexPath']) }
    Resolve-IndexPath

    # Engine settings (Tier 1/2 persists across Reset-AuditEngine; cap and throttle are read live
    # by the dispatcher). The index pass (Phase A) is ALWAYS Tier-1: inline `-2` runs Tier-2 as a
    # second phase over the emitted worklist (Start-AuditTier2List), so the index pass itself never
    # content-fetches. Archive WALKING is forced OFF: the index already contains expanded archive
    # entries, so a top-level archive must NOT trigger a live treebrowser expansion (discovery).
    $script:AuditTier2        = $false
    $script:AuditWalkArchives = $false
    # Headless never outputs the synthetic skipped/oversize findings (they're default-excluded and
    # never written to a CSV), so don't build them - at multi-million scale that's the difference
    # between holding one finding object per relay-eligible file and holding none.
    $script:AuditEmitSkipped  = $false
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
    $lastGc   = [DateTime]::UtcNow
    while ($script:AuditState -ne 'done' -and $script:AuditState -ne 'cancelled' -and $script:AuditState -ne 'idle') {
        Invoke-AuditPump
        # Reclaim the transient per-row churn (Convert-UriToItem strings, parsed rows) promptly so
        # the working set tracks the bounded live set, not what .NET is slow to return on a long run.
        if (([DateTime]::UtcNow - $lastGc).TotalSeconds -ge 10) { [GC]::Collect(); $lastGc = [DateTime]::UtcNow }
        if ($script:AuditVerbosity -ge 3) {
            while ($printed -lt $script:AuditFindings.Count) {
                $f = $script:AuditFindings[$printed]; $printed++
                $loc = (@($f.Repo, $f.Path, $f.Name) | Where-Object { "$_" -ne '' }) -join '/'
                Write-Host ("  [{0}] {1} - {2}" -f $f.Sev, $loc, $f.AllRules)
            }
        }
        if ($script:AuditVerbosity -ge 2 -and ([DateTime]::UtcNow - $lastTick).TotalSeconds -ge 1) {
            $walk = if ((Test-AuditWalkActive) -or (Test-AuditIndexWalkActive)) { ' (reading index)' } else { '' }
            # Use the known total (Tier-2 worklist) as the denominator when set; otherwise $AuditEnq,
            # which grows as the index walk discovers items.
            $den = if ($script:AuditEnqTotal -gt 0) { $script:AuditEnqTotal } else { $script:AuditEnq }
            # ETA only when the total is known (Tier-2 worklist). Use the AVERAGE rate this run
            # (done/elapsed) - far steadier than the rolling FPS that drives the displayed rate.
            $eta = ''
            $rem = $den - $script:AuditDone
            $elapsed = ([DateTime]::UtcNow - $script:AuditStartedAt).TotalSeconds
            if ($script:AuditEnqTotal -gt 0 -and $rem -gt 0 -and $script:AuditDone -gt 0 -and $elapsed -ge 1) {
                $avg = $script:AuditDone / $elapsed
                if ($avg -gt 0) { $eta = "  ETA $(Format-Duration ([int][Math]::Ceiling($rem / $avg)))" }
            }
            Write-Host ("  ...audited $($script:AuditDone)/$den at $($script:AuditRate.FPS)/s, found $($script:AuditFindings.Count)$eta$walk")
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

# Phase A: a Tier-1 audit of the local index to completion, applying excludes. Sources work ONLY from
# the index shards (no searching/discovery); requires an index to be present (a partial one is fine).
# When $emitList is set (inline -2 or --defer-tier2), every relay-eligible file is written through to
# the worklist for a Tier-2 pass. Returns the worklist path (or '').
function Invoke-HeadlessAudit([hashtable]$O, [bool]$emitList = $false) {
    Initialize-AuditRunConfig $O
    Write-V 5 ("Settings: tier=1$(if ($emitList) { '+worklist' } else { '' }) cap=$script:AuditCap workers=$($script:AuditThrottle.MaxConcurrent) delay=$($script:AuditThrottle.MinIntervalMs)ms index=$script:IndexPath out=$script:OutDir")

    # Load the index (lightweight: migrations + the small re-walk skip-set; nothing bulk-loaded).
    if (-not (Test-Path -LiteralPath $script:IndexPath)) {
        throw "No local index found at $($script:IndexPath). Build one first with StartIndex.ps1 (e.g. .\StartIndex.ps1 -F -u $($script:BaseUrl))."
    }
    Import-Index $script:IndexPath
    if (-not $Repos -and @(Get-IndexedRepos).Count -eq 0) {
        throw "The local index at $($script:IndexPath) is empty (no repos). Build it first with StartIndex.ps1."
    }

    Write-V 1 'Auditing the local index...'
    if (-not (Start-AuditIndex)) {
        Write-V 1 'No in-scope indexed repos to audit.'
    }

    # Open the Tier-2 worklist AFTER Start-AuditIndex's reset (which doesn't touch the worklist), so
    # rows are written through during the pump below. Reset-AuditEngine cleared the path either way.
    $wl = ''
    if ($emitList) { $wl = Join-Path $script:OutDir 'tier2-pending.csv'; Open-AuditTier2List $wl }

    # Excludes must be set AFTER the launch (Reset-AuditEngine clears them); the run
    # honours them for new findings and Update-AuditExcludedHeadless catches the rest.
    if ($O.ContainsKey('Exclude')) { Set-AuditExcludes ([string]$O['Exclude']) }

    Invoke-AuditPumpToDone
    Update-AuditExcludedHeadless
    if ($emitList) { Close-AuditTier2List }
    return $wl
}

# Map a user severity token (case-insensitive; full name or short form) to its canonical name, or
# $null if unrecognized.
function Resolve-AuditSev([string]$tok) {
    switch ("$tok".Trim().ToLower()) {
        'critical'      { 'Critical' }      'crit' { 'Critical' }      'c' { 'Critical' }
        'high'          { 'High' }          'h'    { 'High' }
        'medium'        { 'Medium' }        'med'  { 'Medium' }        'm' { 'Medium' }
        'low'           { 'Low' }           'l'    { 'Low' }
        'informational' { 'Informational' } 'info' { 'Informational' } 'inf' { 'Informational' } 'i' { 'Informational' }
        default         { $null }
    }
}
# Parse a comma/space severity list into a canonical-name set; throws on an unknown token.
function Resolve-AuditSevSet([string]$spec) {
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($t in @("$spec" -split '[,\s]+')) {
        if (-not $t) { continue }
        $s = Resolve-AuditSev $t
        if (-not $s) { throw "Unknown --download severity '$t'. Valid: all, count, or any of critical,high,medium,low,informational." }
        [void]$set.Add($s)
    }
    return $set
}
# Print a per-severity count + total size breakdown of a candidate set (the would-be download).
function Write-AuditDownloadBreakdown($cands) {
    $order = 'Critical','High','Medium','Low','Informational'
    $cnt = @{}; $bytes = @{}; $unk = @{}
    foreach ($s in $order) { $cnt[$s] = 0; $bytes[$s] = 0L; $unk[$s] = 0 }
    foreach ($f in @($cands)) {
        $s = [string]$f.Sev; if (-not $cnt.ContainsKey($s)) { $cnt[$s] = 0; $bytes[$s] = 0L; $unk[$s] = 0 }
        $cnt[$s]++
        if ($f.Size -ge 0) { $bytes[$s] += [long]$f.Size } else { $unk[$s]++ }
    }
    Write-Host ''
    Write-Host 'Download set (included, not yet downloaded):'
    $tc = 0; $tb = 0L; $tu = 0
    foreach ($s in $order) {
        if (-not $cnt.ContainsKey($s) -or $cnt[$s] -eq 0) { continue }
        $u = if ($unk[$s] -gt 0) { " (+$($unk[$s]) unknown size)" } else { '' }
        Write-Host ("  {0,-14} {1,7}   {2}{3}" -f $s, $cnt[$s], (Format-Size $bytes[$s]), $u)
        $tc += $cnt[$s]; $tb += $bytes[$s]; $tu += $unk[$s]
    }
    $u = if ($tu -gt 0) { " (+$tu unknown size)" } else { '' }
    Write-Host ("  {0,-14} {1,7}   {2}{3}" -f 'Total', $tc, (Format-Size $tb), $u)
}
# Write the consolidated audit-log.csv (scrape-style: blank Hash/Timestamp) from a candidate set.
function Write-AuditCatalogue($cands) {
    foreach ($f in @($cands)) {
        $arch = if ($f.InArchive) { [string]$f.ArchiveName } else { '' }
        $sz   = if ($f.Size -ge 0) { [long]$f.Size } else { -1 }
        Write-DownloadLog $script:OutDir ([string]$f.Name) ([string]$f.Repo) ([string]$f.Path) $arch `
            $sz ([string]$f.Modified) ([string]$f.Url) ([string]$f.Sev) ([string]$f.AllRules) '' 'audit-log.csv' -Scrape
    }
    Write-V 1 ("Wrote $(@($cands).Count) finding(s) to " + (Join-Path $script:OutDir 'audit-log.csv'))
}

# Write the included findings out per the $downloadSpec:
#   ''        (no --download)         -> CATALOGUE to audit-log.csv only.
#   'count'                           -> catalogue + print the per-severity download breakdown (no download).
#   'all'                             -> DOWNLOAD every included finding (download-log.csv).
#   '<sev,...>' (e.g. high,medium)    -> download only findings of those severities.
# Per-repo audit/<repo>-matches.csv are written through during the run regardless.
function Complete-AuditOutput([string]$downloadSpec) {
    $cands = @(Get-AuditIncludedCandidates)
    Write-AuditSummary
    $spec = "$downloadSpec".Trim().ToLower()

    if (-not $spec -or $spec -eq 'count') {
        Write-AuditCatalogue $cands
        if ($spec -eq 'count') { Write-AuditDownloadBreakdown $cands }
        return
    }

    $sel = $cands
    if ($spec -ne 'all') {
        $set = Resolve-AuditSevSet $spec
        $sel = @($cands | Where-Object { $set.Contains([string]$_.Sev) })
    }
    Write-AuditDownloadBreakdown $sel
    if ($sel.Count -eq 0) { Write-V 1 'No findings to download.'; return }
    $res = Invoke-AuditDownloadSet $sel
    Write-V 1 (Get-DedupDoneLine $res)
    Write-V 1 ('Logged to ' + (Join-Path $script:OutDir 'download-log.csv'))
}

# Download every file listed in a prior audit-log.csv, no auditing. The catalogue left Hash and
# Timestamp blank; this recomputes them and writes download-log.csv with both filled.
function Invoke-DownloadFromLog([string]$file) {
    if (-not (Test-Path -LiteralPath $file)) { throw "Audit-log file not found: $file" }
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

# Apply just the base config (verbosity, auth, repos, out dir) for the paths that don't run the index
# audit (-FromLog, --tier2-resume). $BaseUrl is required only when downloading/fetching is involved.
function Initialize-AuditBaseConfig([hashtable]$O, [bool]$requireBaseUrl = $true) {
    if ($O.ContainsKey('Verbosity')) { $script:AuditVerbosity = [int]$O['Verbosity'] }
    if ($O.ContainsKey('BaseUrl'))   { $script:BaseUrl = ([string]$O['BaseUrl']).TrimEnd('/') }
    if ($O.ContainsKey('ApiKey'))    { $script:ApiKey  = [string]$O['ApiKey'] }
    if ($O.ContainsKey('Token'))     { $script:Token   = [string]$O['Token'] }
    if ($O.ContainsKey('Basic'))     { $script:Basic   = [string]$O['Basic'] }
    if ($O.ContainsKey('Repos'))     { $script:Repos   = [string]$O['Repos'] }
    if ($requireBaseUrl -and -not $script:BaseUrl) { throw 'A base URL is required (-u/--base-url).' }
    if ($script:BaseUrl) { $script:BaseUrl = $script:BaseUrl.TrimEnd('/') }
    Resolve-RunOutput $O
    if ($O.ContainsKey('Cap') -and [long]$O['Cap'] -gt 0)        { $script:AuditCap = [long]$O['Cap'] }
    if ($O.ContainsKey('Workers') -and [int]$O['Workers'] -gt 0) { $script:AuditThrottle.MaxConcurrent = [Math]::Max(1, [Math]::Min(10, [int]$O['Workers'])) }
    if ($O.ContainsKey('DelayMs') -and [int]$O['DelayMs'] -ge 0) { $script:AuditThrottle.MinIntervalMs = [int]$O['DelayMs'] }
}

# ── ENTRY FUNCTION ────────────────────────────────────────────────────────────
# The single audit entry. Tier-2 is a two-phase, resumable, worklist-driven flow:
#   (default Tier-1)   classify the index, catalogue matches to audit-log.csv (or --download).
#   -Tier2 / -2        Phase A (Tier-1 + worklist) then Phase B (content-scan the worklist) in one run.
#   -DeferTier2        Phase A only: Tier-1 + write the worklist (tier2-pending.csv), then stop.
#   -Tier2Resume <f>   Phase B only: content-scan an existing worklist, resumable via its .progress cursor.
#   -FromLog <f>       skip auditing; just download the rows of a prior audit-log.csv.
function Invoke-Audit {
    param(
        [string]$Repos, [string]$RepoTypes,
        [switch]$Tier2, [string]$Download, [string]$Exclude,
        [string]$IndexPath, [long]$Cap, [int]$Workers, [int]$DelayMs,
        [string]$OutDir, [int]$Verbosity,
        [string]$BaseUrl, [string]$ApiKey, [string]$Token, [string]$Basic,
        [string]$FromLog, [switch]$DeferTier2, [string]$Tier2Resume
    )
    $O = $PSBoundParameters

    # -FromLog: skip auditing, just download a prior audit-log.csv.
    if ($O.ContainsKey('FromLog') -and $O['FromLog']) {
        Initialize-AuditBaseConfig $O $true
        Invoke-DownloadFromLog ([string]$O['FromLog'])
        return
    }

    # -Tier2Resume: Phase B over an existing worklist (no index needed). Resumable via its cursor.
    if ($O.ContainsKey('Tier2Resume') -and $O['Tier2Resume']) {
        Initialize-AuditBaseConfig $O $true
        $script:AuditEmitSkipped = $false
        Write-V 1 "Resuming Tier-2 over worklist $($O['Tier2Resume'])..."
        if (-not (Start-AuditTier2List ([string]$O['Tier2Resume']))) {
            throw "Worklist not found or empty: $($O['Tier2Resume'])"
        }
        if ($O.ContainsKey('Exclude')) { Set-AuditExcludes ([string]$O['Exclude']) }
        Invoke-AuditPumpToDone
        Update-AuditExcludedHeadless
        Complete-AuditOutput $Download
        return
    }

    if ($DeferTier2 -and $Tier2) { throw 'Use either -2/--tier2 (scan now) or --defer-tier2 (write the worklist and stop), not both.' }

    if ($Tier2) {
        # If a worklist from a prior interrupted -2 (or a --defer-tier2) is already on disk, RESUME it
        # from its .progress cursor instead of rebuilding it with a fresh Tier-1 pass. Resolve the
        # output layout first so we know where the default worklist would live.
        Initialize-AuditBaseConfig $O $true
        $wlPath = Join-Path $script:OutDir 'tier2-pending.csv'
        if (Test-Path -LiteralPath $wlPath) {
            $cur = Read-AuditT2Cursor $wlPath
            Write-V 1 "Found an existing Tier-2 worklist ($wlPath; $cur row(s) already done) - resuming. Delete it to force a fresh scan."
            $script:AuditEmitSkipped = $false
            if (Start-AuditTier2List $wlPath) {   # fresh (no -KeepFindings); cursor honoured
                if ($O.ContainsKey('Exclude')) { Set-AuditExcludes ([string]$O['Exclude']) }
                Invoke-AuditPumpToDone
                Update-AuditExcludedHeadless
            }
            Complete-AuditOutput $Download
            return
        }
        # Fresh: Phase A (Tier-1 + worklist) then Phase B (continuation), MERGING Tier-2 into Phase A's
        # findings -> one combined audit-log.csv. The worklist + cursor are deleted on full completion.
        $wl = Invoke-HeadlessAudit $O $true
        if ($wl -and (Start-AuditTier2List $wl -KeepFindings)) {
            Write-V 1 'Scanning Tier-2 worklist...'
            Invoke-AuditPumpToDone
            Update-AuditExcludedHeadless
        }
        Complete-AuditOutput $Download
        return
    }

    # Phase A only: --defer-tier2 (Tier-1 + worklist, stop) or plain Tier-1.
    $wl = Invoke-HeadlessAudit $O ([bool]$DeferTier2)
    if ($DeferTier2) {
        Complete-AuditOutput ('')
        Write-V 1 ("Wrote $($script:AuditTier2ListTotal) Tier-2 candidate(s) to $wl")
        Write-V 1 ("  resume Tier-2 later with:  audit --tier2-resume `"$wl`" -u $($script:BaseUrl)  (or just re-run with -2)")
        return
    }
    # Plain Tier-1.
    Complete-AuditOutput $Download
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
        [string]$Query, [string]$Repos, [string]$RepoTypes, [switch]$WalkArchives, [switch]$AllVersions,
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
    # Repo-type scope: default LOCAL only (set in Api.ps1); --repo-types widens the auto-enumeration.
    if ($O.ContainsKey('RepoTypes')) { Set-RepoTypeScope ([string]$O['RepoTypes']) }
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
    'audit'    { Invoke-Audit @splat }
    'search'   { Invoke-Search @splat }
    'help'     { Show-AuditEngineUsage }
    '-h'       { Show-AuditEngineUsage }
    '--help'   { Show-AuditEngineUsage }
    default    { Write-Host "Unknown verb: $verb`n"; Show-AuditEngineUsage }
}
