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

    Or paste Core.ps1, Api.ps1, Index.ps1 then this file into a console and call Invoke-IndexBuild
    with the SAME unix-style flags as the script:
      Invoke-IndexBuild -F -a -u https://art.example.com -v 2
      Invoke-IndexBuild -q secrets -u https://art.example.com --workers 50 --arc-workers 15
    (The native-parameter implementation is Invoke-IndexBuildCore if you'd rather splat -ParamName.)

    Flag <-> parameter map:
      -F/--full           -Full           -q/--query <name>    -Query
      -a/--archives       -Archives       -r/--repos <list>    -Repos
      --repo-types <list> -RepoTypes      --all-repos          -RepoTypes all
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
            '^--no-archives$'    { $p.NoArchives = $true }
            '^--all-versions$'   { $p.AllVersions = $true }
            '^--skip-versions$'  { $p.AllVersions = $false }   # affirms the default (no-op)
            '^--scan-all$'       { $p.ScanAll   = $true }      # disable ALL skip-recommended (versions + files)
            '^--skip$'           { $p.SkipGlobs = $tokens[++$i] }   # add user skip globs to skip-recommended
            '^--resume$'         { $p.Resume    = $true }
            '^(-r|--repos)$'     { $p.Repos     = $tokens[++$i] }
            '^--repo-types$'     { $p.RepoTypes = $tokens[++$i] }
            '^--all-repos$'      { $p.RepoTypes = 'all' }
            '^--index$'          { $p.IndexPath = $tokens[++$i] }
            '^--workers$'        { $p.Workers    = [int]$tokens[++$i] }
            '^--walkers$'        { $p.Walkers    = [int]$tokens[++$i] }
            '^--arc-workers$'    { $p.ArcWorkers = [int]$tokens[++$i] }
            '^--delay$'          { $p.DelayMs    = [int]$tokens[++$i] }
            '^(-v|--verbose)$'   { $p.Verbosity = [int]$tokens[++$i] }
            '^--no-?colou?r$'    { $p.NoColour  = $true }
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
  StartIndex.ps1            <options>     index the entire instance + archives (the DEFAULT)
  StartIndex.ps1 -q <name>  <options>     index the results of an artifact-name search

Scope (defaults to -F --full when neither is given):
  -F, --full              index the entire instance (recursive /api/storage walk) [DEFAULT]
  -q, --query <name>      index the results of this artifact-name quick-search instead
  -r, --repos <a,b>       restrict the scope to these repositories (bypasses the type filter)
      --repo-types <list> repo rclasses to auto-enumerate (default: local). e.g. local,remote
                          or 'all' (every non-virtual repo). --all-repos is shorthand for 'all'.
                          Virtual repos are always skipped (they re-list their backing repos).

Options:
  -a, --archives          expand listable archives + index their internal entries [DEFAULT ON]
      --no-archives       do NOT expand archives (top-level metadata only)
      --all-versions      expand EVERY version of an archive (default: skip - index only the
                          first version of each artifact, by version-normalized filename)
      --scan-all          disable ALL skip-recommended heuristics (index every version AND every
                          curated-noise file, e.g. Jenkins builds/<n>/workflow/<n>.xml). Default:
                          skip-recommended is ON.
      --skip <globs>      add your own skip-recommended globs (comma/space separated, '*'/'?';
                          matched on the repo-relative path/name, e.g. '*/javadoc/*,*.md5'). The
                          high-value carve-outs (credentials.xml, config.xml, build.xml, secrets/*,
                          *.log, injectedEnvVars.txt) are NOT protected from your own --skip.
      --resume            skip files already present in the shards (finish/extend an interrupted
                          build). NOTE: does NOT refresh stale rows - the index is a point-in-time
                          snapshot; --resume only adds what's missing.
      --index <dir>       local index directory to write (default ./output/<host>/index)
      --workers <1-100>   parallel metadata-fetch workers (default 50; long-lived worker loops)
      --walkers <1-32>    parallel storage-walk discovery runspaces (default 20; feed the workers -
                          raise alongside --workers so discovery doesn't starve them)
      --arc-workers <1-20> parallel archive-expansion workers (default 15)
      --delay <ms>        per-request politeness delay (default 0; the adaptive throttle backs off
                          automatically on 429/503)
  -v, --verbose <0-5>     0 silent · 1 summary · 2 progress · 3 milestones · 4 detail · 5 debug (default 1)
      --nocolour          disable coloured (dark-grey) progress output

Auth:
  -u, --base-url <url>    Artifactory base URL (required)
  -t, --token <tok>       bearer token        -k, --api-key <key>   JFrog API key
  -b, --basic <user:pw>   basic auth
'@
}

# ── ENTRY ─────────────────────────────────────────────────────────────────────
# Native-parameter implementation (splat-callable). The public Invoke-IndexBuild front-end below
# accepts the unix-style flags instead, so paste-mode and the .ps1 share one flag vocabulary.
function Invoke-IndexBuildCore {
    param(
        [switch]$Full, [string]$Query, [switch]$Archives, [switch]$NoArchives, [switch]$AllVersions, [switch]$ScanAll, [string]$SkipGlobs,
        [switch]$Resume, [string]$Repos,
        [string]$RepoTypes, [string]$IndexPath, [int]$Workers, [int]$Walkers, [int]$ArcWorkers, [int]$DelayMs, [int]$Verbosity,
        [string]$BaseUrl, [string]$ApiKey, [string]$Token, [string]$Basic, [switch]$NoColour
    )
    $O = $PSBoundParameters
    $script:IndexColour = -not ($O.ContainsKey('NoColour') -and $O['NoColour'])
    if ($O.ContainsKey('Verbosity')) { $script:IndexVerbosity = [int]$O['Verbosity'] }
    if ($O.ContainsKey('BaseUrl'))   { $script:BaseUrl = [string]$O['BaseUrl'] }
    if ($O.ContainsKey('ApiKey'))    { $script:ApiKey  = [string]$O['ApiKey'] }
    if ($O.ContainsKey('Token'))     { $script:Token   = [string]$O['Token'] }
    if ($O.ContainsKey('Basic'))     { $script:Basic   = [string]$O['Basic'] }
    if ($O.ContainsKey('Repos'))     { $script:Repos   = [string]$O['Repos'] }
    # Repo-type scope: default LOCAL only (set in Api.ps1); --repo-types widens the auto-enumeration.
    if ($O.ContainsKey('RepoTypes')) { Set-RepoTypeScope ([string]$O['RepoTypes']) }
    if (-not $script:BaseUrl) { throw 'A base URL is required (-u/--base-url).' }
    $script:BaseUrl = $script:BaseUrl.TrimEnd('/')

    # Scope: default to FULL when neither -F nor -q is given (the index default is the whole instance).
    $hasFull = [bool]($O.ContainsKey('Full') -and $O['Full'])
    $query   = if ($O.ContainsKey('Query')) { [string]$O['Query'] } else { '' }
    if ($hasFull -and $query) { throw 'Choose one scope: -F/--full OR -q/--query, not both.' }
    $full    = $hasFull -or (-not $query)
    # Archives default ON (-a is implied); --no-archives opts out.
    $archives = -not ($O.ContainsKey('NoArchives') -and $O['NoArchives'])

    # Output layout + index dir (output/<host>/index unless --index overrides).
    $script:OutDirExplicit = $false
    Resolve-OutputPaths
    if ($O.ContainsKey('IndexPath') -and $O['IndexPath']) { Set-IndexPath ([string]$O['IndexPath']) }
    Resolve-IndexPath
    $script:IndexEnabled = $true     # building the index is the whole point
    Import-Index $script:IndexPath   # migrations + archive skip-set

    # Drive the build via the shared driver (Index.ps1). Throttle defaults (workers 50 / walkers 20 /
    # arc-workers 15 / delay 0) are applied there unless overridden; 0 / -1 here = "use the default".
    $workers    = if ($O.ContainsKey('Workers'))    { [int]$O['Workers'] }    else { 0 }
    $walkers    = if ($O.ContainsKey('Walkers'))    { [int]$O['Walkers'] }    else { 0 }
    $arcWorkers = if ($O.ContainsKey('ArcWorkers')) { [int]$O['ArcWorkers'] } else { 0 }
    $delay      = if ($O.ContainsKey('DelayMs'))    { [int]$O['DelayMs'] }    else { -1 }
    $allVers    = [bool]($O.ContainsKey('AllVersions') -and $O['AllVersions'])
    $scanAll    = [bool]($O.ContainsKey('ScanAll') -and $O['ScanAll'])
    $skipGlobs  = if ($O.ContainsKey('SkipGlobs')) { [string]$O['SkipGlobs'] } else { '' }
    $resume     = [bool]($O.ContainsKey('Resume') -and $O['Resume'])
    Invoke-IndexBuildRun -Full $full -Archives $archives -Query $query -AllVersions $allVers -Resume $resume `
        -Workers $workers -Walkers $walkers -ArcWorkers $arcWorkers -DelayMs $delay -ScanAll $scanAll -SkipGlobs $skipGlobs
}

# Console/paste front-end: takes the SAME unix-style flags as the script (e.g.
#   Invoke-IndexBuild -F -a -u https://repo.example.com --workers 50 --arc-workers 15 -v 5
# identical to `.\StartIndex.ps1 -F -a -u ... --workers 50 ...`). No param() block, so dash-flags
# land in $args instead of being bound as native parameters; they're parsed by ConvertFrom-IndexArgv
# and forwarded to the native-parameter Invoke-IndexBuildCore.
function Invoke-IndexBuild {
    if (@($args).Count -eq 0) { Show-IndexUsage; return }
    try { $splat = ConvertFrom-IndexArgv @($args) }
    catch { Write-Host "Error: $($_.Exception.Message)`n"; Show-IndexUsage; return }
    if ($splat.ContainsKey('Help')) { Show-IndexUsage; return }
    Invoke-IndexBuildCore @splat
}

# ── DISPATCH (script-file invocation) ─────────────────────────────────────────
# Paste-safe: if/else (not guard-and-return) because a bare `return` does NOT halt the remaining
# pasted lines in an interactive session - so pasting the whole file just shows usage instead of
# throwing on an empty $args.
if (-not $env:ARTCA_NOMAIN) {
    if (@($args).Count -eq 0) {
        Show-IndexUsage
    } else {
        try {
            $splat = ConvertFrom-IndexArgv @($args)
            if ($splat.ContainsKey('Help')) { Show-IndexUsage } else { Invoke-IndexBuildCore @splat }
        } catch {
            Write-Host "Error: $($_.Exception.Message)`n"
            Show-IndexUsage
        }
    }
}
