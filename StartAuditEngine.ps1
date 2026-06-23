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
                the ruleset, cataloguing matches to audit-log.csv (rule + severity). An index
                must exist; pass --populate-index to auto-build a full+archives index first.
                Tier-2 (content scanning) is the DEFAULT - a two-phase, resumable, worklist-
                driven flow: a Tier-1 pass writes tier2-pending.csv listing every file Tier-2
                would content-inspect, then a pass content-scans it (resumable via a .progress
                cursor: pause/crash/cancel and re-run to continue). Use --tier1/--no-tier2 for
                a Tier-1-only catalogue; --defer-tier2 writes the worklist and stops;
                --tier2-resume <file> content-scans an existing worklist later.
                --download [all] DOWNLOADS the matching findings (dedup/rename/hash like the
                TUI's "download all") -> download-log.csv; --download <sev,...> (e.g.
                high,medium) only those severities; --download count prints the per-severity
                count + total size without downloading; --max-size <n> skips oversized files.
                -s/--from-log <file> skips auditing entirely and downloads the files listed in
                a prior audit-log.csv. Per-repo matches are written through to
                audit/<repo>-matches.csv; the consolidated audit-log.csv is rebuilt from them.
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
    and call Invoke-Audit / Invoke-Search with the SAME unix-style flags as the script (no
    verb needed - the function IS the verb):
      Invoke-Audit -u https://art.example.com -2 -v 3
      Invoke-Audit -u https://art.example.com --defer-tier2 -o out
      Invoke-Audit -u https://art.example.com --tier2-resume tier2-pending.csv
      Invoke-Audit -u https://art.example.com -s audit-log.csv --download critical,high,medium
    (The native-parameter implementations are Invoke-AuditCore / Invoke-SearchCore if you'd
    rather splat -ParamName values.)

    Flag <-> parameter map (native names, for the *Core functions / the flag map below):
      -r/--repos <list>   -Repos          --repo-types <list>  -RepoTypes
      --all-repos         -RepoTypes all  -2/--tier2           -Tier2 (default on)
      --tier1/--no-tier2  -NoTier2        --populate-index     -PopulateIndex
      --defer-tier2       -DeferTier2     --tier2-resume <f>   -Tier2Resume
      --download [all|count|<sev,...>]    -Download  (default 'all'; omitted = catalogue only)
      --max-size <size>                   -MaxSize   (per-file download limit, e.g. 100MB; default none)
      -x/--exclude <globs>                -Exclude
      -s/--from-log <f>   -FromLog        --index <dir>        -IndexPath
      -o/--out <dir>      -OutDir         -v/--verbose <0-5>   -Verbosity
      --cap <bytes>       -Cap            --workers <1-50>     -Workers (default 15)
      --delay <ms>        -DelayMs (default 0)
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

# Tighter, no-space duration for the inline progress/Saving lines: 13s / 3m12s / 2h14m / 1d06h. Two
# adjacent units max (hour-scale shows h+m, minute-scale m+s), so the field stays short and stable-width.
function Format-DurationCompact([int]$secs) {
    if ($secs -lt 0) { $secs = 0 }
    if ($secs -lt 60)    { return "${secs}s" }
    if ($secs -lt 3600)  { return ('{0}m{1:00}s' -f [int][Math]::Floor($secs / 60), ($secs % 60)) }
    if ($secs -lt 86400) { return ('{0}h{1:00}m' -f [int][Math]::Floor($secs / 3600), [int][Math]::Floor(($secs % 3600) / 60)) }
    return ('{0}d{1:00}h' -f [int][Math]::Floor($secs / 86400), [int][Math]::Floor(($secs % 86400) / 3600))
}

# Build the single-line audit progress string (dark grey at the call site). Column widths are fixed so
# successive lines align vertically. ETA uses the average rate over the run (steadier than the rolling
# FPS) and a wall-clock finish time; the denominator is the known index-row/worklist total when set
# (so done/total + ETA are meaningful from the very first tick). The bracketed engine-internal counters
# are appended only at verbosity 5.
function Format-AuditProgressLine {
    $den  = if ($script:AuditEnqTotal -gt 0) { $script:AuditEnqTotal } else { $script:AuditEnq }
    $done = $script:AuditDone
    # Each field is its own [bracket], space-separated, after the unbracketed '...audited N/M files' prefix
    # (no column padding - the brackets delimit, so nothing needs to align).
    $fields = [Collections.Generic.List[string]]::new()
    $fields.Add("[{0:0.0} files/s]" -f [double]$script:AuditRate.FPS)
    $fields.Add("[{0} findings]" -f $script:AuditFindings.Count)
    $elapsed = ([DateTime]::UtcNow - $script:AuditStartedAt).TotalSeconds
    if ($den -gt 0 -and $done -gt 0 -and $elapsed -ge 1) {
        $rem = $den - $done; if ($rem -lt 0) { $rem = 0 }
        $avg = $done / $elapsed
        if ($avg -gt 0) {
            $secs = [int][Math]::Ceiling($rem / $avg)
            $fields.Add(("[ETA {0} ({1})]" -f (Format-DurationCompact $secs), ((Get-Date).AddSeconds($secs).ToString('h:mmtt').ToLower())))
        }
    }
    if ($script:AuditVerbosity -ge 5) {
        $fields.Add(("[audit queue:{0} jobs:{1} pending:{2} launched:{3}]" -f `
                    $script:AuditQueue.Count, $script:AuditJobs.Count, $script:AuditPendingNodes.Count, $script:AuditLaunched))
    }
    return ("...audited {0}/{1} files {2}" -f $done, $den, ($fields -join ' '))
}

# Compact, no-space size for inline progress (0.1MB / 10MB / 123KB). '?' for unknown.
function ConvertTo-CompactSize([long]$bytes) {
    if ($bytes -lt 0)          { return '?' }
    if ($bytes -lt 1024)       { return ("{0}B"    -f $bytes) }
    if ($bytes -lt 1048576)    { return ("{0:0.#}KB" -f ($bytes / 1024.0)) }
    if ($bytes -lt 1073741824) { return ("{0:0.#}MB" -f ($bytes / 1048576.0)) }
    return ("{0:0.#}GB" -f ($bytes / 1073741824.0))
}

# 'Saving' line (line A) from the sidecar - the in-progress file. Whole line dark grey, columns aligned:
#   ...saving file <name>   saved i/total   <kbps>   <done>/<total>   ETA <dur> (<wall>)
# The speed/bytes/ETA columns appear at level 5 only (cheap, from the cumulative byte/time accounting).
function Write-DownloadSavingLine($d) {
    if ($script:AuditVerbosity -lt 5) { return }
    $fields = [Collections.Generic.List[string]]::new()
    $fields.Add(("[saved {0}/{1}]" -f $d.Index, $d.Total))
    if ([long]$d.TotalBytes -gt 0 -and [double]$d.ElapsedSec -ge 0.5) {
        $rate = [long]([double]$d.DoneBytes / [double]$d.ElapsedSec)   # bytes/sec
        $fields.Add("[{0:0}kbps]" -f ($rate / 1000.0))
        $fields.Add(("[{0}/{1}]" -f (ConvertTo-CompactSize ([long]$d.DoneBytes)), (ConvertTo-CompactSize ([long]$d.TotalBytes))))
        if ($rate -gt 0) {
            $rem = [long]$d.TotalBytes - [long]$d.DoneBytes; if ($rem -lt 0) { $rem = 0 }
            $secs = [int][Math]::Ceiling($rem / [double]$rate)
            $fields.Add(("[ETA {0} ({1})]" -f (Format-DurationCompact $secs), ((Get-Date).AddSeconds($secs).ToString('h:mmtt').ToLower())))
        }
    }
    Write-AuditColor ("...saving file {0} {1}" -f $d.Name, ($fields -join ' ')) DarkGray
}

# 'Saved' line (line B) - the completed download. 'Downloaded' in grey, the [Sev] tag coloured, filename
# white, size dark grey. When one name produced several distinct hashed files, show '[Multiple]' (coloured
# by the highest severity) + combined size, then up to 3 indented per-file lines and an 'N more unique
# files saved. [sev:count ...]' tail (same cap + colouring as the audit snippet 'more' line).
function Write-DownloadSavedLine($d) {
    if ($script:AuditVerbosity -lt 4) { return }
    $files = @($d.Files)
    if ($files.Count -le 1) {
        $f = if ($files.Count -eq 1) { $files[0] } else { @{ Name=$d.BaseName; Size=-1; Sev='' } }
        if ("$($f.Sev)") { Write-AuditColor ("[{0}] " -f $f.Sev) (Get-AuditSevConsoleColor $f.Sev) -NoNewline }
        Write-AuditColor ([string]$f.Name) White -NoNewline
        if ([long]$f.Size -ge 0) { Write-AuditColor (" ({0})" -f (Format-Size ([long]$f.Size))) DarkGray -NoNewline }
        Write-Host ''
        return
    }
    $totalSize = 0L; $haveSize = $true; $hi = ''; $hiRank = -1
    foreach ($f in $files) {
        if ([long]$f.Size -ge 0) { $totalSize += [long]$f.Size } else { $haveSize = $false }
        $rk = Get-SevRank ([string]$f.Sev); if ($rk -gt $hiRank) { $hiRank = $rk; $hi = [string]$f.Sev }
    }
    Write-AuditColor '[Multiple]' (Get-AuditSevConsoleColor $hi) -NoNewline
    Write-AuditColor (" {0}" -f $d.BaseName) White -NoNewline
    if ($haveSize) { Write-AuditColor (" ({0})" -f (Format-Size $totalSize)) DarkGray -NoNewline }
    Write-Host ''
    $cap = [Math]::Min(3, $files.Count); $shown = @{}
    for ($i = 0; $i -lt $cap; $i++) {
        $f = $files[$i]
        Write-AuditColor ("  [{0}]" -f $f.Sev) (Get-AuditSevConsoleColor $f.Sev) -NoNewline
        Write-AuditColor (" {0}" -f $f.Name) White -NoNewline
        if ([long]$f.Size -ge 0) { Write-AuditColor (" ({0})" -f (Format-Size ([long]$f.Size))) DarkGray -NoNewline }
        Write-Host ''
        $sv = [string]$f.Sev; $shown[$sv] = 1 + $(if ($shown.ContainsKey($sv)) { $shown[$sv] } else { 0 })
    }
    $more = $files.Count - $cap
    if ($more -gt 0) {
        $allsev = @{}; foreach ($f in $files) { $s = [string]$f.Sev; $allsev[$s] = 1 + $(if ($allsev.ContainsKey($s)) { $allsev[$s] } else { 0 }) }
        $remain = @{}
        foreach ($s in $script:AuditSevOrder) { $r = ([int]$(if ($allsev.ContainsKey($s)) { $allsev[$s] } else { 0 })) - ([int]$(if ($shown.ContainsKey($s)) { $shown[$s] } else { 0 })); if ($r -gt 0) { $remain[$s] = $r } }
        Write-AuditColor ("  {0} more" -f $more) White -NoNewline
        Write-AuditColor ' unique files saved.' Gray -NoNewline
        $parts = @($script:AuditSevOrder | Where-Object { $remain.ContainsKey($_) })
        if ($parts.Count -gt 0) {
            Write-AuditColor ' [' Gray -NoNewline
            for ($i = 0; $i -lt $parts.Count; $i++) {
                $s = $parts[$i]
                Write-AuditColor ("{0}:" -f $s) Gray -NoNewline
                Write-AuditColor ([string]$remain[$s]) (Get-AuditSevConsoleColor $s) -NoNewline
                if ($i -lt $parts.Count - 1) { Write-AuditColor ' ' Gray -NoNewline }
            }
            Write-AuditColor ']' Gray -NoNewline
        }
        Write-Host ''
    }
}

# Parse a size string to bytes: plain number, or a binary suffix (K/M/G/T, optional B), e.g.
# '100MB', '1.5g', '500000', '250 KB'. Empty/unset -> 0 (meaning no limit). Throws on garbage.
function Convert-ToBytes([string]$s) {
    $t = "$s".Trim()
    if (-not $t) { return 0 }
    if ($t -match '^\s*(?<n>\d+(?:\.\d+)?)\s*(?<u>[KMGT])?B?\s*$') {
        $mult = switch ("$($Matches['u'])".ToUpper()) { 'K' {1024} 'M' {1048576} 'G' {1073741824} 'T' {1099511627776} default {1} }
        return [long][Math]::Floor([double]$Matches['n'] * $mult)
    }
    throw "Invalid size '$s'. Use bytes or a suffix like 100MB, 1.5G, 500KB."
}

# Drop entries whose KNOWN size exceeds $maxBytes (0 = no limit). Entries with unknown size (-1, e.g.
# some archive entries) are KEPT - we can't measure them up front. Reports how many/how much was
# skipped. Items carry a .Size (bytes) field (findings and from-log rows both do).
function Select-WithinSize($items, [long]$maxBytes) {
    if ($maxBytes -le 0) { return @($items) }
    $kept = [Collections.Generic.List[object]]::new()
    $skip = 0; $skipBytes = 0L
    foreach ($it in @($items)) {
        $sz = -1; if ("$($it.Size)" -match '^-?\d+$') { $sz = [long]$it.Size }
        if ($sz -ge 0 -and $sz -gt $maxBytes) { $skip++; $skipBytes += $sz }
        else { [void]$kept.Add($it) }
    }
    if ($skip -gt 0) { Write-V 1 ("Size limit $(Format-Size $maxBytes): skipping $skip file(s) over the limit ($(Format-Size $skipBytes) not downloaded)") }
    return @($kept.ToArray())
}

# Route the shared bulk-download engine's progress lines to level-4 output (the TUI
# routes the same hook to Show-Popup instead).
$script:DownloadProgress = {
    param($lines)
    # Prefer the engine's structured sidecar (rich per-file Saving/Hashing line); fall back to the plain
    # joined $lines if it isn't set (keeps any non-dedup caller working).
    $d = $script:DownloadProgressData
    if ($null -eq $d) {
        Write-V 4 ('  ' + ((@($lines) | Where-Object { "$_" -ne '' }) -join '  '))
        return
    }
    switch ($d.Kind) {
        'Hashing' { if ($script:AuditVerbosity -ge 5) { Write-AuditColor ("...comparing hashes for {0} ({1}/{2}) [{3}]" -f $d.Name, $d.MemberIndex, $d.MemberCount, $d.Hash) DarkGray } }
        'Saved'   { Write-DownloadSavedLine $d }
        default   { Write-DownloadSavingLine $d }
    }
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
            '^(--no-tier2|--tier1)$' { $p.NoTier2      = $true }
            '^--defer-tier2$'        { $p.DeferTier2   = $true }
            '^--tier2-resume$'       { $p.Tier2Resume  = $tokens[++$i] }
            '^--populate-index$'     { $p.PopulateIndex = $true }
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
            '^--max-size$'           { $p.MaxSize      = $tokens[++$i] }
            '^--preview-count$'      { $p.PreviewCount  = [int]$tokens[++$i] }
            '^--preview-window$'     { $p.PreviewWindow = [int]$tokens[++$i] }
            '^--no-?colou?r$'        { $p.NoColour      = $true }
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
  StartAuditEngine.ps1 audit  <options>             Tier-1 + Tier-2 audit of the index (DEFAULT)
  StartAuditEngine.ps1 audit  --tier1 <options>     Tier-1 only -> audit-log.csv (no content fetch)
  StartAuditEngine.ps1 audit  --populate-index <o>  build a full+archives index first if none exists
  StartAuditEngine.ps1 audit  --defer-tier2 <opts>  Tier-1 + write a Tier-2 worklist, then stop
  StartAuditEngine.ps1 audit  --tier2-resume <file> content-scan a worklist (resumable)
  StartAuditEngine.ps1 audit  --download <options>  audit + download all matches -> download-log.csv
  StartAuditEngine.ps1 audit  --download count      audit + show the per-severity download breakdown
  StartAuditEngine.ps1 audit  --download high,medium   download only those severities
  StartAuditEngine.ps1 audit  -s audit-log.csv      download a previous audit-log (no audit)
  StartAuditEngine.ps1 audit  -s audit-log.csv --download critical,high,medium   ... only those sevs
  StartAuditEngine.ps1 audit  --download all --max-size 100MB   ... skip files over 100 MB
  StartAuditEngine.ps1 search <options>             quick-search (+ optional archive walk) to a CSV

The audit reads ONLY the local index (no searching/discovery) - build one first with StartIndex.ps1,
or pass --populate-index to build it automatically. It audits every indexed artifact AND indexed
archive-internal entry. Tier-2 (content scanning) is the DEFAULT: a Tier-1 pass writes a worklist of
every file Tier-2 would content-inspect (tier2-pending.csv), then a resumable pass content-scans it
(`-2` is implied). Use --tier1/--no-tier2 for a quick Tier-1 catalogue; split the phases with
--defer-tier2 (write the list) and --tier2-resume (scan it later, survives pause/crash/cancel).

Audit options (audit verb):
  -2, --tier2             Tier-2 content scan (this is the DEFAULT; the flag is explicit/no-op)
      --tier1, --no-tier2 Tier-1 only: metadata catalogue, no file content fetched
      --populate-index    if no index exists, auto-build a full+archives index first, then audit
      --defer-tier2       Tier-1 + write the Tier-2 worklist (tier2-pending.csv) and stop
      --tier2-resume <f>  content-scan an existing worklist; resumable via its .progress cursor
      --download [spec]   download matched findings (no flag = catalogue only). spec: 'all' (default),
                          a severity list e.g. 'high,medium' (critical/high/medium/low/informational,
                          short forms c/h/m/l/i ok), or 'count' = catalogue + print the per-severity
                          count and total size of the would-be download set without downloading
  -s, --from-log <file>   skip auditing; download rows of a prior audit-log.csv (fills hashes).
                          combine with --download <sev,...> to grab only those severities, or
                          --download count to preview the per-severity breakdown without downloading
      --max-size <size>   per-file download limit - files larger than this are NOT downloaded
                          (e.g. 100MB, 1.5G, 500KB, or plain bytes). Default: no limit. Files of
                          unknown size are kept. Applies to --download and -s/--from-log.
  -r, --repos <a,b>       restrict to these indexed repositories (bypasses the type filter)
      --repo-types <list> indexed repo rclasses to audit (default: local). e.g. local,remote or
                          'all' (every non-virtual repo). --all-repos is shorthand for 'all'.
  -x, --exclude <globs>   comma/space globs to exclude from the set (e.g. "*.xml,*test*")
      --preview-count <n> max content-match snippets stored per file in audit-log.csv's
                          MatchedContentPreview column (JSON array). Default 10; 0 = no snippets
                          (MatchCount still recorded). NOTE: previews contain matched content, which
                          is often the secret itself - the log then holds live credential material.
      --preview-window <n> TOTAL context characters captured around each match, split evenly each
                          side (default 40 -> 20 left + match + 20 right)
      --index <dir>       local index directory to read (default ./output/<host>/index)
      --cap <bytes>       max file size to content-scan (default 2 MB)
      --workers <1-50>    parallel fetch workers (default 15)
      --delay <ms>        delay between request launches (default 0)

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
  -o, --out <dir>         DOWNLOADS folder for saved files + download-log.csv (default
                          ./output/<host>/downloads). Audit catalogues (audit-log.csv,
                          tier2-pending.csv[.progress], <repo>-matches.csv) go to ./output/<host>/audit.
  -v, --verbose <0-5>     0 silent .. 5 debug (default 1)
      --nocolour          disable coloured console output (severity-tinted tags, grey progress/snippets)
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

# Content-match preview (snippet) settings, shared by every content-scanning path (the index audit
# AND --tier2-resume). --preview-count 0 keeps MatchCount but stores no snippets; --preview-window is
# the TOTAL context characters around each match (split evenly each side).
function Set-AuditPreviewConfig([hashtable]$O) {
    if ($O.ContainsKey('PreviewCount')  -and [int]$O['PreviewCount']  -ge 0) { $script:AuditPreviewMax    = [int]$O['PreviewCount'] }
    if ($O.ContainsKey('PreviewWindow') -and [int]$O['PreviewWindow'] -ge 0) { $script:AuditPreviewWindow = [int]$O['PreviewWindow'] }
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
    Set-AuditPreviewConfig $O
    if ($O.ContainsKey('Cap') -and [long]$O['Cap'] -gt 0)        { $script:AuditCap = [long]$O['Cap'] }
    # Headless throttle DEFAULTS: 15 workers, 0ms delay (more aggressive than the TUI's gentle 3/150).
    $script:AuditThrottle.MaxConcurrent =
        if ($O.ContainsKey('Workers') -and [int]$O['Workers'] -gt 0) { [Math]::Max(1, [Math]::Min($script:AuditMaxWorkers, [int]$O['Workers'])) }
        else { [Math]::Min($script:AuditMaxWorkers, 15) }
    $script:AuditThrottle.MinIntervalMs =
        if ($O.ContainsKey('DelayMs') -and [int]$O['DelayMs'] -ge 0) { [int]$O['DelayMs'] } else { 0 }
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

# Colourised console output for the verbose modes. On by default; turned off by --nocolour (sets
# $AuditColour false), in which case every helper falls back to a plain Write-Host. Uses Write-Host
# -ForegroundColor (not ANSI) so it needs no VT setup and is ignored cleanly when output is redirected.
$script:AuditColour = $true

# Severity -> ConsoleColor, mirroring the TUI's Get-AuditColor palette (critical=red, high=yellow,
# medium=green, low=blue, informational=purple).
function Get-AuditSevConsoleColor([string]$sev) {
    switch ("$sev".ToLower()) {
        'critical'      { 'Red' }
        'high'          { 'Yellow' }
        'medium'        { 'Green' }
        'low'           { 'Cyan' }
        'informational' { 'Magenta' }
        default         { 'Gray' }
    }
}

# Write-Host wrapper that honours $AuditColour: colourise when on (and a colour is given), else plain.
function Write-AuditColor([string]$text, $color = $null, [switch]$NoNewline) {
    if ($script:AuditColour -and $color) { Write-Host $text -ForegroundColor $color -NoNewline:$NoNewline }
    else                                 { Write-Host $text -NoNewline:$NoNewline }
}

# Per-rule colouring: each rule label is coloured by ITS OWN severity (a file can carry rules of
# differing severities, e.g. a High name rule + a Low one). Build a cached rule-name -> severity map
# from the active ruleset (meta rule names + content rule names - the two kinds that appear in a
# finding's rule list); unknown names fall back to Gray via Get-AuditSevConsoleColor's default.
$script:AuditRuleSevMap = $null
function Get-AuditRuleConsoleColor([string]$ruleName) {
    if ($null -eq $script:AuditRuleSevMap) {
        $map = @{}
        $rs = Get-AuditRuleSet
        foreach ($mr in $rs.Meta) { if ($mr.ContainsKey('Name') -and $mr.ContainsKey('Sev')) { $map[[string]$mr.Name] = [string]$mr.Sev } }
        foreach ($k in $rs.Content.Keys) { $map[[string]$k] = [string]$rs.Content[$k].Sev }
        $script:AuditRuleSevMap = $map
    }
    $sev = if ($script:AuditRuleSevMap.ContainsKey($ruleName)) { $script:AuditRuleSevMap[$ruleName] } else { '' }
    return (Get-AuditSevConsoleColor $sev)
}

# Print one finding line (level 3+). At level 5, when the finding carries Tier-2 content-match preview
# snippets, list up to 3 of them as 'Match: <snippet>' beneath it, then - if the file has more matched
# instances than were shown - a 'N more matches found.' line (MatchCount counts every Tier-1 meta match
# plus every Tier-2 content occurrence, so N is the count not surfaced as a snippet).
$script:AuditSevOrder = @('Critical','High','Medium','Low','Informational')
function Write-AuditFindingLine($f, [string]$tag) {
    $loc = (@($f.Repo, $f.Path, $f.Name) | Where-Object { "$_" -ne '' }) -join '/'
    # Filename leads; the path (in [..], light grey) and the containing archive (in (..), light grey) go
    # at the END of the line, e.g.
    #   [Low] credentials.jelly - NameContainsSecret [incrementals/org/.../ServiceAccountCredential/] (kubernetes-4435.jar)
    $slash = $loc.LastIndexOf('/')
    $path  = if ($slash -ge 0) { $loc.Substring(0, $slash + 1) } else { '' }
    $fname = if ($slash -ge 0) { $loc.Substring($slash + 1) }   else { $loc }
    $arc   = if ($f.InArchive -and "$($f.ArchiveName)") { " ($($f.ArchiveName))" } else { '' }
    # Rules are single words, so the line shows them space-separated (no comma).
    $rules = @($f.AllRules -split '\s*,\s*' | Where-Object { $_ })
    if ($tag) {
        # Re-print of a finding already reported in Tier-1: de-emphasised, whole line dark grey.
        $pp = if ($path) { " [$path]" } else { '' }
        Write-AuditColor ("[{0}] {1} - {2}{3}{4}{5}" -f $f.Sev, $fname, ($rules -join ' '), $pp, $arc, $tag) DarkGray
        return
    }
    # Main finding line is NOT indented. -NoNewline segments terminated by Write-Host.
    Write-AuditColor ("[{0}] " -f $f.Sev) (Get-AuditSevConsoleColor $f.Sev) -NoNewline
    Write-AuditColor $fname White -NoNewline
    Write-AuditColor ' - ' White -NoNewline
    for ($i = 0; $i -lt $rules.Count; $i++) {
        Write-AuditColor $rules[$i] (Get-AuditRuleConsoleColor $rules[$i]) -NoNewline
        if ($i -lt $rules.Count - 1) { Write-AuditColor ' ' White -NoNewline }
    }
    if ($path) { Write-AuditColor (" [{0}]" -f $path) Gray -NoNewline }
    if ($arc)  { Write-AuditColor $arc Gray -NoNewline }
    Write-Host ''
    if ($script:AuditVerbosity -ge 5 -and $f.PSObject.Properties['Snippets'] -and $f.Snippets.Count -gt 0) {
        # Subsequent lines (indented 2). Each preview line: the producing rule in [..] coloured by ITS
        # severity, then the snippet grey.
        $cap = [Math]::Min(3, $f.Snippets.Count)
        $shown = @{}
        for ($i = 0; $i -lt $cap; $i++) {
            $sn = $f.Snippets[$i]
            Write-AuditColor ("  [{0}] " -f $sn.Rule) (Get-AuditSevConsoleColor $sn.Sev) -NoNewline
            if ($sn.PSObject.Properties['Match']) {
                # Context grey, the EXACT regex match white.
                Write-AuditColor ([string]$sn.Pre) Gray -NoNewline
                Write-AuditColor ([string]$sn.Match) White -NoNewline
                Write-AuditColor ([string]$sn.Post) Gray
            } else {
                Write-AuditColor ([string]$sn.Text) Gray
            }
            $sv = [string]$sn.Sev; $shown[$sv] = 1 + $(if ($shown.ContainsKey($sv)) { $shown[$sv] } else { 0 })
        }
        $more = [int]$f.MatchCount - $cap
        if ($more -gt 0) {
            # 'N more' in white, 'matches found.' grey, then the remaining counts broken down by severity
            # (each count in its colour). Remaining-by-sev = all matched instances minus the shown snippets.
            Write-AuditColor ("  {0} more" -f $more) White -NoNewline
            Write-AuditColor ' matches found.' Gray -NoNewline
            $ms = if ($f.PSObject.Properties['MatchSev'] -and $f.MatchSev) { $f.MatchSev } else { @{} }
            $remain = @{}
            foreach ($s in $script:AuditSevOrder) {
                $r = ([int]$(if ($ms.ContainsKey($s)) { $ms[$s] } else { 0 })) - ([int]$(if ($shown.ContainsKey($s)) { $shown[$s] } else { 0 }))
                if ($r -gt 0) { $remain[$s] = $r }
            }
            $parts = @($script:AuditSevOrder | Where-Object { $remain.ContainsKey($_) })
            if ($parts.Count -gt 0) {
                Write-AuditColor ' [' Gray -NoNewline
                for ($i = 0; $i -lt $parts.Count; $i++) {
                    $s = $parts[$i]
                    Write-AuditColor ("{0}:" -f $s) Gray -NoNewline
                    Write-AuditColor ([string]$remain[$s]) (Get-AuditSevConsoleColor $s) -NoNewline
                    if ($i -lt $parts.Count - 1) { Write-AuditColor ' ' Gray -NoNewline }
                }
                Write-AuditColor ']' Gray -NoNewline
            }
            Write-Host ''
        }
    }
}

# Drive the engine to completion, emitting progress per verbosity.
function Invoke-AuditPumpToDone {
    if ($script:AuditState -eq 'paused') { $script:AuditState = 'running' }
    $printed  = 0
    # Findings carried in from a prior phase (the Tier-2 -KeepFindings continuation keeps the list,
    # so the first pump tick re-flushes them at $printed 0..N-1). Tag those re-prints as already
    # reported in Tier-1 instead of looking like fresh hits. Zero for every other pump path (they
    # start from an empty findings list), so Tier-1-only / --defer-tier2 / --tier2-resume are unaffected.
    $seenBaseline = $script:AuditFindings.Count
    $lastTick = [DateTime]::MinValue
    $lastGc   = [DateTime]::UtcNow
    while ($script:AuditState -ne 'done' -and $script:AuditState -ne 'cancelled' -and $script:AuditState -ne 'idle') {
        Invoke-AuditPump
        # Reclaim the transient per-row churn (Convert-UriToItem strings, parsed rows) promptly so
        # the working set tracks the bounded live set, not what .NET is slow to return on a long run.
        if (([DateTime]::UtcNow - $lastGc).TotalSeconds -ge 10) { [GC]::Collect(); $lastGc = [DateTime]::UtcNow }
        if ($script:AuditVerbosity -ge 3) {
            while ($printed -lt $script:AuditFindings.Count) {
                $f = $script:AuditFindings[$printed]
                $tag = if ($printed -lt $seenBaseline) { '  (Tier 1 - Seen)' } else { '' }
                $printed++
                Write-AuditFindingLine $f $tag
            }
        }
        if ($script:AuditVerbosity -ge 2 -and ([DateTime]::UtcNow - $lastTick).TotalSeconds -ge 1) {
            Write-AuditColor (Format-AuditProgressLine) DarkGray
            $lastTick = [DateTime]::UtcNow
        }
        Start-Sleep -Milliseconds 100
    }
    if ($script:AuditVerbosity -ge 3) {
        while ($printed -lt $script:AuditFindings.Count) {
            $f = $script:AuditFindings[$printed]
            $tag = if ($printed -lt $seenBaseline) { '  (Tier 1 - Seen)' } else { '' }
            $printed++
            Write-AuditFindingLine $f $tag
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
    $present = @(@('Critical','High','Medium','Low','Informational') | Where-Object { $counts.ContainsKey($_) })
    # Compose the breakdown as -NoNewline segments so each severity's COUNT renders in its own colour
    # (label text stays default), then a final Write-Host terminates the line. Colour-off / verbosity
    # paths still produce the identical plain text via Write-AuditColor's fallback.
    Write-Host ''
    Write-AuditColor 'Audit complete: ' -NoNewline
    Write-AuditColor ([string]$script:AuditFindings.Count) White -NoNewline
    Write-AuditColor ' finding(s)' -NoNewline
    if ($present.Count -gt 0) {
        Write-AuditColor ' [' -NoNewline
        for ($i = 0; $i -lt $present.Count; $i++) {
            $s = $present[$i]
            Write-AuditColor ("{0}:" -f $s) -NoNewline
            Write-AuditColor ([string]$counts[$s]) (Get-AuditSevConsoleColor $s) -NoNewline
            if ($i -lt $present.Count - 1) { Write-AuditColor ' ' -NoNewline }
        }
        Write-AuditColor ']' -NoNewline
    }
    Write-Host ''
}

# Phase A: a Tier-1 audit of the local index to completion, applying excludes. Sources work ONLY from
# the index shards (no searching/discovery); requires an index to be present (a partial one is fine).
# When $emitList is set (inline -2 or --defer-tier2), every relay-eligible file is written through to
# the worklist for a Tier-2 pass. Returns the worklist path (or '').
function Invoke-HeadlessAudit([hashtable]$O, [bool]$emitList = $false) {
    Initialize-AuditRunConfig $O

    # Load the index (lightweight: migrations + the small re-walk skip-set; nothing bulk-loaded).
    Import-Index $script:IndexPath
    $haveIndex = (Test-Path -LiteralPath $script:IndexPath) -and ([bool]$script:Repos -or @(Get-IndexedRepos).Count -gt 0)
    if (-not $haveIndex) {
        $populate = [bool]($O.ContainsKey('PopulateIndex') -and $O['PopulateIndex'])
        if (-not $populate) {
            throw "No local index found at $($script:IndexPath). Build one first with StartIndex.ps1 (e.g. .\StartIndex.ps1 -u $($script:BaseUrl)), or pass --populate-index to build it automatically."
        }
        # Auto-build a full+archives index first, forwarding the relevant config (BaseUrl/auth/repos/
        # repo-types/index-path already set above; verbosity forwarded). Uses the INDEX throttle
        # defaults (workers 50 / walkers 20 / arc-workers 15 / delay 0), not the audit ones.
        Write-V 1 'No local index found - building one first (--populate-index)...'
        $script:IndexVerbosity = $script:AuditVerbosity
        Invoke-IndexBuildRun -Full $true -Archives $true
        $script:IndexManifest = $null; Import-Index $script:IndexPath
        if (-not ([bool]$script:Repos -or @(Get-IndexedRepos).Count -gt 0)) {
            throw "Index build produced nothing to audit at $($script:IndexPath): $(Get-RepoScopeDiagnostic)"
        }
    }

    # Header (non-indented) + indented run details. The audit verb sources work ONLY from the local
    # index, so it's always 'from local index'.
    Write-V 1 'Auditing from local index'
    Write-V 2 "  index dir: $script:IndexPath"
    Write-V 2 ("  settings: tier=1$(if ($emitList) { '+worklist' } else { '' }) cap=$script:AuditCap workers=$($script:AuditThrottle.MaxConcurrent) delay=$($script:AuditThrottle.MinIntervalMs)ms")
    Write-V 2 "  output dir: $script:AuditDir"
    if (-not (Start-AuditIndex)) {
        Write-V 1 'No in-scope indexed repos to audit.'
    }

    # Open the Tier-2 worklist AFTER Start-AuditIndex's reset (which doesn't touch the worklist), so
    # rows are written through during the pump below. Reset-AuditEngine cleared the path either way.
    $wl = ''
    if ($emitList) { $wl = Join-Path $script:AuditDir 'tier2-pending.csv'; Open-AuditTier2List $wl }

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
# Header (non-indented) + indented run details shown before the 'Pending downloads:' section when an
# actual download is about to start (not for the 'count' preview).
function Write-DownloadStartHeader([string]$auditLog, [string]$settings, [string]$downloadDir) {
    Write-V 1 'Starting downloads'
    if ($auditLog) { Write-V 2 "  audit log: $auditLog" }
    Write-V 2 "  settings: $settings"
    Write-V 2 "  download dir: $downloadDir"
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
    Write-AuditColor 'Pending downloads:' Gray
    $tc = 0; $tb = 0L; $tu = 0
    foreach ($s in $order) {
        if (-not $cnt.ContainsKey($s) -or $cnt[$s] -eq 0) { continue }
        # Label + size in default grey; the count coloured by its severity; '(+N unknown size)' dark grey.
        Write-AuditColor ("  {0,-14} " -f $s) Gray -NoNewline
        Write-AuditColor ("{0,7}" -f $cnt[$s]) (Get-AuditSevConsoleColor $s) -NoNewline
        Write-AuditColor ("   {0}" -f (Format-Size $bytes[$s])) Gray -NoNewline
        if ($unk[$s] -gt 0) { Write-AuditColor (" (+{0} unknown size)" -f $unk[$s]) DarkGray -NoNewline }
        Write-Host ''
        $tc += $cnt[$s]; $tb += $bytes[$s]; $tu += $unk[$s]
    }
    # Total row: count in white.
    Write-AuditColor ("  {0,-14} " -f 'Total') Gray -NoNewline
    Write-AuditColor ("{0,7}" -f $tc) White -NoNewline
    Write-AuditColor ("   {0}" -f (Format-Size $tb)) Gray -NoNewline
    if ($tu -gt 0) { Write-AuditColor (" (+{0} unknown size)" -f $tu) DarkGray -NoNewline }
    Write-Host ''
}
# Write the run's output. ALWAYS (re)builds the single definitive audit-log.csv by consolidating the
# cumulative per-repo <repo>-matches.csv (merged Tier-1+Tier-2 label, highest severity, one row per
# file, complete across resumed/split runs - overwritten, no append dups). $downloadSpec then governs
# downloading the included findings of THIS run:
#   ''        (no --download)         -> catalogue only (audit-log.csv).
#   'count'                           -> catalogue + print the per-severity download breakdown.
#   'all'                             -> download every included finding (download-log.csv).
#   '<sev,...>' (e.g. high,medium)    -> download only those severities.
function Complete-AuditOutput([string]$downloadSpec, [long]$maxBytes = 0) {
    $cands = @(Get-AuditIncludedCandidates)
    Write-AuditSummary

    # The definitive consolidated catalogue - always produced after any completed run.
    $logPath = Join-Path $script:AuditDir 'audit-log.csv'
    $n = Build-AuditLogFromMatches $logPath
    if ($script:AuditVerbosity -ge 1) { Write-AuditColor "Consolidated $n finding(s) -> $logPath" DarkGray }

    $spec = "$downloadSpec".Trim().ToLower()
    if (-not $spec) { return }
    if ($spec -eq 'count') { Write-AuditDownloadBreakdown (Select-WithinSize $cands $maxBytes); return }

    $sel = $cands
    if ($spec -ne 'all') {
        $set = Resolve-AuditSevSet $spec
        $sel = @($cands | Where-Object { $set.Contains([string]$_.Sev) })
    }
    $sel = @(Select-WithinSize $sel $maxBytes)   # drop files over the per-file size limit (if any)
    if ($sel.Count -eq 0) { Write-AuditDownloadBreakdown $sel; Write-V 1 'No findings to download.'; return }
    $dlSettings = "severity=$(if ($spec) { $spec } else { 'all' })" + $(if ($maxBytes -gt 0) { " max-size=$(Format-Size $maxBytes)" } else { '' })
    Write-DownloadStartHeader $logPath $dlSettings $script:OutDir
    Write-AuditDownloadBreakdown $sel
    Write-Host ''
    if ($script:AuditVerbosity -ge 1) { Write-AuditColor ("Downloading {0} file{1}." -f $sel.Count, $(if ($sel.Count -ne 1) { 's' } else { '' })) }
    $res = Invoke-AuditDownloadSet $sel
    Write-V 1 (Get-DedupDoneLine $res)
    Write-V 1 ('Logged to ' + (Join-Path $script:OutDir 'download-log.csv'))
}

# Download files listed in a prior audit-log.csv, no auditing. The catalogue left Hash and Timestamp
# blank; this recomputes them and writes download-log.csv with both filled. $downloadSpec narrows the
# set by severity exactly like the audit path's --download: '' or 'all' = every row; '<sev,...>'
# (e.g. high,medium) = only those severities; 'count' = print the per-severity breakdown, no download.
function Invoke-DownloadFromLog([string]$file, [string]$downloadSpec = '', [long]$maxBytes = 0) {
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

    $spec = "$downloadSpec".Trim().ToLower()
    if ($spec -eq 'count') { Write-AuditDownloadBreakdown (Select-WithinSize $entries $maxBytes); return }
    $sel = $entries
    if ($spec -and $spec -ne 'all') {
        $set = Resolve-AuditSevSet $spec
        $sel = @($entries | Where-Object { $set.Contains([string]$_.Sev) })
    }
    $sel = @(Select-WithinSize $sel $maxBytes)   # drop rows over the per-file size limit (if any)
    if ($sel.Count -eq 0) { Write-V 1 "No rows in $file to download (after severity/size filters)."; return }
    $dlSettings = "severity=$(if ($spec -and $spec -ne 'all') { $spec } else { 'all' })" + $(if ($maxBytes -gt 0) { " max-size=$(Format-Size $maxBytes)" } else { '' })
    Write-DownloadStartHeader $file $dlSettings $script:OutDir
    Write-AuditDownloadBreakdown $sel
    Write-Host ''
    if ($script:AuditVerbosity -ge 1) { Write-AuditColor ("Downloading {0} file{1}." -f $sel.Count, $(if ($sel.Count -ne 1) { 's' } else { '' })) }
    $res = Invoke-DedupDownload $sel
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
    Set-AuditPreviewConfig $O
    if ($O.ContainsKey('Cap') -and [long]$O['Cap'] -gt 0)        { $script:AuditCap = [long]$O['Cap'] }
    if ($O.ContainsKey('Workers') -and [int]$O['Workers'] -gt 0) { $script:AuditThrottle.MaxConcurrent = [Math]::Max(1, [Math]::Min(10, [int]$O['Workers'])) }
    if ($O.ContainsKey('DelayMs') -and [int]$O['DelayMs'] -ge 0) { $script:AuditThrottle.MinIntervalMs = [int]$O['DelayMs'] }
}

# ── ENTRY FUNCTION ────────────────────────────────────────────────────────────
# The single audit entry. Tier-2 (content scanning) is the DEFAULT and is a two-phase, resumable,
# worklist-driven flow:
#   (default)          Tier-1 + Tier-2: Phase A (Tier-1 + worklist) then Phase B (content scan), merged.
#   -NoTier2 / --tier1 Tier-1 only: classify the index, catalogue matches to audit-log.csv.
#   -DeferTier2        Phase A only: Tier-1 + write the worklist (tier2-pending.csv), then stop.
#   -Tier2Resume <f>   Phase B only: content-scan an existing worklist, resumable via its .progress cursor.
#   -PopulateIndex     if no index exists, build a full+archives index first, then audit.
#   -FromLog <f>       skip auditing; just download the rows of a prior audit-log.csv.
# Native-parameter implementation (splat-callable). The public Invoke-Audit front-end below accepts
# the unix-style flags instead, so paste-mode and the .ps1 share one flag vocabulary.
function Invoke-AuditCore {
    param(
        [string]$Repos, [string]$RepoTypes,
        [switch]$Tier2, [switch]$NoTier2, [string]$Download, [string]$Exclude,
        [string]$IndexPath, [long]$Cap, [int]$Workers, [int]$DelayMs,
        [string]$OutDir, [int]$Verbosity,
        [string]$BaseUrl, [string]$ApiKey, [string]$Token, [string]$Basic,
        [string]$FromLog, [switch]$DeferTier2, [string]$Tier2Resume, [string]$MaxSize, [switch]$PopulateIndex,
        [int]$PreviewCount, [int]$PreviewWindow, [switch]$NoColour
    )
    $O = $PSBoundParameters
    $script:AuditColour = -not ($O.ContainsKey('NoColour') -and $O['NoColour'])
    # Per-file download size limit (bytes, or a suffix like 100MB). 0 = no limit. Applied to the
    # download selection (and the count/breakdown) so files larger than this aren't fetched.
    $maxBytes = Convert-ToBytes $MaxSize

    # -FromLog: skip auditing, just download a prior audit-log.csv (optionally severity-filtered or
    # previewed via --download <sev,...>|count).
    if ($O.ContainsKey('FromLog') -and $O['FromLog']) {
        Initialize-AuditBaseConfig $O $true
        Invoke-DownloadFromLog ([string]$O['FromLog']) ([string]$Download) $maxBytes
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
        Complete-AuditOutput $Download $maxBytes
        return
    }

    if ($DeferTier2 -and $Tier2) { throw 'Use either -2/--tier2 (scan now) or --defer-tier2 (write the worklist and stop), not both.' }
    # Tier-2 is the DEFAULT; --no-tier2 / --tier1 runs a Tier-1 catalogue only.
    $doTier2 = -not $NoTier2

    if ($DeferTier2) {
        # Phase A only: Tier-1 + write the worklist, then stop (resume later with --tier2-resume / -2).
        $wl = Invoke-HeadlessAudit $O $true
        Complete-AuditOutput ('') $maxBytes
        Write-V 1 ("Wrote $($script:AuditTier2ListTotal) Tier-2 candidate(s) to $wl")
        Write-V 1 ("  resume Tier-2 later with:  audit --tier2-resume `"$wl`" -u $($script:BaseUrl)  (or just re-run with -2)")
        return
    }

    if ($doTier2) {
        # If a worklist from a prior interrupted run (or a --defer-tier2) is already on disk, RESUME it
        # from its .progress cursor instead of rebuilding. Resolve output first so we know where it is.
        Initialize-AuditBaseConfig $O $true
        $wlPath = Join-Path $script:AuditDir 'tier2-pending.csv'
        if (Test-Path -LiteralPath $wlPath) {
            $cur = Read-AuditT2Cursor $wlPath
            Write-V 1 "Found an existing Tier-2 worklist ($wlPath; $cur row(s) already done) - resuming. Delete it to force a fresh scan."
            $script:AuditEmitSkipped = $false
            if (Start-AuditTier2List $wlPath) {   # fresh (no -KeepFindings); cursor honoured
                if ($O.ContainsKey('Exclude')) { Set-AuditExcludes ([string]$O['Exclude']) }
                Invoke-AuditPumpToDone
                Update-AuditExcludedHeadless
            }
            Complete-AuditOutput $Download $maxBytes
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
        Complete-AuditOutput $Download $maxBytes
        return
    }

    # Tier-1 only (--no-tier2): catalogue the index, no content scanning.
    [void](Invoke-HeadlessAudit $O $false)
    Complete-AuditOutput $Download $maxBytes
}

# ── SEARCH (REST + optional archive walk) ─────────────────────────────────────
# Drive the archive-search walk to completion, emitting progress per verbosity.
function Invoke-ArcSearchPumpToDone {
    $lastTick = [DateTime]::MinValue
    while ($script:ArcSearchState -eq 'walking') {
        Invoke-ArcSearchPump
        if ($script:AuditVerbosity -ge 2 -and ([DateTime]::UtcNow - $lastTick).TotalSeconds -ge 1) {
            $walk = if (Test-ArcSearchWalkActive) { ' (walking)' } else { '' }
            Write-AuditColor ("  ...indexed $($script:ArcIndexedArchives.Count) archive(s), $($script:ArcSearchResults.Count) match(es)$walk") DarkGray
            if ($script:AuditVerbosity -ge 5) {
                Write-AuditColor ("    queue=$($script:ArcQueue.Count) jobs=$($script:ArcJobs.Count) indexed=$($script:ArcIndexedArchives.Count)") DarkGray
            }
            $lastTick = [DateTime]::UtcNow
        }
        Start-Sleep -Milliseconds 100
    }
}

# `search` verb: run the public quick-search and, with -w/--walk-archives, also walk the
# instance's listable archives in the background and add internal entries whose name
# matches the query. Writes the combined results to a CSV and (unless --no-index) caches
# walked archive contents to the index for reuse. Native-parameter implementation; the public
# Invoke-Search front-end (below) takes the unix-style flags.
function Invoke-SearchCore {
    param(
        [string]$Query, [string]$Repos, [string]$RepoTypes, [switch]$WalkArchives, [switch]$AllVersions,
        [string]$IndexPath, [switch]$NoIndex, [string]$Offline,
        [long]$Cap, [int]$Workers, [int]$DelayMs,
        [string]$OutDir, [int]$Verbosity,
        [string]$BaseUrl, [string]$ApiKey, [string]$Token, [string]$Basic, [switch]$NoColour
    )
    $O = $PSBoundParameters
    $script:AuditColour = -not ($O.ContainsKey('NoColour') -and $O['NoColour'])
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

# ── CONSOLE/PASTE FRONT-ENDS ──────────────────────────────────────────────────
# Take the SAME unix-style flags as the script (e.g. Invoke-Audit -s audit-log.csv --download
# critical,high,medium --max-size 100MB), identical to `.\StartAuditEngine.ps1 audit -s ...`. No
# param() block, so dash-flags land in $args instead of being bound as native parameters; they're
# parsed by ConvertFrom-AuditArgv and forwarded to the native-parameter Invoke-AuditCore/SearchCore.
function Invoke-Audit {
    if (@($args).Count -eq 0) { Show-AuditEngineUsage; return }
    try { $splat = ConvertFrom-AuditArgv @($args) }
    catch { Write-Host "Error: $($_.Exception.Message)`n"; Show-AuditEngineUsage; return }
    Invoke-AuditCore @splat
}
function Invoke-Search {
    if (@($args).Count -eq 0) { Show-AuditEngineUsage; return }
    try { $splat = ConvertFrom-AuditArgv @($args) }
    catch { Write-Host "Error: $($_.Exception.Message)`n"; Show-AuditEngineUsage; return }
    Invoke-SearchCore @splat
}

# ── DISPATCH (script-file invocation) ─────────────────────────────────────────
# Paste-safe: if/else (not guard-and-return) because a bare `return` does NOT halt the remaining
# pasted lines in an interactive session - so pasting the whole file just shows usage instead of
# throwing on an empty $args (the IndexOutOfRange on `$args[0]`).
if (-not $env:ARTCA_NOMAIN) {
    if (@($args).Count -eq 0) {
        Show-AuditEngineUsage
    } else {
        $verb = [string]$args[0]
        $rest = if ($args.Count -gt 1) { @($args[1..($args.Count - 1)]) } else { @() }
        try {
            $splat = ConvertFrom-AuditArgv $rest
            switch ($verb.ToLower()) {
                'audit'    { Invoke-AuditCore @splat }
                'search'   { Invoke-SearchCore @splat }
                'help'     { Show-AuditEngineUsage }
                '-h'       { Show-AuditEngineUsage }
                '--help'   { Show-AuditEngineUsage }
                default    { Write-Host "Unknown verb: $verb`n"; Show-AuditEngineUsage }
            }
        } catch {
            Write-Host "Error: $($_.Exception.Message)`n"
            Show-AuditEngineUsage
        }
    }
}
