#Requires -Version 5.1
<#
.SYNOPSIS
    Artifactory TUI search using the public Artifactory quick-search REST API
    (GET /artifactory/api/search/artifact). Works anonymously on instances that
    grant the anonymous user read access; otherwise supply a credential.
.DESCRIPTION
    NOTE: this tool does NOT use the browser /ui/api/... endpoint. That endpoint
    requires a frontend session token (aud "jffe@*") that is short-lived and
    revoked whenever the browser refreshes, so scraped cookies cannot be replayed.
    The public REST API below is the supported, scriptable path.
.PARAMETER BaseUrl
    Artifactory base URL, e.g. https://artifactory.example.com  (prompted if omitted).
    A trailing /artifactory is added automatically if not already present.
.PARAMETER ApiKey
    JFrog API key (X-JFrog-Art-Api). Omit for anonymous access.
.PARAMETER Token
    Bearer access/identity token (audience must include Artifactory).
.PARAMETER Basic
    Basic auth as "user:password".
.PARAMETER Repos
    Optional comma-separated list of repositories to restrict the search to.
.PARAMETER PageSize
    Rows per page. Paging is client-side over the result set. Defaults to 0,
    meaning auto-size to fill the current window (and re-fit when it's resized);
    pass a positive number to pin a fixed page size instead.
.PARAMETER Prefetch
    How many pages ahead to eagerly warm in the background (default 5). The page
    you're on plus this many ahead are fetched at full concurrency; pages beyond
    that are trickled in gently. Higher = smoother fast-flicking, more requests.
.PARAMETER OutDir
    Folder downloads are saved into (created if missing). Defaults to
    ./output/<host>/downloads under the current directory.
.PARAMETER Offline
    Run without contacting the server for search. 'index' uses the saved local index as the
    ONLY catalogue (no search queries) but still fetches content/previews/archive listings on
    demand; 'all' makes NO requests at all - search, previews, content and archive listings come
    only from the local index and previously-downloaded files on disk (audit is disabled). Omit
    (or '') for normal online operation.
#>
param(
    [string] $BaseUrl  = '',
    [string] $ApiKey   = '',
    [string] $Token    = '',
    [string] $Basic    = '',
    [string] $Repos    = '',
    [int]    $PageSize = 0,
    [int]    $Prefetch = 5,
    [string] $OutDir   = '',
    [string] $IndexPath = '',
    [ValidateSet('', 'index', 'all')]
    [string] $Offline  = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Allow many concurrent connections (default is 2/host) so the parallel detail
# fetch isn't throttled, and ensure TLS 1.2 is available for HTTPS.
[Net.ServicePointManager]::DefaultConnectionLimit = 64
[Net.ServicePointManager]::SecurityProtocol =
    [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# Windows PowerShell 5.1 leaves the console on the OEM code page (CP437/850),
# which can't encode glyphs outside its set — anything beyond it (e.g. …, the
# truncation marker) is transliterated to '?'. Box-drawing chars survive only
# because they happen to live in CP437. Switch console output to UTF-8 so every
# Unicode glyph renders. Guarded: ISE / redirected output can't set this and throw.
try { [Console]::OutputEncoding = [Text.UTF8Encoding]::new() } catch { }

# ── ANSI ──────────────────────────────────────────────────────────────────────
# $host.UI.SupportsVirtualTerminal is set by the host process (Windows Terminal,
# VS Code, pwsh) — no DLL imports or Add-Type needed.
if ($host.UI.SupportsVirtualTerminal) {
    $E  = [char]27
    $R  = "$E[0m"
    $BD = "$E[1m"
    $DM = "$E[2m"
    $CY = "$E[38;5;117m"
    $MG = "$E[38;5;141m"
    $YL = "$E[38;5;221m"
    $RD = "$E[38;5;203m"
    $HB = "$E[48;5;17m"
    $SB = "$E[48;5;238m"   # selected-row background
} else {
    $R = $BD = $DM = $CY = $MG = $YL = $RD = $HB = $SB = ''
}
$LB = '['; $RB = ']'

# Small badges shown after a name in detailed/preview listings: '+' flags a
# browsable archive, the interpunct (·) flags a previewable text file.
$script:ArcGlyph     = '+'
$script:PreviewGlyph = [char]0x00B7

# Marker appended wherever text is truncated to fit a column (…).
$script:Cut = [char]0x2026

# ── HOST CAPABILITIES ───────────────────────────────────────────────────────────
# PowerShell ISE has no real console: RawUI.ReadKey / KeyAvailable throw or
# misbehave, and RawUI.WindowSize is $null. Probe once so we can fall back to
# Read-Host input and skip the non-blocking poll (which needs a real key buffer)
# on such hosts. ISE is also matched by name, since it returns from some RawUI
# members without throwing yet still can't ReadKey.
$script:CanRawKey = $true
try { [void]$host.UI.RawUI.KeyAvailable } catch { $script:CanRawKey = $false }
if ($host.Name -eq 'Windows PowerShell ISE Host') { $script:CanRawKey = $false }

# In-place frame rendering (the flicker fix) needs both a VT-capable host (for the
# cursor/erase escapes) and a real console. When unavailable we fall back to
# Clear-Host + Write-Host per line.
$script:Vt = ($host.UI.SupportsVirtualTerminal -and $script:CanRawKey)


# ── LOAD COMPONENTS ───────────────────────────────────────────────────────────
# Pull in the function/state definitions from the sibling files. Guarded so it
# only runs when executed as a file ($PSScriptRoot is set) AND the definitions
# aren't already present (Show-Page is the sentinel). Pasting this script into the
# console leaves $PSScriptRoot empty, so the paste path skips this and relies on
# the component files having been pasted beforehand; a second run in the same
# session is likewise a no-op.
if ($PSScriptRoot -and -not (Get-Command Show-Page -ErrorAction SilentlyContinue)) {
    foreach ($component in 'Core','Api','Render','Prefetch','Views','Archive','Index') {
        . (Join-Path $PSScriptRoot "$component.ps1")
    }
    # The audit module is OPTIONAL and split into a headless engine + an interactive
    # view: load BOTH only if both are present beside the others. Their absence leaves
    # the tool working exactly as before.
    $auditEng  = Join-Path $PSScriptRoot 'AuditEngine.ps1'
    $auditView = Join-Path $PSScriptRoot 'AuditView.ps1'
    if ((Test-Path -LiteralPath $auditEng) -and (Test-Path -LiteralPath $auditView)) {
        . $auditEng; . $auditView
    }
}

# Route the shared bulk-download engine's progress through the popup overlay (Core
# leaves the hook $null; the headless engine sets a verbosity writer instead).
$script:DownloadProgress = { param($lines) Show-Popup $lines }

# Capability flag the base files gate every audit reference on. Always defined
# (default $false) so StrictMode is satisfied when the audit module is absent; flipped
# on only once the audit VIEW is present (its menu entry point Show-AuditMenu) —
# whether dot-sourced above (file mode) or pasted beforehand (paste mode).
$script:AuditAvailable = [bool](Get-Command Show-AuditMenu -ErrorAction SilentlyContinue)

# The local index + archive-search engine (Index.ps1) is a CORE component, always loaded
# in file mode; gate its key handlers / pump / startup load on its presence so a paste-mode
# session that pasted only the original component files still runs (the [w]/[W] keys and the
# index simply do nothing).
$script:IndexAvailable = [bool](Get-Command Import-Index -ErrorAction SilentlyContinue)

# ── MAIN ──────────────────────────────────────────────────────────────────────

if ($env:ARTCA_NOMAIN) { return }   # test hook: load functions without the UI loop

if (-not $BaseUrl) {
    Clear-Screen
    Write-Host "`n  ${BD}${MG}ARTCA - Artifactory Search${R}`n"
    Write-Host -NoNewline '  Artifactory URL: '
    $BaseUrl = (Read-Host).Trim()
}
$BaseUrl = $BaseUrl.TrimEnd('/')

# Offline mode: 'index' uses the local index as the only catalogue (no search queries) but still
# fetches content/previews/archive listings on demand; 'all' makes no requests whatsoever (those
# come only from the index + previously-downloaded files on disk). In 'all', the audit feature is
# disabled - it inherently requires fetching file content to scan.
Set-OfflineMode $Offline
if (Test-NetworkBlocked) { $script:AuditAvailable = $false }

# Resolve the per-instance output layout (now that the base URL is known): downloads + audit
# dirs under output/<host>/. An explicit -OutDir is kept verbatim.
$script:OutDirExplicit = ($PSBoundParameters.ContainsKey('OutDir') -and $OutDir)
Resolve-OutputPaths

# Resolve the per-instance index directory (output/<host>/index) and run the lightweight load
# (legacy-index migration + archive skip-set). Per-page metadata is warmed on demand from the
# shards (Warm-IndexMeta), so an indexed page fires no metadata requests. Guarded so the tool
# runs unchanged without the index component.
if ($script:IndexAvailable) {
    if ($PSBoundParameters.ContainsKey('IndexPath') -and $IndexPath) { Set-IndexPath $IndexPath }
    Resolve-IndexPath
    if ($script:IndexEnabled) { Import-Index $script:IndexPath }
}

$query    = Read-Query
if (-not $query) { return }   # return (not exit): quitting a pasted session must not close the console

$page       = 0
$fetch      = $true    # re-query the server only when the query changes
$mode       = 'simple' # 'd' cycles simple -> detailed -> preview
$pendingKey = ''       # a non-nav key absorbed while coalescing a paging burst
$selRow     = 0        # highlighted row within the current page (cursor)
$autoPage   = ($PageSize -le 0)   # 0 (default) => size each page to the window
$pvScroll   = 0        # preview-pane scroll offset for the selected file ([ / ])
$lastPvId   = ''       # previewed item's id last frame; changing it resets the scroll
$excludeText = ''      # results exclude-filter terms ('f' edits, 'i' clears)
$excludeRx   = @()     # compiled glob regexes for $excludeText (empty = no filter)
$hideDone    = $false  # 'h' hides excluded + already-downloaded results from the list
# Archive-search ('w' toggles): also search inside listable archives, walking them in the
# background and appending matching internal entries to the results live. The local index
# ('W' toggles) persists artifact + archive metadata to disk so warm browsing makes no
# server requests. Both read their default from the engine's persistent settings (off / on).
# $arcItems accumulates the archive-walk matches for the current query; $localHits holds the
# local index name-matches; both are merged into the browse set each render.
$arcSearch   = ($script:IndexAvailable -and $script:ArcSearchEnabled)
$arcIndex    = (-not $script:IndexAvailable) -or $script:IndexEnabled
$arcItems    = @()
$localHits   = @()
# The merged/excluded/hidden browse set ($allItems) depends only on the result set + filters,
# NOT on page/selRow - so it's rebuilt only when an input changes (new query, new arc matches,
# exclude/hide toggle, a download). $rebuildView gates that O(totalItems) work; navigation
# redraws reuse the cached list (O(pageSize)), which is what keeps a huge offline result set
# from making every keystroke laggy.
$rebuildView   = $true
$allItems      = @()
$hideableCount = 0
# Local-index results stream in chunks of $chunk rather than all at once, so the whole match set is
# reachable without building it in one go. $searchLoadedRaw = matches pulled from the index so far;
# $searchTotal = total matches (counted once per query). The nav loop tops up the next chunk when
# paging to the end or when excluding/hiding leaves fewer than a window of visible rows.
$chunk          = [int]$script:IndexSearchMax
$searchLoadedRaw = 0
$searchTotal     = 0

# Default to passive audit (Tier-1 only, no archive walk — set in Audit.ps1) so every
# view is flagged for secrets out of the box. The user can turn it off or switch modes
# from the audit menu ([a]). Guarded so the tool runs unchanged without the component.
if ($script:AuditAvailable) { Start-AuditPassive }

:main while ($true) {

    # Auto page size: fill the window, leaving room for the chrome (title, rules,
    # column header, footer rule, nav) plus any transient alert/flash lines, plus
    # one spare row. Recomputed every iteration so a window resize re-fits on the
    # next redraw. The non-preview views render every row of the page, so the page
    # must not exceed what fits; preview windows its rows and tolerates more.
    if ($autoPage) {
        # 8 fixed chrome lines (title, 2 rules, query, 3 table rules/header, spare) plus
        # however many lines the wrapped footer hints took last render (>=1).
        $reserve = 8 + $script:NavLineCount
        if ($script:Alert.Message -and ([DateTime]::UtcNow - $script:Alert.At).TotalSeconds -lt 60) { $reserve++ }
        if ($script:Flash.Message -and ([DateTime]::UtcNow - $script:Flash.At).TotalSeconds -lt 15) { $reserve++ }
        if ($excludeRx.Count -gt 0) { $reserve++ }   # header line showing the active filter
        $PageSize = [Math]::Max(5, (Get-Height) - $reserve)
    }

    if ($fetch) {
        Show-Loading $query
        $result = Search-Artifacts -Query $query
        $fetch  = $false

        if ($result.Error) {
            Show-Error $result.Error
            :errkey while ($true) {
                switch (Read-Key) {
                    's' { $query = Read-Query; if (-not $query) { break main }; $page = 0; $fetch = $true; break errkey }
                    'q' { break main }
                }
            }
            continue main
        }

        # New result set: collect local index name-matches (top-level + already-indexed
        # archive entries) for this query, and restart the archive-search walk when enabled
        # (its background walk targets the current query; the prior query's matches clear).
        $localHits = @()
        $searchLoadedRaw = 0; $searchTotal = 0
        if ($script:IndexAvailable) {
            $arcItems  = @()
            # First chunk only (with the full match count), so a broad query on a large index
            # doesn't build everything at once; the nav loop tops up further chunks on demand.
            $localHits       = @(Search-Index $query 0 $chunk -WantTotal)
            $searchLoadedRaw = $localHits.Count
            $searchTotal     = [int]$script:IndexSearchTotal
            if ($arcSearch) {
                Start-ArcSearch $query $result.Items
                # Surface any instant matches from the on-disk index on this first render;
                # the background walk streams the rest in via the nav-loop poll below.
                $arcItems = @(Receive-ArcSearchResults)
            } else { Stop-ArcSearch }
        }
        $rebuildView = $true   # new query/result set: rebuild the browse set below
    }

    # Browse set = live REST results, then local index name-matches not already present, then
    # archive-walk matches found so far. Deduped by .Uri; REST-first + append-only discovery order
    # keeps paging stable as matches stream in. These passes are O(totalItems) - which is huge for a
    # broad offline index query - so they run ONLY when an input changed ($rebuildView), not on every
    # navigation redraw. Navigation reuses the cached $allItems/$hideableCount (recomputed: new query,
    # arc matches, exclude/hide toggle, download).
    if ($rebuildView) {
        $allItems = @($result.Items)
        if ($script:IndexAvailable) {
            $seenUri = New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($it in $allItems) { [void]$seenUri.Add([string]$it.Uri) }
            foreach ($it in (@($localHits) + @($arcItems))) {
                if ($it -and $seenUri.Add([string]$it.Uri)) { $allItems += $it }
            }
            $allItems = @($allItems)
        }
        # Exclude filter: items whose name matches a glob are dimmed and sorted to the
        # back (included items keep their original order), mirroring the audit view.
        if ($excludeRx.Count -gt 0 -and $allItems.Count -gt 0) {
            $inc = [Collections.Generic.List[object]]::new()
            $exc = [Collections.Generic.List[object]]::new()
            foreach ($it in $allItems) {
                if (Test-NameMatchesAny ([string]$it.Name) $excludeRx) { $exc.Add($it) } else { $inc.Add($it) }
            }
            $allItems = @($inc.ToArray()) + @($exc.ToArray())
        }
        # Hide toggle ('h'): drop excluded + already-downloaded results from the view. Count
        # the hideable ones for the footer hint; the surviving set drives pagination/numbering.
        $hideableCount = @($allItems | Where-Object {
            (Test-Visited ([string]$_.Uri)) -or (Test-NameMatchesAny ([string]$_.Name) $excludeRx)
        }).Count
        if ($hideDone) {
            $allItems = @($allItems | Where-Object {
                -not ((Test-Visited ([string]$_.Uri)) -or (Test-NameMatchesAny ([string]$_.Name) $excludeRx))
            })
        }
        $rebuildView = $false
    }
    $totalItems = $allItems.Count
    $totalPages = [Math]::Max(1, [Math]::Ceiling($totalItems / $PageSize))
    if ($page -ge $totalPages) { $page = $totalPages - 1 }
    $offset     = $page * $PageSize

    # Top up the next chunk of local-index matches when more remain AND either the current view
    # isn't a full window (excluding/hiding trimmed it below $chunk) or we've paged to the last
    # page. Loads one chunk, then re-runs the merge/filter via `continue main`; cascades until the
    # window is filled or everything is loaded. Bounded: $searchLoadedRaw advances each load and
    # the outer guard stops at $searchTotal, so it always terminates.
    if ($script:IndexAvailable -and $searchLoadedRaw -lt $searchTotal -and
        (($totalItems -lt $chunk) -or ($page -ge $totalPages - 1))) {
        Show-Popup @('Loading more results...', "$searchLoadedRaw of $searchTotal scanned")
        $more = @(Search-Index $query $searchLoadedRaw $chunk)
        if ($more.Count -gt 0) {
            $localHits = @($localHits) + $more
            $searchLoadedRaw += $more.Count
            $rebuildView = $true
            continue main
        }
        $searchLoadedRaw = $searchTotal   # nothing more returned; stop topping up
    }
    # Header total: when index matches remain unloaded, show the upper-bound count (REST results +
    # all index matches) so the user knows more exist than the loaded window; else 0 = "(N results)".
    $script:ResultGrandTotal = if ($searchLoadedRaw -lt $searchTotal) { @($result.Items).Count + $searchTotal } else { 0 }
    # Assign in two steps: an `if/else` returning @() collapses to $null in the
    # output stream, which then trips Set-StrictMode on .Count downstream.
    $pageItems = @()
    if ($totalItems -gt 0) {
        $pageItems = @($allItems[$offset..([Math]::Min($offset + $PageSize - 1, $totalItems - 1))])
    }
    # Keep the row cursor within this page; only highlight on a real console.
    if ($selRow -gt $pageItems.Count - 1) { $selRow = [Math]::Max(0, $pageItems.Count - 1) }
    if ($selRow -lt 0) { $selRow = 0 }
    $hl = if ($script:CanRawKey) { $selRow } else { -1 }
    $detailed = ($mode -ne 'simple')   # detailed + preview both fetch size/modified
    $preview  = ($mode -eq 'preview')  # two-pane mode: warm previews in background

    # Reset the preview scroll whenever the previewed item changes (a new file
    # always opens at the top), keyed off the selected item's storage uri.
    $pvId = if ($preview -and $selRow -ge 0 -and $selRow -lt $pageItems.Count) {
        [string]$pageItems[$selRow].Uri
    } else { '' }
    if ($pvId -ne $lastPvId) { $pvScroll = 0; $lastPvId = $pvId }

    # Detailed view only: load the repo map once, then show whatever detail is
    # already cached. We never block on a "Loading details..." screen — the page
    # renders immediately and rows fill in (see the nav loop below) as the
    # background pool lands their entries. Default view does no extra fetching.
    if ($detailed) {
        Initialize-RepoMap
        Receive-Prefetch         # reap finished jobs, freeing pool slots
        if ($script:IndexAvailable) { [void](Warm-IndexMeta $pageItems) }         # fill $MetaCache from the on-disk shards (no network)
        Apply-Meta $pageItems
        if ($script:IndexAvailable) { [void](Update-IndexFromMeta $pageItems) }   # persist newly-known metadata
    }

    # Passive audit (if running): enqueue this page nearest-first and pump once so
    # markers for any matches show on this very render. Guarded — no-op without the
    # audit component. Content findings arrive asynchronously via the nav-loop poll.
    if ($script:AuditAvailable -and $script:AuditState -eq 'passive') {
        [void](Invoke-AuditPassiveTick $pageItems $selRow)
    }

    Show-Page -Query $query -Items $pageItems -Page $page `
              -TotalPages $totalPages -TotalItems $totalItems -Offset $offset -Mode $mode -SelRow $hl -PvScroll $pvScroll -ExcludeRx $excludeRx -Filter $excludeText -HideDone $hideDone -HideableCount $hideableCount

    # Background warming (non-blocking, detailed view only). Build a prefetch
    # window in priority order — current page first, then pages fanning outward
    # (ahead-biased, since skimming runs forward) — cancel any pending work
    # outside it, then (re)queue it. This keeps the pool focused on where the
    # user actually is instead of grinding sequentially through pages they left.
    # Pages beyond the window trickle in gently, ahead only.
    if ($detailed) {
        $back     = 2
        $winPages = [Collections.Generic.List[int]]::new()
        $winPages.Add($page)
        for ($d = 1; $d -le $Prefetch; $d++) {
            if ($page + $d -lt $totalPages)         { $winPages.Add($page + $d) }
            if ($d -le $back -and $page - $d -ge 0) { $winPages.Add($page - $d) }
        }

        $window = [Collections.Generic.List[object]]::new()
        foreach ($pg in $winPages) {
            $s = $pg * $PageSize
            $en = [Math]::Min($s + $PageSize - 1, $totalItems - 1)
            for ($i = $s; $i -le $en; $i++) { $window.Add($allItems[$i]) }
        }

        $keep = @{}
        foreach ($it in $window) { $keep[$it.Uri] = $true }
        Restrict-Prefetch $keep        # drop stale prior-page requests
        Start-Prefetch $window         # queue current page first, then outward

        $thrStart = ($page + $Prefetch + 1) * $PageSize
        if ($thrStart -le $totalItems - 1) {
            # Bound the trickle so we don't hand a huge array to the runspace on
            # every page turn; deeper pages still fill via the nav loop's
            # on-demand prefetch when you get there.
            $thrEnd = [Math]::Min($thrStart + ($PageSize * 20) - 1, $totalItems - 1)
            Start-Lookahead @($allItems[$thrStart..$thrEnd])
        } else {
            Stop-Lookahead
        }
    } else {
        Stop-Lookahead    # back in simple view
        Close-MetaPool    # simple view warms no metadata; free the pool's runspaces
    }

    # Background-warm previews (preview mode only), tiered like the page prefetch:
    # the highlighted row + its nearest neighbours go to the pool at full speed,
    # the rest of the page trickles in one-by-one (nearest-first) until the whole
    # page is warm. The pane shows "Loading..." until each lands; the poll below
    # redraws as they arrive. $pvKeys = fast window; $pvPageKeys = the whole page.
    $pvKeys = @(); $pvPageKeys = @()
    if ($preview -and $pageItems.Count -gt 0) {
        $plan = Get-PreviewPlan $pageItems $selRow
        $keepPv = @{}; foreach ($k in $plan.WindowKeys) { $keepPv[$k] = $true }
        Restrict-PreviewPrefetch $keepPv      # drop fast fetches for rows we left
        Start-PreviewPrefetch $plan.WindowReqs # highlighted first, then nearest, fast
        Start-PreviewLookahead $plan.RestReqs  # the rest, trickled nearest-first
        Warm-OfflinePreviews $pageItems        # offline 'all': seed cache from disk/index (no-op online)
        $pvKeys     = $plan.WindowKeys
        $pvPageKeys = $plan.AllKeys
        # Trim the preview cache so a long skim doesn't pin every file ever viewed;
        # this page's keys are protected from eviction.
        $keepPvCache = @{}; foreach ($k in $pvPageKeys) { $keepPvCache[$k] = $true }
        Restrict-PreviewCache $keepPvCache
        # Archive previews fetch the whole tree - feed any that have resolved into the index.
        if ($script:IndexAvailable) { Save-PreviewedArchives $pageItems }
    } else {
        Restrict-PreviewPrefetch @{}          # left preview mode: drop pending work
        Stop-PreviewLookahead
        Receive-PreviewPrefetch
        Close-PreviewPool                     # free the preview pool's runspaces
    }

    # ISE / non-console hosts can't poll the keyboard, so the live fill-in loop
    # below is disabled there. Instead block briefly for this page's details to
    # arrive (they were just queued above), then redraw once with them filled.
    if ($detailed -and -not $script:CanRawKey -and (Get-MissingMeta $pageItems) -gt 0) {
        Wait-Meta $pageItems 5000
        Show-Page -Query $query -Items $pageItems -Page $page `
                  -TotalPages $totalPages -TotalItems $totalItems -Offset $offset -Mode $mode -SelRow $hl -PvScroll $pvScroll -ExcludeRx $excludeRx -Filter $excludeText -HideDone $hideDone -HideableCount $hideableCount
    }
    # Likewise block briefly for the highlighted item's preview on ISE.
    if ($preview -and -not $script:CanRawKey -and $pageItems.Count -gt 0) {
        $selKey = Get-ItemPreviewKey $pageItems[$selRow]
        if (Test-PreviewLoading $selKey) {
            Wait-Preview $selKey 5000
            Show-Page -Query $query -Items $pageItems -Page $page `
                      -TotalPages $totalPages -TotalItems $totalItems -Offset $offset -Mode $mode -SelRow $hl -PvScroll $pvScroll -ExcludeRx $excludeRx -Filter $excludeText -HideDone $hideDone -HideableCount $hideableCount
        }
    }

    # Rows already populated at the last draw; used so the fill-in poll only
    # repaints when a *new* row actually lands (no needless flicker).
    $shownCached = $pageItems.Count - (Get-MissingMeta $pageItems)
    $pvLoaded    = Get-PreviewLoadedCount $pvPageKeys
    # Consecutive poll ticks where nothing new landed and nothing is in flight.
    # Bounds how long we chase rows that never arrive (denied / persistently
    # failing) before settling for a normal blocking read.
    $idleTicks   = 0

    :nav while ($true) {
        # A non-nav key left over from coalescing a paging burst takes priority.
        if ($pendingKey) {
            $key = $pendingKey; $pendingKey = ''
        }
        # While any row's detail is still blank, or a preview in the window is still
        # loading, poll for keys and redraw as data lands — by *any* path, since we
        # key off the caches, not the queues. Keeps a partially-loaded page (and the
        # preview pane / badges) filling in instead of sitting stale, without ever
        # blocking the keyboard.
        # In offline 'all' no background fetch ever runs, so the metadata/preview clauses can
        # never resolve - skip them (Test-NetworkBlocked) so navigation blocks cleanly instead of
        # spinning the 120 ms poll. Metadata is warmed from the index and previews seeded from disk.
        elseif ($script:CanRawKey -and (
                    ($detailed -and -not (Test-NetworkBlocked) -and (Get-MissingMeta $pageItems) -gt 0 -and $idleTicks -lt 30) -or
                    ($preview  -and -not (Test-NetworkBlocked) -and ((Get-PreviewLoadingCount $pvKeys) -gt 0 -or
                                     ((Get-PreviewPendingCount $pvPageKeys) -gt 0 -and (Test-PreviewLookaheadAlive)))) -or
                    ($script:AuditAvailable -and $script:AuditState -eq 'passive' -and
                        ($script:AuditQueue.Count -gt 0 -or $script:AuditJobs.Count -gt 0)) -or
                    ($arcSearch -and $script:IndexAvailable -and $script:ArcSearchState -eq 'walking'))) {
            $key = Read-KeyTimeoutCased 120
            if ($null -eq $key) {
                Receive-Prefetch
                Receive-PreviewPrefetch
                $redraw = $false

                $nowCached = $pageItems.Count - (Get-MissingMeta $pageItems)
                if ($nowCached -gt $shownCached) {
                    $shownCached = $nowCached
                    $idleTicks   = 0
                    Apply-Meta $pageItems
                    if ($script:IndexAvailable) { [void](Update-IndexFromMeta $pageItems) }   # persist newly-known metadata
                    $redraw = $true
                } elseif ($detailed -and (Get-MissingMeta $pageItems) -gt 0 -and (Get-LoadingMeta $pageItems) -eq 0) {
                    # Nothing landed and nothing is in flight: re-queue the
                    # stragglers (covers transient failures) and count idle time.
                    $idleTicks++
                    Start-Prefetch $pageItems
                }

                if ($preview) {
                    # Re-warm the fast window (sizes that just landed unlock new file
                    # previews); if the trickle finished but page work remains, relaunch
                    # it; redraw when any preview resolves or a badge flips.
                    Receive-PreviewLookahead
                    $plan = Get-PreviewPlan $pageItems $selRow
                    Start-PreviewPrefetch $plan.WindowReqs
                    if (-not (Test-PreviewLookaheadAlive)) {
                        $restPending = @($plan.RestReqs | Where-Object { -not $script:PreviewCache.ContainsKey($_.Key) })
                        if ($restPending.Count -gt 0) { Start-PreviewLookahead $restPending }
                    }
                    $pvKeys     = $plan.WindowKeys
                    $pvPageKeys = $plan.AllKeys
                    $keepPvCache = @{}; foreach ($k in $pvPageKeys) { $keepPvCache[$k] = $true }
                    Restrict-PreviewCache $keepPvCache
                    if ($script:IndexAvailable) { Save-PreviewedArchives $pageItems }   # index resolved archive previews
                    $pvNow      = Get-PreviewLoadedCount $pvPageKeys
                    if ($pvNow -ne $pvLoaded) { $pvLoaded = $pvNow; $redraw = $true }
                }

                # Passive audit: enqueue/pump and redraw as matches land.
                if ($script:AuditAvailable -and $script:AuditState -eq 'passive') {
                    if (Invoke-AuditPassiveTick $pageItems $selRow) { $redraw = $true }
                }

                # Archive-search: advance the background walk and pull in any new matches.
                # New rows change the result set, so break out to the main loop to recompute
                # pagination and redraw (the current page + selection are preserved).
                if ($arcSearch -and $script:IndexAvailable -and $script:ArcSearchState -eq 'walking') {
                    Invoke-ArcSearchPump
                    $arcNew = @(Receive-ArcSearchResults)
                    if ($arcNew.Count -gt 0) { $arcItems = @($arcItems) + $arcNew; $rebuildView = $true; break nav }
                }

                if ($redraw) {
                    Show-Page -Query $query -Items $pageItems -Page $page `
                              -TotalPages $totalPages -TotalItems $totalItems `
                              -Offset $offset -Mode $mode -SelRow $hl -PvScroll $pvScroll -ExcludeRx $excludeRx -Filter $excludeText -HideDone $hideDone -HideableCount $hideableCount
                }
                continue nav
            }
            $idleTicks = 0   # a real keypress interrupts the chase
        } else {
            # Idle: nothing left to poll for, about to block for the next key.
            # Release the background pools' worker runspaces (tens of MB each in
            # PS 5.1); they reopen lazily on the next page turn. Gated on no pooled
            # fetch in flight so an active ahead-prefetch is never aborted.
            Receive-Prefetch; Receive-PreviewPrefetch
            if ($script:PfJobs.Count -eq 0 -and $script:PvJobs.Count -eq 0) { Close-PrefetchPools }
            $key = Read-KeyCased
        }

        # For paging keys, swallow the rest of any held-key burst (Invoke-NavBurst)
        # so we render/warm only the page the user actually lands on — preventing a
        # prefetch backlog that would leave the final page half-loaded. Re-render
        # only if the page actually moved (or a non-nav key was queued behind it).
        # [A] (Shift+A) downloads all not-yet-downloaded, non-excluded results. Handled
        # case-sensitively BEFORE the (case-insensitive) command switch so it doesn't
        # collide with lowercase [a] = audit.
        if ($key -ceq 'A') {
            if ($totalItems -gt 0) {
                Save-ItemSet (@($allItems | Where-Object {
                    -not ((Test-Visited ([string]$_.Uri)) -or (Test-NameMatchesAny ([string]$_.Name) $excludeRx))
                }))
            }
            $rebuildView = $true   # items now downloaded: refresh hideable/hidden set
            break nav
        }
        # [W] (Shift+W) toggles the local index on/off (startup load + all write-through).
        # Case-sensitive BEFORE the switch so it doesn't collide with lowercase [w].
        if ($key -ceq 'W' -and $script:IndexAvailable) {
            $arcIndex = -not $arcIndex
            $script:IndexEnabled = $arcIndex
            # Turning it on mid-session: ensure the lightweight load ran (migration + skip-set);
            # per-page Warm-IndexMeta resumes warming from the shards on the next render.
            if ($arcIndex) { Import-Index $script:IndexPath }
            $script:Flash.Message = "Local index $(if ($arcIndex) { 'on' } else { 'off' }) ($(Split-Path -Leaf $script:IndexPath))"
            $script:Flash.At      = [DateTime]::UtcNow
            break nav
        }
        # [V] (Shift+V) toggles skip-versions for the archive walk: when on (default), only the
        # first version of each artifact is expanded/indexed. Affects archives discovered AFTER
        # the toggle - already-seen ones are unchanged. Case-sensitive BEFORE the switch.
        if ($key -ceq 'V' -and $script:IndexAvailable) {
            $script:ArcSkipVersions = -not $script:ArcSkipVersions
            $script:Flash.Message = "Skip archive versions $(if ($script:ArcSkipVersions) { 'on' } else { 'off' })"
            $script:Flash.At      = [DateTime]::UtcNow
            break nav
        }
        switch -regex ($key) {
            '^(n|right|pagedown|p|left|pageup|home|end)$' {
                $before = $page
                switch -regex ($key) {
                    '^(n|right|pagedown)$' { if ($page -lt $totalPages - 1) { $page++ } }
                    '^(p|left|pageup)$'    { if ($page -gt 0)               { $page-- } }
                    '^home$'               { $page = 0 }
                    '^end$'                { $page = $totalPages - 1 }
                }
                Invoke-NavBurst ([ref]$page) $totalPages ([ref]$pendingKey)
                if ($page -ne $before) { $selRow = 0 }
                if ($page -ne $before -or $pendingKey) { break nav }
            }
            '^(up|k|down|j)$' {
                # Coalesce a held up/down burst into one net move (see Invoke-RowBurst)
                # so holding the key doesn't backlog renders. The move that triggered
                # this case is passed as the initial delta.
                $d = if ($key -match '^(down|j)$') { 1 } else { -1 }
                Invoke-RowBurst ([ref]$page) ([ref]$selRow) $PageSize $totalItems ([ref]$pendingKey) $d
                break nav
            }
            '^(shift\+up|shift\+down)$' {
                # Preview mode only: scroll the selected file/archive contents in the
                # pane. Coalesces a held burst like the row keys (see Invoke-ScrollBurst).
                if ($mode -eq 'preview') {
                    $d = if ($key -eq 'shift+down') { 1 } else { -1 }
                    Invoke-ScrollBurst ([ref]$pvScroll) $script:PvScrollMax ([ref]$pendingKey) $d
                }
                break nav
            }
            '^(enter|o)$' {
                $absIdx = $offset + $selRow
                if ($pageItems.Count -gt 0 -and $absIdx -ge 0 -and $absIdx -lt $totalItems) {
                    if ((Invoke-ItemAction $allItems[$absIdx] ($absIdx + 1) $mode) -eq 'quit') { break main }
                }
                $rebuildView = $true   # a download marks the item visited: refresh hideable/hidden set
                break nav
            }
            '^g$' { $t = Read-PageNumber $totalPages; if ($null -ne $t) { $page = $t; $selRow = 0 }; break nav }
            '^d$' {
                $mode = switch ($mode) { 'simple' { 'detailed' } 'detailed' { 'preview' } default { 'simple' } }
                break nav
            }
            '^y$' {
                # Preview mode: opt the highlighted file into a large (text) or force
                # (non-text) preview, but only when it's actually gated — so the 5 MB
                # ceiling can't be bypassed and archives are left alone.
                if ($mode -eq 'preview' -and $pageItems.Count -gt 0) {
                    $it = $allItems[$offset + $selRow]
                    if (-not (Test-ItemBrowsableArchive $it)) {
                        $u  = Get-ItemUrl $it
                        $sz = if ("$($it.Size)" -ne '' -and "$($it.Size)" -ne '?') { [long]$it.Size } else { -1 }
                        $st = Get-PreviewState ([string]$it.Name) $u $sz
                        if ($st -eq 'large-gated' -or $st -eq 'force-gated') { [void]$script:PreviewOK.Add($u) }
                    }
                    break nav
                }
            }
            '^s$' { $q = Read-Query; if ($q) { if ($script:AuditAvailable) { Reset-AuditEngine }; $query = $q; $page = 0; $selRow = 0; $fetch = $true }; break nav }
            '^f$' {
                # Edit the exclude filter: matching results dim and sort to the back.
                $excludeText = Read-ExcludeFilter $excludeText
                # @() keeps a single-term result an array (a lone regex would otherwise
                # unwrap to a scalar and break $excludeRx.Count downstream).
                $excludeRx   = @(Get-GlobRegexes $excludeText)
                $page = 0; $selRow = 0; $rebuildView = $true
                break nav
            }
            '^i$' {
                # Clear the exclude filter (show all results in their original order).
                if ($excludeRx.Count -gt 0) { $excludeText = ''; $excludeRx = @(); $page = 0; $selRow = 0; $rebuildView = $true }
                break nav
            }
            '^h$' {
                # Toggle hiding excluded + already-downloaded results from the list.
                $hideDone = -not $hideDone; $page = 0; $selRow = 0; $rebuildView = $true; break nav
            }
            '^w$' {
                # Toggle archive-search: also walk listable archives in the background and
                # append matching internal entries to the results. Enabling kicks off the
                # walk for the current query (seeding instant matches from the index);
                # disabling aborts the walk and drops the archive matches from the view.
                if ($script:IndexAvailable) {
                    $arcSearch = -not $arcSearch
                    $script:ArcSearchEnabled = $arcSearch
                    if ($arcSearch) {
                        Start-ArcSearch $query $result.Items
                        $arcItems = @(Receive-ArcSearchResults)
                        $script:Flash.Message = 'Archive-search on: walking listable archives in the background...'
                    } else {
                        Stop-ArcSearch
                        $arcItems = @()
                        $script:Flash.Message = 'Archive-search off.'
                    }
                    $script:Flash.At = [DateTime]::UtcNow
                    $page = 0; $selRow = 0; $rebuildView = $true
                }
                break nav
            }
            '^a$' {
                # Open the audit menu (only when the audit component is loaded).
                if ($script:AuditAvailable) {
                    $ctx = @{
                        LocationLabel = "all $totalItems result$(if ($totalItems -ne 1){'s'}) for '$query'"
                        LocationKind  = 'items'
                        Label         = "search: $query"
                        Items         = $allItems
                    }
                    [void](Show-AuditMenu $ctx)
                    $rebuildView = $true   # audit view may have downloaded/excluded items
                    break nav   # redraw results (markers / returning from audit view)
                }
            }
            '^q$' { break main }
            '^\d[\d,\s-]*$' {
                # Multi-download by number/spec (e.g. 1,3,5-9). The console captures the
                # first digit then reads the rest; ISE returns the whole spec on one line.
                # An empty spec (user cleared the prompt) cancels. Numbers index the
                # displayed list (which excludes hidden rows while hiding is on).
                $spec = if ($script:CanRawKey -and $key.Length -eq 1) { Read-NumberSpec $key } else { $key }
                $idx  = @(Parse-NumberSpec $spec $totalItems)   # @() so an empty spec doesn't $null under StrictMode
                if ($idx.Count -gt 0) { Save-ItemSet (@($idx | ForEach-Object { $allItems[$_ - 1] })) }
                $rebuildView = $true   # downloaded items: refresh hideable/hidden set
                break nav   # redraw the results page
            }
        }
    }
}

Stop-Lookahead          # signal the background trickles to stop (process exit reclaims the rest)
Stop-PreviewLookahead
Close-PrefetchPools     # release the pools' worker runspaces
if ($script:AuditAvailable) { Stop-AuditWork }   # abort any audit workers/walker (matters in paste-mode sessions)
if ($script:IndexAvailable) { Stop-ArcSearch }   # abort any archive-search walk/expansions

Clear-Screen
