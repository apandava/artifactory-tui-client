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
    ./artca-downloads under the current directory.
#>
param(
    [string] $BaseUrl  = '',
    [string] $ApiKey   = '',
    [string] $Token    = '',
    [string] $Basic    = '',
    [string] $Repos    = '',
    [int]    $PageSize = 0,
    [int]    $Prefetch = 5,
    [string] $OutDir   = (Join-Path (Get-Location).Path 'artca-downloads')
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
    foreach ($component in 'Render','Api','Prefetch','Views','Archive') {
        . (Join-Path $PSScriptRoot "$component.ps1")
    }
}

# ── MAIN ──────────────────────────────────────────────────────────────────────

if ($env:ARTCA_NOMAIN) { return }   # test hook: load functions without the UI loop

if (-not $BaseUrl) {
    Clear-Screen
    Write-Host "`n  ${BD}${MG}ARTCA - Artifactory Search${R}`n"
    Write-Host -NoNewline '  Artifactory URL: '
    $BaseUrl = (Read-Host).Trim()
}
$BaseUrl = $BaseUrl.TrimEnd('/')

$query    = Read-Query
if (-not $query) { return }   # return (not exit): quitting a pasted session must not close the console

$page       = 0
$fetch      = $true    # re-query the server only when the query changes
$mode       = 'simple' # 'd' cycles simple -> detailed -> preview
$pendingKey = ''       # a non-nav key absorbed while coalescing a paging burst
$selRow     = 0        # highlighted row within the current page (cursor)
$autoPage   = ($PageSize -le 0)   # 0 (default) => size each page to the window

:main while ($true) {

    # Auto page size: fill the window, leaving room for the chrome (title, rules,
    # column header, footer rule, nav) plus any transient alert/flash lines, plus
    # one spare row. Recomputed every iteration so a window resize re-fits on the
    # next redraw. The non-preview views render every row of the page, so the page
    # must not exceed what fits; preview windows its rows and tolerates more.
    if ($autoPage) {
        $reserve = 9
        if ($script:Alert.Message -and ([DateTime]::UtcNow - $script:Alert.At).TotalSeconds -lt 60) { $reserve++ }
        if ($script:Flash.Message -and ([DateTime]::UtcNow - $script:Flash.At).TotalSeconds -lt 15) { $reserve++ }
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
    }

    $allItems   = @($result.Items)
    $totalItems = $allItems.Count
    $totalPages = [Math]::Max(1, [Math]::Ceiling($totalItems / $PageSize))
    if ($page -ge $totalPages) { $page = $totalPages - 1 }
    $offset     = $page * $PageSize
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

    # Detailed view only: load the repo map once, then show whatever detail is
    # already cached. We never block on a "Loading details..." screen — the page
    # renders immediately and rows fill in (see the nav loop below) as the
    # background pool lands their entries. Default view does no extra fetching.
    if ($detailed) {
        Initialize-RepoMap
        Receive-Prefetch         # reap finished jobs, freeing pool slots
        Apply-Meta $pageItems
    }

    Show-Page -Query $query -Items $pageItems -Page $page `
              -TotalPages $totalPages -TotalItems $totalItems -Offset $offset -Mode $mode -SelRow $hl

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
        Stop-Lookahead   # back in simple view
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
        $pvKeys     = $plan.WindowKeys
        $pvPageKeys = $plan.AllKeys
    } else {
        Restrict-PreviewPrefetch @{}          # left preview mode: drop pending work
        Stop-PreviewLookahead
        Receive-PreviewPrefetch
    }

    # ISE / non-console hosts can't poll the keyboard, so the live fill-in loop
    # below is disabled there. Instead block briefly for this page's details to
    # arrive (they were just queued above), then redraw once with them filled.
    if ($detailed -and -not $script:CanRawKey -and (Get-MissingMeta $pageItems) -gt 0) {
        Wait-Meta $pageItems 5000
        Show-Page -Query $query -Items $pageItems -Page $page `
                  -TotalPages $totalPages -TotalItems $totalItems -Offset $offset -Mode $mode -SelRow $hl
    }
    # Likewise block briefly for the highlighted item's preview on ISE.
    if ($preview -and -not $script:CanRawKey -and $pageItems.Count -gt 0) {
        $selKey = Get-ItemPreviewKey $pageItems[$selRow]
        if (Test-PreviewLoading $selKey) {
            Wait-Preview $selKey 5000
            Show-Page -Query $query -Items $pageItems -Page $page `
                      -TotalPages $totalPages -TotalItems $totalItems -Offset $offset -Mode $mode -SelRow $hl
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
        elseif ($script:CanRawKey -and (
                    ($detailed -and (Get-MissingMeta $pageItems) -gt 0 -and $idleTicks -lt 30) -or
                    ($preview  -and ((Get-PreviewLoadingCount $pvKeys) -gt 0 -or
                                     ((Get-PreviewPendingCount $pvPageKeys) -gt 0 -and (Test-PreviewLookaheadAlive)))))) {
            $key = Read-KeyTimeout 120
            if ($null -eq $key) {
                Receive-Prefetch
                Receive-PreviewPrefetch
                $redraw = $false

                $nowCached = $pageItems.Count - (Get-MissingMeta $pageItems)
                if ($nowCached -gt $shownCached) {
                    $shownCached = $nowCached
                    $idleTicks   = 0
                    Apply-Meta $pageItems
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
                    $pvNow      = Get-PreviewLoadedCount $pvPageKeys
                    if ($pvNow -ne $pvLoaded) { $pvLoaded = $pvNow; $redraw = $true }
                }

                if ($redraw) {
                    Show-Page -Query $query -Items $pageItems -Page $page `
                              -TotalPages $totalPages -TotalItems $totalItems `
                              -Offset $offset -Mode $mode -SelRow $hl
                }
                continue nav
            }
            $idleTicks = 0   # a real keypress interrupts the chase
        } else {
            $key = Read-Key
        }

        # For paging keys, swallow the rest of any held-key burst (Invoke-NavBurst)
        # so we render/warm only the page the user actually lands on — preventing a
        # prefetch backlog that would leave the final page half-loaded. Re-render
        # only if the page actually moved (or a non-nav key was queued behind it).
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
            '^(up|k)$' {
                if ($selRow -gt 0)            { $selRow-- }
                elseif ($page -gt 0)          { $page--; $selRow = $PageSize - 1 }
                break nav
            }
            '^(down|j)$' {
                if ($selRow -lt $pageItems.Count - 1)  { $selRow++ }
                elseif ($page -lt $totalPages - 1)     { $page++; $selRow = 0 }
                break nav
            }
            '^(enter|o)$' {
                $absIdx = $offset + $selRow
                if ($pageItems.Count -gt 0 -and $absIdx -ge 0 -and $absIdx -lt $totalItems) {
                    if ((Invoke-ItemAction $allItems[$absIdx] ($absIdx + 1) $mode) -eq 'quit') { break main }
                }
                break nav
            }
            '^g$' { $t = Read-PageNumber $totalPages; if ($null -ne $t) { $page = $t; $selRow = 0 }; break nav }
            '^d$' {
                $mode = switch ($mode) { 'simple' { 'detailed' } 'detailed' { 'preview' } default { 'simple' } }
                break nav
            }
            '^y$' {
                # Preview mode: opt the highlighted (large/unknown) file into preview.
                if ($mode -eq 'preview' -and $pageItems.Count -gt 0) {
                    $u = Get-ItemUrl $allItems[$offset + $selRow]
                    [void]$script:PreviewOK.Add($u)
                    break nav
                }
            }
            '^s$' { $q = Read-Query; if ($q) { $query = $q; $page = 0; $selRow = 0; $fetch = $true }; break nav }
            '^q$' { break main }
            '^\d+$' {
                # Console captures one digit then reads the rest; ISE's Read-Host
                # already returns the whole number on one line.
                $sel = if ($script:CanRawKey -and $key.Length -eq 1) {
                    Read-ItemNumber $key
                } else {
                    $n = 0; if ([int]::TryParse($key, [ref]$n)) { $n } else { $null }
                }
                if ($null -ne $sel -and $sel -ge 1 -and $sel -le $totalItems) {
                    if ((Invoke-ItemAction $allItems[$sel - 1] $sel $mode) -eq 'quit') { break main }
                }
                break nav   # redraw the results page
            }
        }
    }
}

Stop-Lookahead          # signal the background trickles to stop (process exit reclaims the rest)
Stop-PreviewLookahead

Clear-Screen
