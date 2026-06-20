# AuditView.ps1 - interactive view half of the ARTCA audit module.
#
# The OPTIONAL credential/secret audit, VIEW half: the full-screen results view, the
# audit menu, on-demand preview, passive (background) mode, severity colours/letters,
# row formatting, metadata/preview warming, and the interactive download wrappers.
# Loaded ONLY by the TUI (StartTui.ps1), alongside the headless AuditEngine.ps1 it
# drives. Needs Core.ps1 + Api.ps1 + the TUI render layer + AuditEngine.ps1 in scope.
#
# Definitions only; nothing here runs on its own.
#
# File conventions: UTF-8 without BOM, LF endings; any non-ASCII glyph that affects
# execution is a numeric [char] escape (literal Unicode only in comments).

# Order page items nearest-first around the selection (like the preview plan) so
# passive auditing prioritises what the user is looking at.
function Get-AuditNearOrder($items, [int]$sel) {
    $items = @($items)
    $out = [Collections.Generic.List[object]]::new()
    if ($items.Count -eq 0) { return @() }
    if ($sel -lt 0 -or $sel -ge $items.Count) { $sel = 0 }
    $out.Add($items[$sel])
    $max = [Math]::Max($sel, $items.Count - 1 - $sel)
    for ($d = 1; $d -le $max; $d++) {
        if ($sel + $d -lt $items.Count) { $out.Add($items[$sel + $d]) }
        if ($sel - $d -ge 0)            { $out.Add($items[$sel - $d]) }
    }
    return $out.ToArray()
}

# Keep the passive content queue to JUST the on-screen items, ordered nearest-first
# (the keys, nearest-cursor first). Pending content fetches for items no longer on the
# page are dropped and forgotten (removed from $AuditSeen) so the engine never lags
# behind on pages the user has flicked past — and so a revisit re-audits them. Archive
# expansion jobs (non-file) are left untouched. In-flight fetches are allowed to finish
# (their result is still a valid finding); only not-yet-started work is discarded.
function Restrict-AuditPassive([string[]]$orderedKeys) {
    if ($script:AuditQueue.Count -eq 0) { return }
    $rank = @{}
    foreach ($k in $orderedKeys) { if ($k -and -not $rank.ContainsKey($k)) { $rank[$k] = $true } }
    $kept    = [Collections.Generic.Queue[object]]::new()   # non-file jobs, original order
    $onPage  = @{}                                           # on-page file recs by key
    foreach ($rec in $script:AuditQueue) {
        $kind = [string]$rec.Kind; if (-not $kind) { $kind = 'file' }
        if ($kind -ne 'file') { $kept.Enqueue($rec); continue }
        if ($rank.ContainsKey($rec.Key)) { $onPage[$rec.Key] = $rec }
        else {
            [void]$script:AuditSeen.Remove($rec.Key)
            [void]$script:AuditSeenPath.Remove((Get-AuditPathIdentity $rec))
            if ($script:AuditEnq -gt 0) { $script:AuditEnq-- }
        }
    }
    foreach ($k in $orderedKeys) { if ($onPage.ContainsKey($k)) { $kept.Enqueue($onPage[$k]) } }
    $script:AuditQueue = $kept
}

# Called each frame by the base results loop while passive auditing: enqueue the
# current page (nearest-first), drop stale off-page work, pump, and report whether the
# view should redraw.
function Invoke-AuditPassiveTick($pageItems, [int]$selRow) {
    if ($script:AuditState -ne 'passive') { return $false }
    $ordered = @(Get-AuditNearOrder $pageItems $selRow)
    Add-AuditWork $ordered
    Restrict-AuditPassive (@($ordered | ForEach-Object { [string]$_.Uri }))
    Invoke-AuditPump
    $d = $script:AuditDirty; $script:AuditDirty = $false
    return $d
}

# Passive + a large file the user explicitly opted to preview: audit just that file
# at the full audit cap (its size already exceeds the passive/preview cap).
function Invoke-AuditPassiveBig($item) {
    if ($script:AuditState -ne 'passive' -or -not $script:AuditTier2) { return }
    $rec = New-AuditWorkItem $item
    $m = Test-AuditMeta $rec.Name $rec.Path
    if ($m.Discard -or $m.ContentRules.Count -eq 0) { return }
    [void]$script:AuditSeen.Add($rec.Key)
    $rec.ContentRules   = $m.ContentRules
    $rec.HasMetaFinding = ($m.Findings.Count -gt 0)
    $rec.Previewable    = $true
    $rec.Cap            = $script:AuditCap
    $script:AuditQueue.Enqueue($rec)
}

# Collect every file (non-folder) node under a tree node, recursing folders. Nested
# sub-archives can't be listed (Artifactory limitation) so they're left as files.
function Get-AuditTreeFiles($node, $subCache, $acc) {
    foreach ($n in @(Get-NodeKidsResolved $node $subCache)) {
        if ($null -eq $n) { continue }
        if (Get-NodeIsFolder $n) { Get-AuditTreeFiles $n $subCache $acc }
        else { $acc.Add($n) }
    }
}

# Passive tick for the archive tree: enqueue the visible file rows nearest-first
# around the cursor, pump, and report whether to redraw. Folders/sub-archives are
# skipped (sub-archives can't be listed).
function Invoke-AuditPassiveTickTree($rows, [int]$cursor, [string]$arcName) {
    if ($script:AuditState -ne 'passive') { return $false }
    $rows = @($rows)
    if ($rows.Count -gt 0) {
        if ($cursor -lt 0 -or $cursor -ge $rows.Count) { $cursor = 0 }
        $order = [Collections.Generic.List[int]]::new(); $order.Add($cursor)
        $max = [Math]::Max($cursor, $rows.Count - 1 - $cursor)
        for ($d = 1; $d -le $max; $d++) {
            if ($cursor + $d -lt $rows.Count) { $order.Add($cursor + $d) }
            if ($cursor - $d -ge 0)           { $order.Add($cursor - $d) }
        }
        $nodes = [Collections.Generic.List[object]]::new()
        foreach ($idx in $order) { $row = $rows[$idx]; if ($row -and -not $row.IsFolder) { $nodes.Add($row.Node) } }
        Add-AuditWorkNodes $nodes.ToArray() $arcName
        Restrict-AuditPassive (@($nodes.ToArray() | ForEach-Object { [string](Get-EntryUrl $_) }))
    } else {
        Restrict-AuditPassive @()
    }
    Invoke-AuditPump
    $d = $script:AuditDirty; $script:AuditDirty = $false
    return $d
}

# One-column status glyph for a file key, used by the base row renderers:
#   coloured '!'  a finding (severity colour)
#   grey '?'      passive mode: not yet scanned (or still in flight)
#   ''            scanned with nothing found, or not auditing this view
# The '?' progress glyph appears only while a PASSIVE audit is still working through
# the current view; a scanned-clean row is left blank (no '*'), and after a one-shot
# location/full audit only the '!' findings mark the rows.
function Get-AuditMarker([string]$key) {
    if (-not $key) { return '' }
    if ($script:AuditFlags.ContainsKey($key)) {
        $col = Get-AuditColor $script:AuditFlags[$key]
        return "${col}!${R}"   # $col/$R empty on a non-VT host -> plain '!'
    }
    # Passive: '?' while a row is still pending; blank once scanned with no match.
    if ($script:AuditState -eq 'passive' -and -not $script:AuditDecided.Contains($key)) {
        return "${DM}?${R}"
    }
    return ''
}

# Matched audit rule(s) for an item key (its storage uri), or '' when the item isn't
# flagged. Used by the search view to show the matched rule while passive auditing.
function Get-AuditRuleLabel([string]$key) {
    if ($key -and $script:AuditFindingIdx.ContainsKey($key)) { return [string]$script:AuditFindingIdx[$key].AllRules }
    return ''
}


# Human-readable progress/rate header lines for the audit view.
function Get-AuditStatusLines([int]$w) {
    $st = switch ($script:AuditState) {
        'running' { "${YL}running${R}" } 'paused' { "${RD}paused${R}" }
        'done' { "${CY}done${R}" } 'cancelled' { "${DM}cancelled${R}" } default { "$script:AuditState" }
    }
    $walk = if (Test-AuditWalkActive) { ' +walking' } else { '' }
    $prog = "audited ${BD}$script:AuditDone${R}${DM}/$script:AuditEnq$walk${R}  found ${BD}$($script:AuditFindings.Count)${R}"
    $thr  = "workers ${BD}$($script:AuditThrottle.MaxConcurrent)${R} delay ${BD}$($script:AuditThrottle.MinIntervalMs)${R}ms"
    # Fixed-width rate value so the line doesn't jitter as the number changes.
    $fps = '{0,6:0.0}' -f [double]$script:AuditRate.FPS
    $rate = "${DM}$fps files/s${R}"
    # Settings the run was started with (constant for the run): scan tier and whether
    # listable archives are walked and their entries audited.
    $set = "${DM}$(if ($script:AuditTier2) { 'Tier 2' } else { 'Tier 1' }) | archives $(if ($script:AuditWalkArchives) { 'on' } else { 'off' })${R}"
    # Everything on one line; the scope is truncated hard so the rate/workers/delay on the
    # right stay visible (Write-Frame clips anything still over the width as a backstop).
    $l1 = "  ${DM}Audit:${R} $(Trunc $script:AuditScope ([Math]::Max(8,$w-110)))   $set   $st   $prog   $rate   $thr"
    return @($l1)
}

# ── PREVIEW (synchronous, on demand) ──────────────────────────────────────────
# Preview-pane lines for the selected finding, served from the SAME background
# preview cache the search views use (warmed by Update-AuditPreviewWarm): the pane
# shows "Loading..." until the fetch lands, then the file's wrapped text (or, for a
# listable archive, a shallow tree listing). Wrapped output is memoised by key+width
# so scrolling/neighbour redraws don't re-wrap. No content is retained beyond the
# shared cache, which is trimmed to the visible page.
$script:AuditPvKey   = ''
$script:AuditPvLines = @()
function Get-AuditPreviewLines($f, [int]$paneW, [int]$maxLines, [int]$scroll = 0) {
    $script:PvScrollMax = 0
    $L = [Collections.Generic.List[string]]::new()
    $L.Add($script:PaneRuleTag)
    $L.Add("${BD}${YL}Preview${R}")
    $L.Add("${DM}$(Trunc $f.AllRules $paneW)${R}")
    $L.Add('')
    $name  = [string]$f.Name
    $isArc = (Get-IsArchive $name) -and (-not $f.InArchive)

    # Listable archive: show a shallow tree listing from the cache.
    if ($isArc) {
        $key = Get-ArcPreviewKey ([string]$f.Uri)
        if (-not $script:PreviewCache.ContainsKey($key)) { $L.Add("${DM}Loading preview...${R}"); return $L.ToArray() }
        $tree = $script:PreviewCache[$key]
        if (-not $tree.Ok) {
            $L.Add("${RD}Could not read archive.${R}")
            if ($tree.Error) { foreach ($wl in (Wrap-Text ([string]$tree.Error) $paneW)) { $L.Add("${DM}$wl${R}") } }
            return $L.ToArray()
        }
        $listKey = "AUD|$($f.Uri)|$paneW"
        if ($script:AuditPvKey -ne $listKey) {
            $rowsList = [Collections.Generic.List[string]]::new()
            Add-ArcListingLines @($tree.Nodes) '' $rowsList $paneW 2000
            $script:AuditPvLines = @($rowsList.ToArray()); $script:AuditPvKey = $listKey
        }
        if (@($script:AuditPvLines).Count -eq 0) { $L.Add("${DM}(empty archive)${R}"); return $L.ToArray() }
        foreach ($wl in (Get-ScrolledLines $script:AuditPvLines $maxLines $scroll)) { $L.Add($wl) }
        return $L.ToArray()
    }

    $url    = [string]$f.Url
    $forced = $script:PreviewOK.Contains($url)
    # Downloaded and excluded findings have their preview content freed; both can be
    # brought back with [y] (re-fetched). Skip these messages once force-opted so the
    # actual content renders below.
    if (((Test-Visited $f.Key) -or (Test-Downloaded $url)) -and -not $forced) {
        $L.Add("${DM}Downloaded - content cleared from memory.${R}")
        $L.Add("${DM}Press [d] to download again, or ${YL}[y]${R}${DM} to preview again.${R}")
        return $L.ToArray()
    }
    if ((-not $f.Included) -and -not $forced) {
        $L.Add("${DM}Excluded - content cleared from memory.${R}")
        $L.Add("${YL}Press [y] to force preview${R}${DM} again.${R}")
        return $L.ToArray()
    }
    $sz    = [long]$f.Size
    $state = Get-AuditPreviewability $name $url $sz
    $szTxt = if ($sz -ge 0) { Format-Size $sz } else { 'unknown size' }
    switch ($state) {
        'large-gated' {
            $L.Add("${YL}Large file ($szTxt).${R}"); $L.Add("${DM}Press [y] to preview it anyway.${R}")
            return $L.ToArray()
        }
        'toolarge' {
            $L.Add("${RD}File too large to preview ($szTxt).${R}")
            $L.Add("${DM}The 5 MB preview limit can't be overridden.${R}")
            return $L.ToArray()
        }
        'force-gated' {
            $L.Add("${DM}This is not a known text format.${R}")
            $L.Add("${YL}Press [y] to force preview${R}${DM} (extract readable text).${R}")
            return $L.ToArray()
        }
        'force-toolarge' {
            $L.Add("${DM}This is not a known text format.${R}")
            $L.Add("${RD}File too large to force preview ($szTxt).${R}")
            $L.Add("${DM}The 5 MB preview limit can't be overridden.${R}")
            return $L.ToArray()
        }
    }
    # 'auto' / 'large' / 'force': content is (being) fetched in the background.
    $key = Get-FilePreviewKey $url
    if (-not $script:PreviewCache.ContainsKey($key)) { $L.Add("${DM}Loading preview...${R}"); return $L.ToArray() }
    $res = $script:PreviewCache[$key]
    if (-not $res.Ok) {
        $L.Add("${RD}Could not load file for preview.${R}")
        if ($res.Error) { foreach ($wl in (Wrap-Text ([string]$res.Error) $paneW)) { $L.Add("${DM}$wl${R}") } }
        return $L.ToArray()
    }
    if ($null -eq $res.Bytes) { $L.Add("${RD}Could not load file for preview.${R}"); return $L.ToArray() }
    # Force preview extracts readable characters from a non-text file; otherwise decode
    # the text normally. Memoised by key + width + mode so scrolling reuses it.
    $force   = ($state -eq 'force')
    $wrapKey = "$($f.Key)|$paneW|$(if ($force) { 'R' } else { 'T' })"
    if ($script:AuditPvKey -ne $wrapKey) {
        # @(...) keeps a single-line result an array (so .Count is always valid); the
        # try/catch guards against a decode/extraction failure on malformed content.
        try {
            $text = if ($force) { Convert-BytesToReadable $res.Bytes } else { Convert-BytesToText $res.Bytes }
            $script:AuditPvLines = @(Wrap-Text $text $paneW)
            $script:AuditPvKey   = $wrapKey
        } catch {
            $L.Add("${RD}Failed to $(if ($force) { 'force ' })preview file.${R}")
            return $L.ToArray()
        }
    }
    if ($force -and @($script:AuditPvLines).Count -eq 0) { $L.Add("${DM}(no readable text found)${R}"); return $L.ToArray() }
    foreach ($wl in (Get-ScrolledLines $script:AuditPvLines $maxLines $scroll)) { $L.Add($wl) }
    return $L.ToArray()
}

# ── DOWNLOAD (with CSV tracking) ──────────────────────────────────────────────
# Download one finding into $OutDir, log it, and purge it (mark downloaded). Returns
# a status line styled like Save-Item.
function Save-AuditFinding($f, [string]$DestName = '') {
    try {
        if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
    } catch { return "${RD}${BD}Download failed:${R} cannot create ${CY}$OutDir${R}" }
    # $DestName is the (possibly hash-tagged) on-disk name from a bulk download; the CSV
    # still logs $f.Name (the original). Hash = storage checksum '<algo>:<hex>' when known;
    # archive entries have none, so it's computed from the saved bytes after the download.
    $fn   = if ($DestName) { $DestName } else { [string]$f.Name }
    $hash = if (-not $f.InArchive -and $f.Uri -and $script:MetaCache.ContainsKey($f.Uri) -and
                $script:MetaCache[$f.Uri].PSObject.Properties['Hash']) { [string]$script:MetaCache[$f.Uri].Hash } else { '' }
    $dest = Join-Path $OutDir $fn
    $old = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'
    try {
        Invoke-WebRequest -Uri $f.Url -Headers (Get-AuthHeaders) -OutFile $dest -ErrorAction Stop
        $len = -1; try { $len = (Get-Item $dest).Length } catch { }
        if (-not $hash) { $hash = Get-FileSha256 $dest }
        Write-DownloadLog $OutDir $f.Name $f.Repo $f.Path $(if ($f.InArchive) { [string]$f.ArchiveName } else { '' }) $len $f.Modified $f.Url $f.Sev $f.AllRules $hash
        Mark-Downloaded $f.Key $f.Url
        # Re-sort so the now-downloaded row drops to the very back (Mark-Downloaded only
        # changed the visited set, not the findings count, so nudge the sort explicitly).
        $script:AuditSortDirty = $true
        $sz = if ($len -ge 0) { ' (' + (Format-Size $len) + ')' } else { '' }
        return "${BD}Saved${R} to ${CY}$dest${R}$sz"
    } catch {
        try { if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Force } } catch { }
        return "${RD}${BD}Download failed:${R} $(Get-HttpErrorDetail $_)"
    } finally { $ProgressPreference = $old }
}

# Confirm + download a set of findings. Identical content is written to disk once (the same
# bytes under different paths/archives collapse to one file), but every finding is still
# logged to download-log.csv, so each occurrence stays individually recorded — matching the
# UI rows. Archive entries have no storage checksum, so their content is hashed from the
# bytes at download time. Shared by 'A' (download all included) and the numeric multi-download.
function Save-AuditFindingSet($candidates) {
    $candidates = @($candidates | Where-Object { $_ })
    if ($candidates.Count -eq 0) { Show-Popup @('Nothing to download.', '', 'press any key'); [void](Read-Key); return }
    $bytes = 0L; $haveAll = $true
    foreach ($f in $candidates) { if ($f.Size -ge 0) { $bytes += [long]$f.Size } else { $haveAll = $false } }
    $szStr = if ($haveAll) { Format-Size $bytes } else { "$(Format-Size $bytes)+ (some sizes unknown)" }
    $lines = @("${BD}Download $($candidates.Count) finding$(if ($candidates.Count -ne 1){'s'})?${R}",
               "${DM}Identical files are saved once on disk; each finding is still logged.${R}",
               "Total size: ${CY}$szStr${R}", "Into: ${CY}$OutDir${R}",
               "${DM}Each finding and its download URL is logged to download-log.csv there.${R}")
    if (-not (Confirm-Prompt $lines)) { return }
    # The engine builds the dedup entries (carrying any cached storage checksum) and runs
    # the shared dedup download; it also re-sorts so downloaded rows drop to the back.
    $res = Invoke-AuditDownloadSet $candidates
    Show-Popup @((Get-DedupDoneLine $res), "Into $OutDir", '', 'press any key')
    [void](Read-Key)
}

# 'A' download all: every INCLUDED, not-yet-downloaded finding.
function Save-AuditIncluded {
    Save-AuditFindingSet (Get-AuditIncludedCandidates)
}


# Re-apply the current exclude set across every finding: matches are excluded, the
# rest are left as-is (so manual [x] toggles on non-matching rows are preserved).
function Update-AuditExclusions {
    foreach ($f in $script:AuditFindings) {
        if (Test-AuditExcluded ([string]$f.Name)) {
            # Newly excluded: free its cached preview and reset the force-opt, matching
            # the manual [x] path so an excluded finding holds no preview content.
            if ($f.Included) {
                Clear-PreviewMem ([string]$f.Url)
                [void]$script:PreviewOK.Remove([string]$f.Url)
            }
            $f.Included = $false
        }
    }
    $script:AuditSortDirty = $true; $script:AuditDirty = $true
}

# 'Include all': clear the exclude filter and mark every finding included (including
# the otherwise default-excluded oversize text findings).
function Enable-AllAuditFindings {
    $script:AuditExcludes = @()
    foreach ($f in $script:AuditFindings) { $f.Included = $true }
    $script:AuditSortDirty = $true; $script:AuditDirty = $true
}

# Full-screen prompt to edit the exclude filter; the field is prefilled with the
# current terms so they can be tweaked. Returns the entered string (blank clears).
function Read-AuditFilter([string]$current) {
    Clear-Screen
    Write-Host "  ${BD}${MG}ARTCA${R}  ${DM}Audit exclude filter${R}`n"
    Write-Host "  ${DM}Space/comma-separated name globs to EXCLUDE from the download.${R}"
    Write-Host "  ${DM}e.g.  *.xml   *testing*   *.log   secret?.txt      (clear = no filter)${R}`n"
    if (-not $script:CanRawKey -and $current) { Write-Host "  ${DM}Current:${R} $current`n" }
    Write-Host -NoNewline "  Exclude: ${BD}${CY}"
    $s = Read-LineEdit $current
    Write-Host -NoNewline $R
    return $s
}

# ── MODIFIED FORMATTING ───────────────────────────────────────────────────────
# Normalise a finding's Modified into the same yyyy-MM-dd the search detailed view
# shows. Storage metadata is ISO 8601 (just take the date); archive-tree entries
# report epoch millis, which are converted first.
function Format-AuditModified([string]$s) {
    if (-not $s) { return '' }
    if ($s -match '^\d{10,}$') {
        $e = Format-Epoch $s   # 'yyyy-MM-dd HH:mm' (from Archive.ps1)
        if ($e) { return $e.Substring(0, [Math]::Min(10, $e.Length)) }
        return ''
    }
    return $s.Substring(0, [Math]::Min(10, $s.Length))
}

# ── ROW NAME CELL (with badges) ───────────────────────────────────────────────
# Mirror of Format-NameCell for findings: a '+' badge for a listable archive, a '.'
# badge for a previewable file. A non-previewable file gets the '.' badge too, but
# ONLY once it has been force-previewed (its url opted into PreviewOK). In preview
# mode the badge starts grey and turns yellow once that item's preview has loaded in
# the background (matching the search views); elsewhere it's solid yellow.
function Format-AuditNameCell($f, [int]$nameW, [bool]$dim, [bool]$preview) {
    $name  = [string]$f.Name
    $isArc = (Get-IsArchive $name) -and (-not $f.InArchive)
    $col   = if ($dim) { $DM } else { $CY }
    if ($isArc) {
        $glyph = $script:ArcGlyph;     $pkey = (Get-ArcPreviewKey ([string]$f.Uri))
    } elseif ((Get-IsPreviewable $name) -or $script:PreviewOK.Contains([string]$f.Url)) {
        $glyph = $script:PreviewGlyph; $pkey = (Get-FilePreviewKey ([string]$f.Url))
    } else {
        return "${col}$(Clip $name $nameW)${R}"
    }
    $gcol = if ($dim) { $DM }
            elseif ($preview) { if ($pkey -and $script:PreviewCache.ContainsKey($pkey)) { $YL } else { $DM } }
            else { $YL }
    $avail = [Math]::Max(1, $nameW - 2)            # reserve " <glyph>"
    $txt   = Trunc $name $avail
    $pad   = [Math]::Max(0, $nameW - $txt.Length - 2)
    return "${col}${txt}${R}${gcol} ${glyph}${R}$(' ' * $pad)"
}

# ── METADATA / PREVIEW WARMING ────────────────────────────────────────────────
# Warm storage metadata (size + ISO lastModified) for the visible findings via the
# shared prefetch pool, exactly as the search view does, so the Modified column fills
# in. Only fetches each uri once (AuditMetaTried) so denials aren't retried forever.
function Start-AuditMetaWarm($pageFindings) {
    $batch = [Collections.Generic.List[object]]::new()
    foreach ($f in @($pageFindings)) {
        if (-not $f -or -not $f.Uri) { continue }
        if ($script:MetaCache.ContainsKey($f.Uri) -or $script:AuditMetaTried.Contains($f.Uri)) { continue }
        [void]$script:AuditMetaTried.Add($f.Uri)
        $batch.Add([PSCustomObject]@{ Uri = [string]$f.Uri })
    }
    if ($batch.Count -gt 0) { Start-Prefetch $batch.ToArray() }
}

# Copy any landed storage metadata into the finding objects (Modified + Size), the
# audit-findings analogue of Apply-Meta. Cheap; called every render.
function Apply-AuditPageMeta($pageFindings) {
    $changed = $false
    foreach ($f in @($pageFindings)) {
        if (-not $f -or -not $f.Uri -or -not $script:MetaCache.ContainsKey($f.Uri)) { continue }
        $m = $script:MetaCache[$f.Uri]
        if (-not $f.Modified -and "$($m.Modified)" -ne '') { $f.Modified = "$($m.Modified)"; $changed = $true }
        if ($f.Size -lt 0 -and "$($m.Size)" -ne '')        { try { $f.Size = [long]$m.Size; $changed = $true } catch { } }
    }
    if ($changed) { $script:AuditDirty = $true }
}

# Audit findings use the same preview-eligibility model as the search/tree views;
# these delegate to the shared Get-PreviewState / Test-PreviewLoadable (Views.ps1) so
# the 512 KB auto cap, the [y] opt-in, the 5 MB hard ceiling, and force-preview of
# non-text files all behave identically everywhere.
function Get-AuditPreviewability([string]$name, [string]$url, [long]$sz) { Get-PreviewState $name $url $sz }
function Test-AuditPreviewLoadable([string]$state) { Test-PreviewLoadable $state }

# Background-preview request for a finding (file contents or archive listing), or
# $null when there's nothing to load. Uses the finding's own Url so archive-internal
# entries resolve correctly (unlike Get-ItemPreviewRequest, which recomputes it).
function Get-AuditPreviewRequest($f) {
    if ($null -eq $f) { return $null }
    $name  = [string]$f.Name
    $isArc = (Get-IsArchive $name) -and (-not $f.InArchive)
    if ($isArc) {
        if (-not $f.Uri) { return $null }
        $repoKey = [string]$f.Repo
        $archPath = if ($f.Path) { "$($f.Path)/$name" } else { $name }
        $rq = Get-TreeBrowseRequest $repoKey (Get-RepoTypeForUI $repoKey) `
                  ([string](Resolve-Repo $repoKey).PackageType) $archPath $name
        return @{ Key=(Get-ArcPreviewKey ([string]$f.Uri)); Kind='archive';
                  Uri=$rq.Uri; Body=$rq.Body; Headers=$rq.Headers; Ua=$rq.Ua }
    }
    $url = [string]$f.Url
    if (-not $url) { return $null }
    # A downloaded or excluded finding has its preview content freed and is NOT warmed,
    # unless the user force-opted it back in with [y] (tracked in PreviewOK).
    $forced = $script:PreviewOK.Contains($url)
    if ((Test-Downloaded $url) -and -not $forced) { return $null }
    if ((-not $f.Included)     -and -not $forced) { return $null }
    $sz  = if ($f.Size -ge 0) { [long]$f.Size } else { -1 }
    if (Test-AuditPreviewLoadable (Get-AuditPreviewability $name $url $sz)) {
        return @{ Key=(Get-FilePreviewKey $url); Kind='file'; Url=$url; Headers=(Get-AuthHeaders) }
    }
    return $null
}

# Plan the visible page's preview warming around the cursor (mirror of Get-PreviewPlan
# for findings): a fast window near the selection, the rest trickled by the lookahead.
function Get-AuditPreviewPlan($pageFindings, [int]$selRow, [int]$radius = 4) {
    $winReqs  = [Collections.Generic.List[object]]::new()
    $restReqs = [Collections.Generic.List[object]]::new()
    $allKeys  = [Collections.Generic.List[string]]::new()
    $items = @($pageFindings)
    if ($items.Count -gt 0) {
        # Clamp the cursor into range first: a stale/out-of-range selRow (e.g. right after
        # hiding rows shrinks the page) would otherwise index past the array or onto a $null.
        if ($selRow -lt 0) { $selRow = 0 }
        if ($selRow -ge $items.Count) { $selRow = $items.Count - 1 }
        $order = [Collections.Generic.List[int]]::new(); $order.Add($selRow)
        $max = [Math]::Max($selRow, $items.Count - 1 - $selRow)
        for ($d = 1; $d -le $max; $d++) {
            if ($selRow + $d -lt $items.Count) { $order.Add($selRow + $d) }
            if ($selRow - $d -ge 0)            { $order.Add($selRow - $d) }
        }
        foreach ($idx in $order) {
            if ($idx -lt 0 -or $idx -ge $items.Count) { continue }
            $rq = Get-AuditPreviewRequest $items[$idx]
            if (-not $rq) { continue }
            $allKeys.Add($rq.Key)
            if ([Math]::Abs($idx - $selRow) -le $radius) { $winReqs.Add($rq) } else { $restReqs.Add($rq) }
        }
    }
    return [PSCustomObject]@{ WindowReqs=@($winReqs.ToArray()); RestReqs=@($restReqs.ToArray()); AllKeys=@($allKeys.ToArray()) }
}

# Warm the page's previews (preview mode only): fast window via the pool, the rest
# trickled, stale fetches/cache trimmed to the visible page.
function Update-AuditPreviewWarm($pageFindings, [int]$selWithin) {
    $plan = Get-AuditPreviewPlan $pageFindings $selWithin
    $keep = @{}; foreach ($k in $plan.AllKeys) { $keep[$k] = $true }
    Restrict-PreviewPrefetch $keep
    Start-PreviewPrefetch $plan.WindowReqs
    Start-PreviewLookahead $plan.RestReqs
    Restrict-PreviewCache $keep
}

# Drop all in-flight preview work (leaving preview mode or the view entirely).
function Stop-AuditPreviewWarm {
    Restrict-PreviewPrefetch @{}
    Stop-PreviewLookahead
}

# ── AUDIT RESULTS VIEW ────────────────────────────────────────────────────────
# Search-results-style listing of findings, sorted highest-severity first, that
# doubles as the live progress screen for automatic audits: while running it polls
# + pumps the engine so rows appear as they're found, with pause/resume/cancel and
# real-time throttle controls. 'v' adds a preview pane; entries can be toggled
# in/out of the bulk download; 'a' downloads all included.
function Show-AuditView {
    $sel = 0; $mode = 'results'; $pvScroll = 0; $lastPvKey = ''; $lastWarmKey = ''; $selKey = ''
    $hideDone = $false    # hide excluded + already-downloaded findings from the list
    $navFooterLines = 1   # wrapped footer height from last render (reserved in body sizing)
    $notice = if ($script:AuditState -eq 'paused') {
        @{ Message = "${YL}Paused - set delay with ${LB}+/-${RB} (0-5000ms) and workers with ${LB}w/W${RB} (1-10), then ${LB}p${RB} to start.${R}"; At = [DateTime]::UtcNow }
    } else { @{ Message = ''; At = [DateTime]::MinValue } }
    $pendingKey = $null

    while ($true) {
        $active = ($script:AuditState -eq 'running' -or $script:AuditState -eq 'paused')
        $full   = @(Get-AuditSortedFindings)
        # Excluded + already-downloaded findings can be hidden from the list. Count them
        # for the footer hint; window the list when hiding is on.
        $hideableCount = @($full | Where-Object { (-not $_.Included) -or (Test-Visited $_.Key) }).Count
        # @(...) around the if/else: an else-branch that yields an empty collection would
        # otherwise collapse to $null under StrictMode and break $list.Count below.
        $list   = @(if ($hideDone) { @($full | Where-Object { $_.Included -and -not (Test-Visited $_.Key) }) } else { $full })
        $total  = $list.Count
        # Keep the cursor on the SAME finding when the list re-sorts (new results
        # loading in, or an exclude moving a row): if we know the selected item's key
        # and it's no longer under the cursor, move the cursor to wherever it landed.
        if ($selKey -and $total -gt 0 -and -not ($sel -ge 0 -and $sel -lt $total -and [string]$list[$sel].Key -eq $selKey)) {
            for ($i = 0; $i -lt $total; $i++) { if ([string]$list[$i].Key -eq $selKey) { $sel = $i; break } }
        }
        if ($sel -lt 0) { $sel = 0 }
        if ($sel -gt $total - 1) { $sel = [Math]::Max(0, $total - 1) }
        $w = ((Get-Width) - 1)
        $preview = ($mode -eq 'results-preview')

        $cur = if ($total -gt 0 -and $sel -lt $total) { $list[$sel] } else { $null }
        $pvKey = if ($preview -and $cur) { [string]$cur.Key } else { '' }
        if ($pvKey -ne $lastPvKey) { $pvScroll = 0; $lastPvKey = $pvKey }

        $L = [Collections.Generic.List[string]]::new()
        $title = '  ARTCA  Audit Findings  '
        $url   = $BaseUrl
        $avail = $w - $title.Length - 4
        if ($url.Length -gt $avail) { $url = Clip $url ([Math]::Max(1, $avail)) }
        $rt    = "  $url  "
        $gap   = [Math]::Max(0, $w - $title.Length - $rt.Length)
        $L.Add("${HB}${BD}${MG}${title}${R}${HB}$(' ' * $gap)${DM}${rt}${R}")
        $L.Add("$DM$(HR $w)$R")
        foreach ($sl in (Get-AuditStatusLines $w)) { $L.Add($sl) }
        if ($notice.Message -and ([DateTime]::UtcNow - $notice.At).TotalSeconds -lt 8) {
            $L.Add("  $(Trunc $notice.Message ($w - 4))")
        }

        # Column geometry.
        $rightW = if ($preview) { [Math]::Max(28, [int]($w * 0.42)) } else { 0 }
        $colW   = if ($preview) { $w - $rightW - 3 } else { $w }
        # Tight fixed widths (Sev is a single letter; Rule is capped low) so columns
        # pack together like the search view instead of leaving wide mid-table gaps;
        # Name (and Path, when shown) absorb the slack.
        $numW = 4; $sevW = 3; $typeW = 5; $sizeW = 9; $modW = 10
        $repoW = 0; $rtypeW = 0; $ptypeW = 0; $pathW = 0
        if ($preview) {
            $ruleW = [Math]::Min(16, [Math]::Max(8, [int]($colW * 0.18)))
            $fixed = $numW + $sevW + $typeW + $sizeW + $modW + $ruleW + 14
            $nameW = [Math]::Max(10, $colW - $fixed)
        } else {
            $ruleW  = [Math]::Min(18, [Math]::Max(10, [int]($colW * 0.15)))
            $rtypeW = 6; $ptypeW = 8
            $repoW  = [Math]::Min(16, [Math]::Max(8, [int]($colW * 0.14)))
            $fixed  = $numW + $sevW + $typeW + $sizeW + $modW + $ruleW + $repoW + $rtypeW + $ptypeW + 18
            $rest   = [Math]::Max(12, $colW - $fixed)
            $nameW  = [Math]::Max(10, [int]($rest * 0.55))
            $pathW  = [Math]::Max(0, $rest - $nameW)
        }

        $hdrCells = @(
            (ClipR '#' $numW), (Clip 'Sev' $sevW), (Clip 'Name' $nameW), (Clip 'Type' $typeW),
            (ClipR 'Size' $sizeW), (Clip 'Modified' $modW), (Clip 'Rule' $ruleW)
        )
        if (-not $preview) {
            $hdrCells += (Clip 'Repo' $repoW); $hdrCells += (Clip 'RType' $rtypeW); $hdrCells += (Clip 'PType' $ptypeW)
            if ($pathW -gt 0) { $hdrCells += (Clip 'Path' $pathW) }
        }
        $hdrLine = "${BD}${YL}$($hdrCells -join ' ')${R}"

        # Top border + page geometry. The page is computed BEFORE any row is built so
        # we only ever format the rows actually on screen — formatting the whole
        # findings list every frame was the cause of the navigation lag.
        $L.Add("$DM$(HR-Join $w ($(if ($preview) { $colW + 1 } else { $w }) ) ([char]0x252C))$R")
        # Reserve the bottom border + the wrapped footer (its height from last frame)
        # + one spare, so a multi-line footer is never clipped.
        $bodyH = [Math]::Max(4, (Get-Height) - $L.Count - (2 + $navFooterLines))
        $rowsH = [Math]::Max(1, $bodyH - 2)          # minus the column header + its divider
        $totalPages = [Math]::Max(1, [int][Math]::Ceiling($total / $rowsH))
        $page = [int][Math]::Floor($sel / $rowsH)
        if ($page -ge $totalPages) { $page = $totalPages - 1 }
        if ($page -lt 0) { $page = 0 }
        $offset = $page * $rowsH
        $end = [Math]::Min($offset + $rowsH - 1, $total - 1)

        # Warm storage metadata (fills the Modified column) and, in preview mode, the
        # background preview cache for the visible page — the same machinery the search
        # views use. Metadata copy-in runs every render (cheap); the fetch launches are
        # gated on the page/selection actually changing so the lookahead isn't thrashed.
        $pageFindings = if ($total -gt 0) { @($list[$offset..$end]) } else { @() }
        $selWithin = $sel - $offset
        Apply-AuditPageMeta $pageFindings
        $warmKey = "$offset|$end|$sel|$preview|$total"
        if ($warmKey -ne $lastWarmKey) {
            Start-AuditMetaWarm $pageFindings
            if ($preview) { Update-AuditPreviewWarm $pageFindings $selWithin } else { Stop-AuditPreviewWarm }
            $lastWarmKey = $warmKey
        }

        $leftLines = [Collections.Generic.List[string]]::new()
        $leftLines.Add("  $hdrLine")
        $leftLines.Add($script:HeaderRuleTag)
        if ($total -eq 0) {
            # No placeholder while active (startup / scanning); rows appear as they're found.
            if (-not $active) { $leftLines.Add("  ${DM}No findings.${R}") }
        } else {
            for ($ri = $offset; $ri -le $end; $ri++) {
                $f   = $list[$ri]
                $sels = ($ri -eq $sel)
                $excluded = (-not $f.Included)
                $downloaded = Test-Visited $f.Key
                $dim = ($excluded -or $downloaded)
                # Column colours mirror the non-audit detailed view: Type yellow,
                # Size/RType default, Repo/PType magenta, Modified/Path dim. Dimmed rows
                # (excluded or downloaded) wash every cell out, including the severity
                # marker letter.
                $cType = if ($dim) { $DM } else { $YL }
                $cDim  = if ($dim) { $DM } else { '' }
                $cRepo = if ($dim) { $DM } else { $MG }
                $sevCol = if ($dim) { $DM } else { Get-AuditColor $f.Sev }
                $sevCell = if ($script:Vt) { "${sevCol}$(Clip (Get-AuditLetter $f.Sev) $sevW)${R}" } else { Clip (Get-AuditLetter $f.Sev) $sevW }
                $size = if ($f.Size -ge 0) { Format-Size $f.Size } else { '?' }
                # Show '?' until the storage-metadata warm lands a date (mirrors the
                # search view's Modified column and the Size cell above); a blank cell
                # otherwise looks like the column is broken when the fetch is slow/denied.
                $modd = Format-AuditModified ([string]$f.Modified)
                if (-not $modd) { $modd = '?' }
                $cells = @(
                    "${DM}$(ClipR ([string]($ri + 1)) $numW)${R}",
                    $sevCell,
                    (Format-AuditNameCell $f $nameW $dim $preview),
                    "${cType}$(Clip ([string]$f.FileType) $typeW)${R}",
                    "${cDim}$(ClipR $size $sizeW)${R}",
                    "${DM}$(Clip $modd $modW)${R}",
                    "${DM}$(Clip ([string]$f.Rule) $ruleW)${R}"
                )
                if (-not $preview) {
                    $repo  = if ($f.Repo) { [string]$f.Repo } else { '?' }
                    $rmeta = Resolve-Repo $repo
                    $cells += "${cRepo}$(Clip $repo $repoW)${R}"
                    $cells += "${cDim}$(Clip ([string]$rmeta.Type) $rtypeW)${R}"
                    $cells += "${cRepo}$(Clip ([string]$rmeta.PackageType) $ptypeW)${R}"
                    if ($pathW -gt 0) { $cells += (Format-PathCell ([string]$f.Path) $pathW ([bool]$f.InArchive) $DM $cDim) }
                }
                $mark = if ($downloaded) { "${DM}d${R} " } elseif ($excluded) { "${DM}x${R} " } elseif ($sels) { "${BD}${YL}>${R} " } else { '  ' }
                $line = "$mark$($cells -join ' ')"
                if ($sels) { $line = Highlight-Row $line $colW }
                $leftLines.Add($line)
            }
        }

        if (-not $preview) {
            foreach ($ll in $leftLines) {
                if ($ll -eq $script:HeaderRuleTag) { $L.Add("${DM}$(HR $w)${R}") } else { $L.Add($ll) }
            }
            for ($i = $leftLines.Count; $i -lt $bodyH; $i++) { $L.Add('') }
        } else {
            $script:PvScrollMax = 0
            $rightLines = @()
            if ($cur) {
                # Same field set as the search/tree preview detail pane, plus the audit
                # severity and matched rule(s).
                $labelW = 11
                $valMax = [Math]::Max(6, $rightW - $labelW - 1)
                $rmeta  = Resolve-Repo ([string]$cur.Repo)
                $szTxt  = if ($cur.Size -ge 0) { Format-Size $cur.Size } else { '?' }
                $modTxt = Format-AuditModified ([string]$cur.Modified)
                $rl = [Collections.Generic.List[string]]::new()
                $rl.Add("${BD}${CY}$(Trunc ([string]$cur.Name) $rightW)${R}")
                $rl.Add('')
                $rl.Add("${DM}$('Repository'.PadRight($labelW))${R}${MG}$(Trunc ([string]$cur.Repo) $valMax)${R}")
                $rl.Add("${DM}$('Path'.PadRight($labelW))${R}$(Trunc ([string]$cur.Path) $valMax)")
                if ($cur.InArchive) { $rl.Add("${DM}$('Archive'.PadRight($labelW))${R}${YL}$(Trunc ([string]$cur.ArchiveName) $valMax)${R}") }
                $rl.Add("${DM}$('Type'.PadRight($labelW))${R}${YL}$(Trunc ([string]$cur.FileType) $valMax)${R}")
                $rl.Add("${DM}$('Size'.PadRight($labelW))${R}$szTxt")
                if ($modTxt) { $rl.Add("${DM}$('Modified'.PadRight($labelW))${R}$(Trunc $modTxt $valMax)") }
                $rl.Add("${DM}$('Repo type'.PadRight($labelW))${R}$($rmeta.Type)")
                $rl.Add("${DM}$('Pkg type'.PadRight($labelW))${R}${MG}$($rmeta.PackageType)${R}")
                $rl.Add("${DM}$('Severity'.PadRight($labelW))${R}$(Get-AuditColor $cur.Sev)$($cur.Sev)${R}")
                $rl.Add("${DM}$('Rules'.PadRight($labelW))${R}$(Trunc ([string]$cur.AllRules) $valMax)")
                # Get-AuditPreviewLines prepends 4 lines (pane rule, "Preview", rules, blank)
                # before the scrollable body, so reserve those 4 here. Reserving only the 2
                # the search pane uses overflowed bodyH by 2 lines, clipping the last body
                # line — which is the "n more below" indicator.
                $pvMax = [Math]::Max(1, $bodyH - $rl.Count - 4)
                foreach ($pl in (Get-AuditPreviewLines $cur $rightW $pvMax $pvScroll)) { $rl.Add($pl) }
                $rightLines = $rl.ToArray()
            }
            for ($i = 0; $i -lt $bodyH; $i++) {
                $lc = if ($i -lt $leftLines.Count)  { $leftLines[$i] }  else { '' }
                $rc = if ($i -lt $rightLines.Count) { $rightLines[$i] } else { '' }
                if ($rc -eq $script:PaneRuleTag)       { $L.Add((Format-PaneRule $lc $colW $rightW)) }
                elseif ($lc -eq $script:HeaderRuleTag) { $L.Add((Format-HeaderRule $rc $colW)) }
                else { $L.Add("$(Fit-Vis $lc $colW) ${DM}$([char]0x2502)${R} $rc") }
            }
        }

        $L.Add("$DM$(HR-Join $w ($(if ($preview) { $colW + 1 } else { $w }) ) ([char]0x2534))$R")

        # Footer controls.
        $nav = [Collections.Generic.List[string]]::new()
        if ($total -gt 0) {
            $nav.Add("${DM}Page ${BD}$($page + 1)${R}${DM}/$totalPages${R}")
            $nav.Add("${BD}${LB}$([char]0x2191)$([char]0x2193)${RB}${R}${DM} move${R}")
            $nav.Add("${BD}${LB}$([char]0x2190)$([char]0x2192)${RB}${R}${DM} page${R}")
            $nav.Add("${BD}${LB}$([char]0x21B5)${RB}${R}${DM} download${R}")
            $nav.Add("${BD}${LB}#${RB}${R}${DM} multi-download${R}")
            $nav.Add("${BD}${LB}x${RB}${R}${DM} $(if ($cur -and (Test-Visited $cur.Key)) { 'un-download' } elseif ($cur -and $cur.Included) { 'exclude' } else { 'include' })${R}")
            $nav.Add("${BD}${LB}A${RB}${R}${DM} download all${R}")
            $nav.Add("${BD}${LB}f${RB}${R}${DM} filter$(if (@($script:AuditExcludes).Count -gt 0) { " ($(@($script:AuditExcludes).Count))" })${R}")
            $nav.Add("${BD}${LB}i${RB}${R}${DM} include all${R}")
            $nav.Add("${BD}${LB}d${RB}${R}${DM} $(if ($preview) { 'results view' } else { 'preview view' })${R}")
            if ($preview -and $cur) {
                $curUrl = [string]$cur.Url
                $pst = Get-AuditPreviewability ([string]$cur.Name) $curUrl ([long]$cur.Size)
                $hidden = ((Test-Visited $cur.Key) -or (Test-Downloaded $curUrl) -or (-not $cur.Included)) `
                          -and -not $script:PreviewOK.Contains($curUrl)
                if ($hidden)                    { $nav.Add("${BD}${LB}y${RB}${R}${DM} preview again${R}") }
                elseif ($pst -eq 'large-gated') { $nav.Add("${BD}${LB}y${RB}${R}${DM} preview large${R}") }
                elseif ($pst -eq 'force-gated') { $nav.Add("${BD}${LB}y${RB}${R}${DM} force preview${R}") }
            }
            if ($preview -and $script:PvScrollMax -gt 0) { $nav.Add("${BD}${LB}Shift+$([char]0x2191)$([char]0x2193)${RB}${R}${DM} scroll${R}") }
        }
        # Hide/show excluded + downloaded findings. Outside the $total>0 block so the
        # 'unhide' hint still shows when everything is hidden (the list is then empty).
        if ($hideDone)                { $nav.Add("${BD}${LB}h${RB}${R}${DM} unhide $hideableCount hidden${R}") }
        elseif ($hideableCount -gt 0) { $nav.Add("${BD}${LB}h${RB}${R}${DM} hide $hideableCount excluded/done${R}") }
        if ($active) {
            $nav.Add("${BD}${LB}p${RB}${R}${DM} $(if ($script:AuditState -eq 'paused') { 'resume' } else { 'pause' })${R}")
            $nav.Add("${BD}${LB}c${RB}${R}${DM} cancel${R}")
            $nav.Add("${BD}${LB}+/-${RB}${R}${DM} delay $($script:AuditThrottle.MinIntervalMs)ms${R}")
            $nav.Add("${BD}${LB}w/W${RB}${R}${DM} workers $($script:AuditThrottle.MaxConcurrent)${R}")
        }
        $nav.Add("${BD}${LB}q${RB}${R}${DM} back${R}")
        $navWrapped = @(Wrap-Hints $nav.ToArray() $w)
        foreach ($nl in $navWrapped) { $L.Add($nl) }
        $navFooterLines = [Math]::Max(1, $navWrapped.Count)
        Show-Frame $L.ToArray()

        # Input: poll while the engine is active OR while metadata/preview fetches are
        # still in flight, so the Modified column and preview badges/pane fill in live;
        # otherwise block on a keypress.
        $busy = $active -or ($script:PfQueued.Count -gt 0) -or ($script:PvQueued.Count -gt 0)
        if ($pendingKey) { $key = $pendingKey; $pendingKey = $null }
        elseif ($busy -and $script:CanRawKey) {
            # Cased read so the worker control can tell 'w' (fewer) from 'W' (more).
            $key = Read-KeyTimeoutCased 150
            if ($null -eq $key) {
                if ($active) { Invoke-AuditPump }
                Receive-Prefetch; Receive-PreviewPrefetch; Receive-PreviewLookahead
                $script:AuditDirty = $false; continue
            }
        } else { $key = Read-KeyCased }

        # Worker count: 'w' fewer, 'W' more (1..AuditMaxWorkers). Handled before the
        # case-insensitive switch, which can't distinguish the two cases.
        if ($key -ceq 'w' -or $key -ceq 'W') {
            $delta = if ($key -ceq 'W') { 1 } else { -1 }
            $script:AuditThrottle.MaxConcurrent =
                [Math]::Max(1, [Math]::Min($script:AuditMaxWorkers, [int]$script:AuditThrottle.MaxConcurrent + $delta))
        }

        switch -regex ($key) {
            '^(up|k|down|j)$' {
                $d = if ($key -match '^(down|j)$') { 1 } else { -1 }
                $sel += $d; if ($sel -lt 0) { $sel = 0 }; if ($sel -gt $total - 1) { $sel = [Math]::Max(0, $total - 1) }
            }
            '^(pageup|left)$'    { $sel = [Math]::Max(0, $sel - $rowsH) }
            '^(pagedown|right)$' { $sel = [Math]::Min([Math]::Max(0, $total - 1), $sel + $rowsH) }
            '^home$' { $sel = 0 }
            '^end$'  { $sel = [Math]::Max(0, $total - 1) }
            '^(shift\+up|shift\+down)$' {
                if ($preview) { $d = if ($key -eq 'shift+down') { 1 } else { -1 }
                    Invoke-ScrollBurst ([ref]$pvScroll) $script:PvScrollMax ([ref]$pendingKey) $d }
            }
            '^d$' {
                if ($preview) { $mode = 'results'; Stop-AuditPreviewWarm } else { $mode = 'results-preview' }
                $script:AuditPvKey = ''; $lastWarmKey = ''
            }
            '^(x| )$' {
                if ($cur) {
                    if (Test-Visited $cur.Key) {
                        # On a downloaded entry, [x] returns it to its normal un-downloaded
                        # state (rather than toggling exclude); it re-sorts back up out of
                        # the downloaded group.
                        Unmark-Downloaded ([string]$cur.Key) ([string]$cur.Url)
                        $script:AuditSortDirty = $true
                    } else {
                        $cur.Included = (-not $cur.Included); $script:AuditSortDirty = $true
                        # Excluding drops the row to the back; advance to the next row so the
                        # cursor doesn't follow the excluded item down there. Free its cached
                        # preview (like a download) and reset the force-opt so [y] is required
                        # to bring the preview back.
                        if (-not $cur.Included) {
                            Clear-PreviewMem ([string]$cur.Url)
                            [void]$script:PreviewOK.Remove([string]$cur.Url)
                            $script:AuditPvKey = ''
                            $sel = [Math]::Min($sel + 1, [Math]::Max(0, $total - 1))
                        }
                    }
                }
            }
            '^f$' {
                $curTerms = (@($script:AuditExcludes | ForEach-Object { $_.Text }) -join ' ')
                Set-AuditExcludes (Read-AuditFilter $curTerms)
                Update-AuditExclusions
                $n = @($script:AuditExcludes).Count
                $notice = if ($n -gt 0) {
                    @{ Message = "${YL}Excluding $n pattern$(if ($n -ne 1){'s'}): $((@($script:AuditExcludes | ForEach-Object { $_.Text }) -join ', '))${R}"; At = [DateTime]::UtcNow }
                } else { @{ Message = "${DM}Exclude filter cleared.${R}"; At = [DateTime]::UtcNow } }
            }
            '^i$' {
                Enable-AllAuditFindings
                $notice = @{ Message = "${YL}All findings included (exclude filter cleared).${R}"; At = [DateTime]::UtcNow }
            }
            '^(enter|o)$' {
                if ($cur) {
                    Show-Popup @('Downloading', $cur.Name)
                    $notice = @{ Message = (Save-AuditFinding $cur); At = [DateTime]::UtcNow }
                    $script:AuditPvKey = ''
                    # The downloaded row drops to the very back; advance so the cursor
                    # stays put rather than following it down there.
                    $sel = [Math]::Min($sel + 1, [Math]::Max(0, $total - 1))
                }
            }
            '^y$' {
                # Opt the selected file into a preview again: a gated large/non-text file
                # (within the 5 MB ceiling), or a downloaded/excluded finding whose preview
                # was cleared. Re-warm so the content is fetched and the badge/pane update.
                if ($preview -and $cur) {
                    $url = [string]$cur.Url
                    $st  = Get-AuditPreviewability ([string]$cur.Name) $url ([long]$cur.Size)
                    $hidden = ((Test-Visited $cur.Key) -or (Test-Downloaded $url) -or (-not $cur.Included)) `
                              -and -not $script:PreviewOK.Contains($url)
                    if ($st -eq 'large-gated' -or $st -eq 'force-gated' -or $hidden) {
                        [void]$script:PreviewOK.Add($url)
                        $script:AuditPvKey = ''; $lastWarmKey = ''
                    }
                }
            }
            '^a$' { Save-AuditIncluded }
            '^h$' { $hideDone = -not $hideDone; $sel = 0; $selKey = '' }
            '^\d[\d,\s-]*$' {
                # Multi-download by number; the spec indexes the VISIBLE rows. An empty
                # spec (the user cleared the prompt) cancels back to the list.
                if ($total -gt 0) {
                    $spec = if ($script:CanRawKey -and $key.Length -eq 1) { Read-NumberSpec $key } else { $key }
                    $idx  = @(Parse-NumberSpec $spec $total)   # @() so an empty spec doesn't $null under StrictMode
                    if ($idx.Count -gt 0) { Save-AuditFindingSet (@($idx | ForEach-Object { $list[$_ - 1] })); $script:AuditPvKey = '' }
                }
            }
            '^p$' { if ($script:AuditState -eq 'paused') { Resume-AuditEngine } else { Suspend-AuditEngine } }
            '^c$' {
                if ($active) {
                    Stop-AuditWork
                    $script:AuditState = if ($script:AuditFindings.Count -gt 0) { 'done' } else { 'cancelled' }
                    $notice = @{ Message = "${YL}Audit cancelled - showing findings so far.${R}"; At = [DateTime]::UtcNow }
                }
            }
            '^(\+|=)$' { Step-AuditDelay 1 }    # slower (more delay)
            '^(\-|_)$' { Step-AuditDelay -1 }   # faster (less delay)
            '^(q|b)$' {
                if ($active) { Stop-AuditWork; $script:AuditState = if ($script:AuditFindings.Count -gt 0) { 'done' } else { 'cancelled' } }
                Stop-AuditPreviewWarm
                return
            }
        }
        # Remember the now-selected finding's key so the cursor can follow it across the
        # next re-sort (see the reconcile at the loop top).
        $selKey = if ($total -gt 0 -and $sel -ge 0 -and $sel -lt $total) { [string]$list[$sel].Key } else { '' }
    }
}

# ── AUDIT MENU ────────────────────────────────────────────────────────────────
# The popup shown when the user presses [a]. $ctx supplies the scope-specific bits
# as plain data (NOT a scriptblock — a closure would bind to an isolated module
# scope where the dot-sourced Start-Audit* functions aren't visible):
#   LocationLabel — text describing what "Audit location" will cover
#   LocationKind  — 'items' (results) or 'nodes' (archive entries)
#   Label         — scope label recorded on the run
#   Items         — the items / nodes to audit
#   ArcName       — archive name (nodes only)
# Passive returns 'passive' (caller keeps browsing); location/full open the audit
# view and return 'view'; cancel returns ''. When passive is already running, option
# 1 toggles it OFF (returns 'passive-off').
function Show-AuditMenu($ctx) {
    while ($true) {
        # Redrawn each loop so the 'w' toggle reflects immediately.
        $passiveOn = ($script:AuditState -eq 'passive')
        $passiveLine = if ($passiveOn) { '1  Passive   - currently ON; select to turn off' }
                       else            { '1  Passive   - scan the current view in the background, flag matches' }
        $walkState = if ($script:AuditWalkArchives) { 'ON' } else { 'OFF' }
        $tierLine  = if ($script:AuditTier2) { 't  Analysis: Tier 2 (metadata + content)' }
                     else                    { 't  Analysis: Tier 1 (metadata only)' }
        Show-Popup @(
            'Audit mode  (credential / secret discovery)',
            '',
            $passiveLine,
            "2  Location  - $($ctx.LocationLabel)",
            '3  Full      - scan the entire Artifactory instance',
            '',
            'Audit settings (applies on new audit)',
            $tierLine,
            "w  Walk through listable archives: $walkState",
            '',
            'q  cancel')
        switch (Read-Key) {
            '1' {
                if ($passiveOn) { Reset-AuditEngine; return 'passive-off' }
                Start-AuditPassive; return 'passive'
            }
            '2' {
                if ($ctx.LocationKind -eq 'nodes') { Start-AuditLocationNodes $ctx.Label $ctx.Items $ctx.ArcName }
                else { Start-AuditLocation $ctx.Label $ctx.Items }
                Show-AuditView; return 'view'
            }
            '3' {
                if (Confirm-Prompt @("${BD}Full audit of the entire instance?${R}",
                                     'This can issue a very large number of requests.',
                                     "${DM}Use the throttle controls in the audit view to pace it.${R}")) {
                    Start-AuditFull; Show-AuditView
                }
                return 'view'
            }
            't'    { $script:AuditTier2 = -not $script:AuditTier2 }                 # toggle, redraw
            'w'    { $script:AuditWalkArchives = -not $script:AuditWalkArchives }   # toggle, redraw
            'q'    { return '' }
            'enter'{ }
        }
    }
}

