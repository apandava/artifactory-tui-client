# Views.ps1 — part of the ARTCA Artifactory TUI (see StartTui.ps1).
#
# This file holds function and $script:-state definitions only; nothing here runs
# on its own. It is loaded two ways:
#   · dot-sourced automatically by StartTui.ps1 when the tool is run as a file, or
#   · pasted directly into the PowerShell console (paste the component files first,
#     then StartTui.ps1 last) to run the tool without executing the .ps1 files.
# Load order among the component files does not matter.
# ── VISITED + PREVIEW STATE ───────────────────────────────────────────────────
# Items the user has opened/viewed/downloaded (keys: storage uri or download url),
# rendered washed-out afterwards. Preview content is cached in memory by download
# url so a later download reuses it instead of re-fetching.
$script:PreviewOK    = New-Object 'System.Collections.Generic.HashSet[string]'  # large/non-text files user opted to preview
$script:PreviewLimit = 512000                                           # 0.5 MB auto-preview cap
$script:PreviewHardLimit = 5242880                                      # 5 MB hard ceiling for manual opt-in (large + force preview)

# Preview-pane scrolling. The selected file's wrapped contents (or an archive's
# entry listing) can exceed the pane height; the user scrolls with Shift+Up/Down.
# $PvScrollMax is the largest valid scroll offset for the current preview (set by
# the renderer each frame, read by the nav loops to clamp). Decoding/wrapping a file
# and building an archive listing are O(size), so the results are memoized (keyed by
# url/uri + pane width) and reused across scroll steps and neighbour redraws instead
# of being rebuilt on every keystroke.
$script:PvScrollMax       = 0
# Number of lines the wrapped footer hints occupied on the last search-view render, so
# the next page-size calc (StartTui) and the preview body height reserve that space.
# A one-frame lag on resize self-corrects; defaults to one line.
$script:NavLineCount      = 1
# Stable footer reservation for the preview pane's body-height calc. The footer gains and
# loses selection-dependent hints ([y] preview / Shift+scroll) as you move the cursor, so
# its wrapped height flips between one and two lines. Reserving the *tallest* footer seen
# at the current width (rather than the last render's) keeps the body — and the bottom
# divider — from bobbing up and down during navigation. Reset when the width changes.
$script:NavReserve        = 1
$script:NavReserveW       = 0
$script:WrapCacheKey      = ''
$script:WrapCacheLines    = @()
$script:ArcListCacheKey   = ''
$script:ArcListCacheLines = @()

# Window a list of rendered content lines around a scroll offset, adding a
# "N more above" / "N more below" indicator row (each consuming one line) whenever
# content lies off-pane in that direction. Sets $script:PvScrollMax so the nav loop
# can clamp the offset; returns the lines unchanged when everything already fits.
# The top indicator costs a row, so a raw offset of 1 would merely replace the first
# line with the indicator and not move the text. To avoid that dead first step, once
# scrolled at all we advance the first visible line by an extra row, so every step
# scrolls the content by one and the last line is still reachable at PvScrollMax.
# A pane too short for indicators (< 3 rows) falls back to a plain window.
function Get-ScrolledLines([string[]]$lines, [int]$avail, [int]$scroll) {
    if ($null -eq $lines) { $lines = @() }
    $avail = [Math]::Max(1, $avail)
    $total = $lines.Count
    if ($total -le $avail) { $script:PvScrollMax = 0; return $lines }

    if ($avail -lt 3) {
        $script:PvScrollMax = $total - $avail
        $sc  = [Math]::Max(0, [Math]::Min($scroll, $script:PvScrollMax))
        $end = [Math]::Min($total - 1, $sc + $avail - 1)
        $o = [Collections.Generic.List[string]]::new()
        for ($i = $sc; $i -le $end; $i++) { $o.Add($lines[$i]) }
        return $o.ToArray()
    }

    $script:PvScrollMax = $total - $avail
    $sc    = [Math]::Max(0, [Math]::Min($scroll, $script:PvScrollMax))
    # Skip the dead first step: any positive offset advances the first visible line an
    # extra row to pay for the top indicator, so the content actually moves by one.
    $first = if ($sc -gt 0) { $sc + 1 } else { 0 }
    $top   = ($first -gt 0)
    $contentH = $avail - $(if ($top) { 1 } else { 0 })
    $end = [Math]::Min($total - 1, $first + $contentH - 1)
    if (($total - 1 - $end) -gt 0) { $contentH--; $end = $first + $contentH - 1 }   # reserve bottom indicator
    $below = $total - 1 - $end
    $out = [Collections.Generic.List[string]]::new()
    if ($top)         { $out.Add("${DM}$([char]0x2191) $first more above${R}") }
    for ($i = $first; $i -le $end; $i++) { $out.Add($lines[$i]) }
    if ($below -gt 0) { $out.Add("${DM}$([char]0x2193) $below more below${R}") }
    return $out.ToArray()
}


# Sentinel emitted by Get-PreviewLines in place of the preview's horizontal rule.
# Two-pane compositors recognise it and draw a rule that joins the vertical pane
# separator with a T-junction (instead of a bare dash row floating beside it).
# NUL-wrapped so it can never collide with real content.
$script:PaneRuleTag = "$([char]0)PANE_RULE$([char]0)"

# Sentinel placed in the LEFT pane (after the column header) to request a header
# divider that joins the vertical pane separator from the left with a ┤. Mirror of
# $PaneRuleTag for the opposite pane; NUL-wrapped for the same reason.
$script:HeaderRuleTag = "$([char]0)HDR_RULE$([char]0)"


# Apply a background to a whole row so the highlight survives the per-cell resets:
# re-assert the background after every reset, then pad to width under it. No-op on
# non-VT hosts (where $R is empty and the regex would misbehave).
function Highlight-Row([string]$s, [int]$width) {
    if (-not $script:Vt) { return $s }
    # Fit to exactly $width first (ANSI-safe), then re-assert the background after
    # every reset so the highlight spans the whole row without overflowing it.
    $t = (Fit-Vis $s $width) -replace ([regex]::Escape($R)), "$R$SB"
    return "$SB$t$R"
}


# Render a fixed-width ($w columns) Path-column cell in colour $dim. When $isArc — the
# file came from an archive listing — an 'A' marker (colour $markCol, default the plain
# value colour) is appended just past the path text, with the cell padded out so column
# alignment is preserved.
function Format-PathCell([string]$path, [int]$w, [bool]$isArc, [string]$dim, [string]$markCol = '') {
    if ($w -le 0) { return '' }
    if (-not $isArc) { return "${dim}$(Clip $path $w)${R}" }
    $txt = Trunc $path ([Math]::Max(1, $w - 2))      # truncated (ellipsis if long), not padded
    $pad = [Math]::Max(0, $w - $txt.Length - 2)      # reserve " A"
    return "${dim}${txt}${R} ${markCol}A${R}$(' ' * $pad)"
}



# Decode bytes to text (UTF-8, BOM-aware).
function Convert-BytesToText([byte[]]$bytes) {
    if ($null -eq $bytes -or $bytes.Length -eq 0) { return '' }
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        return [Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3)
    }
    return [Text.Encoding]::UTF8.GetString($bytes)
}

# 'strings'-like extraction of the human-readable characters from arbitrary bytes,
# for force-previewing a non-text file. Printable ASCII (and tabs) are kept; runs are
# separated by newlines wherever a non-printable byte breaks them, so unrelated
# strings don't merge into one line. Bounded to the 5 MB hard preview limit.
function Convert-BytesToReadable([byte[]]$bytes) {
    if ($null -eq $bytes -or $bytes.Length -eq 0) { return '' }
    $n  = [Math]::Min($bytes.Length, $script:PreviewHardLimit)
    $sb = [Text.StringBuilder]::new()
    $inRun = $false
    for ($i = 0; $i -lt $n; $i++) {
        $b = $bytes[$i]
        if ($b -eq 9 -or ($b -ge 32 -and $b -le 126)) { [void]$sb.Append([char]$b); $inRun = $true }       # tab + printable ASCII
        elseif ($b -eq 10 -or $b -eq 13)              { [void]$sb.Append([char]$b); $inRun = $false }       # LF / CR pass through
        elseif ($inRun)                               { [void]$sb.Append("`n");     $inRun = $false }       # break the run on a binary byte
    }
    return $sb.ToString()
}

# Word-wrap text to $width columns, hard-breaking tokens longer than the width and
# stripping control chars. Returns an array of lines.
function Wrap-Text([string]$s, [int]$width) {
    if ($width -lt 1) { $width = 1 }
    $out = [Collections.Generic.List[string]]::new()
    $s = ($s -replace "`t", '    ') -replace "`r", ''
    foreach ($line in ($s -split "`n")) {
        $clean = ($line -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', '')
        if ($clean -eq '') { $out.Add(''); continue }
        $cur = ''
        foreach ($word in ($clean -split ' ')) {
            $tok = $word
            while ($tok.Length -gt $width) {
                if ($cur -ne '') { $out.Add($cur); $cur = '' }
                $out.Add($tok.Substring(0, $width)); $tok = $tok.Substring($width)
            }
            if ($cur -eq '') { $cur = $tok }
            elseif (($cur.Length + 1 + $tok.Length) -le $width) { $cur = "$cur $tok" }
            else { $out.Add($cur); $cur = $tok }
        }
        $out.Add($cur)
    }
    return $out.ToArray()
}

# Render a right-pane horizontal divider that joins the vertical pane separator
# with a T-junction (├), so it reads as one connected rule rather than a dash row
# floating a column to the right of the separator. $leftW is the left pane width
# (where the separator sits); $rightW is the right pane the rule spans.
function Format-PaneRule([string]$leftCell, [int]$leftW, [int]$rightW) {
    $tee = [char]0x251C; $hz = [char]0x2500
    return "$(Fit-Vis $leftCell $leftW) ${DM}$tee$([string]$hz * ([Math]::Max(1, $rightW + 1)))${R}"
}

# Render a left-pane horizontal divider (between the column header and the rows)
# that joins the vertical pane separator from the left with a ┤, so it reads as one
# connected rule. Spans the left pane; $rightCell is whatever the right pane shows
# on this row (drawn unchanged to the right of the junction). $leftW is the left
# pane width (the separator sits at $leftW + 1).
function Format-HeaderRule([string]$rightCell, [int]$leftW) {
    $tee = [char]0x2524; $hz = [char]0x2500
    return "${DM}$([string]$hz * ($leftW + 1))$tee${R} $rightCell"
}

# Preview-pane block showing a single explanatory message in place of contents
# (e.g. a nested sub-archive that can't be browsed). Same shape as Get-PreviewLines
# — a $PaneRuleTag divider, the "Preview" header, then the wrapped message — so the
# two-pane compositor connects the divider to the pane separator.
function Get-PreviewMessageLines([string]$msg, [int]$paneW) {
    $L = [Collections.Generic.List[string]]::new()
    $L.Add($script:PaneRuleTag)
    $L.Add("${BD}${YL}Preview${R}")
    foreach ($wl in (Wrap-Text $msg $paneW)) { $L.Add("${DM}$wl${R}") }
    return $L.ToArray()
}

# Classify how a file can be previewed, given its name, url and size. The single
# source of truth shared by the search, tree and audit views:
#   auto           - text type within the 512 KB auto cap (fetched without asking)
#   large          - text type, opted in via [y], within the 5 MB hard ceiling
#   large-gated    - text type over the auto cap; offer [y] preview large
#   toolarge       - text type over the 5 MB ceiling; no option
#   force          - non-text type, opted in via [y] (force preview), within 5 MB
#   force-gated    - non-text type; offer [y] force preview
#   force-toolarge - non-text type over the 5 MB ceiling; no option
# Unknown sizes (-1) are allowed to opt in (the ceiling can't be pre-checked).
# NOTE: callers must exclude browsable archives before calling this (an archive name
# isn't "previewable", so it would otherwise classify as force-gated).
function Get-PreviewState([string]$name, [string]$url, [long]$sz) {
    $overHard = ($sz -ge 0 -and $sz -gt $script:PreviewHardLimit)
    if (Get-IsPreviewable $name) {
        if ($sz -ge 0 -and $sz -le $script:PreviewLimit) { return 'auto' }
        if ($overHard) { return 'toolarge' }
        if ($script:PreviewOK.Contains($url)) { return 'large' }
        return 'large-gated'
    }
    if ($overHard) { return 'force-toolarge' }
    if ($script:PreviewOK.Contains($url)) { return 'force' }
    return 'force-gated'
}

# True if the preview content should be fetched in the background now.
function Test-PreviewLoadable([string]$state) {
    return ($state -eq 'auto' -or $state -eq 'large' -or $state -eq 'force')
}

# Build the preview-section lines for a file: a "Preview" header then either the
# wrapped contents (force preview extracts readable characters from a non-text file),
# or a message (gated large / force / too large / downloaded / failed). $sizeBytes is
# -1 when unknown. The leading divider is emitted as $PaneRuleTag so the two-pane
# compositor can connect it to the pane separator (see Format-PaneRule).
function Get-PreviewLines([string]$name, [string]$url, [long]$sizeBytes, [int]$paneW, [int]$maxLines, [int]$scroll = 0) {
    $script:PvScrollMax = 0   # not scrollable unless the success path below says so
    $L = [Collections.Generic.List[string]]::new()
    $L.Add($script:PaneRuleTag)
    $L.Add("${BD}${YL}Preview${R}")
    # A downloaded file's bytes were purged from memory; don't re-fetch a preview.
    if (Test-Downloaded $url) {
        $L.Add("${DM}Downloaded - content cleared from memory.${R}")
        return $L.ToArray()
    }
    $state = Get-PreviewState $name $url $sizeBytes
    $szTxt = if ($sizeBytes -ge 0) { Format-Size $sizeBytes } else { 'unknown size' }
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
    # 'auto' / 'large' / 'force': contents come from the background preview cache
    # (warmed by the nav loop); the pane shows a loading line until the fetch lands.
    $key = Get-FilePreviewKey $url
    if (-not $script:PreviewCache.ContainsKey($key)) {
        $L.Add("${DM}Loading preview...${R}"); return $L.ToArray()
    }
    $res = $script:PreviewCache[$key]
    if (-not $res.Ok) {
        $L.Add("${RD}Could not load file for preview.${R}")
        if ($res.Error) { foreach ($wl in (Wrap-Text ([string]$res.Error) $paneW)) { $L.Add("${DM}$wl${R}") } }
        return $L.ToArray()
    }
    $bytes = $res.Bytes
    if ($null -eq $bytes) { $L.Add("${RD}Could not load file for preview.${R}"); return $L.ToArray() }
    # Seed the byte cache so a later download of this file reuses the fetch.
    Add-MemFile $url $bytes
    # Decoding + wrapping is O(file size); memoize the last file's wrapped lines (keyed
    # by url + pane width + mode) so scrolling and neighbour redraws reuse them instead
    # of re-wrapping on every keystroke. Force preview extracts readable characters.
    $force   = ($state -eq 'force')
    $wrapKey = "$url|$paneW|$(if ($force) { 'R' } else { 'T' })"
    if ($script:WrapCacheKey -eq $wrapKey) {
        $wrapped = @($script:WrapCacheLines)
    } else {
        # @(...) keeps a single-line result an array (so .Count is always valid); the
        # try/catch guards against a decode/extraction failure on malformed content.
        try {
            $text    = if ($force) { Convert-BytesToReadable $bytes } else { Convert-BytesToText $bytes }
            $wrapped = @(Wrap-Text $text $paneW)
        } catch {
            $L.Add("${RD}Failed to $(if ($force) { 'force ' })preview file.${R}")
            return $L.ToArray()
        }
        $script:WrapCacheKey = $wrapKey; $script:WrapCacheLines = $wrapped
    }
    if ($force -and $wrapped.Count -eq 0) { $L.Add("${DM}(no readable text found)${R}"); return $L.ToArray() }
    # Window the wrapped lines around the scroll offset, with above/below indicators
    # when the file overflows the pane (Shift+Up/Down scrolls; see Get-ScrolledLines).
    foreach ($wl in (Get-ScrolledLines $wrapped $maxLines $scroll)) { $L.Add($wl) }
    return $L.ToArray()
}

# Recursively render an archive's nodes as an indented tree listing, appending
# display lines to $acc. Folders are expanded only down to $maxDepth levels (the
# preview is a glimpse, not the full browser — use the tree view for deeper
# navigation); deeper folders are still listed, just not descended into. Folder
# names are magenta, files cyan; each line is truncated to $paneW. Stops once $acc
# reaches $cap rows so a huge archive doesn't build thousands of lines just to be
# trimmed. (Uses the archive-node accessors defined further down; resolved at call
# time.) $depth is the 1-based level of $nodes.
function Add-ArcListingLines($nodes, [string]$prefix, $acc, [int]$paneW, [int]$cap, [int]$depth = 1, [int]$maxDepth = 2) {
    $sorted = @(Sort-Nodes $nodes)
    for ($i = 0; $i -lt $sorted.Count; $i++) {
        if ($acc.Count -ge $cap) { return }
        $n        = $sorted[$i]
        $isLast   = ($i -eq $sorted.Count - 1)
        $isFolder = Get-NodeIsFolder $n
        $branch   = if ($isLast) { "$([char]0x2514)$([char]0x2500)$([char]0x2500) " }
                    else         { "$([char]0x251C)$([char]0x2500)$([char]0x2500) " }
        $name = Get-NodeName $n
        $disp = if ($isFolder) { "$name/" } else { $name }
        $disp = Trunc $disp ([Math]::Max(1, $paneW - $prefix.Length - $branch.Length))
        $col  = if ($isFolder) { $MG } else { $CY }
        $acc.Add("${DM}$prefix$branch${R}${col}$disp${R}")
        if ($isFolder -and $depth -lt $maxDepth) {
            $childPrefix = $prefix + $(if ($isLast) { '    ' } else { "$([char]0x2502)   " })
            Add-ArcListingLines (Get-NodeChildren $n) $childPrefix $acc $paneW $cap ($depth + 1) $maxDepth
        }
    }
}

# Preview-pane lines for a listable archive: an "Archive preview" header then a
# shallow tree listing of its entries (fetched once and cached by item uri).
# Mirrors the shape of Get-PreviewLines (leading $PaneRuleTag so the divider
# connects).
function Get-ArchivePreviewLines($item, [int]$paneW, [int]$maxLines, [int]$scroll = 0) {
    $script:PvScrollMax = 0   # not scrollable unless the listing below overflows
    $L = [Collections.Generic.List[string]]::new()
    $L.Add($script:PaneRuleTag)
    $L.Add("${BD}${YL}Archive preview${R}")
    # Entry listing comes from the background preview cache (warmed by the nav loop).
    $key = Get-ArcPreviewKey ([string]$item.Uri)
    if (-not $script:PreviewCache.ContainsKey($key)) {
        $L.Add("${DM}Loading preview...${R}"); return $L.ToArray()
    }
    $tree = $script:PreviewCache[$key]
    if (-not $tree.Ok) {
        $L.Add("${RD}Could not read archive.${R}")
        if ($tree.Error) { foreach ($wl in (Wrap-Text ([string]$tree.Error) $paneW)) { $L.Add("${DM}$wl${R}") } }
        return $L.ToArray()
    }
    # Build the shallow listing once (bounded so a huge archive can't build forever)
    # and memoize it by uri + pane width, so scrolling reuses it instead of rebuilding
    # the tree every keystroke.
    $listKey = "$($item.Uri)|$paneW"
    if ($script:ArcListCacheKey -eq $listKey) {
        $rows = $script:ArcListCacheLines
    } else {
        $rowsList = [Collections.Generic.List[string]]::new()
        Add-ArcListingLines @($tree.Nodes) '' $rowsList $paneW 2000
        $rows = $rowsList.ToArray()
        $script:ArcListCacheKey = $listKey; $script:ArcListCacheLines = $rows
    }
    if ($rows.Count -eq 0) { $L.Add("${DM}(empty archive)${R}"); return $L.ToArray() }
    foreach ($wl in (Get-ScrolledLines $rows $maxLines $scroll)) { $L.Add($wl) }
    return $L.ToArray()
}

# Pack footer hint segments across as many lines as needed so none are cut off on a
# narrow window (Join-Justified crams them onto one line, which the frame then
# truncates). Segments are kept whole and left-packed with a fixed gap; a new line
# starts whenever the next segment wouldn't fit. Returns the array of lines.
function Wrap-Hints([string[]]$Segments, [int]$width, [int]$lead = 2, [int]$gap = 3) {
    $segs = @($Segments | Where-Object { "$_" -ne '' })
    if ($segs.Count -eq 0) { return @() }
    $w = [Math]::Max(1, $width)
    $budget = [Math]::Max(1, $w - $lead)
    # Greedily pack whole segments into lines (fixed gap between them).
    $rows = [Collections.Generic.List[object]]::new()
    $line = [Collections.Generic.List[string]]::new(); $curLen = 0
    foreach ($s in $segs) {
        $sl = Vis-Len $s
        if ($line.Count -eq 0) { [void]$line.Add($s); $curLen = $sl }
        elseif (($curLen + $gap + $sl) -le $budget) { [void]$line.Add($s); $curLen += $gap + $sl }
        else { $rows.Add($line); $line = [Collections.Generic.List[string]]::new(); [void]$line.Add($s); $curLen = $sl }
    }
    if ($line.Count -gt 0) { $rows.Add($line) }
    # A single line stays left-aligned (lead margin). When the hints wrap onto multiple
    # lines, centre each line within the width so they sit balanced rather than left-crammed.
    $out = [Collections.Generic.List[string]]::new()
    foreach ($lrow in $rows) {
        $joined = (@($lrow) -join (' ' * $gap))
        if ($rows.Count -le 1) { $out.Add((' ' * $lead) + $joined) }
        else {
            $pad = [Math]::Max(0, [int](($w - (Vis-Len $joined)) / 2))
            $out.Add((' ' * $pad) + $joined)
        }
    }
    return $out.ToArray()
}

# Evenly distribute footer hint segments across $width (justified), so the key
# tooltips span the window instead of crowding the left.
function Join-Justified([string[]]$Segments, [int]$width) {
    $segs = @($Segments)
    if ($segs.Count -eq 0) { return '' }
    $lead = 2
    $textLen = 0; foreach ($s in $segs) { $textLen += (Vis-Len $s) }
    if ($segs.Count -eq 1) { return (' ' * $lead) + $segs[0] }
    $gaps  = $segs.Count - 1
    $slack = $width - $lead - $textLen
    if ($slack -lt $gaps) { return (' ' * $lead) + ($segs -join '   ') }   # too tight; simple
    $base  = [Math]::Floor($slack / $gaps); $extra = $slack - ($base * $gaps)
    $sb = [Text.StringBuilder]::new(); [void]$sb.Append(' ' * $lead)
    for ($i = 0; $i -lt $segs.Count; $i++) {
        [void]$sb.Append($segs[$i])
        if ($i -lt $gaps) { $g = $base; if ($i -lt $extra) { $g++ }; [void]$sb.Append(' ' * $g) }
    }
    return $sb.ToString()
}

# ── DISPLAY ───────────────────────────────────────────────────────────────────

# Build a fixed-width ($nameW) name cell, left-aligned and padded to the column
# edge, with an optional one-char badge placed immediately after the name text:
# '+' for a browsable archive, '·' for a previewable file. A non-previewable file
# gets the '·' badge too, but ONLY once it has been force-previewed (its url opted
# into PreviewOK). Space for the badge is reserved before truncating, so even an
# ellipsised long name still shows it. In preview mode the badge starts dim (grey)
# and turns yellow once that item's preview has loaded; elsewhere it's always yellow.
function Format-NameCell([object]$item, [int]$nameW, [bool]$vis, [bool]$preview = $false) {
    $name = [string]$item.Name
    # A preview/fetch error (e.g. blacked-out repo) flags the whole cell red.
    $errored = Test-ItemPreviewError $item
    $col  = if ($errored) { $RD } elseif ($vis) { $DM } else { $CY }
    if     (Test-ItemBrowsableArchive $item) { $glyph = $script:ArcGlyph }
    elseif ((Get-IsPreviewable $name) -or $script:PreviewOK.Contains((Get-ItemUrl $item))) { $glyph = $script:PreviewGlyph }
    else   { return "${col}$(Clip $name $nameW)${R}" }

    $gcol = if ($errored) { $RD }
            elseif ($vis) { $DM }
            elseif ($preview) {
                $k = Get-ItemPreviewKey $item
                if ($k -and $script:PreviewCache.ContainsKey($k)) { $YL } else { $DM }
            } else { $YL }

    $avail = [Math]::Max(1, $nameW - 2)          # reserve " <glyph>"
    $txt   = Trunc $name $avail                  # ellipsis if too long, no padding
    $pad   = [Math]::Max(0, $nameW - $txt.Length - 2)
    return "${col}${txt}${R}${gcol} ${glyph}${R}$(' ' * $pad)"
}

# Build one detailed-mode data row (no gutter), sized to fit $colW. Columns are
# packed with single-space gaps to minimise wasted space. Visited rows render
# washed-out (dim).
# In preview mode only #, Name, Type, Size, Modified are shown (the right pane
# carries repo/path/etc.); Name takes all the freed width.
function Format-DetailedRow($item, [int]$Number, [int]$colW, [bool]$vis, [bool]$preview = $false, [bool]$showRule = $false, [int]$numW = 4) {
    $typeW = 5; $sizeW = 9; $modW = 10; $rtypeW = 6; $ptypeW = 8; $ruleW = 0
    $repoW = [Math]::Min(16, [Math]::Max(8, [int]($colW * 0.14)))
    if ($preview) {
        $nameW = [Math]::Max(10, $colW - ($numW + $typeW + $sizeW + $modW + 8))  # 4 gaps + 2 gutter + 2 margin
        $pathW = 0
    } else {
        if ($showRule) { $ruleW = [Math]::Min(20, [Math]::Max(10, [int]($colW * 0.16))) }
        $fixed = $numW + $typeW + $sizeW + $modW + $repoW + $rtypeW + $ptypeW + 12 + $(if ($showRule) { $ruleW + 1 } else { 0 })
        $rest  = [Math]::Max(12, $colW - $fixed)
        $nameW = [Math]::Max(10, [int]($rest * 0.55))
        $pathW = [Math]::Max(0, $rest - $nameW)
    }

    $name = if ($item.Name) { $item.Name } else { '?' }
    $type = [string]$item.FileType
    $size = if ("$($item.Size)" -ne '') { Format-Size $item.Size } else { '?' }
    $modified = if ($item.Modified) { $item.Modified.Substring(0, [Math]::Min(10, $item.Modified.Length)) } else { '?' }

    # Visited rows wash the whole line out: every field (and the badge) goes dim.
    $cType = if ($vis) { $DM } else { $YL }
    $cDim  = if ($vis) { $DM } else { '' }      # size/rtype: normally default color
    $cRepo = if ($vis) { $DM } else { $MG }

    $nameCell = Format-NameCell $item $nameW $vis $preview
    $cells = @(
        "${DM}$(ClipR ([string]$Number) $numW)${R}",
        $nameCell,
        "${cType}$(Clip $type $typeW)${R}",
        "${cDim}$(ClipR $size $sizeW)${R}",
        "${DM}$(Clip $modified $modW)${R}"
    )
    if (-not $preview) {
        $repo  = if ($item.Repo) { $item.Repo } else { '?' }
        $rmeta = Resolve-Repo $repo
        $cells += "${cRepo}$(Clip $repo $repoW)${R}"
        $cells += "${cDim}$(Clip ([string]$rmeta.Type) $rtypeW)${R}"
        $cells += "${cRepo}$(Clip ([string]$rmeta.PackageType) $ptypeW)${R}"
        if ($pathW -gt 0) { $cells += (Format-PathCell ([string]$item.Path) $pathW ([bool](Get-ItemArchiveName $item)) $DM $cDim) }
        if ($showRule)    { $cells += "${cDim}$(Clip (Get-AuditRuleLabel ([string]$item.Uri)) $ruleW)${R}" }
    }
    return ($cells -join ' ')
}

function Format-DetailedHeader([int]$colW, [bool]$preview = $false, [bool]$showRule = $false, [int]$numW = 4) {
    $typeW = 5; $sizeW = 9; $modW = 10; $rtypeW = 6; $ptypeW = 8; $ruleW = 0
    $repoW = [Math]::Min(16, [Math]::Max(8, [int]($colW * 0.14)))
    if ($preview) {
        $nameW = [Math]::Max(10, $colW - ($numW + $typeW + $sizeW + $modW + 8))  # match Format-DetailedRow
        $hdr = @((ClipR '#' $numW), (Clip 'Name' $nameW), (Clip 'Type' $typeW), (ClipR 'Size' $sizeW),
                 (Clip 'Modified' $modW))
    } else {
        if ($showRule) { $ruleW = [Math]::Min(20, [Math]::Max(10, [int]($colW * 0.16))) }
        # Must match Format-DetailedRow's $fixed EXACTLY (same +12) so the header columns line up
        # with the data columns; a divergent constant shifts every heading off its values.
        $fixed = $numW + $typeW + $sizeW + $modW + $repoW + $rtypeW + $ptypeW + 12 + $(if ($showRule) { $ruleW + 1 } else { 0 })
        $rest  = [Math]::Max(12, $colW - $fixed)
        $nameW = [Math]::Max(10, [int]($rest * 0.55))
        $pathW = [Math]::Max(0, $rest - $nameW)
        $hdr = @((ClipR '#' $numW), (Clip 'Name' $nameW), (Clip 'Type' $typeW), (ClipR 'Size' $sizeW),
                 (Clip 'Modified' $modW), (Clip 'Repo' $repoW), (Clip 'RType' $rtypeW), (Clip 'PType' $ptypeW))
        if ($pathW -gt 0) { $hdr += (Clip 'Path' $pathW) }
        if ($showRule)    { $hdr += (Clip 'Rule' $ruleW) }
    }
    return "${BD}${YL}$($hdr -join ' ')${R}"
}

# ── NAME GLOB FILTER ──────────────────────────────────────────────────────────
# Shared exclude-filter helpers (used by the search view; mirror of the audit view's
# glob exclude). '*' = any run, '?' = one char; matching is case-insensitive and
# anchored to the whole name.
function ConvertTo-GlobRegex([string]$glob) {
    $g = "$glob".Trim()
    if (-not $g) { return $null }
    $sb = [Text.StringBuilder]::new()
    [void]$sb.Append('^')
    foreach ($ch in $g.ToCharArray()) {
        switch ($ch) {
            '*' { [void]$sb.Append('.*') }
            '?' { [void]$sb.Append('.') }
            default { [void]$sb.Append([regex]::Escape([string]$ch)) }
        }
    }
    [void]$sb.Append('$')
    return [regex]::new($sb.ToString(), ([Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant'))
}

# Parse a filter string (terms separated by commas/whitespace) into compiled regexes.
function Get-GlobRegexes([string]$terms) {
    $out = [Collections.Generic.List[object]]::new()
    foreach ($t in @("$terms" -split '[,\s]+')) {
        if (-not $t) { continue }
        $rx = ConvertTo-GlobRegex $t
        if ($rx) { [void]$out.Add($rx) }
    }
    return @($out.ToArray())
}

# True if a name matches any of the compiled glob regexes.
function Test-NameMatchesAny([string]$name, $rxList) {
    foreach ($rx in @($rxList)) { if ($rx -and $rx.IsMatch("$name")) { return $true } }
    return $false
}

# Upper-bound total result count the launcher sets per render: when > the loaded/shown count it's
# displayed as "N shown - ~T total" (local-index matches stream in chunks, so more exist than are
# loaded). 0 = everything is loaded, so the header shows the plain "(N results)" form.
$script:ResultGrandTotal = 0
function Show-Page([string]$Query, [object[]]$Items, [int]$Page,
                   [int]$TotalPages, [int]$TotalItems, [int]$Offset,
                   [string]$Mode = 'simple', [int]$SelRow = -1, [int]$PvScroll = 0,
                   [object[]]$ExcludeRx = @(), [string]$Filter = '',
                   [bool]$HideDone = $false, [int]$HideableCount = 0) {

    if ($null -eq $Items) { $Items = @() }
    $w = ((Get-Width) - 1)
    $detailed = ($Mode -eq 'detailed' -or $Mode -eq 'preview')
    $preview  = ($Mode -eq 'preview')
    # While a passive audit is running, surface the matched rule: a Rule column in the
    # simple/detailed tables, and a Rule line in the preview detail pane.
    $showRule = ($script:AuditAvailable -and $script:AuditState -eq 'passive')
    $L = [Collections.Generic.List[string]]::new()

    # Header bar.
    $title = '  ARTCA  Artifactory Search  '
    $url   = $BaseUrl
    $avail = $w - $title.Length - 4
    if ($url.Length -gt $avail) { $url = Clip $url ([Math]::Max(1, $avail)) }
    $right = "  $url  "
    $gap   = [Math]::Max(0, $w - $title.Length - $right.Length)
    $L.Add("${HB}${BD}${MG}${title}${R}${HB}$(' ' * $gap)${DM}${right}${R}")
    $L.Add("$DM$(HR $w)$R")
    $countStr = if ($script:ResultGrandTotal -gt $TotalItems) {
        "$TotalItems shown $([char]0x00B7) ~$($script:ResultGrandTotal) total"
    } else { "$TotalItems result$(if ($TotalItems -ne 1) {'s'})" }
    $pageStr = "Page $($Page + 1) of $TotalPages  ($countStr)"
    $rPad    = [Math]::Max(0, $w - 9 - $Query.Length - $pageStr.Length)
    $L.Add("  Query: ${BD}${CY}${Query}${R}$(' ' * $rPad)${DM}${pageStr}${R}")
    if ($Filter) {
        $L.Add("  ${DM}Excluding (dimmed, sent to back):${R} ${YL}$(Trunc $Filter ($w - 36))${R}")
    }
    $al = $script:Alert
    if ($al.Message -and ([DateTime]::UtcNow - $al.At).TotalSeconds -lt 60) {
        $L.Add("  ${RD}${BD}! $(Trunc $al.Message ($w - 4))${R}")
    }
    $fl = $script:Flash
    if ($fl.Message -and ([DateTime]::UtcNow - $fl.At).TotalSeconds -lt 15) {
        $L.Add("  $($fl.Message)")
    }

    # Column area width — narrower in preview mode to make room for the pane.
    $rightW = if ($preview) { [Math]::Max(28, [int]($w * 0.40)) } else { 0 }
    $colW   = if ($preview) { $w - $rightW - 3 } else { $w }

    # Build the column header + data rows (each row already includes its gutter).
    $ruleW = 0
    # The '#' column must fit the largest row number (1-based, max = $TotalItems) so it is NEVER
    # truncated; widen from the default 4 for large result sets. Sized off the total (not the current
    # page) so the column width stays stable as you page. Shared by detailed + simple rendering.
    $numW = [Math]::Max(4, ([string][Math]::Max(1, $TotalItems)).Length)
    if ($detailed) { $hdrLine = Format-DetailedHeader $colW $preview $showRule $numW }
    else {
        # Budget: gutter(2) + num + 3 single-space gaps = 5 overhead columns.
        $repoW = 22
        if ($showRule) { $ruleW = [Math]::Min(20, [Math]::Max(10, [int]($colW * 0.16))) }
        $avail = [Math]::Max(20, $colW - $numW - $repoW - 8 - $(if ($showRule) { $ruleW + 1 } else { 0 }))
        $nameW = [Math]::Max(16, [int]($avail * 0.55))
        $pathW = [Math]::Max(8, $avail - $nameW)
        $hdr = "$(ClipR '#' $numW) $(Clip 'Name' $nameW) $(Clip 'Repository' $repoW) $(Clip 'Path' $pathW)"
        if ($showRule) { $hdr += " $(Clip 'Rule' $ruleW)" }
        $hdrLine = "${BD}${YL}$hdr${R}"
    }

    $rowStrs = [Collections.Generic.List[string]]::new()
    # NB: do NOT name the loop var $r — PowerShell is case-insensitive, so $r would
    # alias $R (the ANSI reset) and corrupt every ${R} in this function.
    for ($ri = 0; $ri -lt $Items.Count; $ri++) {
        $item = $Items[$ri]
        # Excluded (filter-matched) rows wash out like visited rows; the nav loop has
        # already sorted them to the back.
        $vis  = (Test-Visited ([string]$item.Uri)) -or (Test-NameMatchesAny ([string]$item.Name) $ExcludeRx)
        $sel  = ($ri -eq $SelRow)
        if ($detailed) {
            $rowBody = Format-DetailedRow $item ($Offset + $ri + 1) $colW $vis $preview $showRule $numW
        } else {
            # Simple view shows no archive/preview badges (detailed/preview only).
            $name = if ($item.Name) { $item.Name } else { '?' }
            $repo = if ($item.Repo) { $item.Repo } else { '?' }
            $cName = if (Test-ItemPreviewError $item) { $RD } elseif ($vis) { $DM } else { $CY }
            $cRepo = if ($vis) { $DM } else { $MG }
            $nameCell = "${cName}$(Clip $name $nameW)${R}"
            $pathCell = Format-PathCell ([string]$item.Path) $pathW ([bool](Get-ItemArchiveName $item)) $DM $(if ($vis) { $DM } else { '' })
            $rowBody = "${DM}$(ClipR ([string]($Offset + $ri + 1)) $numW)${R} $nameCell ${cRepo}$(Clip $repo $repoW)${R} $pathCell"
            # Rule cell uses the plain value colour (light), washed to dim only on visited
            # rows — matching the detailed view (was always dim here).
            if ($showRule) { $cRule = if ($vis) { $DM } else { '' }; $rowBody += " ${cRule}$(Clip (Get-AuditRuleLabel ([string]$item.Uri)) $ruleW)${R}" }
        }
        # Gutter is two visible columns: selection caret + audit severity marker
        # ('!' coloured by remapped severity). The marker only appears when the
        # audit component is loaded and this row has a finding (guarded so the base
        # tool works unchanged without it).
        $selCh = if ($sel) { "${BD}${YL}>${R}" } else { ' ' }
        $mkCh  = ' '
        if ($script:AuditAvailable) { $am = Get-AuditMarker ([string]$item.Uri); if ($am) { $mkCh = $am } }
        $line = "$selCh$mkCh$rowBody"
        if ($sel) { $line = Highlight-Row $line $colW }
        $rowStrs.Add($line)
    }

    if (-not $preview) {
        $L.Add("$DM$(HR $w)$R")
        $L.Add("  $hdrLine")
        $L.Add("$DM$(HR $w)$R")
        if ($Items.Count -eq 0) { $L.Add(''); $L.Add("  ${DM}No results.${R}") }
        else { foreach ($rs in $rowStrs) { $L.Add($rs) } }   # $rs already carries its 2-col gutter
    } else {
        # Two-pane: column table on the left, file preview on the right. The rule
        # carries a ┬ at the divider column (colW+1) so it joins the vertical bar.
        $L.Add("$DM$(HR-Join $w ($colW + 1) ([char]0x252C))$R")
        # Reserve the bottom border + the footer (its tallest height seen at this width,
        # so the divider doesn't bob as hints wrap) + one spare against clipping.
        $bodyH = [Math]::Max(4, (Get-Height) - $L.Count - (2 + $script:NavReserve))

        # Window the rows around the cursor (2 lines reserved: column header + the
        # header divider beneath it).
        $rowsH = [Math]::Max(1, $bodyH - 2)
        $sIdx = 0; $eIdx = $rowStrs.Count - 1; $indTop = $false; $indBot = $false
        if ($rowStrs.Count -gt $rowsH) {
            $winH = [Math]::Max(1, $rowsH - 2)
            $cur  = [Math]::Max(0, $SelRow)
            $sIdx = [Math]::Max(0, [Math]::Min($cur - [int]($winH / 2), $rowStrs.Count - $winH))
            $eIdx = $sIdx + $winH - 1
            $indTop = $true; $indBot = $true
        }
        $leftLines = [Collections.Generic.List[string]]::new()
        $leftLines.Add("  $hdrLine")
        $leftLines.Add($script:HeaderRuleTag)   # divider between header and rows
        if ($Items.Count -eq 0) { $leftLines.Add("  ${DM}No results.${R}") }
        else {
            # The two indicator slots stay reserved while scrolling (so the window height
            # is constant), but each shows its arrow only when rows are actually hidden in
            # that direction — otherwise it's blank, never a meaningless "0 more".
            if ($indTop) { $leftLines.Add($(if ($sIdx -gt 0) { "  ${DM}$([char]0x2191) $sIdx more${R}" } else { '' })) }
            for ($ri = $sIdx; $ri -le $eIdx; $ri++) { $leftLines.Add($rowStrs[$ri]) }   # gutter already included
            if ($indBot) { $belowN = $rowStrs.Count - 1 - $eIdx; $leftLines.Add($(if ($belowN -gt 0) { "  ${DM}$([char]0x2193) $belowN more${R}" } else { '' })) }
        }

        # Right pane: details + preview for the selected item.
        $script:PvScrollMax = 0   # reset; Get-PreviewLines sets it for a scrollable file
        $rightLines = @()
        if ($SelRow -ge 0 -and $SelRow -lt $Items.Count) {
            $sItem = $Items[$SelRow]
            $sUrl  = Get-ItemUrl $sItem
            $sBytes = if ("$($sItem.Size)" -ne '' -and "$($sItem.Size)" -ne '?') { [long]$sItem.Size } else { -1 }
            $szTxt = if ($sBytes -ge 0) { Format-Size $sBytes } else { '?' }
            $repo   = if ($sItem.Repo) { $sItem.Repo } else { '?' }
            $rmeta  = Resolve-Repo $repo
            $labelW = 11
            $valMax = [Math]::Max(6, $rightW - $labelW - 1)
            $rl = [Collections.Generic.List[string]]::new()
            $rl.Add("${BD}${CY}$(Trunc ([string]$sItem.Name) $rightW)${R}")
            $rl.Add('')
            $rl.Add("${DM}$('Repository'.PadRight($labelW))${R}${MG}$(Trunc $repo $valMax)${R}")
            $rl.Add("${DM}$('Path'.PadRight($labelW))${R}$(Trunc ([string]$sItem.Path) $valMax)")
            $sArc = Get-ItemArchiveName $sItem
            if ($sArc) { $rl.Add("${DM}$('Archive'.PadRight($labelW))${R}${YL}$(Trunc $sArc $valMax)${R}") }
            $rl.Add("${DM}$('Type'.PadRight($labelW))${R}${YL}$(Trunc ([string]$sItem.FileType) $valMax)${R}")
            $rl.Add("${DM}$('Size'.PadRight($labelW))${R}$szTxt")
            if ($sItem.Modified) { $rl.Add("${DM}$('Modified'.PadRight($labelW))${R}$(Trunc ([string]$sItem.Modified) $valMax)") }
            $sHash = if ("$($sItem.Hash)") { [string]$sItem.Hash }
                     elseif ($sItem.Uri -and $script:MetaCache.ContainsKey($sItem.Uri) -and
                             $script:MetaCache[$sItem.Uri].PSObject.Properties['Hash']) { [string]$script:MetaCache[$sItem.Uri].Hash }
                     else { '' }
            if ($sHash) {
                # Stored as '<algo>:<hex>'; show the algorithm as the label, the hex as the value.
                $hParts = $sHash -split ':', 2
                $hLabel = switch ($hParts[0]) { 'sha256' { 'SHA-256' } 'sha1' { 'SHA-1' } 'md5' { 'MD5' } default { 'Hash' } }
                $hVal   = if ($hParts.Count -gt 1) { $hParts[1] } else { $sHash }
                $rl.Add("${DM}$($hLabel.PadRight($labelW))${R}$(Trunc $hVal $valMax)")
            }
            $rl.Add("${DM}$('Repo type'.PadRight($labelW))${R}$($rmeta.Type)")
            $rl.Add("${DM}$('Pkg type'.PadRight($labelW))${R}${MG}$($rmeta.PackageType)${R}")
            if ($showRule) {
                $rule = Get-AuditRuleLabel ([string]$sItem.Uri)
                if ($rule) { $rl.Add("${DM}$('Rule'.PadRight($labelW))${R}${YL}$(Trunc $rule $valMax)${R}") }
            }
            $pvMax  = [Math]::Max(1, $bodyH - $rl.Count - 2)
            $pvLines = if (Test-ItemBrowsableArchive $sItem) {
                Get-ArchivePreviewLines $sItem $rightW $pvMax $PvScroll
            } else {
                Get-PreviewLines ([string]$sItem.Name) $sUrl $sBytes $rightW $pvMax $PvScroll
            }
            foreach ($pl in $pvLines) { $rl.Add($pl) }
            $rightLines = $rl.ToArray()
        }

        for ($i = 0; $i -lt $bodyH; $i++) {
            $lc = if ($i -lt $leftLines.Count)  { $leftLines[$i] }  else { '' }
            $rc = if ($i -lt $rightLines.Count) { $rightLines[$i] } else { '' }
            if ($rc -eq $script:PaneRuleTag)        { $L.Add((Format-PaneRule $lc $colW $rightW)) }
            elseif ($lc -eq $script:HeaderRuleTag)  { $L.Add((Format-HeaderRule $rc $colW)) }
            else { $L.Add("$(Fit-Vis $lc $colW) ${DM}$([char]0x2502)${R} $rc") }
        }
        $L.Add("$DM$(HR-Join $w ($colW + 1) ([char]0x2534))$R")
    }

    # Footer
    if (-not $preview) { $L.Add("$DM$(HR $w)$R") }
    $arrowL = [char]0x2190; $arrowR = [char]0x2192
    $nav = [Collections.Generic.List[string]]::new()
    if ($SelRow -ge 0) {
        $nav.Add("${BD}${LB}$([char]0x2191)$([char]0x2193)${RB}${R}${DM} move${R}")
        $nav.Add("${BD}${LB}$([char]0x21B5)${RB}${R}${DM} open${R}")
    }
    if ($Page -gt 0)               { $nav.Add("${BD}${LB}p${RB}/${arrowL}${R}${DM} prev${R}") }
    if ($Page -lt $TotalPages - 1) { $nav.Add("${BD}${LB}n${RB}/${arrowR}${R}${DM} next${R}") }
    if ($TotalPages -gt 1) { $nav.Add("${BD}${LB}g${RB}${R}${DM} page${R}") }
    if ($preview -and $SelRow -ge 0 -and $SelRow -lt $Items.Count) {
        $sIt = $Items[$SelRow]
        if (-not (Test-ItemBrowsableArchive $sIt)) {
            $sUrl = Get-ItemUrl $sIt
            $sSz  = if ("$($sIt.Size)" -ne '' -and "$($sIt.Size)" -ne '?') { [long]$sIt.Size } else { -1 }
            switch (Get-PreviewState ([string]$sIt.Name) $sUrl $sSz) {
                'large-gated' { $nav.Add("${BD}${LB}y${RB}${R}${DM} preview large${R}") }
                'force-gated' { $nav.Add("${BD}${LB}y${RB}${R}${DM} force preview${R}") }
            }
        }
    }
    if ($preview -and $script:PvScrollMax -gt 0) { $nav.Add("${BD}${LB}Shift+$([char]0x2191)$([char]0x2193)${RB}${R}${DM} scroll${R}") }
    if ($TotalItems -gt 0) {
        $nav.Add("${BD}${LB}#${RB}${R}${DM} multi-download${R}")
        $nav.Add("${BD}${LB}A${RB}${R}${DM} download all${R}")
    }
    $nextMode = switch ($Mode) { 'simple' { 'detailed' } 'detailed' { 'preview' } default { 'simple' } }
    $nav.Add("${BD}${LB}d${RB}${R}${DM} $nextMode view${R}")
    $nav.Add("${BD}${LB}s${RB}${R}${DM} search${R}")
    $nav.Add("${BD}${LB}f${RB}${R}${DM} filter$(if (@($ExcludeRx).Count -gt 0) { " ($(@($ExcludeRx).Count))" })${R}")
    if (@($ExcludeRx).Count -gt 0) { $nav.Add("${BD}${LB}i${RB}${R}${DM} show all${R}") }
    if ($HideDone)                { $nav.Add("${BD}${LB}h${RB}${R}${DM} unhide $HideableCount hidden${R}") }
    elseif ($HideableCount -gt 0) { $nav.Add("${BD}${LB}h${RB}${R}${DM} hide $HideableCount${R}") }
    if ($script:AuditAvailable) {
        $aLbl = if ($script:AuditState -eq 'passive') { "${YL}audit: passive${R}${DM}" } else { 'audit' }
        $nav.Add("${BD}${LB}a${RB}${R}${DM} $aLbl${R}")
    }
    # Archive-search status: yellow "(walking)" while the background walk runs.
    if ($script:IndexAvailable) {
        if ($script:ArcSearchEnabled) {
            $wLbl = if ($script:ArcSearchState -eq 'walking') { "${YL}archive search: on (walking)${R}${DM}" } else { "${YL}archive search: on${R}${DM}" }
            $nav.Add("${BD}${LB}w${RB}${R}${DM} $wLbl${R}")
            # Skip-versions toggle: only meaningful while the archive walk is active. Version-skip is
            # under the skip-recommended umbrella, so it's effectively off when --scan-all turned that off.
            $vLbl = if ($script:SkipRecommended -and $script:ArcSkipVersions) { 'skip-versions: on' } else { 'skip-versions: off' }
            $nav.Add("${BD}${LB}V${RB}${R}${DM} $vLbl${R}")
        } else {
            $nav.Add("${BD}${LB}w${RB}${R}${DM} archive search${R}")
        }
        # Local index status: record count, a yellow "(writing)" pulse on a write this frame.
        $idxState = if ($script:IndexEnabled) {
            $wr = if ($script:IndexWroteTick) { " ${YL}(writing)${R}${DM}" } else { '' }
            "index: $($script:IndexCount)$wr"
        } else { 'index: off' }
        $nav.Add("${BD}${LB}W${RB}${R}${DM} $idxState${R}")
        $script:IndexWroteTick = $false   # one-shot: consumed at render
    }
    # Offline indicator (read-only status, no key): shows the active --offline mode.
    if (Get-Command Get-OfflineMode -ErrorAction SilentlyContinue) {
        $om = Get-OfflineMode
        if ($om) { $nav.Add("${YL}offline: $om${R}") }
    }
    $nav.Add("${BD}${LB}q${RB}${R}${DM} quit${R}")
    $navLines = @(Wrap-Hints $nav.ToArray() $w)
    foreach ($nl in $navLines) { $L.Add($nl) }
    # Remember the wrapped footer height so the next page-size calc reserves for it.
    $script:NavLineCount = [Math]::Max(1, $navLines.Count)
    # Grow the stable preview reservation to the tallest footer seen at this width; reset
    # it when the width changes (a resize re-wraps everything, so start fresh).
    if ($script:NavReserveW -ne $w) { $script:NavReserveW = $w; $script:NavReserve = $script:NavLineCount }
    else { $script:NavReserve = [Math]::Max($script:NavReserve, $script:NavLineCount) }

    Show-Frame $L.ToArray()
}

function Show-Error([string]$Msg) {
    $L = [Collections.Generic.List[string]]::new()
    $L.Add(''); $L.Add("  ${RD}${BD}Error:${R} $Msg"); $L.Add('')
    $L.Add("  ${DM}401: anonymous user lacks read/search permission - supply -Token / -Basic / -ApiKey.${R}")
    $L.Add("  ${DM}403: authenticated but not permitted to search these repositories.${R}")
    $L.Add("  ${DM}404: check the base URL - it should be the host (the /artifactory suffix is added for you).${R}")
    $L.Add("  ${DM}429: server is rate-limiting - wait a moment and try again.${R}")
    $L.Add(''); $L.Add("  ${BD}${LB}s${RB}${R}${DM} try again   ${BD}${LB}q${RB}${R}${DM} quit${R}")
    Show-Frame $L.ToArray()
}

function Show-Loading([string]$Query) {
    $lines = @('Searching', $Query)
    # Offline (index/all): the catalogue is streamed from the on-disk shards, which is the
    # perceptible pause here - label it. Test-SearchLocalOnly is the existing offline predicate.
    if ($script:IndexAvailable -and (Test-SearchLocalOnly)) { $lines += @('', 'Loading offline index...') }
    Show-Popup $lines
}

# Download an artifact into $OutDir (created on demand). Returns a status line.
# On failure, the server's response body (Artifactory returns a JSON error with
# a human-readable reason, e.g. a "blacked out" repo) is surfaced verbatim
# rather than the bare "(404) Not Found" from the exception message.
function Save-Item([object]$item, [string]$url, [string]$DestName = '') {
    try {
        if (-not (Test-Path -LiteralPath $OutDir)) {
            New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
        }
    } catch {
        return "${RD}${BD}Download failed:${R} cannot create folder ${CY}$OutDir${R} - $($_.Exception.Message)"
    }
    # $DestName is the (possibly hash-tagged) on-disk filename from a bulk download; the
    # CSV still logs $item.Name (the original) plus the hash ('<algo>:<hex>' storage checksum).
    $fn   = if ($DestName) { $DestName } else { [string]$item.Name }
    $hfn  = if ($DestName -and $DestName -ne [string]$item.Name) { [string]$DestName } else { '' }
    $hash = if ("$($item.Hash)") { [string]$item.Hash }
            elseif ($item.Uri -and $script:MetaCache.ContainsKey($item.Uri) -and
                    $script:MetaCache[$item.Uri].PSObject.Properties['Hash']) { [string]$script:MetaCache[$item.Uri].Hash }
            else { '' }
    $dest = Join-Path $OutDir $fn
    # Reuse bytes already held in memory from an earlier preview, if present.
    if ($script:MemFiles.ContainsKey($url)) {
        try {
            [System.IO.File]::WriteAllBytes($dest, $script:MemFiles[$url])
            $len = -1; try { $len = (Get-Item $dest).Length } catch { }
            if (-not $hash) { $hash = 'sha256:' + (Get-BytesSha256 $script:MemFiles[$url]) }
            Write-DownloadLog $OutDir ([string]$item.Name) ([string]$item.Repo) ([string]$item.Path) (Get-ItemArchiveName $item) $len ([string]$item.Modified) $url '' '' $hash 'download-log.csv' -hashFileName $hfn
            Mark-Downloaded ([string]$item.Uri) $url
            $sz = if ($len -ge 0) { ' (' + (Format-Size $len) + ')' } else { '' }
            return "${BD}Saved${R} to ${CY}$dest${R}$sz ${DM}(from preview cache)${R}"
        } catch { }   # fall through to a normal download on any write error
    }
    if (Test-NetworkBlocked) {
        return "${YL}Offline:${R} content not cached this session - can't download without a connection. ${DM}(A previously-downloaded copy may already be in $OutDir.)${R}"
    }
    $old  = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        Invoke-WebRequest -Uri $url -Headers (Get-AuthHeaders) -OutFile $dest -ErrorAction Stop
        $len = -1; try { $len = (Get-Item $dest).Length } catch { }
        if (-not $hash) { $hash = Get-FileSha256 $dest }
        Write-DownloadLog $OutDir ([string]$item.Name) ([string]$item.Repo) ([string]$item.Path) (Get-ItemArchiveName $item) $len ([string]$item.Modified) $url '' '' $hash 'download-log.csv' -hashFileName $hfn
        Mark-Downloaded ([string]$item.Uri) $url
        $sz = if ($len -ge 0) { ' (' + (Format-Size $len) + ')' } else { '' }
        return "${BD}Saved${R} to ${CY}$dest${R}$sz"
    } catch {
        # A failed -OutFile request may leave an empty/partial file behind.
        try { if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Force } } catch { }
        return "${RD}${BD}Download failed:${R} $(Get-HttpErrorDetail $_)"
    } finally {
        $ProgressPreference = $old
    }
}


# Confirm + download a set of search-result items. Identical content is saved once; every
# item is still logged. Shared by the results view's 'A' (download all) and numeric multi-download.
function Save-ItemSet($items) {
    $items = @($items | Where-Object { $_ })
    if ($items.Count -eq 0) { Show-Popup @('Nothing to download.', '', 'press any key'); [void](Read-Key); return }
    $bytes = 0L; $haveAll = $true
    foreach ($it in $items) {
        if ("$($it.Size)" -ne '' -and "$($it.Size)" -ne '?') { try { $bytes += [long]$it.Size } catch { $haveAll = $false } }
        else { $haveAll = $false }
    }
    $szStr = if ($haveAll) { Format-Size $bytes } else { "$(Format-Size $bytes)+ (some sizes unknown)" }
    $lines = @("${BD}Download $($items.Count) item$(if ($items.Count -ne 1){'s'})?${R}",
               "${DM}Identical files are saved once on disk; each entry is still logged.${R}",
               "Total size: ${CY}$szStr${R}", "Into: ${CY}$OutDir${R}")
    if (-not (Confirm-Prompt $lines)) { return }
    $entries = @($items | ForEach-Object {
        [PSCustomObject]@{
            Ref = $_; Name = [string]$_.Name; Url = (Get-ItemUrl $_); KnownHash = [string]$_.Hash
            Repo = [string]$_.Repo; Path = [string]$_.Path; Archive = (Get-ItemArchiveName $_)
            Size = $(if ("$($_.Size)" -ne '' -and "$($_.Size)" -ne '?') { try { [long]$_.Size } catch { [long]-1 } } else { [long]-1 })
            Modified = [string]$_.Modified; Sev = ''; Rule = ''; VisitKey = [string]$_.Uri
        }
    })
    $res = Invoke-DedupDownload $entries
    Show-Popup @((Get-DedupDoneLine $res), "Into $OutDir", '', 'press any key')
    [void](Read-Key)
}

