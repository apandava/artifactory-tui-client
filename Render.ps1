# Render.ps1 — part of the ARTCA Artifactory TUI (see StartTui.ps1).
#
# This file holds function and $script:-state definitions only; nothing here runs
# on its own. It is loaded two ways:
#   · dot-sourced automatically by StartTui.ps1 when the tool is run as a file, or
#   · pasted directly into the PowerShell console (paste the component files first,
#     then StartTui.ps1 last) to run the tool without executing the .ps1 files.
# Load order among the component files does not matter.
# ── HELPERS ───────────────────────────────────────────────────────────────────

# Pad/truncate to exactly $n columns. When text is cut off, end it with … so the
# truncation is visible. ($script:Cut is the marker, defined once below.)
function Clip([string]$s, [int]$n) {
    if ($s.Length -gt $n) { return $s.Substring(0, $n - 1) + $script:Cut }
    return $s.PadRight($n)
}

function ClipR([string]$s, [int]$n) {
    if ($s.Length -gt $n) { return $s.Substring(0, $n - 1) + $script:Cut }
    return $s.PadLeft($n)
}

# Truncate without padding (for free-form values), with the … marker.
function Trunc([string]$s, [int]$n) {
    if ($s.Length -gt $n) { return $s.Substring(0, [Math]::Max(1, $n - 1)) + $script:Cut }
    return $s
}

function HR([int]$w) { [string][char]0x2500 * $w }

# A horizontal rule of $w dashes carrying a junction glyph at column $col, so a
# vertical pane divider sitting at that column joins it cleanly (┬ above, ┴ below)
# instead of leaving a gap. Falls back to a plain rule if $col is out of range.
function HR-Join([int]$w, [int]$col, [char]$junction) {
    if ($col -lt 0 -or $col -ge $w) { return (HR $w) }
    $hz = [char]0x2500
    return ([string]$hz * $col) + $junction + ([string]$hz * ($w - $col - 1))
}

# WindowSize is $null in ISE; fall back to the buffer width, then a sane default.
function Get-Width {
    try { $sz = $host.UI.RawUI.WindowSize; if ($sz -and $sz.Width  -gt 0) { return $sz.Width  } } catch { }
    try { $bs = $host.UI.RawUI.BufferSize; if ($bs -and $bs.Width  -gt 0) { return $bs.Width  } } catch { }
    return 120
}

function Get-Height {
    try { $sz = $host.UI.RawUI.WindowSize; if ($sz -and $sz.Height -gt 0) { return $sz.Height } } catch { }
    try { $bs = $host.UI.RawUI.BufferSize; if ($bs -and $bs.Height -gt 0) { return $bs.Height } } catch { }
    return 40
}

# Normalise a RawUI key into a token. Printable keys return their lowercased
# character; navigation keys (which carry no .Character) return a name so the
# nav loop can treat arrows / PageUp-Down / Home-End as paging shortcuts.
function ConvertTo-KeyToken($k) {
    $ch = $k.Character
    if ($ch -and [int][char]$ch -ge 32) { return ([string]$ch).ToLower() }
    # Shift+Up / Shift+Down get distinct tokens (used to scroll the preview pane);
    # the shift state rides on ControlKeyState. Guarded since some hosts omit it —
    # there it just degrades to a plain arrow.
    $shift = $false
    try { $shift = ($k.ControlKeyState -band [System.Management.Automation.Host.ControlKeyStates]::ShiftPressed) -ne 0 } catch { }
    switch ([int]$k.VirtualKeyCode) {
        37 { 'left' }
        38 { if ($shift) { 'shift+up' }   else { 'up' } }
        39 { 'right' }
        40 { if ($shift) { 'shift+down' } else { 'down' } }
        33 { 'pageup' }  34 { 'pagedown' } 36 { 'home' }  35 { 'end' }
        13 { 'enter' }
        8  { 'backspace' }
        default { '' }
    }
}

function Read-Key {
    # ISE / non-console hosts: no RawUI.ReadKey, so read a typed line instead
    # (the user presses the command letter/number then Enter).
    if (-not $script:CanRawKey) { return (Read-Host).Trim().ToLower() }
    ConvertTo-KeyToken ($host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown'))
}

# Like ConvertTo-KeyToken but preserves letter case, so a screen can distinguish
# Shift-modified keys (e.g. e/E, c/C, g/G). Navigation keys map as usual.
function ConvertTo-KeyTokenCased($k) {
    $ch = $k.Character
    if ($ch -and [int][char]$ch -ge 32) { return [string]$ch }
    ConvertTo-KeyToken $k
}

# Case-preserving blocking read, used by the tree view. ISE returns the typed
# line verbatim (case kept).
function Read-KeyCased {
    if (-not $script:CanRawKey) { return (Read-Host).Trim() }
    ConvertTo-KeyTokenCased ($host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown'))
}

# Return the next *meaningful* buffered key as a token, or $null if none is
# pending — without ever blocking. This is the crux of the seamless redraw:
# KeyAvailable also counts key-up events (left behind when you release a held
# nav key), but ReadKey('IncludeKeyDown') would BLOCK on those waiting for a
# key-down — freezing the poll so the page never refreshes. So we read with
# IncludeKeyUp too and drain key-up / modifier-only events here. Returns $null
# on hosts without a real key buffer (ISE), which disables the burst/poll paths.
function Read-KeyNow {
    if (-not $script:CanRawKey) { return $null }
    while ($host.UI.RawUI.KeyAvailable) {
        $k = $host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown,IncludeKeyUp')
        if (-not $k.KeyDown) { continue }              # discard key-up events
        $t = ConvertTo-KeyToken $k
        if ($t -ne '') { return $t }                  # skip modifier-only keys
    }
    return $null
}

# Non-blocking read: wait up to $TimeoutMs for a real keypress, returning $null
# if none arrives. Lets the main loop redraw as background detail fetches land
# without ever blocking the keyboard.
function Read-KeyTimeout([int]$TimeoutMs) {
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    do {
        $t = Read-KeyNow
        if ($null -ne $t) { return $t }
        Start-Sleep -Milliseconds 25
    } while ([DateTime]::UtcNow -lt $deadline)
    return $null
}

# Case-preserving variants of the non-blocking poll, for the archive tree (which
# distinguishes e/E, c/C, g/G). Same key-up draining as Read-KeyNow.
function Read-KeyNowCased {
    if (-not $script:CanRawKey) { return $null }
    while ($host.UI.RawUI.KeyAvailable) {
        $k = $host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown,IncludeKeyUp')
        if (-not $k.KeyDown) { continue }
        $t = ConvertTo-KeyTokenCased $k
        if ($t -ne '') { return $t }
    }
    return $null
}
function Read-KeyTimeoutCased([int]$TimeoutMs) {
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    do {
        $t = Read-KeyNowCased
        if ($null -ne $t) { return $t }
        Start-Sleep -Milliseconds 25
    } while ([DateTime]::UtcNow -lt $deadline)
    return $null
}

# Coalesce a held-key navigation burst. When the user holds (or rapidly taps) a
# paging key, the input buffer fills with repeats; rendering and warming every
# intermediate page just builds a prefetch backlog that starves the page they
# actually stop on. So we drain all *buffered* nav keys here and apply them to
# $Page in one go, leaving only the final page to render and warm. The first
# non-nav key encountered is handed back via $Pending so the caller processes it
# next instead of dropping it.
function Invoke-NavBurst([ref]$Page, [int]$TotalPages, [ref]$Pending) {
    while ($true) {
        $k = Read-KeyNowCased       # non-blocking; drains key-up events (case preserved)
        if ($null -eq $k) { break }
        switch -regex ($k) {
            '^(n|right|pagedown)$' { if ($Page.Value -lt $TotalPages - 1) { $Page.Value++ } }
            '^(p|left|pageup)$'    { if ($Page.Value -gt 0)               { $Page.Value-- } }
            '^home$'               { $Page.Value = 0 }
            '^end$'                { $Page.Value = $TotalPages - 1 }
            default                { $Pending.Value = $k; return }
        }
    }
}

# Coalesce a held-key row-movement burst (up/down, k/j) — the cursor-level analogue
# of Invoke-NavBurst, and the fix for hold-to-scroll lag. Holding an arrow fills the
# input buffer with repeats; applying and rendering every intermediate row builds a
# backlog that keeps scrolling for a moment after the key is released. So we drain
# all *buffered* row keys and apply their NET movement in one go, leaving a single
# destination to render and warm. Movement is computed on the absolute item index
# (page*PageSize + row), so a burst crosses page boundaries exactly like a single
# step does and clamps at the ends. $InitialDelta is the move from the keypress that
# triggered the burst (+1 down, -1 up), already counted so the caller needn't apply
# it first. The first non-row key encountered is handed back via $Pending.
function Invoke-RowBurst([ref]$Page, [ref]$SelRow, [int]$PageSize, [int]$TotalItems, [ref]$Pending, [int]$InitialDelta) {
    $delta = $InitialDelta
    $stop  = $false
    while (-not $stop) {
        $k = Read-KeyNowCased       # non-blocking; drains key-up events (case preserved)
        if ($null -eq $k) { break }
        switch -regex ($k) {
            '^(down|j)$' { $delta++ }
            '^(up|k)$'   { $delta-- }
            default      { $Pending.Value = $k; $stop = $true }
        }
    }
    if ($TotalItems -le 0 -or $PageSize -le 0) { return }
    $abs = ($Page.Value * $PageSize) + $SelRow.Value + $delta
    if ($abs -lt 0)                  { $abs = 0 }
    if ($abs -gt ($TotalItems - 1))  { $abs = $TotalItems - 1 }
    $Page.Value   = [int][Math]::Floor($abs / $PageSize)
    $SelRow.Value = $abs - ($Page.Value * $PageSize)
}

# Flat-cursor analogue of Invoke-RowBurst for the archive tree (no paging — the
# cursor just moves within $RowCount rows). Same coalescing so holding up/down
# doesn't backlog. Uses the case-preserving poll since the tree distinguishes
# shifted keys; the first non-row key is handed back via $Pending.
function Invoke-TreeRowBurst([ref]$Cursor, [int]$RowCount, [ref]$Pending, [int]$InitialDelta) {
    $delta = $InitialDelta
    $stop  = $false
    while (-not $stop) {
        $k = Read-KeyNowCased       # non-blocking; drains key-up events
        if ($null -eq $k) { break }
        switch -regex -casesensitive ($k) {
            '^(down|j)$' { $delta++ }
            '^(up|k)$'   { $delta-- }
            default      { $Pending.Value = $k; $stop = $true }
        }
    }
    if ($RowCount -le 0) { return }
    $c = $Cursor.Value + $delta
    if ($c -lt 0)                 { $c = 0 }
    if ($c -gt ($RowCount - 1))   { $c = $RowCount - 1 }
    $Cursor.Value = $c
}

# Coalesce a held preview-scroll burst (Shift+Down / Shift+Up) into one net offset
# change, the same way Invoke-RowBurst coalesces selection moves, so holding a scroll
# key doesn't backlog renders. $InitialDelta is the move from the triggering keypress
# (already counted). The result is clamped to [0, $MaxScroll]; the first non-scroll
# key encountered is handed back via $Pending. Uses the case-preserving poll so a
# drained Shift-letter (e.g. E in the tree view) keeps its case for the caller.
function Invoke-ScrollBurst([ref]$Scroll, [int]$MaxScroll, [ref]$Pending, [int]$InitialDelta) {
    $delta = $InitialDelta
    $stop  = $false
    while (-not $stop) {
        $k = Read-KeyNowCased       # non-blocking; drains key-up events
        if ($null -eq $k) { break }
        switch -regex ($k) {
            '^shift\+down$' { $delta++ }
            '^shift\+up$'   { $delta-- }
            default         { $Pending.Value = $k; $stop = $true }
        }
    }
    $s = $Scroll.Value + $delta
    if ($s -lt 0)          { $s = 0 }
    if ($s -gt $MaxScroll) { $s = $MaxScroll }
    $Scroll.Value = $s
}

function Clear-Screen { Clear-Host }

# Visible length of a string, ignoring ANSI SGR/escape sequences — so colored
# cells can be padded/truncated by what the user actually sees.
$script:AnsiRe = "$([char]27)\[[0-9;?]*[A-Za-z]"
function Strip-Ansi([string]$s) { return ($s -replace $script:AnsiRe, '') }
function Vis-Len([string]$s)     { return (Strip-Ansi $s).Length }

# Right-pad a (possibly colored) string to $n visible columns.
function Pad-Vis([string]$s, [int]$n) {
    $len = Vis-Len $s
    if ($len -lt $n) { return $s + (' ' * ($n - $len)) }
    return $s
}

# Fit a (possibly colored) string to EXACTLY $n visible columns: truncate if too
# long, pad if too short — copying ANSI escape sequences verbatim (they don't
# count toward width). This guarantees a fixed column edge, so the two-pane
# divider stays perfectly straight regardless of content length.
function Fit-Vis([string]$s, [int]$n) {
    $esc = [char]27
    $sb  = [Text.StringBuilder]::new()
    $vis = 0; $i = 0
    while ($i -lt $s.Length) {
        $c = $s[$i]
        if ($c -eq $esc) {
            # Copy a full CSI escape (ESC [ ... letter) without counting it.
            [void]$sb.Append($c); $i++
            if ($i -lt $s.Length -and $s[$i] -eq '[') {
                [void]$sb.Append($s[$i]); $i++
                while ($i -lt $s.Length -and ($s[$i] -match '[0-9;?]')) { [void]$sb.Append($s[$i]); $i++ }
                if ($i -lt $s.Length) { [void]$sb.Append($s[$i]); $i++ }
            }
        } elseif ($vis -lt $n) {
            [void]$sb.Append($c); $vis++; $i++
        } else {
            $i++   # past the width limit: drop visible chars, keep scanning for ANSI
        }
    }
    [void]$sb.Append($R)                                   # close any open styling
    if ($vis -lt $n) { [void]$sb.Append(' ' * ($n - $vis)) }
    return $sb.ToString()
}

# Low-level frame writer (does NOT remember the frame). On a VT console it's
# flicker-free: hide cursor, home, overwrite each line (erase-to-EOL clears
# leftovers) and erase below — one write, so unchanged cells repaint in place.
function Write-Frame([string[]]$Lines) {
    if ($null -eq $Lines) { $Lines = @() }
    if (-not $script:Vt) {
        Clear-Host
        foreach ($l in $Lines) { Write-Host $l }
        return
    }
    # Never exceed the window height, or the terminal scrolls and our home anchor
    # drifts. Leave the last row free so a trailing newline can't scroll either.
    $h = [Math]::Max(1, (Get-Height) - 1)
    if ($Lines.Count -gt $h) { $Lines = $Lines[0..($h - 1)] }

    # Hard cap each line to one column under the width: a line that reaches the
    # last column makes the terminal auto-wrap, which desyncs our line-by-line
    # cursor model and mangles the screen. Truncate any over-long line.
    $maxW = [Math]::Max(1, (Get-Width) - 1)

    $E  = [char]27
    $sb = [Text.StringBuilder]::new()
    [void]$sb.Append("$E[?25l")          # hide cursor (no blink while painting)
    [void]$sb.Append("$E[H")             # cursor home
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        $ln = $Lines[$i]
        if ((Vis-Len $ln) -gt $maxW) { $ln = Fit-Vis $ln $maxW }
        [void]$sb.Append($ln)
        [void]$sb.Append("$E[K")         # erase rest of this line
        if ($i -lt $Lines.Count - 1) { [void]$sb.Append("`n") }
    }
    [void]$sb.Append("$E[J")             # erase everything below the last line
    [void]$sb.Append("$E[?25h")          # show cursor
    [Console]::Out.Write($sb.ToString())
}

# Render a full screen and remember it as the base for any popup overlay.
$script:BaseLines = @()
function Show-Frame([string[]]$Lines) {
    if ($null -eq $Lines) { $Lines = @() }
    $script:BaseLines = @($Lines)
    Write-Frame $Lines
}

# Visible-aware substring helpers (ANSI codes don't count toward width).
function Vis-Take([string]$s, [int]$n) {
    $esc = [char]27; $sb = [Text.StringBuilder]::new(); $vis = 0; $i = 0
    while ($i -lt $s.Length -and $vis -lt $n) {
        $c = $s[$i]
        if ($c -eq $esc) {
            [void]$sb.Append($c); $i++
            if ($i -lt $s.Length -and $s[$i] -eq '[') {
                [void]$sb.Append($s[$i]); $i++
                while ($i -lt $s.Length -and ($s[$i] -match '[0-9;?]')) { [void]$sb.Append($s[$i]); $i++ }
                if ($i -lt $s.Length) { [void]$sb.Append($s[$i]); $i++ }
            }
        } else { [void]$sb.Append($c); $vis++; $i++ }
    }
    return $sb.ToString()
}
function Vis-Skip([string]$s, [int]$n) {
    $esc = [char]27; $vis = 0; $i = 0
    while ($i -lt $s.Length -and $vis -lt $n) {
        $c = $s[$i]
        if ($c -eq $esc) {
            $i++
            if ($i -lt $s.Length -and $s[$i] -eq '[') {
                $i++
                while ($i -lt $s.Length -and ($s[$i] -match '[0-9;?]')) { $i++ }
                if ($i -lt $s.Length) { $i++ }
            }
        } else { $vis++; $i++ }
    }
    return $s.Substring($i)
}

# Composite $seg (visible width = its length) onto $base starting at column $atCol.
function Overlay-Line([string]$base, [string]$seg, [int]$atCol, [int]$totalW) {
    $base  = Pad-Vis $base $totalW
    $left  = Vis-Take $base $atCol
    $right = Vis-Skip $base ($atCol + (Vis-Len $seg))
    return "$left$R$seg$R$right"
}

# Draw a centered message box over the last rendered frame (a popup), instead of
# blanking the screen. Body lines are plain text (no ANSI needed).
function Show-Popup([string[]]$Body) {
    $w = [Math]::Max(20, (Get-Width) - 1)
    $base = @($script:BaseLines)
    $screenH = if ($base.Count -gt 0) { $base.Count } else { [Math]::Max(6, (Get-Height) - 1) }

    $innerW = 10
    foreach ($l in $Body) { $innerW = [Math]::Max($innerW, (Vis-Len $l)) }
    $innerW = [Math]::Min($innerW, $w - 8)
    $boxW   = $innerW + 4
    $atCol  = [Math]::Max(0, [int](($w - $boxW) / 2))
    $boxH   = $Body.Count + 2
    $top    = [Math]::Max(0, [int](($screenH - $boxH) / 2))

    # Sharp corners (┌┐└┘) over rounded ones (╭╮╰╯): the rounded glyphs have no
    # mapping in the legacy console code pages (CP437/850), so they get emitted as
    # '?'. The sharp corners exist there and in every console font.
    $tl=[char]0x250C; $tr=[char]0x2510; $bl=[char]0x2514; $br=[char]0x2518; $hz=[char]0x2500; $vt=[char]0x2502
    $box = [Collections.Generic.List[string]]::new()
    $box.Add("${MG}$tl$([string]$hz * ($boxW - 2))$tr${R}")
    foreach ($l in $Body) {
        $pad = $innerW - (Vis-Len $l)
        if ($pad -lt 0) { $pad = 0 }
        $box.Add("${MG}$vt${R} $l$(' ' * $pad) ${MG}$vt${R}")
    }
    $box.Add("${MG}$bl$([string]$hz * ($boxW - 2))$br${R}")

    # Ensure the base has enough rows to host the box.
    $out = [Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $screenH; $i++) { $out.Add($(if ($i -lt $base.Count) { $base[$i] } else { '' })) }
    for ($i = 0; $i -lt $box.Count; $i++) {
        $rr = $top + $i
        if ($rr -ge 0 -and $rr -lt $out.Count) { $out[$rr] = Overlay-Line $out[$rr] $box[$i] $atCol $w }
    }
    Write-Frame $out.ToArray()   # write but keep BaseLines intact for the next popup
}



# ── INPUT ─────────────────────────────────────────────────────────────────────

# Blocking line input seeded with an editable initial value, so a filter can be
# tweaked instead of retyped from scratch. On a real console the initial text is
# echoed and the user edits from the end (type to append, Backspace to delete);
# Enter commits. ISE / no-raw-key hosts can't prefill, so they fall back to a plain
# Read-Host. The caller prints the prompt prefix (and any colour) first.
function Read-LineEdit([string]$initial) {
    if (-not $script:CanRawKey) { return (Read-Host).Trim() }
    $buf = [Text.StringBuilder]::new()
    [void]$buf.Append("$initial")
    [Console]::Write("$initial")
    while ($true) {
        $k  = $host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        $vk = $k.VirtualKeyCode
        $ch = $k.Character
        if     ($vk -eq 13) { break }                                  # Enter commits
        elseif ($vk -eq 8)  { if ($buf.Length -gt 0) { [void]$buf.Remove($buf.Length - 1, 1); [Console]::Write("`b `b") } }  # Backspace
        elseif ($ch -and ([int][char]$ch) -ge 32) { [void]$buf.Append([char]$ch); [Console]::Write([string]$ch) }            # printable
        # arrows / Esc / function keys: ignored (end-of-line editing only)
    }
    [Console]::Write("`r`n")
    return $buf.ToString().Trim()
}

function Read-Query {
    # Non-VT hosts (ISE / plain cmd) can't address the cursor to host a field inside a
    # box, so they keep the plain top-left prompt.
    if (-not $script:Vt) {
        Clear-Screen
        Write-Host "  ${BD}${MG}ARTCA${R}  ${DM}$BaseUrl${R}`n"
        Write-Host "  ${DM}Examples:  *.env   *.properties   myapp   secret.xml${R}`n"
        Write-Host -NoNewline "  Search: ${BD}${CY}"
        $q = Read-Host
        Write-Host -NoNewline $R
        return $q.Trim()
    }

    # VT host: draw a centred message box (same style as Show-Popup) and read the query
    # in a field inside it.
    $w       = [Math]::Max(20, (Get-Width) - 1)
    $screenH = [Math]::Max(6, (Get-Height) - 1)
    $label   = "${BD}Search:${R} "
    $body = @(
        "${BD}${MG}ARTCA${R}  ${DM}$BaseUrl${R}",
        '',
        "${DM}Examples:  *.env   *.properties   myapp   secret.xml${R}",
        '',
        $label
    )
    # Inner width: widest line, with headroom to type, capped to the screen. Lines wider
    # than the cap (e.g. a long base URL) are truncated so nothing overruns the border.
    $innerW = 44
    foreach ($l in $body) { $innerW = [Math]::Max($innerW, (Vis-Len $l)) }
    $innerW = [Math]::Min($innerW, $w - 8)
    $body   = @($body | ForEach-Object { if ((Vis-Len $_) -gt $innerW) { Fit-Vis $_ $innerW } else { $_ } })
    $boxW   = $innerW + 4
    $atCol  = [Math]::Max(0, [int](($w - $boxW) / 2))
    $boxH   = $body.Count + 2
    $top    = [Math]::Max(0, [int](($screenH - $boxH) / 2))

    $tl=[char]0x250C; $tr=[char]0x2510; $bl=[char]0x2514; $br=[char]0x2518; $hz=[char]0x2500; $vt=[char]0x2502
    $box = [Collections.Generic.List[string]]::new()
    $box.Add("${MG}$tl$([string]$hz * ($boxW - 2))$tr${R}")
    foreach ($l in $body) {
        $pad = [Math]::Max(0, $innerW - (Vis-Len $l))
        $box.Add("${MG}$vt${R} $l$(' ' * $pad) ${MG}$vt${R}")
    }
    $box.Add("${MG}$bl$([string]$hz * ($boxW - 2))$br${R}")

    # Compose the box onto a blank, full-height screen so it sits centred.
    $out = [Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $screenH; $i++) {
        $rr = $i - $top
        if ($rr -ge 0 -and $rr -lt $box.Count) { $out.Add((' ' * $atCol) + $box[$rr]) } else { $out.Add('') }
    }
    Show-Frame $out.ToArray()

    # Park the cursor just past the "Search:" label inside the box (ANSI is 1-based) and
    # read the line there so the typed query appears in the box.
    $rowAbs = $top + 1 + ($body.Count - 1)        # +1 skips the top border
    $colAbs = $atCol + 2 + (Vis-Len $label)       # border + space + label
    [Console]::Out.Write("$([char]27)[$($rowAbs + 1);$($colAbs + 1)H${BD}${CY}")
    $q = Read-LineEdit ''
    Write-Host -NoNewline $R
    return $q.Trim()
}

# Full-screen prompt to edit the results exclude filter; the field is prefilled with
# the current terms so they can be tweaked. Returns the entered string (blank clears).
function Read-ExcludeFilter([string]$current) {
    Clear-Screen
    Write-Host "  ${BD}${MG}ARTCA${R}  ${DM}Exclude filter${R}`n"
    Write-Host "  ${DM}Space/comma-separated name globs to EXCLUDE (matches are dimmed${R}"
    Write-Host "  ${DM}and sent to the back).  e.g.  *.sha1   *.pom   *sources*    (clear = no filter)${R}`n"
    if (-not $script:CanRawKey -and $current) { Write-Host "  ${DM}Current:${R} $current`n" }
    Write-Host -NoNewline "  Exclude: ${BD}${CY}"
    $s = Read-LineEdit $current
    Write-Host -NoNewline $R
    return $s
}

# The first digit was already captured (no-echo); echo it, then read the rest.
function Read-ItemNumber([string]$first) {
    Write-Host -NoNewline "`n  ${BD}${CY}View item #${R} $first"
    $rest = Read-Host
    $s = ("$first" + "$rest").Trim()
    $n = 0
    if ([int]::TryParse($s, [ref]$n)) { return $n }
    return $null
}

# Prompt for a 1-based page number; return the 0-based index, or $null if the
# input is blank or out of range.
function Read-PageNumber([int]$TotalPages) {
    Write-Host -NoNewline "`n  ${BD}${CY}Go to page${R} ${DM}(1-$TotalPages):${R} "
    $s = (Read-Host).Trim()
    $n = 0
    if ([int]::TryParse($s, [ref]$n) -and $n -ge 1 -and $n -le $TotalPages) { return $n - 1 }
    return $null
}

