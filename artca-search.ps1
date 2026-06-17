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
    switch ([int]$k.VirtualKeyCode) {
        37 { 'left' }    38 { 'up' }      39 { 'right' }  40 { 'down' }
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
        $k = Read-KeyNow            # non-blocking; drains key-up events
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

function Format-Size([object]$bytes) {
    if ($null -eq $bytes -or "$bytes" -eq '') { return '' }
    $b = [double]$bytes
    if ($b -lt 0) { return '' }
    $units = 'B','KB','MB','GB','TB','PB'
    $i = 0
    while ($b -ge 1024 -and $i -lt $units.Count - 1) { $b /= 1024; $i++ }
    if ($i -eq 0) { return "$([int]$b) B" }
    return ('{0:0.0} {1}' -f $b, $units[$i])
}

function Get-Ext([string]$name) {
    $dot = $name.LastIndexOf('.')
    if ($dot -gt 0 -and $dot -lt $name.Length - 1) { return $name.Substring($dot + 1) }
    return ''
}

# ── VISITED + PREVIEW STATE ───────────────────────────────────────────────────
# Items the user has opened/viewed/downloaded (keys: storage uri or download url),
# rendered washed-out afterwards. Preview content is cached in memory by download
# url so a later download reuses it instead of re-fetching.
$script:Visited      = New-Object 'System.Collections.Generic.HashSet[string]'
$script:MemFiles     = @{}                                              # url -> [byte[]]
$script:PreviewOK    = New-Object 'System.Collections.Generic.HashSet[string]'  # large files user opted to preview
$script:PreviewLimit = 512000                                           # 0.5 MB preview cap

# Sentinel emitted by Get-PreviewLines in place of the preview's horizontal rule.
# Two-pane compositors recognise it and draw a rule that joins the vertical pane
# separator with a T-junction (instead of a bare dash row floating beside it).
# NUL-wrapped so it can never collide with real content.
$script:PaneRuleTag = "$([char]0)PANE_RULE$([char]0)"

# Sentinel placed in the LEFT pane (after the column header) to request a header
# divider that joins the vertical pane separator from the left with a ┤. Mirror of
# $PaneRuleTag for the opposite pane; NUL-wrapped for the same reason.
$script:HeaderRuleTag = "$([char]0)HDR_RULE$([char]0)"

function Mark-Visited([string]$key) { if ($key) { [void]$script:Visited.Add($key) } }
function Test-Visited([string]$key) { return ($key -and $script:Visited.Contains($key)) }

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

# Constructed download URL for a search item (repo/path/name under the REST base).
function Get-ItemUrl($item) {
    $repo = if ($item.Repo) { $item.Repo } else { '' }
    $seg  = if ($item.Path) { "$($item.Path)/" } else { '' }
    return "$(Get-ArtBase)/$repo/$seg$($item.Name)"
}

# Extensions we treat as human-readable text (previewable).
$script:TextExts = @(
    'txt','text','log','md','markdown','rst','adoc','asciidoc','me','readme','nfo',
    'html','htm','xhtml','xml','xsl','xslt','svg','rss','atom','wsdl','plist',
    'json','json5','jsonl','ndjson','yaml','yml','toml','ini','cfg','conf','config',
    'properties','props','env','editorconfig','gitignore','gitattributes','dockerignore',
    'csv','tsv','tab',
    'cmd','bat','ps1','psm1','psd1','sh','bash','zsh','fish','ksh','command',
    'py','pyw','rb','pl','pm','php','phtml','tcl','lua','r','jl','groovy','gradle',
    'js','mjs','cjs','jsx','ts','tsx','vue','svelte','coffee',
    'css','scss','sass','less','styl',
    'java','kt','kts','scala','clj','cljs','cljc','edn','go','rs','swift','m','mm',
    'c','h','cc','cpp','cxx','hpp','hh','hxx','cs','fs','fsx','vb','d','dart','nim','zig',
    'ex','exs','erl','hrl','hs','lhs','ml','mli','elm','rkt','scm','lisp','el',
    'sql','graphql','gql','proto','thrift','avsc',
    'tf','tfvars','hcl','bicep','tpl','jinja','j2','mustache','hbs','ejs','erb','haml','slim',
    'make','mk','mak','cmake','am','in','spec','rake','gemspec','podspec','cabal',
    'asm','s','vhd','vhdl','v','sv','verilog',
    'tex','bib','sty','cls','rtf','org','textile','wiki','pod',
    'srt','vtt','sub','ass','ssa','lrc','cue','m3u','m3u8','pls',
    'diff','patch','reg','desktop','service','manifest','mf','sf','classpath','project',
    'pom','sbt','lock','sum','mod','gradle','npmrc','yarnrc','babelrc','eslintrc',
    'prettierrc','dockerfile','procfile','makefile','jenkinsfile','vagrantfile','gemfile'
)

function Get-IsPreviewable([string]$name) {
    $ext = (Get-Ext $name).ToLower()
    if ($ext -and ($script:TextExts -contains $ext)) { return $true }
    # Extensionless but well-known text filenames.
    $bare = $name.ToLower()
    return @('dockerfile','makefile','jenkinsfile','vagrantfile','procfile','gemfile',
             'license','readme','changelog','authors','notice','copying','install',
             'manifest','rakefile','gemfile.lock') -contains $bare
}

# Fetch raw bytes for a url (no caching). $null on failure.
function Get-FileBytes([string]$url) {
    $old = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'
    try {
        $resp = Invoke-WebRequest -Uri $url -Headers (Get-AuthHeaders) -UseBasicParsing -ErrorAction Stop
        if ($resp.RawContentStream) { return $resp.RawContentStream.ToArray() }
        if ($resp.Content -is [byte[]]) { return [byte[]]$resp.Content }
        return [Text.Encoding]::UTF8.GetBytes([string]$resp.Content)
    } catch { return $null }
    finally { $ProgressPreference = $old }
}


# Decode bytes to text (UTF-8, BOM-aware).
function Convert-BytesToText([byte[]]$bytes) {
    if ($null -eq $bytes -or $bytes.Length -eq 0) { return '' }
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        return [Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3)
    }
    return [Text.Encoding]::UTF8.GetString($bytes)
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

# Build the preview-section lines for a file: a "Preview" header then either the
# wrapped contents, or a message (not previewable / large / failed). $sizeBytes is
# -1 when unknown. Honours the size cap unless the url is in $PreviewOK.
# The leading divider is emitted as $PaneRuleTag so the two-pane compositor can
# connect it to the pane separator (see Format-PaneRule).
function Get-PreviewLines([string]$name, [string]$url, [long]$sizeBytes, [int]$paneW, [int]$maxLines) {
    $L = [Collections.Generic.List[string]]::new()
    $L.Add($script:PaneRuleTag)
    $L.Add("${BD}${YL}Preview${R}")
    if (-not (Get-IsPreviewable $name)) {
        $L.Add("${DM}This file format can't be previewed.${R}")
        return $L.ToArray()
    }
    $tooBig = ($sizeBytes -gt $script:PreviewLimit) -or ($sizeBytes -lt 0)
    if ($tooBig -and -not $script:PreviewOK.Contains($url)) {
        $szTxt = if ($sizeBytes -ge 0) { Format-Size $sizeBytes } else { 'unknown size' }
        $L.Add("${YL}Large file ($szTxt).${R}")
        $L.Add("${DM}Press [y] to preview it anyway.${R}")
        return $L.ToArray()
    }
    # Contents come from the background preview cache (warmed by the nav loop); the
    # pane shows a loading line until the fetch lands, never blocking input.
    $key = Get-FilePreviewKey $url
    if (-not $script:PreviewCache.ContainsKey($key)) {
        $L.Add("${DM}Loading preview...${R}"); return $L.ToArray()
    }
    $res = $script:PreviewCache[$key]
    if (-not $res.Ok) { $L.Add("${RD}$($res.Error)${R}"); return $L.ToArray() }
    $bytes = $res.Bytes
    if ($null -eq $bytes) { $L.Add("${RD}Could not load file for preview.${R}"); return $L.ToArray() }
    # Seed the byte cache so a later download of this file reuses the fetch.
    if (-not $script:MemFiles.ContainsKey($url)) { $script:MemFiles[$url] = $bytes }
    $text  = Convert-BytesToText $bytes
    $wrapped = Wrap-Text $text $paneW
    $shown = [Math]::Min($wrapped.Count, [Math]::Max(1, $maxLines))
    for ($i = 0; $i -lt $shown; $i++) { $L.Add($wrapped[$i]) }
    if ($wrapped.Count -gt $shown) { $L.Add("${DM}$script:Cut ($($wrapped.Count - $shown) more lines)${R}") }
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
function Get-ArchivePreviewLines($item, [int]$paneW, [int]$maxLines) {
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
    $cap  = [Math]::Max(1, $maxLines)
    $rows = [Collections.Generic.List[string]]::new()
    Add-ArcListingLines @($tree.Nodes) '' $rows $paneW ($cap + 1)
    if ($rows.Count -eq 0) { $L.Add("${DM}(empty archive)${R}"); return $L.ToArray() }
    $shown = [Math]::Min($rows.Count, $cap)
    for ($i = 0; $i -lt $shown; $i++) { $L.Add($rows[$i]) }
    if ($rows.Count -gt $shown) { $L.Add("${DM}$script:Cut ($($rows.Count - $shown) more)${R}") }
    return $L.ToArray()
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

# Turn a caught web-request ErrorRecord into a readable message. Artifactory
# returns a JSON body like {"errors":[{"status":404,"message":"..."}]} that
# explains *why* (e.g. a repo is blacked out) — far more useful than the bare
# "(404) Not Found" in the exception. We read the response body and prefer its
# message(s), falling back to the raw body, then the exception text.
function Get-HttpErrorDetail($err) {
    $ex   = $err.Exception
    $code = 0
    try { if ($ex.Response) { $code = [int]$ex.Response.StatusCode } } catch { }
    $body = ''
    try {
        if ($ex.Response) {
            $body = [System.IO.StreamReader]::new($ex.Response.GetResponseStream()).ReadToEnd()
        }
    } catch { }
    $msg = ''
    if ($body) {
        try {
            $j = $body | ConvertFrom-Json
            if ($j.PSObject.Properties['errors'] -and $j.errors) {
                $msg = (@($j.errors | ForEach-Object { "$($_.message)" }) -join '; ')
            } elseif ($j.PSObject.Properties['message']) {
                $msg = "$($j.message)"
            }
        } catch { }
        if (-not $msg) { $msg = $body.Trim() }
    }
    if (-not $msg) { $msg = $ex.Message }
    if ($code -gt 0) { return "HTTP $code - $msg" }
    return $msg
}

# ── AUTH ──────────────────────────────────────────────────────────────────────

function Get-AuthHeaders {
    $h = @{}
    if     ($ApiKey) { $h['X-JFrog-Art-Api'] = $ApiKey }
    elseif ($Token)  { $h['Authorization']   = "Bearer $Token" }
    elseif ($Basic)  {
        $bytes = [Text.Encoding]::ASCII.GetBytes($Basic)
        $h['Authorization'] = "Basic $([Convert]::ToBase64String($bytes))"
    }
    return $h
}

# Build the artifactory REST base, tolerating URLs that already include /artifactory.
function Get-ArtBase {
    if ($BaseUrl -match '/artifactory/?$') { return $BaseUrl.TrimEnd('/') }
    return "$BaseUrl/artifactory"
}

# ── REPO METADATA ─────────────────────────────────────────────────────────────
# /api/repositories gives rclass (LOCAL/REMOTE/VIRTUAL) + packageType per repo.
# Fetched once; remote-cache repos (<key>-cache) inherit from their base repo.

$script:RepoMap       = @{}
$script:RepoMapLoaded = $false
$script:MetaCache     = [hashtable]::Synchronized(@{})   # written by background prefetch threads

# ── RATE-LIMIT / PARTIAL-RESULT DETECTION ─────────────────────────────────────
# We don't throttle; we just watch for trouble and tell the user. $Alert is a
# notice surfaced in the UI: set by any worker on HTTP 429/503, and by the search
# when it returns far fewer results than we've previously seen for the same query.
# $QueryMax remembers the largest result count seen per query this session — the
# baseline for the partial-result heuristic. ($Alert is synchronized because the
# background workers write to it from other threads.)
$script:Alert    = [hashtable]::Synchronized(@{ Message = ''; At = [DateTime]::MinValue })
$script:QueryMax = @{}

# $Flash is a transient, neutral one-shot notice shown on the results page (e.g.
# a download confirmation after returning from the item view). Main-thread only.
$script:Flash = @{ Message = ''; At = [DateTime]::MinValue }

function Initialize-RepoMap {
    if ($script:RepoMapLoaded) { return }
    $script:RepoMapLoaded = $true   # only attempt once, even if it fails
    $script:RepoMap = @{}
    try {
        $repos = Invoke-RestMethod -Uri "$(Get-ArtBase)/api/repositories" `
                     -Headers (Get-AuthHeaders) -ErrorAction Stop
        foreach ($r in $repos) {
            $script:RepoMap[$r.key] = [PSCustomObject]@{
                Type        = "$($r.type)"
                PackageType = "$($r.packageType)"
            }
        }
    } catch { }   # anonymous instances may deny this; columns degrade to '?'
}

function Resolve-Repo([string]$repo) {
    if ($script:RepoMap.ContainsKey($repo)) { return $script:RepoMap[$repo] }
    if ($repo -match '^(.*)-cache$' -and $script:RepoMap.ContainsKey($Matches[1])) {
        $base = $script:RepoMap[$Matches[1]]
        return [PSCustomObject]@{ Type = 'CACHE'; PackageType = $base.PackageType }
    }
    return [PSCustomObject]@{ Type = '?'; PackageType = '?' }
}

# Copy any already-cached size/modified onto the items for display. This never
# touches the network — fetching is done entirely by the background prefetch
# pool below, so rows simply populate as their entries land in the cache.
# Cheap; safe to call on every redraw.
function Apply-Meta([object[]]$Items) {
    if ($null -eq $Items) { return }
    foreach ($it in $Items) {
        if ($it -and $script:MetaCache.ContainsKey($it.Uri)) {
            $m = $script:MetaCache[$it.Uri]
            $it.Size = $m.Size; $it.Modified = $m.Modified
        }
    }
}

# How many of these items don't yet have cached detail.
function Get-MissingMeta([object[]]$Items) {
    if ($null -eq $Items) { return 0 }
    @($Items | Where-Object { $_ -and -not $script:MetaCache.ContainsKey($_.Uri) }).Count
}

# How many items are still genuinely in flight (uncached but queued in the
# pool). Used to decide whether to keep polling for fill-in: once nothing is
# in flight, a still-missing row is a failed/denied fetch, so we stop waiting
# rather than spin forever.
function Get-LoadingMeta([object[]]$Items) {
    if ($null -eq $Items) { return 0 }
    @($Items | Where-Object {
        $_ -and -not $script:MetaCache.ContainsKey($_.Uri) -and $script:PfQueued.ContainsKey($_.Uri)
    }).Count
}

# Block (up to $TimeoutMs) until every item has cached detail, retrying any
# straggler that isn't in flight. Used only on hosts without a real key buffer
# (ISE), where the non-blocking fill-in poll can't run; the items must already
# have been queued by the caller. Applies the results before returning.
function Wait-Meta([object[]]$Items, [int]$TimeoutMs) {
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    while ((Get-MissingMeta $Items) -gt 0 -and [DateTime]::UtcNow -lt $deadline) {
        Receive-Prefetch
        if ((Get-LoadingMeta $Items) -eq 0) { Start-Prefetch $Items }   # retry stragglers
        Start-Sleep -Milliseconds 60
    }
    Apply-Meta $Items
}

# ── BACKGROUND PREFETCH ───────────────────────────────────────────────────────
# Warm the cache for upcoming pages without blocking input: jobs run on a shared
# pool and write straight into the synchronized cache. The main loop never waits
# on them — by the time the user pages forward the entries are usually ready.

$script:PfPool   = $null
$script:PfJobs   = [Collections.Generic.List[object]]::new()
$script:PfQueued = @{}   # uris currently in flight (main-thread only)

$script:PfScript = {
    param($uri, $headers, $cache, $alert)
    try {
        $info = Invoke-RestMethod -Uri $uri -Headers $headers -ErrorAction Stop
        $m = [PSCustomObject]@{ Size = ''; Modified = '' }
        if ($info.PSObject.Properties['size'])         { $m.Size     = $info.size }
        if ($info.PSObject.Properties['lastModified']) { $m.Modified = "$($info.lastModified)" }
        $cache[$uri] = $m
    } catch {
        $code = 0
        try { if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode } } catch { }
        if ($code -eq 429 -or $code -eq 503) {
            $alert.Message = "Server rate-limited a details request (HTTP $code) - some details may be missing."
            $alert.At      = [DateTime]::UtcNow
        }
    }
}

# Dispose finished jobs and free their in-flight slots (only touches completed
# handles, so it never blocks on a running fetch).
function Receive-Prefetch {
    if ($script:PfJobs.Count -eq 0) { return }
    $still = [Collections.Generic.List[object]]::new()
    foreach ($j in $script:PfJobs) {
        if ($j.Handle.IsCompleted) {
            try { [void]$j.PS.EndInvoke($j.Handle) } catch { }
            try { $j.PS.Dispose() } catch { }
            $script:PfQueued.Remove($j.Uri)
        } else {
            $still.Add($j)
        }
    }
    $script:PfJobs = $still
}

# Cancel any in-flight / queued prefetch whose uri isn't in $Keep. The pool is
# FIFO, so when the user skims far ahead the requests for pages they've left
# would otherwise hog the workers and starve the page they're actually on. We
# drop that stale work (aborting mid-flight is fine — it just frees a slot) so
# the next Start-Prefetch for the current page goes straight to the front.
# Already-cached results are untouched; only pending fetches are discarded.
function Restrict-Prefetch([hashtable]$Keep) {
    if ($script:PfJobs.Count -eq 0) { return }
    $still = [Collections.Generic.List[object]]::new()
    foreach ($j in $script:PfJobs) {
        if ($Keep.ContainsKey($j.Uri)) { $still.Add($j); continue }
        try { [void]$j.PS.Stop() } catch { }
        try { $j.PS.Dispose() }    catch { }
        $script:PfQueued.Remove($j.Uri)
    }
    $script:PfJobs = $still
}

function Start-Prefetch([object[]]$Items) {
    if ($null -eq $Items) { return }
    Receive-Prefetch
    $headers = Get-AuthHeaders
    foreach ($it in $Items) {
        if (-not $it) { continue }
        $u = $it.Uri
        if ($script:MetaCache.ContainsKey($u) -or $script:PfQueued.ContainsKey($u)) { continue }
        if ($null -eq $script:PfPool) {
            $script:PfPool = [RunspaceFactory]::CreateRunspacePool(1, 10)
            $script:PfPool.Open()
        }
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $script:PfPool
        [void]$ps.AddScript($script:PfScript).AddArgument($u).AddArgument($headers).AddArgument($script:MetaCache).AddArgument($script:Alert)
        $script:PfJobs.Add([PSCustomObject]@{ PS = $ps; Handle = $ps.BeginInvoke(); Uri = $u })
        $script:PfQueued[$u] = $true
    }
}

# ── THROTTLED LOOKAHEAD ───────────────────────────────────────────────────────
# After the burst, keep trickling the pages beyond it one request at a time at a
# gentle rate. This is a single self-pacing background runspace: it
# walks the uris sequentially, sleeps between fetches, and bails when the shared
# cancel flag is set. The main loop supersedes it (cancel + relaunch) whenever
# the current page changes, so only one trickle runs at a time.

$script:LaPS     = $null
$script:LaHandle = $null
$script:LaCancel = $null
$script:LaReap   = [Collections.Generic.List[object]]::new()

$script:LaScript = {
    param($uris, $headers, $cache, $cancel, $throttleMs, $alert)
    foreach ($u in $uris) {
        if ($cancel.stop) { break }
        if (-not $cache.ContainsKey($u)) {
            try {
                $info = Invoke-RestMethod -Uri $u -Headers $headers -ErrorAction Stop
                $m = [PSCustomObject]@{ Size = ''; Modified = '' }
                if ($info.PSObject.Properties['size'])         { $m.Size     = $info.size }
                if ($info.PSObject.Properties['lastModified']) { $m.Modified = "$($info.lastModified)" }
                $cache[$u] = $m
            } catch {
                $code = 0
                try { if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode } } catch { }
                if ($code -eq 429 -or $code -eq 503) {
                    $alert.Message = "Server rate-limited a details request (HTTP $code) - some details may be missing."
                    $alert.At      = [DateTime]::UtcNow
                }
            }
            Start-Sleep -Milliseconds $throttleMs
        }
    }
}

function Receive-Lookahead {
    if ($script:LaReap.Count -eq 0) { return }
    $still = [Collections.Generic.List[object]]::new()
    foreach ($j in $script:LaReap) {
        if ($j.Handle.IsCompleted) {
            try { [void]$j.PS.EndInvoke($j.Handle) } catch { }
            try { $j.PS.Dispose() } catch { }
        } else { $still.Add($j) }
    }
    $script:LaReap = $still
}

function Stop-Lookahead {
    if ($script:LaCancel) { $script:LaCancel.stop = $true }   # signal; don't block
    if ($script:LaPS) {
        $script:LaReap.Add([PSCustomObject]@{ PS = $script:LaPS; Handle = $script:LaHandle })
    }
    $script:LaPS = $null; $script:LaHandle = $null; $script:LaCancel = $null
    Receive-Lookahead
}

function Start-Lookahead([object[]]$Items) {
    Stop-Lookahead   # supersede any in-flight trickle
    if ($null -eq $Items) { return }
    $uris = @($Items | Where-Object { $_ -and -not $script:MetaCache.ContainsKey($_.Uri) } |
              ForEach-Object { $_.Uri })
    if ($uris.Count -eq 0) { return }

    $cancel = [hashtable]::Synchronized(@{ stop = $false })
    $ps     = [PowerShell]::Create()
    [void]$ps.AddScript($script:LaScript).
        AddArgument($uris).AddArgument((Get-AuthHeaders)).
        AddArgument($script:MetaCache).AddArgument($cancel).AddArgument(150).
        AddArgument($script:Alert)
    $script:LaCancel = $cancel
    $script:LaPS     = $ps
    $script:LaHandle = $ps.BeginInvoke()
}

# ── BACKGROUND PREVIEW PREFETCH ───────────────────────────────────────────────
# Previews (a file's text, or an archive's entry listing) used to be fetched
# synchronously the moment a row was highlighted, so every cursor move blocked on
# the network. Instead we warm them on a small runspace pool that writes into a
# synchronized cache; the preview pane shows "Loading..." until the entry lands,
# and the main loop keeps taking keystrokes the whole time. Mirrors the metadata
# prefetch system above. Cache keys are kind-prefixed ("F|<url>" for a file,
# "A|<uri>" for an archive) so the one cache serves both render paths.
$script:PreviewCache = [hashtable]::Synchronized(@{})   # key -> result (bg-written)
$script:PvPool   = $null
$script:PvJobs   = [Collections.Generic.List[object]]::new()
$script:PvQueued = @{}   # keys in flight (main-thread only)

function Get-FilePreviewKey([string]$url) { "F|$url" }
function Get-ArcPreviewKey([string]$uri)  { "A|$uri" }

# Shared error-extraction, injected into every background worker (runspaces can't
# see our functions). Pulls a useful message off a failed web request: the HTTP
# status plus the server's own error body — so a blacked-out-repo 404 surfaces as
# "HTTP 404 - The repository '...' is blacked out..." rather than a generic line.
$script:PvErrFn = @'
function Get-WkError($e) {
    $code = 0
    try { if ($e.Exception.Response) { $code = [int]$e.Exception.Response.StatusCode } } catch { }
    # The server's response body: $e.ErrorDetails.Message holds it for failed web
    # cmdlets (reliable even after the cmdlet consumed the stream); fall back to
    # reading the response stream directly.
    $bd = ''
    try { if ($e.ErrorDetails -and $e.ErrorDetails.Message) { $bd = "$($e.ErrorDetails.Message)" } } catch { }
    if (-not $bd) {
        try { if ($e.Exception.Response) { $bd = [System.IO.StreamReader]::new($e.Exception.Response.GetResponseStream()).ReadToEnd() } } catch { }
    }
    $detail = ''
    if ($bd) {
        try {
            $j = $bd | ConvertFrom-Json
            if ($j.PSObject.Properties['errors'] -and $j.errors) { $detail = (@($j.errors | ForEach-Object { "$($_.message)" }) -join '; ') }
            elseif ($j.PSObject.Properties['message']) { $detail = "$($j.message)" }
        } catch { $detail = $bd.Trim() }
    }
    $msg = if ($detail -and $code -gt 0) { "HTTP $code - $detail" }
           elseif ($detail)             { $detail }
           elseif ($code -gt 0)         { "HTTP $code" }
           else                         { '' }
    return [PSCustomObject]@{ Code = $code; Message = $msg }
}

'@

# File preview worker: fetch raw bytes; decoding/wrapping stays on the main thread.
# Get-WkError is injected ahead of this body by Start-PreviewPrefetch (a separate
# AddScript) so $PvErrFn isn't duplicated and param() can stay first here.
$script:PvFileScript = {
    param($key, $url, $headers, $cache, $alert)
    $old = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'
    try {
        $resp = Invoke-WebRequest -Uri $url -Headers $headers -UseBasicParsing -ErrorAction Stop
        $bytes = if ($resp.RawContentStream) { $resp.RawContentStream.ToArray() }
                 elseif ($resp.Content -is [byte[]]) { [byte[]]$resp.Content }
                 else { [Text.Encoding]::UTF8.GetBytes([string]$resp.Content) }
        $cache[$key] = [PSCustomObject]@{ Ok = $true; Bytes = $bytes; Nodes = $null; Error = '' }
    } catch {
        $we = Get-WkError $_
        if ($we.Code -eq 429 -or $we.Code -eq 503) { $alert.Message = "Server rate-limited a preview request (HTTP $($we.Code))."; $alert.At = [DateTime]::UtcNow }
        $err = if ($we.Message) { $we.Message } else { "Could not load file for preview." }
        $cache[$key] = [PSCustomObject]@{ Ok = $false; Bytes = $null; Nodes = $null; Error = $err }
    } finally { $ProgressPreference = $old }
}

# Archive preview worker: POST the tree-browser request, store the top-level nodes.
$script:PvArcScript = {
    param($key, $uri, $body, $headers, $ua, $cache, $alert)
    try {
        $resp = Invoke-RestMethod -Uri $uri -Method Post -Body $body `
                    -ContentType 'application/json' -Headers $headers -UserAgent $ua -ErrorAction Stop
        $data = if ($resp.PSObject.Properties['data'] -and $resp.data) { @(@($resp.data) | Where-Object { $null -ne $_ }) } else { @() }
        $cache[$key] = [PSCustomObject]@{ Ok = $true; Bytes = $null; Nodes = $data; Error = '' }
    } catch {
        $we = Get-WkError $_
        if ($we.Code -eq 429 -or $we.Code -eq 503) { $alert.Message = "Server rate-limited a preview request (HTTP $($we.Code))."; $alert.At = [DateTime]::UtcNow }
        $err = if ($we.Message) { $we.Message } else { "Could not read archive." }
        $cache[$key] = [PSCustomObject]@{ Ok = $false; Bytes = $null; Nodes = $null; Error = $err }
    }
}

# Reap finished preview jobs, freeing their in-flight slots (completed handles only).
function Receive-PreviewPrefetch {
    if ($script:PvJobs.Count -eq 0) { return }
    $still = [Collections.Generic.List[object]]::new()
    foreach ($j in $script:PvJobs) {
        if ($j.Handle.IsCompleted) {
            try { [void]$j.PS.EndInvoke($j.Handle) } catch { }
            try { $j.PS.Dispose() } catch { }
            $script:PvQueued.Remove($j.Key)
        } else { $still.Add($j) }
    }
    $script:PvJobs = $still
}

# Cancel any in-flight preview fetch whose key isn't in $Keep, so a fast skim
# doesn't leave stale neighbour fetches starving the row the user lands on.
function Restrict-PreviewPrefetch([hashtable]$Keep) {
    if ($script:PvJobs.Count -eq 0) { return }
    $still = [Collections.Generic.List[object]]::new()
    foreach ($j in $script:PvJobs) {
        if ($Keep.ContainsKey($j.Key)) { $still.Add($j); continue }
        try { [void]$j.PS.Stop() } catch { }
        try { $j.PS.Dispose() }    catch { }
        $script:PvQueued.Remove($j.Key)
    }
    $script:PvJobs = $still
}

# Queue preview fetches for a list of request descriptors (see Get-ItemPreviewRequest
# / Get-NodePreviewRequest). Already-cached or in-flight keys are skipped; $null
# entries (nothing to preview) are ignored. Requests are queued in the order given,
# so callers put the highlighted row first.
function Start-PreviewPrefetch($Requests) {
    if ($null -eq $Requests) { return }
    Receive-PreviewPrefetch
    foreach ($rq in $Requests) {
        if (-not $rq) { continue }
        $k = $rq.Key
        if ($script:PreviewCache.ContainsKey($k) -or $script:PvQueued.ContainsKey($k)) { continue }
        if ($null -eq $script:PvPool) {
            $script:PvPool = [RunspaceFactory]::CreateRunspacePool(1, 6)
            $script:PvPool.Open()
        }
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $script:PvPool
        [void]$ps.AddScript($script:PvErrFn)   # define Get-WkError in the worker scope
        if ($rq.Kind -eq 'file') {
            [void]$ps.AddScript($script:PvFileScript).AddArgument($k).AddArgument($rq.Url).
                AddArgument($rq.Headers).AddArgument($script:PreviewCache).AddArgument($script:Alert)
        } else {
            [void]$ps.AddScript($script:PvArcScript).AddArgument($k).AddArgument($rq.Uri).AddArgument($rq.Body).
                AddArgument($rq.Headers).AddArgument($rq.Ua).AddArgument($script:PreviewCache).AddArgument($script:Alert)
        }
        $script:PvJobs.Add([PSCustomObject]@{ PS = $ps; Handle = $ps.BeginInvoke(); Key = $k })
        $script:PvQueued[$k] = $true
    }
}

# True if $key names a preview that's loadable but not yet resolved (in flight or
# still to be queued) — i.e. the pane should show "Loading...".
function Test-PreviewLoading([string]$key) {
    return ($key -and -not $script:PreviewCache.ContainsKey($key))
}

# Count of these keys still loading / still in flight, used to decide whether to
# keep polling.
function Get-PreviewLoadingCount([string[]]$keys) {
    if ($null -eq $keys) { return 0 }
    @($keys | Where-Object { $_ -and $script:PvQueued.ContainsKey($_) -and -not $script:PreviewCache.ContainsKey($_) }).Count
}

# Count of these keys already resolved (cached), used to detect fill-in progress.
function Get-PreviewLoadedCount([string[]]$keys) {
    if ($null -eq $keys) { return 0 }
    @($keys | Where-Object { $_ -and $script:PreviewCache.ContainsKey($_) }).Count
}

# Count of these keys not yet resolved (loading or still to be trickled).
function Get-PreviewPendingCount([string[]]$keys) {
    if ($null -eq $keys) { return 0 }
    @($keys | Where-Object { $_ -and -not $script:PreviewCache.ContainsKey($_) }).Count
}

# Block (up to $TimeoutMs) for a single key to resolve. Used on ISE / non-console
# hosts where the live poll can't run; the caller must have queued it first.
function Wait-Preview([string]$key, [int]$TimeoutMs) {
    if (-not $key) { return }
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    while (-not $script:PreviewCache.ContainsKey($key) -and [DateTime]::UtcNow -lt $deadline) {
        Receive-PreviewPrefetch
        Start-Sleep -Milliseconds 60
    }
}

# ── THROTTLED PREVIEW LOOKAHEAD ───────────────────────────────────────────────
# After the fast window (the highlighted row + its nearest neighbours, warmed at
# full concurrency by the pool), the *rest* of the page's previews are trickled in
# one at a time at a gentle rate by a single self-pacing runspace — nearest-first,
# until the whole page is warm. Mirrors Start-Lookahead for metadata. Superseded
# (cancelled + relaunched) whenever the selection moves, so the trickle always
# fans out from where the cursor actually is.
$script:PvLaPS     = $null
$script:PvLaHandle = $null
$script:PvLaCancel = $null
$script:PvLaReap   = [Collections.Generic.List[object]]::new()

$script:PvLaScript = {
    param($reqs, $cache, $cancel, $throttleMs, $alert)
    foreach ($rq in $reqs) {
        if ($cancel.stop) { break }
        $k = $rq.Key
        if ($cache.ContainsKey($k)) { continue }
        try {
            if ($rq.Kind -eq 'file') {
                $old = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'
                try {
                    $resp  = Invoke-WebRequest -Uri $rq.Url -Headers $rq.Headers -UseBasicParsing -ErrorAction Stop
                    $bytes = if ($resp.RawContentStream) { $resp.RawContentStream.ToArray() }
                             elseif ($resp.Content -is [byte[]]) { [byte[]]$resp.Content }
                             else { [Text.Encoding]::UTF8.GetBytes([string]$resp.Content) }
                    $cache[$k] = [PSCustomObject]@{ Ok = $true; Bytes = $bytes; Nodes = $null; Error = '' }
                } finally { $ProgressPreference = $old }
            } else {
                $resp = Invoke-RestMethod -Uri $rq.Uri -Method Post -Body $rq.Body `
                            -ContentType 'application/json' -Headers $rq.Headers -UserAgent $rq.Ua -ErrorAction Stop
                $data = if ($resp.PSObject.Properties['data'] -and $resp.data) { @(@($resp.data) | Where-Object { $null -ne $_ }) } else { @() }
                $cache[$k] = [PSCustomObject]@{ Ok = $true; Bytes = $null; Nodes = $data; Error = '' }
            }
        } catch {
            $we = Get-WkError $_
            if ($we.Code -eq 429 -or $we.Code -eq 503) { $alert.Message = "Server rate-limited a preview request (HTTP $($we.Code))."; $alert.At = [DateTime]::UtcNow }
            $err = if ($we.Message) { $we.Message } elseif ($rq.Kind -eq 'file') { "Could not load file for preview." } else { "Could not read archive." }
            $cache[$k] = [PSCustomObject]@{ Ok = $false; Bytes = $null; Nodes = $null; Error = $err }
        }
        if (-not $cancel.stop) { Start-Sleep -Milliseconds $throttleMs }
    }
}

function Receive-PreviewLookahead {
    if ($script:PvLaReap.Count -eq 0) { return }
    $still = [Collections.Generic.List[object]]::new()
    foreach ($j in $script:PvLaReap) {
        if ($j.Handle.IsCompleted) {
            try { [void]$j.PS.EndInvoke($j.Handle) } catch { }
            try { $j.PS.Dispose() } catch { }
        } else { $still.Add($j) }
    }
    $script:PvLaReap = $still
}

function Stop-PreviewLookahead {
    if ($script:PvLaCancel) { $script:PvLaCancel.stop = $true }   # signal; don't block
    if ($script:PvLaPS) {
        $script:PvLaReap.Add([PSCustomObject]@{ PS = $script:PvLaPS; Handle = $script:PvLaHandle })
    }
    $script:PvLaPS = $null; $script:PvLaHandle = $null; $script:PvLaCancel = $null
    Receive-PreviewLookahead
}

# True while the trickle runspace is still running.
function Test-PreviewLookaheadAlive {
    return ($null -ne $script:PvLaHandle -and -not $script:PvLaHandle.IsCompleted)
}

# (Re)launch the trickle over $Requests (already-cached keys are skipped inside the
# worker too). Supersedes any running trickle.
function Start-PreviewLookahead($Requests) {
    Stop-PreviewLookahead
    if ($null -eq $Requests) { return }
    $pending = @($Requests | Where-Object { $_ -and -not $script:PreviewCache.ContainsKey($_.Key) })
    if ($pending.Count -eq 0) { return }
    $cancel = [hashtable]::Synchronized(@{ stop = $false })
    $ps     = [PowerShell]::Create()
    [void]$ps.AddScript($script:PvErrFn)   # define Get-WkError in the worker scope
    [void]$ps.AddScript($script:PvLaScript).
        AddArgument($pending).AddArgument($script:PreviewCache).
        AddArgument($cancel).AddArgument(200).AddArgument($script:Alert)
    $script:PvLaCancel = $cancel
    $script:PvLaPS     = $ps
    $script:PvLaHandle = $ps.BeginInvoke()
}

# Plan the page's preview warming around the cursor. Visiting indices nearest-first
# (the highlighted row, then fanning outward), it splits the loadable previews into:
#   WindowReqs/WindowKeys — within $radius of the cursor: warmed fast by the pool.
#   RestReqs              — beyond $radius, nearest-first: trickled by the lookahead.
#   AllKeys               — every loadable preview key on the page (progress / poll).
function Get-PreviewPlan($pageItems, [int]$selRow, [int]$radius = 4) {
    $winReqs  = [Collections.Generic.List[object]]::new()
    $winKeys  = [Collections.Generic.List[string]]::new()
    $restReqs = [Collections.Generic.List[object]]::new()
    $allKeys  = [Collections.Generic.List[string]]::new()
    if ($null -ne $pageItems -and $pageItems.Count -gt 0) {
        $order = [Collections.Generic.List[int]]::new()
        $order.Add($selRow)
        $max = [Math]::Max($selRow, $pageItems.Count - 1 - $selRow)
        for ($d = 1; $d -le $max; $d++) {
            if ($selRow + $d -lt $pageItems.Count) { $order.Add($selRow + $d) }
            if ($selRow - $d -ge 0)                { $order.Add($selRow - $d) }
        }
        foreach ($idx in $order) {
            $rq = Get-ItemPreviewRequest $pageItems[$idx]
            if (-not $rq) { continue }
            $allKeys.Add($rq.Key)
            if ([Math]::Abs($idx - $selRow) -le $radius) { $winReqs.Add($rq); $winKeys.Add($rq.Key) }
            else { $restReqs.Add($rq) }
        }
    }
    return [PSCustomObject]@{
        WindowReqs = @($winReqs.ToArray());  WindowKeys = @($winKeys.ToArray())
        RestReqs   = @($restReqs.ToArray()); AllKeys    = @($allKeys.ToArray())
    }
}

# Fast preview window (highlighted entry first, fanning outward) over archive-tree
# rows (each carrying a .Node) rather than results items. The tree isn't paged and
# can be huge, so entries beyond the window aren't trickled — only the window warms.
# Returns { Reqs; Keys }.
function Get-NodePreviewWindow($rows, [int]$cursor, [int]$radius = 4) {
    $reqs = [Collections.Generic.List[object]]::new()
    $keys = [Collections.Generic.List[string]]::new()
    if ($null -eq $rows -or $rows.Count -eq 0) {
        return [PSCustomObject]@{ Reqs = @(); Keys = @() }
    }
    $order = [Collections.Generic.List[int]]::new()
    $order.Add($cursor)
    for ($d = 1; $d -le $radius; $d++) {
        if ($cursor + $d -lt $rows.Count) { $order.Add($cursor + $d) }
        if ($cursor - $d -ge 0)           { $order.Add($cursor - $d) }
    }
    foreach ($idx in $order) {
        if ($idx -lt 0 -or $idx -ge $rows.Count) { continue }
        $rq = Get-NodePreviewRequest $rows[$idx].Node
        if ($rq) { $reqs.Add($rq); $keys.Add($rq.Key) }
    }
    return [PSCustomObject]@{ Reqs = @($reqs.ToArray()); Keys = @($keys.ToArray()) }
}

# ── SEARCH ────────────────────────────────────────────────────────────────────
# Parse a storage URI such as
#   https://host/artifactory/api/storage/<repo>/<dir>/<file>
# into repo / path / name, and resolve repo type + package type.

function Convert-UriToItem([string]$uri) {
    $marker = '/api/storage/'
    $idx    = $uri.IndexOf($marker)
    $rel    = if ($idx -ge 0) { $uri.Substring($idx + $marker.Length) } else { $uri }
    $rel    = $rel.TrimEnd('/')
    $parts  = $rel -split '/'
    $repo   = if ($parts.Count -ge 1) { $parts[0] } else { '?' }
    $name   = if ($parts.Count -ge 1) { $parts[-1] } else { '?' }
    $path   = if ($parts.Count -ge 3) { ($parts[1..($parts.Count - 2)] -join '/') }
              elseif ($parts.Count -eq 2) { '' }
              else { '' }
    return [PSCustomObject]@{
        Name     = $name
        Repo     = $repo
        Path     = $path
        Uri      = $uri
        FileType = Get-Ext $name
        Size     = ''           # size + modified filled lazily, detailed view only
        Modified = ''
    }
}

function Search-Artifacts([string]$Query) {
    $uri = "$(Get-ArtBase)/api/search/artifact?name=$([Uri]::EscapeDataString($Query))"
    if ($Repos) { $uri += "&repos=$([Uri]::EscapeDataString($Repos))" }

    try {
        $resp  = Invoke-RestMethod -Uri $uri -Method Get -Headers (Get-AuthHeaders) -ErrorAction Stop
        $items = @()
        if ($resp.PSObject.Properties['results']) {
            $items = @($resp.results | ForEach-Object { Convert-UriToItem $_.uri })
        }
        $total = $items.Count

        # Partial-result detection: compare against the most results we've ever
        # seen for this exact query this session. A big drop means the server
        # returned a truncated set (load/throttling), not that matches vanished.
        $prev = if ($script:QueryMax.ContainsKey($Query)) { $script:QueryMax[$Query] } else { 0 }
        if ($prev -gt 0 -and $total -lt [int]($prev * 0.8)) {
            $script:Alert.Message = "Results may be incomplete: got $total, but saw $prev earlier for '$Query' - the server may be throttling. Press [s] to search again."
            $script:Alert.At      = [DateTime]::UtcNow
        } else {
            $script:Alert.Message = ''   # clear any stale notice on a clean result
        }
        if ($total -gt $prev) { $script:QueryMax[$Query] = $total }

        return [PSCustomObject]@{ Items = $items; Total = $total; Error = $null }
    }
    catch {
        return [PSCustomObject]@{ Items = @(); Total = 0; Error = (Get-HttpErrorDetail $_) }
    }
}

# ── DISPLAY ───────────────────────────────────────────────────────────────────

# Build a fixed-width ($nameW) name cell, left-aligned and padded to the column
# edge, with an optional one-char badge placed immediately after the name text:
# '+' for a browsable archive, '·' for a previewable file. Space for the badge is
# reserved before truncating, so even an ellipsised long name still shows it.
# In preview mode the badge starts dim (grey) and turns yellow once that item's
# preview has loaded in the background; elsewhere it's always yellow.
function Format-NameCell([object]$item, [int]$nameW, [bool]$vis, [bool]$preview = $false) {
    $name = [string]$item.Name
    # A preview/fetch error (e.g. blacked-out repo) flags the whole cell red.
    $errored = Test-ItemPreviewError $item
    $col  = if ($errored) { $RD } elseif ($vis) { $DM } else { $CY }
    if     (Get-IsArchive $name)     { $glyph = $script:ArcGlyph }
    elseif (Get-IsPreviewable $name) { $glyph = $script:PreviewGlyph }
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
function Format-DetailedRow($item, [int]$Number, [int]$colW, [bool]$vis, [bool]$preview = $false) {
    $numW = 4; $typeW = 5; $sizeW = 9; $modW = 10; $rtypeW = 6; $ptypeW = 8
    $repoW = [Math]::Min(16, [Math]::Max(8, [int]($colW * 0.14)))
    if ($preview) {
        $nameW = [Math]::Max(10, $colW - ($numW + $typeW + $sizeW + $modW + 8))  # 4 gaps + 2 gutter + 2 margin
        $pathW = 0
    } else {
        $fixed = $numW + $typeW + $sizeW + $modW + $repoW + $rtypeW + $ptypeW + 12  # 8 gaps + 2 gutter + 2 margin
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
        if ($pathW -gt 0) { $cells += "${DM}$(Clip ([string]$item.Path) $pathW)${R}" }
    }
    return ($cells -join ' ')
}

function Format-DetailedHeader([int]$colW, [bool]$preview = $false) {
    $numW = 4; $typeW = 5; $sizeW = 9; $modW = 10; $rtypeW = 6; $ptypeW = 8
    $repoW = [Math]::Min(16, [Math]::Max(8, [int]($colW * 0.14)))
    if ($preview) {
        $nameW = [Math]::Max(10, $colW - ($numW + $typeW + $sizeW + $modW + 8))  # match Format-DetailedRow
        $hdr = @((ClipR '#' $numW), (Clip 'Name' $nameW), (Clip 'Type' $typeW), (ClipR 'Size' $sizeW),
                 (Clip 'Modified' $modW))
    } else {
        $fixed = $numW + $typeW + $sizeW + $modW + $repoW + $rtypeW + $ptypeW + 18
        $rest  = [Math]::Max(12, $colW - $fixed)
        $nameW = [Math]::Max(10, [int]($rest * 0.55))
        $pathW = [Math]::Max(0, $rest - $nameW)
        $hdr = @((ClipR '#' $numW), (Clip 'Name' $nameW), (Clip 'Type' $typeW), (ClipR 'Size' $sizeW),
                 (Clip 'Modified' $modW), (Clip 'Repo' $repoW), (Clip 'RType' $rtypeW), (Clip 'PType' $ptypeW))
        if ($pathW -gt 0) { $hdr += (Clip 'Path' $pathW) }
    }
    return "${BD}${YL}$($hdr -join ' ')${R}"
}

function Show-Page([string]$Query, [object[]]$Items, [int]$Page,
                   [int]$TotalPages, [int]$TotalItems, [int]$Offset,
                   [string]$Mode = 'simple', [int]$SelRow = -1) {

    if ($null -eq $Items) { $Items = @() }
    $w = ((Get-Width) - 1)
    $detailed = ($Mode -eq 'detailed' -or $Mode -eq 'preview')
    $preview  = ($Mode -eq 'preview')
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
    $pageStr = "Page $($Page + 1) of $TotalPages  ($TotalItems result$(if ($TotalItems -ne 1) {'s'}))"
    $rPad    = [Math]::Max(0, $w - 9 - $Query.Length - $pageStr.Length)
    $L.Add("  Query: ${BD}${CY}${Query}${R}$(' ' * $rPad)${DM}${pageStr}${R}")
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
    if ($detailed) { $hdrLine = Format-DetailedHeader $colW $preview }
    else {
        # Budget: gutter(2) + num + 3 single-space gaps = 5 overhead columns.
        $numW = 4; $repoW = 22
        $avail = [Math]::Max(20, $colW - $numW - $repoW - 8)   # 3 gaps + 2 gutter + margin
        $nameW = [Math]::Max(16, [int]($avail * 0.55))
        $pathW = [Math]::Max(8, $avail - $nameW)
        $hdrLine = "${BD}${YL}$(ClipR '#' $numW) $(Clip 'Name' $nameW) $(Clip 'Repository' $repoW) $(Clip 'Path' $pathW)${R}"
    }

    $rowStrs = [Collections.Generic.List[string]]::new()
    # NB: do NOT name the loop var $r — PowerShell is case-insensitive, so $r would
    # alias $R (the ANSI reset) and corrupt every ${R} in this function.
    for ($ri = 0; $ri -lt $Items.Count; $ri++) {
        $item = $Items[$ri]
        $vis  = Test-Visited ([string]$item.Uri)
        $sel  = ($ri -eq $SelRow)
        if ($detailed) {
            $rowBody = Format-DetailedRow $item ($Offset + $ri + 1) $colW $vis $preview
        } else {
            # Simple view shows no archive/preview badges (detailed/preview only).
            $name = if ($item.Name) { $item.Name } else { '?' }
            $repo = if ($item.Repo) { $item.Repo } else { '?' }
            $cName = if (Test-ItemPreviewError $item) { $RD } elseif ($vis) { $DM } else { $CY }
            $cRepo = if ($vis) { $DM } else { $MG }
            $nameCell = "${cName}$(Clip $name $nameW)${R}"
            $rowBody = "${DM}$(ClipR ([string]($Offset + $ri + 1)) $numW)${R} $nameCell ${cRepo}$(Clip $repo $repoW)${R} ${DM}$(Clip ([string]$item.Path) $pathW)${R}"
        }
        $g = if ($sel) { "${BD}${YL}>${R} " } else { '  ' }
        $line = "$g$rowBody"
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
        $bodyH = [Math]::Max(4, (Get-Height) - $L.Count - 3)

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
            if ($indTop) { $leftLines.Add("  ${DM}$([char]0x2191) $sIdx more${R}") }
            for ($ri = $sIdx; $ri -le $eIdx; $ri++) { $leftLines.Add($rowStrs[$ri]) }   # gutter already included
            if ($indBot) { $leftLines.Add("  ${DM}$([char]0x2193) $($rowStrs.Count - 1 - $eIdx) more${R}") }
        }

        # Right pane: details + preview for the selected item.
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
            $rl.Add("${DM}$('Type'.PadRight($labelW))${R}${YL}$(Trunc ([string]$sItem.FileType) $valMax)${R}")
            $rl.Add("${DM}$('Size'.PadRight($labelW))${R}$szTxt")
            if ($sItem.Modified) { $rl.Add("${DM}$('Modified'.PadRight($labelW))${R}$(Trunc ([string]$sItem.Modified) $valMax)") }
            $rl.Add("${DM}$('Repo type'.PadRight($labelW))${R}$($rmeta.Type)")
            $rl.Add("${DM}$('Pkg type'.PadRight($labelW))${R}${MG}$($rmeta.PackageType)${R}")
            $pvMax  = [Math]::Max(1, $bodyH - $rl.Count - 2)
            $pvLines = if (Get-IsArchive ([string]$sItem.Name)) {
                Get-ArchivePreviewLines $sItem $rightW $pvMax
            } else {
                Get-PreviewLines ([string]$sItem.Name) $sUrl $sBytes $rightW $pvMax
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
    if ($preview) { $nav.Add("${BD}${LB}y${RB}${R}${DM} preview big${R}") }
    $nav.Add("${BD}${LB}#${RB}${R}${DM} view${R}")
    $nextMode = switch ($Mode) { 'simple' { 'detailed' } 'detailed' { 'preview' } default { 'simple' } }
    $nav.Add("${BD}${LB}d${RB}${R}${DM} $nextMode view${R}")
    $nav.Add("${BD}${LB}s${RB}${R}${DM} search${R}")
    $nav.Add("${BD}${LB}q${RB}${R}${DM} quit${R}")
    $L.Add((Join-Justified $nav.ToArray() $w))

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
    Show-Popup @('Searching', $Query)
}

# Download an artifact into $OutDir (created on demand). Returns a status line.
# On failure, the server's response body (Artifactory returns a JSON error with
# a human-readable reason, e.g. a "blacked out" repo) is surfaced verbatim
# rather than the bare "(404) Not Found" from the exception message.
function Save-Item([object]$item, [string]$url) {
    try {
        if (-not (Test-Path -LiteralPath $OutDir)) {
            New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
        }
    } catch {
        return "${RD}${BD}Download failed:${R} cannot create folder ${CY}$OutDir${R} - $($_.Exception.Message)"
    }
    $dest = Join-Path $OutDir $item.Name
    # Reuse bytes already held in memory from an earlier preview, if present.
    if ($script:MemFiles.ContainsKey($url)) {
        try {
            [System.IO.File]::WriteAllBytes($dest, $script:MemFiles[$url])
            $sz = ''; try { $sz = ' (' + (Format-Size (Get-Item $dest).Length) + ')' } catch { }
            return "${BD}Saved${R} to ${CY}$dest${R}$sz ${DM}(from preview cache)${R}"
        } catch { }   # fall through to a normal download on any write error
    }
    $old  = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        Invoke-WebRequest -Uri $url -Headers (Get-AuthHeaders) -OutFile $dest -ErrorAction Stop
        $sz = ''
        try { $sz = ' (' + (Format-Size (Get-Item $dest).Length) + ')' } catch { }
        return "${BD}Saved${R} to ${CY}$dest${R}$sz"
    } catch {
        # A failed -OutFile request may leave an empty/partial file behind.
        try { if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Force } } catch { }
        return "${RD}${BD}Download failed:${R} $(Get-HttpErrorDetail $_)"
    } finally {
        $ProgressPreference = $old
    }
}

# ── ARCHIVE BROWSER ──────────────────────────────────────────────────────────
# Artifactory supports the '!' path separator in the storage API to list archive
# internals without downloading the binary:
#   GET /api/storage/{repo}/{path/archive.jar}!/          — root listing
#   GET /api/storage/{repo}/{path/archive.jar}!/com/pkg/  — subdirectory
# The response has a 'children' array identical to normal folder listings.

$script:ArchiveExts = @('zip','jar','war','ear','aar','tar','gz','tgz','rar','7z',
                         'apk','ipa','nupkg','whl','egg')

function Get-IsArchive([string]$name) {
    $ext = (Get-Ext $name).ToLower()
    return $script:ArchiveExts -contains $ext
}

# The /ui/ frontend endpoints reject callers that don't look like the web app,
# returning 403 even for anonymous reads that the public REST API would allow.
# So for the tree-browser call we add the same browser-style headers the web UI
# sends: an XHR marker, a matching Origin/Referer, a normal Accept, and a UA.
# We also force identity encoding: Windows PowerShell 5.1 does NOT auto-decompress
# gzip/br responses, so advertising compression yields a garbled (binary) body.
# Any configured auth header is preserved on top.
function Get-UiHeaders {
    $h = Get-AuthHeaders
    $origin = $BaseUrl.TrimEnd('/')
    $h['Accept']           = 'application/json, text/plain, */*'
    $h['X-Requested-With'] = 'XMLHttpRequest'
    $h['Origin']           = $origin
    $h['Referer']          = "$origin/ui/"
    $h['Accept-Encoding']  = 'identity'
    return $h
}

# The treebrowser archive call returns the WHOLE archive tree, fully nested, in
# a single response: each folder node carries a 'children' array of child nodes
# all the way down (there is no per-folder fetch — the web UI navigates this tree
# client-side, and so do we). These accessors read node fields defensively: the
# display name lives under text (or name); a folder is flagged by folder/isFolder
# or implied by type; children holds the nested entries for a folder.
function Get-NodeName($n) {
    if ($null -eq $n) { return '' }
    if ($n.PSObject.Properties['text'] -and "$($n.text)") { return "$($n.text)" }
    if ($n.PSObject.Properties['name'] -and "$($n.name)") { return "$($n.name)" }
    return ''
}

function Get-NodeIsFolder($n) {
    if ($null -eq $n) { return $false }
    if ($n.PSObject.Properties['folder'])   { return [bool]$n.folder }
    if ($n.PSObject.Properties['isFolder']) { return [bool]$n.isFolder }
    if ($n.PSObject.Properties['type']) {
        return @('folder','junction','paginatedjunction','archive','repository') -contains "$($n.type)".ToLower()
    }
    return $false
}

# A folder's children come as an array of node objects. Guard against a missing
# property or a non-array placeholder (treated as an unexpanded / empty folder).
# Null entries are stripped: a malformed/empty subtree (e.g. an unbrowsable nested
# archive) can yield array slots that are $null, and every node accessor would
# throw on them under StrictMode.
function Get-NodeChildren($n) {
    if ($null -eq $n) { return @() }
    if ($n.PSObject.Properties['children']) {
        $c = $n.children
        if ($c -is [Array]) { return @($c | Where-Object { $null -ne $_ }) }
    }
    return @()
}

# Order a level for display: folders first, then files, each alphabetical. Null
# entries are dropped up front so the accessors never see them.
function Sort-Nodes($nodes) {
    $clean   = @(@($nodes) | Where-Object { $null -ne $_ })
    $folders = @($clean | Where-Object {      (Get-NodeIsFolder $_) } | Sort-Object { (Get-NodeName $_).ToLower() })
    $files   = @($clean | Where-Object { -not (Get-NodeIsFolder $_) } | Sort-Object { (Get-NodeName $_).ToLower() })
    return @($folders + $files)
}

# A stable per-node key for tracking which folders are expanded. The node's
# archive path is unique; fall back to the name if absent.
function Get-NodeKey($n) {
    if ($null -eq $n) { return '' }
    if ($n.PSObject.Properties['path'] -and "$($n.path)") { return "$($n.path)" }
    return (Get-NodeName $n)
}

# Resolve a node's children for navigation: folders carry them inline; archive
# *files* are expandable too, but their sub-tree is fetched lazily and stored in
# $subCache keyed by node key (empty array until loaded).
function Get-NodeKidsResolved($n, $subCache) {
    if ($null -eq $n) { return @() }
    if (Get-NodeIsFolder $n) { return @(Get-NodeChildren $n) }
    if (Get-NodeIsArchive $n) {
        $k = Get-NodeKey $n
        if ($subCache -and $subCache.ContainsKey($k)) { return @(@($subCache[$k]) | Where-Object { $null -ne $_ }) }
        return @()
    }
    return @()
}

# Flatten the tree into the ordered list of currently-visible rows, honouring
# which folders/archives are expanded. Each row records the data needed to draw
# its connectors (the chain of "is this ancestor the last child" flags, and
# whether the row itself is the last child), its parent node, and whether it is
# expandable. Rows are appended to $rows (a List passed by reference).
function Add-TreeRows($nodes, $ancestorLast, $expanded, $subCache, $parent, $rows) {
    $sorted = @(Sort-Nodes $nodes)
    for ($i = 0; $i -lt $sorted.Count; $i++) {
        $n          = $sorted[$i]
        $isLast     = ($i -eq $sorted.Count - 1)
        $isFolder   = Get-NodeIsFolder $n
        $isArchive  = Get-NodeIsArchive $n
        # Only folders are expandable. Nested sub-archives aren't browsable through
        # the tree-browser endpoint, so they're treated as plain files (selecting
        # one downloads it) rather than offered for an expansion that always fails.
        $expandable = $isFolder
        $key        = Get-NodeKey $n
        $kids       = @(Get-NodeChildren $n)
        $hasKids    = $kids.Count -gt 0
        $isOpen     = $expandable -and $expanded.Contains($key)
        $rows.Add([PSCustomObject]@{
            Node         = $n
            Name         = Get-NodeName $n
            IsFolder     = $isFolder
            IsArchive    = $isArchive
            Expandable   = $expandable
            HasKids      = $hasKids
            IsOpen       = $isOpen
            Key          = $key
            Depth        = @($ancestorLast).Count
            AncestorLast = @($ancestorLast)
            IsLast       = $isLast
            Parent       = $parent
        })
        if ($isOpen -and $kids.Count -gt 0) {
            Add-TreeRows $kids (@($ancestorLast) + $isLast) $expanded $subCache $n $rows
        }
    }
}

# Recursively add every folder key to $set (expand all). Sub-archives aren't
# expandable, so they're skipped.
function Add-AllFolderKeys($nodes, $expanded, $subCache) {
    foreach ($n in @($nodes)) {
        if (Get-NodeIsFolder $n) {
            [void]$expanded.Add((Get-NodeKey $n))
            Add-AllFolderKeys (Get-NodeChildren $n) $expanded $subCache
        }
    }
}

# Recursively collect file (non-folder) descendants of $nodes whose name matches
# $pattern (wildcard, case-insensitive). Each hit becomes a lightweight item with
# the fields Save-Item / the results view need. Folders and loaded sub-archives
# are descended into.
function Get-MatchingFiles($nodes, $subCache, [string]$pattern, $acc) {
    foreach ($n in @($nodes)) {
        if (Get-NodeIsFolder $n) {
            Get-MatchingFiles (Get-NodeChildren $n) $subCache $pattern $acc
            continue
        }
        $name = Get-NodeName $n
        if ($name -like $pattern) { $acc.Add($n) }
        if (Get-NodeIsArchive $n) {
            $kids = Get-NodeKidsResolved $n $subCache
            if ($kids.Count -gt 0) { Get-MatchingFiles $kids $subCache $pattern $acc }
        }
    }
}

function Get-RepoTypeForUI([string]$repo) {
    switch ((Resolve-Repo $repo).Type.ToUpper()) {
        'LOCAL'   { return 'local'   }
        'REMOTE'  { return 'remote'  }
        'VIRTUAL' { return 'virtual' }
        'CACHE'   { return 'cached'  }
        default   { return 'local'   }
    }
}

# Fetch the full archive tree via the Artifactory UI tree-browser endpoint (the
# same call the web UI makes). This works regardless of whether archive indexing
# is configured on the repository, which is why it succeeds where the storage API
# '!/' separator returns 404. A single POST returns the entire archive contents
# nested under each folder's 'children' — so we make ONE call and navigate the
# result client-side; there is no per-folder fetch.
# Build the treebrowser POST request (uri / body / headers / user-agent) without
# sending it. Shared by the synchronous Invoke-TreeBrowse and the background
# preview worker (which can't call these helpers from its isolated runspace, so it
# needs the request fully materialised on the main thread).
function Get-TreeBrowseRequest([string]$repoKey, [string]$repoType, [string]$repoPkgType,
                               [string]$path, [string]$text) {
    $body = [ordered]@{
        projectKey    = ''
        type          = 'paginatedJunction'
        repoType      = $repoType
        repoKey       = $repoKey
        path          = $path
        text          = $text
        trashcan      = $false
        repoPkgType   = $repoPkgType
        continueState = ''
        limit         = $null
        isFolder      = $false
        isArchive     = $true
        mustInclude   = $null
    } | ConvertTo-Json -Compress
    return [PSCustomObject]@{
        Uri     = "$($BaseUrl.TrimEnd('/'))/ui/api/v1/ui/v2/treebrowser?compacted=false"
        Body    = $body
        Headers = (Get-UiHeaders)
        Ua      = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/151.0'
    }
}

function Invoke-TreeBrowse([string]$repoKey, [string]$repoType, [string]$repoPkgType,
                           [string]$path, [string]$text) {
    $rq = Get-TreeBrowseRequest $repoKey $repoType $repoPkgType $path $text
    try {
        $resp = Invoke-RestMethod -Uri $rq.Uri -Method Post -Body $rq.Body `
                    -ContentType 'application/json' -Headers $rq.Headers `
                    -UserAgent $rq.Ua -ErrorAction Stop
        $data = if ($resp.PSObject.Properties['data'] -and $resp.data) { @(@($resp.data) | Where-Object { $null -ne $_ }) } else { @() }
        return [PSCustomObject]@{ Ok = $true; Nodes = $data; Error = '' }
    } catch {
        return [PSCustomObject]@{ Ok = $false; Nodes = @(); Error = (Get-HttpErrorDetail $_) }
    }
}

function Get-ArchiveTree([object]$item) {
    $repoKey     = [string]$item.Repo
    $repoType    = Get-RepoTypeForUI $repoKey
    $repoPkgType = [string](Resolve-Repo $repoKey).PackageType
    $archPath    = if ($item.Path) { "$($item.Path)/$($item.Name)" } else { [string]$item.Name }
    return Invoke-TreeBrowse $repoKey $repoType $repoPkgType $archPath ([string]$item.Name)
}

# Is this file small enough to auto-preview in the background? Unknown sizes and
# anything over the cap are gated behind an explicit [y] (PreviewOK), matching the
# synchronous Get-PreviewLines logic — so we never auto-stream a huge file.
function Test-FileAutoPreviewable([string]$url, [long]$sizeBytes) {
    if ($sizeBytes -ge 0 -and $sizeBytes -le $script:PreviewLimit) { return $true }
    return $script:PreviewOK.Contains($url)
}

# The preview-cache key for a results item, or '' when there's nothing to load in
# the background (not previewable, or a gated large file). Cheap; called per row
# to decide the badge's load-state colour.
function Get-ItemPreviewKey($item) {
    $name = [string]$item.Name
    if (Get-IsArchive $name) { return (Get-ArcPreviewKey ([string]$item.Uri)) }
    if (Get-IsPreviewable $name) {
        $url = Get-ItemUrl $item
        $sz  = if ("$($item.Size)" -ne '' -and "$($item.Size)" -ne '?') { [long]$item.Size } else { -1 }
        if (Test-FileAutoPreviewable $url $sz) { return (Get-FilePreviewKey $url) }
    }
    return ''
}

# A full background-fetch request descriptor for a results item, or $null when
# there's nothing to load. Used by Start-PreviewPrefetch.
function Get-ItemPreviewRequest($item) {
    $name = [string]$item.Name
    if (Get-IsArchive $name) {
        $repoKey     = [string]$item.Repo
        $repoType    = Get-RepoTypeForUI $repoKey
        $repoPkgType = [string](Resolve-Repo $repoKey).PackageType
        $archPath    = if ($item.Path) { "$($item.Path)/$($item.Name)" } else { $name }
        $rq          = Get-TreeBrowseRequest $repoKey $repoType $repoPkgType $archPath $name
        return @{ Key = (Get-ArcPreviewKey ([string]$item.Uri)); Kind = 'archive';
                  Uri = $rq.Uri; Body = $rq.Body; Headers = $rq.Headers; Ua = $rq.Ua }
    }
    if (Get-IsPreviewable $name) {
        $url = Get-ItemUrl $item
        $sz  = if ("$($item.Size)" -ne '' -and "$($item.Size)" -ne '?') { [long]$item.Size } else { -1 }
        if (Test-FileAutoPreviewable $url $sz) {
            return @{ Key = (Get-FilePreviewKey $url); Kind = 'file'; Url = $url; Headers = (Get-AuthHeaders) }
        }
    }
    return $null
}

# Preview-cache key for an archive-tree node, or '' when it has nothing to load in
# the background (folder, nested sub-archive, non-previewable, or gated large file).
function Get-NodePreviewKey($n) {
    if ($null -eq $n -or (Get-NodeIsFolder $n) -or (Get-NodeIsArchive $n)) { return '' }
    if (-not (Get-IsPreviewable (Get-NodeName $n))) { return '' }
    $url = Get-EntryUrl $n
    if (-not $url) { return '' }
    $info = Get-NodeInfo $n
    $sz   = if ($info -and $info.PSObject.Properties['size']) { [long]$info.size } else { -1 }
    if (Test-FileAutoPreviewable $url $sz) { return (Get-FilePreviewKey $url) }
    return ''
}

# Background-fetch request for an archive-tree node's preview, or $null.
function Get-NodePreviewRequest($n) {
    $key = Get-NodePreviewKey $n
    if (-not $key) { return $null }
    return @{ Key = $key; Kind = 'file'; Url = (Get-EntryUrl $n); Headers = (Get-AuthHeaders) }
}

# The natural preview key for an item/node (archive listing or file contents),
# ignoring the size gate — used to look up whether a fetch *that was attempted*
# came back as an error, so the row can be flagged.
function Get-ItemNaturalPreviewKey($item) {
    $name = [string]$item.Name
    if (Get-IsArchive $name)     { return (Get-ArcPreviewKey ([string]$item.Uri)) }
    if (Get-IsPreviewable $name) { return (Get-FilePreviewKey (Get-ItemUrl $item)) }
    return ''
}

# True if a preview fetch for this item resolved to an error (e.g. the server
# refused to serve the artifact — a blacked-out repo, 404, auth failure). The row
# is then drawn red. A still-loading or never-fetched item is not "errored".
function Test-ItemPreviewError($item) {
    $key = Get-ItemNaturalPreviewKey $item
    if (-not $key -or -not $script:PreviewCache.ContainsKey($key)) { return $false }
    return (-not $script:PreviewCache[$key].Ok)
}

# As Test-ItemPreviewError, for an archive-tree node (a previewable file entry).
function Test-NodePreviewError($n) {
    if ($null -eq $n -or (Get-NodeIsFolder $n) -or (Get-NodeIsArchive $n)) { return $false }
    if (-not (Get-IsPreviewable (Get-NodeName $n))) { return $false }
    $url = Get-EntryUrl $n
    if (-not $url) { return $false }
    $key = Get-FilePreviewKey $url
    if (-not $script:PreviewCache.ContainsKey($key)) { return $false }
    return (-not $script:PreviewCache[$key].Ok)
}

# Fetch the contents of a sub-archive (an archive file *inside* the tree) by
# pointing the tree-browser at the node's own path with isArchive=true. Used to
# expand nested archives inline, like folders.
function Get-ArchiveSubtree([string]$repoKey, [string]$path, [string]$text) {
    $repoType    = Get-RepoTypeForUI $repoKey
    $repoPkgType = [string](Resolve-Repo $repoKey).PackageType
    return Invoke-TreeBrowse $repoKey $repoType $repoPkgType $path $text
}

# An archive *file* node (not a folder) whose name has an archive extension — i.e.
# something we can expand inline by fetching its sub-tree.
function Get-NodeIsArchive($n) {
    if ($null -eq $n) { return $false }
    if (Get-NodeIsFolder $n) { return $false }
    return Get-IsArchive (Get-NodeName $n)
}

# The General-tab info object carried by a node (size/compressed/modificationTime
# /crc), or $null. Sometimes it arrives stringified; we only use real objects.
function Get-NodeInfo($n) {
    if ($null -eq $n) { return $null }
    if ($n.PSObject.Properties['tabs']) {
        foreach ($t in @($n.tabs)) {
            if ($t -and $t.PSObject.Properties['info'] -and $t.info -and ($t.info -isnot [string])) {
                return $t.info
            }
        }
    }
    return $null
}

# Repo-relative download path for an internal entry (the repoKey/...zip!/entry
# form Artifactory serves single archive entries from), or '' for folders.
function Get-NodeDownloadPath($n) {
    if ($null -eq $n) { return '' }
    if ($n.PSObject.Properties['downloadPath'] -and "$($n.downloadPath)") { return "$($n.downloadPath)" }
    return ''
}

# Epoch-millis (as Artifactory reports archive-entry times) to a local datetime.
function Format-Epoch($ms) {
    try { return [DateTimeOffset]::FromUnixTimeMilliseconds([int64]$ms).LocalDateTime.ToString('yyyy-MM-dd HH:mm') }
    catch { return '' }
}

# Full download URL for an internal archive entry (repoKey + downloadPath, the
# repo/...zip!/entry form Artifactory serves single entries from).
function Get-EntryUrl($n) {
    if ($null -eq $n) { return '' }
    $dp = Get-NodeDownloadPath $n
    if (-not $dp) { return '' }
    $repo = if ($n.PSObject.Properties['repoKey']) { "$($n.repoKey)" } else { '' }
    return "$(Get-ArtBase)/$repo/$dp"
}

# Internal (within-archive) path of a node, with the archive prefix stripped.
function Get-NodeInternalPath($n) {
    if ($null -eq $n) { return '' }
    $np = if ($n.PSObject.Properties['path'])        { "$($n.path)" }        else { '' }
    $ap = if ($n.PSObject.Properties['archivePath']) { "$($n.archivePath)" } else { '' }
    if ($ap -and $np.StartsWith($ap)) { return $np.Substring($ap.Length).TrimStart('/') }
    return $np
}

# Detail-pane lines for a tree node (an internal archive entry).
function Get-NodeDetailLines($n, [int]$paneW) {
    $labelW = 11
    $valMax = [Math]::Max(6, $paneW - $labelW - 1)
    $L = [Collections.Generic.List[string]]::new()
    $name     = Get-NodeName $n
    $isFolder = Get-NodeIsFolder $n
    $isArc    = Get-NodeIsArchive $n
    $info     = Get-NodeInfo $n

    $L.Add("${BD}${CY}$(Trunc $name $paneW)${R}")
    $L.Add('')
    $typeStr = if ($isFolder) { 'folder' } elseif ($isArc) { "$(Get-Ext $name) (archive)" } else { Get-Ext $name }
    $L.Add("${DM}$('Type'.PadRight($labelW))${R}${YL}$(Trunc $typeStr $valMax)${R}")
    $L.Add("${DM}$('Path'.PadRight($labelW))${R}$(Trunc ('/' + (Get-NodeInternalPath $n)) $valMax)")
    if ($info) {
        if ($info.PSObject.Properties['size'])             { $L.Add("${DM}$('Size'.PadRight($labelW))${R}$(Format-Size $info.size)") }
        if ($info.PSObject.Properties['compressed'])       { $L.Add("${DM}$('Compressed'.PadRight($labelW))${R}$(Format-Size $info.compressed)") }
        if ($info.PSObject.Properties['modificationTime']) { $L.Add("${DM}$('Modified'.PadRight($labelW))${R}$(Format-Epoch $info.modificationTime)") }
        if ($info.PSObject.Properties['crc'] -and "$($info.crc)" -and "$($info.crc)" -ne '0') {
            $L.Add("${DM}$('CRC'.PadRight($labelW))${R}$(Trunc "$($info.crc)" $valMax)")
        }
    }
    if (-not $isFolder) {
        $url = Get-EntryUrl $n
        if ($url) {
            $L.Add(''); $L.Add("${DM}Download${R}")
            foreach ($wl in (Wrap-Text $url $paneW)) { $L.Add("${CY}$wl${R}") }
        }
    }
    return $L.ToArray()
}

# Detail-pane lines for the archive file itself (the synthetic tree root), using
# its storage metadata (fetched once by the caller).
function Get-ArchiveItemDetailLines($item, $info, [int]$paneW) {
    $labelW = 11
    $valMax = [Math]::Max(6, $paneW - $labelW - 1)
    $repo  = if ($item.Repo) { $item.Repo } else { '?' }
    $rmeta = Resolve-Repo $repo
    $L = [Collections.Generic.List[string]]::new()
    $L.Add("${BD}${CY}$(Trunc ([string]$item.Name) ([Math]::Max(1, $paneW - 6)))${R}   ${YL}$script:ArcGlyph${R}")
    $L.Add('')
    $L.Add("${DM}$('Repository'.PadRight($labelW))${R}${MG}$(Trunc $repo $valMax)${R}")
    $L.Add("${DM}$('Path'.PadRight($labelW))${R}$(Trunc ([string]$item.Path) $valMax)")
    $L.Add("${DM}$('Type'.PadRight($labelW))${R}${YL}$(Trunc ([string]$item.FileType) $valMax)${R}")
    if ($info) {
        if ($info.PSObject.Properties['size'])         { $L.Add("${DM}$('Size'.PadRight($labelW))${R}$(Format-Size $info.size)") }
        if ($info.PSObject.Properties['lastModified']) { $L.Add("${DM}$('Modified'.PadRight($labelW))${R}$(Trunc "$($info.lastModified)" $valMax)") }
        if ($info.PSObject.Properties['mimeType'])     { $L.Add("${DM}$('MIME'.PadRight($labelW))${R}$(Trunc "$($info.mimeType)" $valMax)") }
    }
    $L.Add("${DM}$('Repo type'.PadRight($labelW))${R}$($rmeta.Type)")
    $L.Add("${DM}$('Pkg type'.PadRight($labelW))${R}${MG}$($rmeta.PackageType)${R}")
    return $L.ToArray()
}

# Download a single internal archive entry. Returns a status line (same styling
# as Save-Item). Files are saved under a per-archive subfolder of $OutDir.
function Save-ArchiveEntry($node, [string]$subDir) {
    $url = Get-EntryUrl $node
    if (-not $url) { return "${RD}${BD}Download failed:${R} no download path for $(Get-NodeName $node)" }
    $destDir = if ($subDir) { Join-Path $OutDir $subDir } else { $OutDir }
    try {
        if (-not (Test-Path -LiteralPath $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
    } catch {
        return "${RD}${BD}Download failed:${R} cannot create folder ${CY}$destDir${R} - $($_.Exception.Message)"
    }
    $dest = Join-Path $destDir (Get-NodeName $node)
    # Reuse bytes already held in memory from an earlier preview, if present.
    if ($script:MemFiles.ContainsKey($url)) {
        try { [System.IO.File]::WriteAllBytes($dest, $script:MemFiles[$url]); return "${BD}Saved${R} to ${CY}$dest${R} ${DM}(from preview cache)${R}" } catch { }
    }
    $old  = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'
    try {
        Invoke-WebRequest -Uri $url -Headers (Get-AuthHeaders) -OutFile $dest -ErrorAction Stop
        return "${BD}Saved${R} to ${CY}$dest${R}"
    } catch {
        try { if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Force } } catch { }
        return "${RD}${BD}Download failed:${R} $(Get-HttpErrorDetail $_)"
    } finally { $ProgressPreference = $old }
}

# A simple yes/no confirmation screen. $Lines is the message body. Returns $true
# only on 'y'.
function Confirm-Prompt([string[]]$Lines) {
    $w = ((Get-Width) - 1)
    $L = [Collections.Generic.List[string]]::new()
    $L.Add(''); foreach ($ln in $Lines) { $L.Add("  $ln") }
    $L.Add(''); $L.Add("  ${BD}${LB}y${RB}${R}${DM} yes${R}    ${BD}${LB}n${RB}${R}${DM} no${R}")
    Show-Frame $L.ToArray()
    while ($true) {
        switch (Read-Key) {
            'y' { return $true }
            'n' { return $false }
            'q' { return $false }
        }
    }
}

# Parse a multi-number spec like "21,27,35,53-57" (comma- and/or space-separated,
# with ranges) into sorted, unique, 1-based indices clamped to [1,$max].
function Parse-NumberSpec([string]$spec, [int]$max) {
    $set = New-Object 'System.Collections.Generic.SortedSet[int]'
    foreach ($tok in ($spec -split '[,\s]+')) {
        if (-not $tok) { continue }
        if ($tok -match '^(\d+)-(\d+)$') {
            $a = [int]$Matches[1]; $b = [int]$Matches[2]
            if ($a -gt $b) { $t = $a; $a = $b; $b = $t }
            for ($i = $a; $i -le $b; $i++) { if ($i -ge 1 -and $i -le $max) { [void]$set.Add($i) } }
        } elseif ($tok -match '^\d+$') {
            $i = [int]$tok; if ($i -ge 1 -and $i -le $max) { [void]$set.Add($i) }
        }
    }
    return @($set)
}

# First digit already captured no-echo; echo it then read the rest of a number
# spec (digits, commas, spaces, dashes). Returns the full typed string.
function Read-NumberSpec([string]$first) {
    if (-not $script:CanRawKey) { return ("$first").Trim() }
    Write-Host -NoNewline "`n  ${BD}${CY}Download #${R} ${DM}(e.g. 1,3,5-9):${R} $first"
    $rest = Read-Host
    return ("$first$rest").Trim()
}

# Confirm + download a set of entry nodes into a per-archive subfolder, warning
# with the file count and total size first, then showing progress and a summary.
# Shared by the search view's "download all" and numeric multi-select.
function Save-Entries($nodes, [string]$arcName) {
    $nodes = @($nodes)
    $total = $nodes.Count
    if ($total -eq 0) { return }
    $w = ((Get-Width) - 1)
    $bytes = 0L; $haveSize = $true
    foreach ($n in $nodes) {
        $info = Get-NodeInfo $n
        if ($info -and $info.PSObject.Properties['size']) { $bytes += [int64]$info.size } else { $haveSize = $false }
    }
    $szStr = if ($haveSize) { Format-Size $bytes } else { "$(Format-Size $bytes)+ (some sizes unknown)" }
    $sub   = ($arcName -replace '[\\/:*?"<>|]', '_')
    $ok = Confirm-Prompt @(
        "${BD}Download $total file$(if ($total -ne 1){'s'})?${R}",
        "Total size: ${CY}$szStr${R}",
        "Into: ${CY}$(Join-Path $OutDir $sub)${R}"
    )
    if (-not $ok) { return }
    $done = 0; $fail = 0; $i = 0
    foreach ($n in $nodes) {
        $i++
        Show-Popup @("Downloading $i / $total", (Get-NodeName $n))
        $res = Save-ArchiveEntry $n $sub
        if ($res -like "*Download failed*") { $fail++ } else { $done++; Mark-Visited (Get-EntryUrl $n) }
    }
    Show-Popup @("Done.  Saved $done, failed $fail.", "Into $(Join-Path $OutDir $sub)", '', "press any key")
    [void](Read-Key)
}

# Results view for an in-archive search: a list of matching files navigable with
# a highlight cursor (like the tree). Enter downloads the highlighted entry;
# typing a number / spec (e.g. 21,27,53-57) downloads that selection; A downloads
# all — selections warn with count + total size first. $scopeLabel is the folder
# the search ran under; $matches are file nodes; $arcName seeds the save subfolder.
function Show-TreeSearchResults($matches, [string]$query, [string]$scopeLabel, [string]$arcName) {
    $matches = @($matches)
    $sub     = ($arcName -replace '[\\/:*?"<>|]', '_')
    $cursor  = 0

    while ($true) {
        $w        = ((Get-Width) - 1)
        $total    = $matches.Count
        $pageSize = [Math]::Max(5, (Get-Height) - 10)
        $totalPages = [Math]::Max(1, [Math]::Ceiling($total / $pageSize))
        if ($cursor -lt 0) { $cursor = 0 }
        if ($cursor -gt $total - 1) { $cursor = [Math]::Max(0, $total - 1) }
        $page   = [int][Math]::Floor($cursor / $pageSize)
        $offset = $page * $pageSize

        $L = [Collections.Generic.List[string]]::new()
        $title = '  ARTCA  Archive Search  '
        $gap   = [Math]::Max(0, $w - $title.Length)
        $L.Add("${HB}${BD}${MG}${title}${R}${HB}$(' ' * $gap)${R}")
        $L.Add("$DM$(HR $w)$R")
        $pageStr = "Page $($page + 1) of $totalPages  ($total match$(if ($total -ne 1){'es'}))"
        $rpad = [Math]::Max(1, $w - 10 - $query.Length - $pageStr.Length)
        $L.Add("  Match: ${BD}${CY}$query${R}$(' ' * $rpad)${DM}$pageStr${R}")
        $L.Add("  ${DM}under /$(Trunc $scopeLabel ($w - 12))${R}")
        $L.Add("$DM$(HR $w)$R")

        $numW = 5; $nameW = 42; $sizeW = 10
        $pathW = [Math]::Max(10, $w - $numW - $nameW - $sizeW - 10)
        $L.Add("  ${BD}${YL}$(ClipR '#' $numW)  $(Clip 'Name' $nameW)  $(ClipR 'Size' $sizeW)  $(Clip 'Path' $pathW)${R}")
        $L.Add("$DM$(HR $w)$R")

        if ($total -eq 0) {
            $L.Add(''); $L.Add("  ${DM}No matches.${R}")
        } else {
            $end = [Math]::Min($offset + $pageSize - 1, $total - 1)
            for ($i = $offset; $i -le $end; $i++) {
                $n    = $matches[$i]
                $sel  = ($i -eq $cursor)
                $info = Get-NodeInfo $n
                $sz   = if ($info -and $info.PSObject.Properties['size']) { Format-Size $info.size } else { '' }
                $nm   = Get-NodeName $n
                $arc  = Get-NodeIsArchive $n
                $numCell = "${DM}$(ClipR ([string]($i + 1)) $numW)${R}"
                $nameCell = if ($arc -and $sel) { "${BD}${CY}$(Clip $nm ([Math]::Max(1, $nameW - 2)))${R}${YL} $script:ArcGlyph${R}" }
                            elseif ($arc)  { "${CY}$(Clip $nm ([Math]::Max(1, $nameW - 2)))${R}${YL} $script:ArcGlyph${R}" }
                            elseif ($sel)  { "${BD}${CY}$(Clip $nm $nameW)${R}" }
                            else           { "${CY}$(Clip $nm $nameW)${R}" }
                $gutter = if ($sel) { "${BD}${CY}>${R} " } else { '  ' }
                $L.Add("$gutter$numCell  $nameCell  $(ClipR $sz $sizeW)  ${DM}$(Clip (Get-NodeInternalPath $n) $pathW)${R}")
            }
        }

        $L.Add(''); $L.Add("$DM$(HR $w)$R")
        $nav = [Collections.Generic.List[string]]::new()
        $nav.Add("${BD}${LB}$([char]0x2191)$([char]0x2193)${RB}${R}${DM} move${R}")
        if ($total -gt 0) {
            $nav.Add("${BD}${LB}$([char]0x21B5)${RB}${R}${DM} download${R}")
            $nav.Add("${BD}${LB}#${RB}${R}${DM} select (e.g. 1,3,5-9)${R}")
            $nav.Add("${BD}${LB}A${RB}${R}${DM} all${R}")
        }
        $nav.Add("${BD}${LB}b${RB}${R}${DM} back to tree${R}")
        $L.Add("  $($nav -join '   ')")
        Show-Frame $L.ToArray()

        switch -regex (Read-Key) {
            '^(up|k)$'       { if ($cursor -gt 0)           { $cursor-- } }
            '^(down|j)$'     { if ($cursor -lt $total - 1)  { $cursor++ } }
            '^(pageup|left)$'   { $cursor = [Math]::Max(0, $cursor - $pageSize) }
            '^(pagedown|right)$'{ $cursor = [Math]::Min($total - 1, $cursor + $pageSize) }
            '^home$'         { $cursor = 0 }
            '^end$'          { $cursor = $total - 1 }
            '^(enter|o)$' {
                if ($total -gt 0) {
                    $n = $matches[$cursor]
                    Show-Popup @("Downloading", (Get-NodeName $n))
                    $res = Save-ArchiveEntry $n $sub
                    if ($res -notlike "*Download failed*") { Mark-Visited (Get-EntryUrl $n) }
                    Show-Popup @((Strip-Ansi $res), '', "press any key")
                    [void](Read-Key)
                }
            }
            '^\d[\d,\s-]*$' {
                if ($total -gt 0) {
                    # Console captures one digit then reads the rest; ISE's Read-Host
                    # already returns the whole spec on one line.
                    $spec = if ($script:CanRawKey -and $_.Length -eq 1) { Read-NumberSpec $_ } else { $_ }
                    $idx  = Parse-NumberSpec $spec $total
                    if ($idx.Count -gt 0) {
                        $picked = @($idx | ForEach-Object { $matches[$_ - 1] })
                        Save-Entries $picked $arcName
                    }
                }
            }
            '^a$' { if ($total -gt 0) { Save-Entries $matches $arcName } }
            '^(b|q)$' { return }
        }
    }
}

# Lazily fetch a sub-archive node's contents into $subCache (no-op if cached).
function Load-SubArchive($node, $item, $subCache) {
    $k = Get-NodeKey $node
    if ($subCache.ContainsKey($k)) { return }
    $repoK = if ($node.PSObject.Properties['repoKey']) { "$($node.repoKey)" } else { [string]$item.Repo }
    $np    = if ($node.PSObject.Properties['path'])    { "$($node.path)" }    else { '' }
    $res   = Get-ArchiveSubtree $repoK $np (Get-NodeName $node)
    $subCache[$k] = if ($res.Ok) { @($res.Nodes) } else { @() }
}

# Prompt for an in-archive search query (case-preserving line input).
function Read-TreeQuery {
    Show-Frame @('', "  ${BD}${CY}Search in archive${R}${DM}  (name; * and ? wildcards):${R}", '')
    Write-Host -NoNewline "  > ${BD}${CY}"
    $q = Read-Host
    Write-Host -NoNewline $R
    return $q.Trim()
}

# Interactive tree browser for an archive, opened straight from search results.
# One call fetches the whole tree; we render it as a collapsible tree on the left
# with a live detail pane on the right. The synthetic root is the archive file
# itself (its detail pane shows storage metadata). Sub-archives expand inline.
function Show-ArchiveTree([object]$item) {
    Initialize-RepoMap
    Stop-PreviewLookahead   # halt the results-page preview trickle while browsing

    Show-Popup @("Reading archive", $item.Name)
    $tree = Get-ArchiveTree $item

    if (-not $tree.Ok) {
        Show-Popup @("Could not read archive:", $tree.Error, '',
            "The archive may not be browsable - check repository settings or credentials.",
            '', "[b] back")
        do { $k = Read-Key } until ($k -match '^(b|q|enter|left|backspace)$')
        return
    }

    # Storage metadata for the archive file itself (for the root's detail pane).
    $rootInfo = $null
    try { $rootInfo = Invoke-RestMethod -Uri $item.Uri -Headers (Get-AuthHeaders) -ErrorAction Stop } catch { }

    # Synthetic root node = the archive file, holding the real top-level entries.
    $archPath = if ($item.Path) { "$($item.Path)/$($item.Name)" } else { [string]$item.Name }
    $rootNode = [PSCustomObject]@{
        text = [string]$item.Name; folder = $true; children = @($tree.Nodes)
        path = $archPath; archivePath = ''; __root = $true
    }
    $rootKey  = Get-NodeKey $rootNode

    $subCache = @{}   # node key -> sub-archive children (lazy)
    $expanded = New-Object 'System.Collections.Generic.HashSet[string]'
    [void]$expanded.Add($rootKey)
    foreach ($n in @($tree.Nodes)) { if (Get-NodeIsFolder $n) { [void]$expanded.Add((Get-NodeKey $n)) } }
    # Folders/archives the user has expanded at least once this session. Unlike
    # $expanded (which shrinks on collapse), $seen only grows, so the "?" badge
    # marks folders never looked in and never reappears once a folder is opened.
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'

    $rows = [Collections.Generic.List[object]]::new()
    Add-TreeRows @($rootNode) @() $expanded $subCache $null $rows
    $cursor      = 0
    $rebuild     = $false
    $forceKey    = $null   # when set, position the cursor on this key after a rebuild
    $notice      = @{ Message = ''; At = [DateTime]::MinValue }
    $previewMode = $false  # 'v' toggles the preview pane under file details

    # Connector glyphs (char codes keep the file ASCII).
    $vert = "$([char]0x2502)   "; $gapS = '    '
    $tee  = "$([char]0x251C)$([char]0x2500)$([char]0x2500) "
    $ell  = "$([char]0x2514)$([char]0x2500)$([char]0x2500) "
    $open = [char]0x25BE; $clsd = [char]0x25B8; $vbar = [char]0x2502

    while ($true) {
        if ($rebuild) {
            $keepKey = if ($forceKey) { $forceKey }
                       elseif ($rows.Count -gt 0 -and $cursor -lt $rows.Count) { $rows[$cursor].Key }
                       else { $null }
            $forceKey = $null
            $rows = [Collections.Generic.List[object]]::new()
            Add-TreeRows @($rootNode) @() $expanded $subCache $null $rows
            if ($keepKey) {
                for ($i = 0; $i -lt $rows.Count; $i++) {
                    if ($rows[$i].Key -eq $keepKey) { $cursor = $i; break }
                }
            }
            if ($cursor -ge $rows.Count) { $cursor = [Math]::Max(0, $rows.Count - 1) }
            $rebuild = $false
        }

        # Record everything currently expanded as "seen" (open implies seen), so a
        # folder opened even once never shows the "?" badge again, regardless of
        # how it was expanded (enter, e/E, arrow). $seen never shrinks.
        foreach ($k in $expanded) { [void]$seen.Add($k) }

        $w   = ((Get-Width) - 1)
        $cur = if ($rows.Count -gt 0 -and $cursor -lt $rows.Count) { $rows[$cursor] } else { $null }

        # Background-warm previews for entries around the cursor (preview mode only),
        # so the pane shows "Loading..." then fills in without blocking keys. On ISE
        # (no key poll) block briefly for the highlighted entry before drawing.
        $tvKeys = @()
        if ($previewMode -and $rows.Count -gt 0) {
            $tw = Get-NodePreviewWindow $rows $cursor
            $keepPv = @{}; foreach ($pk in $tw.Keys) { $keepPv[$pk] = $true }
            Restrict-PreviewPrefetch $keepPv
            Start-PreviewPrefetch $tw.Reqs
            $tvKeys = $tw.Keys
            if (-not $script:CanRawKey -and $cur) {
                $selKey = Get-NodePreviewKey $cur.Node
                if (Test-PreviewLoading $selKey) { Wait-Preview $selKey 5000 }
            }
        } else {
            Restrict-PreviewPrefetch @{}; Receive-PreviewPrefetch
        }

        # Pane geometry.
        $rightW = [Math]::Max(24, [int]($w * 0.34))
        $leftW  = $w - $rightW - 3
        if ($leftW -lt 24) { $leftW = 24; $rightW = [Math]::Max(10, $w - 3 - $leftW) }

        $L = [Collections.Generic.List[string]]::new()
        $title = '  ARTCA  Archive Tree  '
        $url   = $BaseUrl
        $avail = $w - $title.Length - 4
        if ($url.Length -gt $avail) { $url = Clip $url ([Math]::Max(1, $avail)) }
        $rt    = "  $url  "
        $gap   = [Math]::Max(0, $w - $title.Length - $rt.Length)
        $L.Add("${HB}${BD}${MG}${title}${R}${HB}$(' ' * $gap)${DM}${rt}${R}")
        $L.Add("$DM$(HR $w)$R")
        $L.Add("  ${YL}$script:ArcGlyph${R} ${BD}${CY}$(Trunc ([string]$item.Name) ($w - 8))${R}")
        if ($notice.Message -and ([DateTime]::UtcNow - $notice.At).TotalSeconds -lt 8) {
            $L.Add("  $($notice.Message)")
        } else {
            $curPath = if ($cur) { Get-NodeInternalPath $cur.Node } else { '' }
            $L.Add("  ${DM}$(Trunc ('/' + $curPath) ($w - 4))${R}")
        }
        # Top border of the tree/detail panes: ┬ at the divider column (leftW+1).
        $L.Add("$DM$(HR-Join $w ($leftW + 1) ([char]0x252C))$R")

        $bodyH = [Math]::Max(3, (Get-Height) - 9)

        # Build the left (tree) lines, windowed around the cursor with indicators.
        $leftLines = [Collections.Generic.List[string]]::new()
        if ($rows.Count -eq 0) {
            $leftLines.Add("  ${DM}(empty archive)${R}")
        } else {
            if ($rows.Count -le $bodyH) { $sRow = 0; $eRow = $rows.Count - 1; $ind = $false }
            else {
                $winH = [Math]::Max(1, $bodyH - 2)
                $sRow = [Math]::Max(0, [Math]::Min($cursor - [int]($winH / 2), $rows.Count - $winH))
                $eRow = $sRow + $winH - 1
                $ind  = $true
            }
            if ($ind) { $leftLines.Add("  ${DM}$([char]0x2191) $sRow more${R}") }
            for ($i = $sRow; $i -le $eRow; $i++) {
                $row = $rows[$i]
                $sel = ($i -eq $cursor)

                $pfx = ''
                if ($row.Depth -gt 0) {
                    # Skip the synthetic root's own slot in the ancestor chain.
                    for ($d = 1; $d -lt $row.AncestorLast.Count; $d++) {
                        $pfx += if ($row.AncestorLast[$d]) { $gapS } else { $vert }
                    }
                    $pfx += if ($row.IsLast) { $ell } else { $tee }
                }

                # Trailing badges (reserve 2 cols so they survive name truncation):
                #  '+'  a never-opened folder — it has contents not yet looked in.
                #  '·'  a previewable plain file.
                # Once a folder is opened the '+' is gone for good (even after a
                # collapse) since $seen, unlike IsOpen, never resets. Sub-archives
                # get neither badge — they're treated as plain, non-expandable files.
                $unseen = $row.IsFolder -and $row.HasKids -and -not $seen.Contains($row.Key)
                $pv     = (-not $row.IsFolder) -and (-not $row.IsArchive) -and (Get-IsPreviewable $row.Name)

                # Downloaded files render washed-out (dim); a failed preview fetch
                # (e.g. blacked-out repo) flags the entry red.
                $dlVisited = (-not $row.IsFolder) -and (Test-Visited (Get-EntryUrl $row.Node))
                $entryErr  = Test-NodePreviewError $row.Node

                $disp  = if ($row.IsFolder) { "$($row.Name)/" } else { $row.Name }
                $nameW = [Math]::Max(1, $leftW - 2 - $pfx.Length)
                if ($unseen -or $pv) { $nameW = [Math]::Max(1, $nameW - 2) }
                $disp  = Trunc $disp $nameW
                # The '·' badge is red on error, else starts grey in preview mode and
                # turns yellow once this entry's preview has loaded in the background.
                $pvCol = if ($entryErr) { $RD }
                         elseif ($dlVisited) { $DM }
                         elseif ($previewMode) {
                             $pk = Get-NodePreviewKey $row.Node
                             if ($pk -and $script:PreviewCache.ContainsKey($pk)) { $YL } else { $DM }
                         } else { $YL }
                $badge = if ($unseen) { "${YL} +${R}" }
                         elseif ($pv) { "${pvCol} $script:PreviewGlyph${R}" }
                         else { '' }

                # Sub-archives share the plain-file styling (same colour); their only
                # distinction shows in the preview pane.
                $gutter = if ($sel) { "${BD}${YL}>${R} " } else { '  ' }
                $body = if ($row.IsFolder) {
                    if ($sel) { "${BD}${MG}$disp${R}$badge" } else { "${MG}$disp${R}$badge" }
                } elseif ($entryErr) {
                    if ($sel) { "${BD}${RD}$disp${R}$badge" } else { "${RD}$disp${R}$badge" }
                } else {
                    if ($dlVisited) { if ($sel) { "${BD}${DM}$disp${R}$badge" } else { "${DM}$disp${R}$badge" } }
                    elseif ($sel)   { "${BD}${CY}$disp${R}$badge" } else { "$disp$badge" }
                }
                $leftLines.Add("$gutter${DM}$pfx${R}$body")
            }
            if ($ind) { $leftLines.Add("  ${DM}$([char]0x2193) $($rows.Count - 1 - $eRow) more${R}") }
        }

        # Build the right (detail) lines for the hovered node. In preview mode a
        # file's contents are shown underneath its details.
        $detail = @()
        if ($cur) {
            if ($cur.Node.PSObject.Properties['__root']) { $detail = @(Get-ArchiveItemDetailLines $item $rootInfo $rightW) }
            else {
                $detail = @(Get-NodeDetailLines $cur.Node $rightW)
                if ($previewMode -and -not $cur.IsFolder) {
                    if ($cur.IsArchive) {
                        $detail += @(Get-PreviewMessageLines "Nested archive contents can't be browsed or previewed." $rightW)
                    } else {
                        $info = Get-NodeInfo $cur.Node
                        $sz   = if ($info -and $info.PSObject.Properties['size']) { [long]$info.size } else { -1 }
                        $detail += @(Get-PreviewLines (Get-NodeName $cur.Node) (Get-EntryUrl $cur.Node) $sz $rightW ($bodyH - $detail.Count - 2))
                    }
                }
            }
        }

        # Compose the two panes row by row. Fit-Vis pins the left cell to exactly
        # $leftW columns so the divider stays perfectly straight.
        for ($i = 0; $i -lt $bodyH; $i++) {
            $lc = if ($i -lt $leftLines.Count) { $leftLines[$i] } else { '' }
            $rc = if ($i -lt $detail.Count)    { $detail[$i] }    else { '' }
            if ($rc -eq $script:PaneRuleTag) { $L.Add((Format-PaneRule $lc $leftW $rightW)) }
            else { $L.Add("$(Fit-Vis $lc $leftW) ${DM}$vbar${R} $rc") }
        }

        # Footer (two hint lines), justified across the full width. The hints adapt
        # to the highlighted row: only actions actually possible for that selection
        # are shown — no expand/collapse on a plain file, no download on a folder.
        # Bottom border closes the panes: ┴ at the divider column (leftW+1).
        $L.Add("$DM$(HR-Join $w ($leftW + 1) ([char]0x2534))$R")
        $canExpand   = [bool]($cur -and $cur.Expandable)
        $canDownload = [bool]($cur -and -not $cur.IsFolder)
        # 'c' collapses the current node if open, else its (non-root) parent.
        $canCollapse = [bool]($cur -and ($cur.IsOpen -or
                       ($cur.Parent -and -not $cur.Node.PSObject.Properties['__root'])))
        $actVerb = if ($canExpand)        { if ($cur.IsOpen) { 'collapse' } else { 'expand' } }
                   elseif ($canDownload)  { 'download' } else { '' }
        $pvLabel = if ($previewMode) { 'preview off' } else { 'preview on' }

        $r1 = [Collections.Generic.List[string]]::new()
        $r1.Add("${BD}${LB}$([char]0x2191)$([char]0x2193)${RB}${R}${DM} move${R}")
        if ($actVerb)   { $r1.Add("${BD}${LB}$([char]0x21B5)${RB}${R}${DM} $actVerb${R}") }
        if ($canExpand) {
            $r1.Add("${BD}${LB}e${RB}${R}${DM} expand level${R}")
            $r1.Add("${BD}${LB}E${RB}${R}${DM} expand all${R}")
        }
        if ($canCollapse) { $r1.Add("${BD}${LB}c${RB}${R}${DM} collapse${R}") }
        $r1.Add("${BD}${LB}C${RB}${R}${DM} collapse all${R}")
        $r1.Add("${BD}${LB}v${RB}${R}${DM} $pvLabel${R}")

        $r2 = [Collections.Generic.List[string]]::new()
        $r2.Add("${BD}${LB}g/G${RB}${R}${DM} top/bottom${R}")
        $r2.Add("${BD}${LB}n/p${RB}${R}${DM} next/prev folder${R}")
        $r2.Add("${BD}${LB}/${RB}${R}${DM} search${R}")
        if ($canDownload)                  { $r2.Add("${BD}${LB}d${RB}${R}${DM} download${R}") }
        if ($previewMode -and $canDownload) { $r2.Add("${BD}${LB}y${RB}${R}${DM} preview big${R}") }
        $r2.Add("${BD}${LB}q${RB}${R}${DM} back${R}")
        $L.Add((Join-Justified $r1.ToArray() $w))
        $L.Add((Join-Justified $r2.ToArray() $w))

        Show-Frame $L.ToArray()

        # Poll (non-blocking) while a windowed preview is still loading so the pane
        # and badges fill in live; otherwise block for the next key. A timeout just
        # reaps and loops, redrawing with whatever has landed.
        $kc = if ($previewMode -and $script:CanRawKey -and (Get-PreviewLoadingCount $tvKeys) -gt 0) {
                  Read-KeyTimeoutCased 120
              } else { Read-KeyCased }
        if ($null -eq $kc) { Receive-PreviewPrefetch; continue }

        switch -regex -casesensitive ($kc) {
            '^(up|k)$'   { if ($cursor -gt 0)               { $cursor-- } }
            '^(down|j)$' { if ($cursor -lt $rows.Count - 1) { $cursor++ } }
            '^home$'     { $cursor = 0 }
            '^end$'      { $cursor = $rows.Count - 1 }
            '^g$'        { $cursor = 0 }
            '^G$'        { $cursor = $rows.Count - 1 }

            '^(enter|o)$' {
                if ($cur -and $cur.Expandable) {
                    if ($cur.IsOpen) { [void]$expanded.Remove($cur.Key) }
                    else { $msg = Expand-TreeNodeInline $cur $item $subCache $expanded
                           if ($msg) { $notice = @{ Message = $msg; At = [DateTime]::UtcNow } } }
                    $rebuild = $true
                } elseif ($cur) {
                    Download-EntryInline $cur $item ([ref]$notice) $w
                }
            }
            '^d$' { if ($cur -and -not $cur.IsFolder) { Download-EntryInline $cur $item ([ref]$notice) $w } }

            '^right$' {
                if ($cur -and $cur.Expandable -and -not $cur.IsOpen) {
                    $msg = Expand-TreeNodeInline $cur $item $subCache $expanded
                    if ($msg) { $notice = @{ Message = $msg; At = [DateTime]::UtcNow } }
                    $rebuild = $true
                } elseif ($cursor -lt $rows.Count - 1) { $cursor++ }
            }
            '^left$' {
                if ($cur -and $cur.Expandable -and $cur.IsOpen) {
                    [void]$expanded.Remove($cur.Key); $rebuild = $true
                } elseif ($cur -and $cur.Parent) {
                    $forceKey = Get-NodeKey $cur.Parent; $rebuild = $true
                }
            }

            '^e$' {
                # Expand all sibling folders at the current level. Only meaningful
                # when the selection itself is expandable (a folder); a no-op on a
                # file or sub-archive, matching the context menu.
                if ($cur -and $cur.Expandable) {
                    $parentNode = if ($cur.Parent) { $cur.Parent } else { $cur.Node }
                    foreach ($s in @(Get-NodeChildren $parentNode)) {
                        if (Get-NodeIsFolder $s) { [void]$expanded.Add((Get-NodeKey $s)) }
                    }
                    $rebuild = $true
                }
            }
            '^E$' { Add-AllFolderKeys @($rootNode) $expanded $subCache; $rebuild = $true }
            '^c$' {
                # Collapse the current folder (or the parent of the current file).
                if ($cur -and $cur.Expandable -and $cur.IsOpen) {
                    [void]$expanded.Remove($cur.Key); $rebuild = $true
                } elseif ($cur -and $cur.Parent -and -not $cur.Node.PSObject.Properties['__root']) {
                    [void]$expanded.Remove((Get-NodeKey $cur.Parent))
                    $forceKey = Get-NodeKey $cur.Parent; $rebuild = $true
                }
            }
            '^C$' {
                $expanded.Clear(); [void]$expanded.Add($rootKey)
                $cursor = 0; $rebuild = $true
            }

            '^n$' { for ($i = $cursor + 1; $i -lt $rows.Count; $i++) { if ($rows[$i].Expandable) { $cursor = $i; break } } }
            '^p$' { for ($i = $cursor - 1; $i -ge 0;            $i--) { if ($rows[$i].Expandable) { $cursor = $i; break } } }

            '^v$' { $previewMode = -not $previewMode }
            '^y$' {
                # Opt a large/unknown file into preview despite the size cap.
                if ($previewMode -and $cur -and -not $cur.IsFolder) {
                    [void]$script:PreviewOK.Add((Get-EntryUrl $cur.Node))
                }
            }

            '^(/|s)$' {
                if ($cur) {
                    $scopeNode = if (($cur.IsFolder) -or $cur.Node.PSObject.Properties['__root']) { $cur.Node }
                                 elseif ($cur.Parent) { $cur.Parent } else { $rootNode }
                    $q = Read-TreeQuery
                    if ($q) {
                        $pattern = if ($q -match '[*?]') { $q } else { "*$q*" }
                        $acc = [Collections.Generic.List[object]]::new()
                        Get-MatchingFiles (Get-NodeKidsResolved $scopeNode $subCache) $subCache $pattern $acc
                        $scopeLabel = Get-NodeInternalPath $scopeNode
                        Show-TreeSearchResults $acc $q $scopeLabel ([string]$item.Name)
                    }
                }
            }

            '^(b|q|backspace)$' { return }
        }
    }
}

# Mark a folder node expanded. Only folders are expandable (sub-archives are
# treated as plain files), so this is a simple set insert; the $item/$subCache
# parameters are kept for call-site symmetry. Returns '' (no failure path).
function Expand-TreeNodeInline($cur, $item, $subCache, $expanded) {
    if (-not $cur.Expandable) { return '' }
    [void]$expanded.Add($cur.Key)
    return ''
}

# Download the selected internal entry, reporting via the tree's $notice line.
function Download-EntryInline($cur, $item, [ref]$Notice, [int]$w) {
    if ($cur.IsFolder) { return }
    Show-Popup @("Downloading", $cur.Name)
    $sub = ([string]$item.Name) -replace '[\\/:*?"<>|]', '_'
    $Notice.Value = @{ Message = (Save-ArchiveEntry $cur.Node $sub); At = [DateTime]::UtcNow }
    Mark-Visited (Get-EntryUrl $cur.Node)
}

# Item detail screen with download / back / quit. Returns 'back' or 'quit'.
function View-Item([object]$item, [int]$Number) {
    Initialize-RepoMap   # so repo/package type are accurate even from simple view
    $w      = ((Get-Width) - 1)
    $labelW = 14
    $valMax = [Math]::Max(10, $w - 2 - $labelW)

    # Pull full storage info for rich detail + the real download URL.
    $info = $null
    try { $info = Invoke-RestMethod -Uri $item.Uri -Headers (Get-AuthHeaders) -ErrorAction Stop } catch { }

    $repo  = if ($item.Repo) { $item.Repo } else { '?' }
    $rmeta = Resolve-Repo $repo
    $size = ''; $modified = ''; $mime = ''; $dl = ''
    if ($info) {
        if ($info.PSObject.Properties['size'])         { $size     = Format-Size $info.size }
        if ($info.PSObject.Properties['lastModified']) { $modified = "$($info.lastModified)" }
        if ($info.PSObject.Properties['mimeType'])     { $mime     = "$($info.mimeType)" }
        if ($info.PSObject.Properties['downloadUri'])  { $dl       = "$($info.downloadUri)" }
    }
    if (-not $dl) {
        $seg = if ($item.Path) { "$($item.Path)/" } else { '' }
        $dl  = "$(Get-ArtBase)/$repo/$seg$($item.Name)"
    }

    $isArchive = Get-IsArchive ([string]$item.Name)

    while ($true) {
        $L = [Collections.Generic.List[string]]::new()
        $title = '  ARTCA  Item Detail  '
        $url   = $BaseUrl
        $avail = $w - $title.Length - 4
        if ($url.Length -gt $avail) { $url = Clip $url ([Math]::Max(1, $avail)) }
        $right = "  $url  "
        $gap   = [Math]::Max(0, $w - $title.Length - $right.Length)
        $L.Add("${HB}${BD}${MG}${title}${R}${HB}$(' ' * $gap)${DM}${right}${R}")
        $L.Add("$DM$(HR $w)$R")

        $arcTag = if ($isArchive) { "  ${YL}$script:ArcGlyph archive${R}" } else { '' }
        $L.Add("  ${BD}${CY}$(Trunc ([string]$item.Name) $valMax)${R}   ${DM}#$Number${R}$arcTag")
        $L.Add("$DM$(HR $w)$R")

        $L.Add("  ${DM}$('Repository'.PadRight($labelW))${R}${MG}$(Trunc $repo $valMax)${R}")
        $L.Add("  ${DM}$('Path'.PadRight($labelW))${R}$(Trunc ([string]$item.Path) $valMax)")
        $L.Add("  ${DM}$('Type'.PadRight($labelW))${R}${YL}$(Trunc ([string]$item.FileType) $valMax)${R}")
        $L.Add("  ${DM}$('Size'.PadRight($labelW))${R}$size")
        $L.Add("  ${DM}$('Modified'.PadRight($labelW))${R}$modified")
        $L.Add("  ${DM}$('Repo type'.PadRight($labelW))${R}$($rmeta.Type)")
        $L.Add("  ${DM}$('Package type'.PadRight($labelW))${R}${MG}$($rmeta.PackageType)${R}")
        if ($mime) { $L.Add("  ${DM}$('MIME'.PadRight($labelW))${R}$(Trunc $mime $valMax)") }
        # Download URL: word-wrapped across lines so it's never truncated and stays
        # fully clickable.
        $dlWrap = @(Wrap-Text $dl ($w - $labelW - 2))
        $L.Add("  ${DM}$('Download'.PadRight($labelW))${R}${CY}$($dlWrap[0])${R}")
        for ($k = 1; $k -lt $dlWrap.Count; $k++) { $L.Add("  $(' ' * $labelW)${CY}$($dlWrap[$k])${R}") }

        $L.Add("$DM$(HR $w)$R")
        $fnav = [Collections.Generic.List[string]]::new()
        $fnav.Add("${BD}${LB}d${RB}${R}${DM} download${R}")
        if ($isArchive) { $fnav.Add("${BD}${LB}t${RB}${R}${DM} browse archive${R}") }
        $fnav.Add("${BD}${LB}b${RB}${R}${DM} back to results${R}")
        $fnav.Add("${BD}${LB}q${RB}${R}${DM} quit${R}")
        $L.Add("  $($fnav -join '   ')")
        Show-Frame $L.ToArray()

        switch -regex (Read-Key) {
            '^d$' {
                Show-Popup @("Downloading", $item.Name)
                # Stash the result as a flash notice and return to the results
                # page (the user wanted download to drop them back, not linger).
                $script:Flash.Message = Save-Item $item $dl
                $script:Flash.At      = [DateTime]::UtcNow
                Mark-Visited ([string]$item.Uri)
                return 'back'
            }
            '^t$' { if ($isArchive) { Show-ArchiveTree $item } }
            '^b$' { return 'back' }
            '^s$' { return 'back' }
            '^q$' { return 'quit' }
        }
    }
}

# Act on a chosen result row, per the current view:
#   simple              -> open the detail page (archives get a browse/explore
#                          option inside View-Item, shown like any other file).
#   detailed / preview  -> archives open the tree browser; plain files download
#                          straight away and flash the result on the results page.
# Returns 'quit' to exit the app, otherwise ''.
function Invoke-ItemAction([object]$chosen, [int]$Number, [string]$Mode) {
    Mark-Visited ([string]$chosen.Uri)
    if ($Mode -eq 'simple') {
        return (View-Item $chosen $Number)            # 'back' or 'quit'
    }
    if (Get-IsArchive ([string]$chosen.Name)) {
        Show-ArchiveTree $chosen
        return ''
    }
    Show-Popup @("Downloading", $chosen.Name)
    $script:Flash.Message = Save-Item $chosen (Get-ItemUrl $chosen)
    $script:Flash.At      = [DateTime]::UtcNow
    return ''
}

# ── INPUT ─────────────────────────────────────────────────────────────────────

function Read-Query {
    Clear-Screen
    Write-Host "  ${BD}${MG}ARTCA${R}  ${DM}$BaseUrl${R}`n"
    Write-Host "  ${DM}Examples:  *.env   *.properties   myapp   secret.xml${R}`n"
    Write-Host -NoNewline "  Search: ${BD}${CY}"
    $q = Read-Host
    Write-Host -NoNewline $R
    return $q.Trim()
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
if (-not $query) { exit }

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
