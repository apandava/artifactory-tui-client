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
$script:Visited      = New-Object 'System.Collections.Generic.HashSet[string]'
$script:MemFiles     = @{}                                              # url -> [byte[]]
$script:MemOrder     = [Collections.Generic.List[string]]::new()        # insertion order, for eviction
$script:MemFilesCap  = 32                                               # max files held for download reuse
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
$script:WrapCacheKey      = ''
$script:WrapCacheLines    = @()
$script:ArcListCacheKey   = ''
$script:ArcListCacheLines = @()

# Window a list of rendered content lines around a scroll offset, adding a
# "N more above" / "N more below" indicator row (each consuming one line) whenever
# content lies off-pane in that direction. Sets $script:PvScrollMax so the nav loop
# can clamp the offset; returns the lines unchanged when everything already fits.
# The +1 in $PvScrollMax accounts for the top indicator's row, so the last content
# line is still reachable at maximum scroll. A pane too short for indicators
# (< 3 rows) falls back to a plain window.
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

    $script:PvScrollMax = $total - $avail + 1
    $sc  = [Math]::Max(0, [Math]::Min($scroll, $script:PvScrollMax))
    $top = ($sc -gt 0)
    $contentH = $avail - $(if ($top) { 1 } else { 0 })
    $end = [Math]::Min($total - 1, $sc + $contentH - 1)
    if (($total - 1 - $end) -gt 0) { $contentH--; $end = $sc + $contentH - 1 }   # reserve bottom indicator
    $below = $total - 1 - $end
    $out = [Collections.Generic.List[string]]::new()
    if ($top)         { $out.Add("${DM}$([char]0x2191) $sc more above${R}") }
    for ($i = $sc; $i -le $end; $i++) { $out.Add($lines[$i]) }
    if ($below -gt 0) { $out.Add("${DM}$([char]0x2193) $below more below${R}") }
    return $out.ToArray()
}

# Cache a file's raw bytes by url so a later download can reuse them instead of
# re-fetching, bounded to $MemFilesCap entries (oldest evicted first). The bytes
# are the SAME array the preview cache holds (shared by reference, not copied), so
# this adds only a dictionary entry, never a second copy of the file. Eviction
# only means a re-fetch on a later download, which is user-initiated and rare.
function Add-MemFile([string]$url, [byte[]]$bytes) {
    if (-not $url -or $null -eq $bytes -or $script:MemFiles.ContainsKey($url)) { return }
    $script:MemFiles[$url] = $bytes
    $script:MemOrder.Add($url)
    while ($script:MemOrder.Count -gt $script:MemFilesCap) {
        $old = $script:MemOrder[0]; $script:MemOrder.RemoveAt(0)
        [void]$script:MemFiles.Remove($old)
    }
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

function Mark-Visited([string]$key) { if ($key) { [void]$script:Visited.Add($key) } }
function Test-Visited([string]$key) { return ($key -and $script:Visited.Contains($key)) }

# Files written to disk this session (keyed by both storage key and download url).
# A downloaded file's preview is no longer fetched/shown and its cached bytes are
# purged: re-download is the way to see it again. Keeps memory down and avoids
# re-fetching content the user already has on disk.
$script:Downloaded = New-Object 'System.Collections.Generic.HashSet[string]'
function Test-Downloaded([string]$k) { return ($k -and $script:Downloaded.Contains($k)) }

# Mark a file downloaded: record it (so it greys out + is skipped for preview),
# drop any cached bytes, and evict its resolved preview so it isn't redrawn.
function Mark-Downloaded([string]$key, [string]$url) {
    Mark-Visited $key
    if ($key) { [void]$script:Downloaded.Add($key) }
    if ($url) {
        [void]$script:Downloaded.Add($url)
        if ($script:MemFiles.ContainsKey($url)) {
            [void]$script:MemFiles.Remove($url)
            $idx = $script:MemOrder.IndexOf($url); if ($idx -ge 0) { $script:MemOrder.RemoveAt($idx) }
        }
        $pk = Get-FilePreviewKey $url
        if ($script:PreviewCache.ContainsKey($pk)) { [void]$script:PreviewCache.Remove($pk) }
    }
}

# Append one row to download-log.csv in the folder the file was saved to (created
# with a header on first write). Every download — audit or not — is logged here;
# non-audit downloads pass 'N/A' for severity/rule. Quoting is RFC-4180; the file
# is UTF-8. Failures are swallowed so logging never blocks a download.
function Write-DownloadLog([string]$dir, [string]$name, [string]$repo, [string]$path,
                           [long]$sizeBytes, [string]$modified, [string]$url,
                           [string]$severity, [string]$rule) {
    try {
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $csv  = Join-Path $dir 'download-log.csv'
        $q    = { param($v) '"' + ("$v" -replace '"','""') + '"' }
        $cols = @('Timestamp','FileName','Repository','Path','SizeBytes','Modified','DownloadUrl','Severity','MatchedRule')
        $sz   = if ($sizeBytes -ge 0) { "$sizeBytes" } else { '' }
        $row  = @((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $name, $repo, $path, $sz, $modified, $url,
                  $(if ($severity) { $severity } else { 'N/A' }), $(if ($rule) { $rule } else { 'N/A' }))
        $new = -not (Test-Path -LiteralPath $csv)
        $sb  = [Text.StringBuilder]::new()
        if ($new) { [void]$sb.AppendLine((@($cols | ForEach-Object { & $q $_ }) -join ',')) }
        [void]$sb.AppendLine((@($row | ForEach-Object { & $q $_ }) -join ','))
        [System.IO.File]::AppendAllText($csv, $sb.ToString(), [Text.UTF8Encoding]::new($false))
    } catch { }
}

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
            $L.Add("${DM}This file format can't be previewed.${R}")
            $L.Add("${YL}Press [y] to force preview${R}${DM} (extract readable text).${R}")
            return $L.ToArray()
        }
        'force-toolarge' {
            $L.Add("${DM}This file format can't be previewed.${R}")
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
    if     (Get-IsArchive $name) { $glyph = $script:ArcGlyph }
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

function Show-Page([string]$Query, [object[]]$Items, [int]$Page,
                   [int]$TotalPages, [int]$TotalItems, [int]$Offset,
                   [string]$Mode = 'simple', [int]$SelRow = -1, [int]$PvScroll = 0,
                   [object[]]$ExcludeRx = @(), [string]$Filter = '') {

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
        # Excluded (filter-matched) rows wash out like visited rows; the nav loop has
        # already sorted them to the back.
        $vis  = (Test-Visited ([string]$item.Uri)) -or (Test-NameMatchesAny ([string]$item.Name) $ExcludeRx)
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
            $rl.Add("${DM}$('Type'.PadRight($labelW))${R}${YL}$(Trunc ([string]$sItem.FileType) $valMax)${R}")
            $rl.Add("${DM}$('Size'.PadRight($labelW))${R}$szTxt")
            if ($sItem.Modified) { $rl.Add("${DM}$('Modified'.PadRight($labelW))${R}$(Trunc ([string]$sItem.Modified) $valMax)") }
            $rl.Add("${DM}$('Repo type'.PadRight($labelW))${R}$($rmeta.Type)")
            $rl.Add("${DM}$('Pkg type'.PadRight($labelW))${R}${MG}$($rmeta.PackageType)${R}")
            $pvMax  = [Math]::Max(1, $bodyH - $rl.Count - 2)
            $pvLines = if (Get-IsArchive ([string]$sItem.Name)) {
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
        if (-not (Get-IsArchive ([string]$sIt.Name))) {
            $sUrl = Get-ItemUrl $sIt
            $sSz  = if ("$($sIt.Size)" -ne '' -and "$($sIt.Size)" -ne '?') { [long]$sIt.Size } else { -1 }
            switch (Get-PreviewState ([string]$sIt.Name) $sUrl $sSz) {
                'large-gated' { $nav.Add("${BD}${LB}y${RB}${R}${DM} preview large${R}") }
                'force-gated' { $nav.Add("${BD}${LB}y${RB}${R}${DM} force preview${R}") }
            }
        }
    }
    if ($preview -and $script:PvScrollMax -gt 0) { $nav.Add("${BD}${LB}Shift+$([char]0x2191)$([char]0x2193)${RB}${R}${DM} scroll${R}") }
    $nav.Add("${BD}${LB}#${RB}${R}${DM} view${R}")
    $nextMode = switch ($Mode) { 'simple' { 'detailed' } 'detailed' { 'preview' } default { 'simple' } }
    $nav.Add("${BD}${LB}d${RB}${R}${DM} $nextMode view${R}")
    $nav.Add("${BD}${LB}s${RB}${R}${DM} search${R}")
    $nav.Add("${BD}${LB}f${RB}${R}${DM} filter$(if (@($ExcludeRx).Count -gt 0) { " ($(@($ExcludeRx).Count))" })${R}")
    if (@($ExcludeRx).Count -gt 0) { $nav.Add("${BD}${LB}i${RB}${R}${DM} show all${R}") }
    if ($script:AuditAvailable) {
        $aLbl = if ($script:AuditState -eq 'passive') { "${YL}audit: passive${R}${DM}" } else { 'audit' }
        $nav.Add("${BD}${LB}a${RB}${R}${DM} $aLbl${R}")
    }
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
            $len = -1; try { $len = (Get-Item $dest).Length } catch { }
            Write-DownloadLog $OutDir ([string]$item.Name) ([string]$item.Repo) ([string]$item.Path) $len ([string]$item.Modified) $url '' ''
            Mark-Downloaded ([string]$item.Uri) $url
            $sz = if ($len -ge 0) { ' (' + (Format-Size $len) + ')' } else { '' }
            return "${BD}Saved${R} to ${CY}$dest${R}$sz ${DM}(from preview cache)${R}"
        } catch { }   # fall through to a normal download on any write error
    }
    $old  = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        Invoke-WebRequest -Uri $url -Headers (Get-AuthHeaders) -OutFile $dest -ErrorAction Stop
        $len = -1; try { $len = (Get-Item $dest).Length } catch { }
        Write-DownloadLog $OutDir ([string]$item.Name) ([string]$item.Repo) ([string]$item.Path) $len ([string]$item.Modified) $url '' ''
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

