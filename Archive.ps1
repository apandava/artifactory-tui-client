# Archive.ps1 — part of the ARTCA Artifactory TUI (see StartTui.ps1).
#
# This file holds function and $script:-state definitions only; nothing here runs
# on its own. It is loaded two ways:
#   · dot-sourced automatically by StartTui.ps1 when the tool is run as a file, or
#   · pasted directly into the PowerShell console (paste the component files first,
#     then StartTui.ps1 last) to run the tool without executing the .ps1 files.
# Load order among the component files does not matter.
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
    $pendingKc   = $null   # non-row key handed back by a coalesced up/down burst

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
            Restrict-PreviewCache $keepPv   # bound the cache; the window is protected
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
        if ($pendingKc) {
            $kc = $pendingKc; $pendingKc = $null
        } elseif ($previewMode -and $script:CanRawKey -and (Get-PreviewLoadingCount $tvKeys) -gt 0) {
            $kc = Read-KeyTimeoutCased 120
        } else {
            # Idle: about to block for the next key. Free the background pools'
            # runspaces if nothing is in flight; they reopen lazily on next use.
            Receive-PreviewPrefetch
            if ($script:PvJobs.Count -eq 0) { Close-PrefetchPools }
            $kc = Read-KeyCased
        }
        if ($null -eq $kc) { Receive-PreviewPrefetch; continue }

        switch -regex -casesensitive ($kc) {
            '^(up|k|down|j)$' {
                # Coalesce a held up/down burst into one net cursor move so holding
                # the key doesn't backlog renders (see Invoke-TreeRowBurst).
                $d = if ($kc -cmatch '^(down|j)$') { 1 } else { -1 }
                Invoke-TreeRowBurst ([ref]$cursor) $rows.Count ([ref]$pendingKc) $d
            }
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

