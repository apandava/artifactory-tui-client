# Core.ps1 — headless shared layer of the ARTCA Artifactory tool.
#
# This file holds the NON-INTERACTIVE primitives shared by every run-mode: the
# search/download data layer, hashing + dedup-download engine, the download-log CSV
# writer, visited/bytes tracking, archive tree-data accessors, and a couple of pure
# utilities. It has NO terminal/UI dependency, so it is loaded by BOTH the TUI
# (StartTui.ps1) and the non-interactive audit engine (StartAuditEngine.ps1).
#
# Like the other component files it holds function/$script:-state definitions only;
# nothing here runs on its own. It is loaded two ways:
#   · dot-sourced automatically by a launcher when run as a file, or
#   · pasted directly into the console (components first, launcher last).
# Load order among the component files does not matter (names bind at call time).
#
# File conventions match the rest of the codebase: UTF-8 without BOM, LF endings,
# any non-ASCII glyph that affects execution is a numeric [char] escape.

# ── PURE UTILITIES ────────────────────────────────────────────────────────────
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

# ── BACKGROUND-WORKER ERROR PARSER ────────────────────────────────────────────
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

# ── VISITED / DOWNLOADED / BYTES TRACKING ─────────────────────────────────────
# Items the user has opened/viewed/downloaded (keys: storage uri or download url),
# rendered washed-out afterwards. Preview content is cached in memory by download
# url so a later download reuses it instead of re-fetching.
$script:Visited      = New-Object 'System.Collections.Generic.HashSet[string]'
$script:MemFiles     = @{}                                              # url -> [byte[]]
$script:MemOrder     = [Collections.Generic.List[string]]::new()        # insertion order, for eviction
$script:MemFilesCap  = 32                                               # max files held for download reuse

# Files written to disk this session (keyed by both storage key and download url).
# A downloaded file's preview is no longer fetched/shown and its cached bytes are
# purged: re-download is the way to see it again. Keeps memory down and avoids
# re-fetching content the user already has on disk.
$script:Downloaded = New-Object 'System.Collections.Generic.HashSet[string]'

function Mark-Visited([string]$key) { if ($key) { [void]$script:Visited.Add($key) } }
function Test-Visited([string]$key) { return ($key -and $script:Visited.Contains($key)) }
function Test-Downloaded([string]$k) { return ($k -and $script:Downloaded.Contains($k)) }

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

# Purge a url's cached preview bytes and resolved preview from memory so held content
# is freed; a later preview re-fetches. Used both when a file is downloaded and when an
# audit finding is excluded. The resolved-preview eviction is a TUI concern: it is
# skipped when the preview layer (Prefetch.ps1) isn't loaded — i.e. the headless engine.
function Clear-PreviewMem([string]$url) {
    if (-not $url) { return }
    if ($script:MemFiles.ContainsKey($url)) {
        [void]$script:MemFiles.Remove($url)
        $idx = $script:MemOrder.IndexOf($url); if ($idx -ge 0) { $script:MemOrder.RemoveAt($idx) }
    }
    if (Get-Command Get-FilePreviewKey -ErrorAction SilentlyContinue) {
        $pk = Get-FilePreviewKey $url
        if ($script:PreviewCache -and $script:PreviewCache.ContainsKey($pk)) { [void]$script:PreviewCache.Remove($pk) }
    }
}

# Mark a file downloaded: record it (so it greys out + is skipped for preview),
# drop any cached bytes, and evict its resolved preview so it isn't redrawn.
function Mark-Downloaded([string]$key, [string]$url) {
    Mark-Visited $key
    if ($key) { [void]$script:Downloaded.Add($key) }
    if ($url) {
        [void]$script:Downloaded.Add($url)
        Clear-PreviewMem $url
    }
}

# Reverse Mark-Downloaded: forget a file was downloaded so it returns to its normal
# (un-downloaded) state — no longer dimmed, and re-sorted out of the downloaded group.
# Purged preview bytes are not restored; a later preview just re-fetches them.
function Unmark-Downloaded([string]$key, [string]$url) {
    if ($key) { [void]$script:Visited.Remove($key); [void]$script:Downloaded.Remove($key) }
    if ($url) { [void]$script:Downloaded.Remove($url) }
}

# ── OFFLINE MODE ──────────────────────────────────────────────────────────────
# Controls how much we rely on the server vs. what's already on disk:
#   ''      online (default): search hits the server; content/previews/archive listings fetched.
#   'index' the local index is the ONLY catalogue - never issue search queries - but content,
#           previews, and archive listings are still fetched from the server on demand.
#   'all'   issue NO network requests whatsoever: search comes from the index, and content /
#           previews / archive listings are shown ONLY when already on disk (a downloaded file in
#           the downloads folder, tracked by download-log.csv) or in the index (archive listings).
# Two predicates derive the behaviour: Test-SearchLocalOnly (index OR all) gates search;
# Test-NetworkBlocked (all only) gates every other request.
$script:OfflineMode = ''
function Set-OfflineMode([string]$m) {
    $v = "$m".Trim().ToLower()
    if ($v -ne 'index' -and $v -ne 'all') { $v = '' }
    $script:OfflineMode = $v
}
function Get-OfflineMode      { return $script:OfflineMode }
function Test-SearchLocalOnly { return ($script:OfflineMode -eq 'index' -or $script:OfflineMode -eq 'all') }
function Test-NetworkBlocked  { return ($script:OfflineMode -eq 'all') }

# Disk fallback for offline 'all': resolve a download url to the bytes already saved under the
# downloads folder (download-log.csv maps DownloadUrl -> original FileName + content Hash). The
# saved file is either that FileName or, if a bulk download disambiguated a name collision, the
# dedup-tagged "<TAG>.<FileName>" (TAG = first 7 hex of the hash; see Get-DedupTag). $null when
# the url was never downloaded or the file is gone. Log parsed once, lazily.
$script:DownloadLogIndex       = $null
function Get-DownloadLogIndex {
    if ($null -ne $script:DownloadLogIndex) { return $script:DownloadLogIndex }
    $map = @{}
    try {
        $csv = Join-Path $OutDir 'download-log.csv'
        if (Test-Path -LiteralPath $csv) {
            foreach ($row in (Import-Csv -LiteralPath $csv)) {
                $u = "$($row.DownloadUrl)"
                if ($u -and $row.Timestamp) { $map[$u] = @{ FileName = "$($row.FileName)"; Hash = "$($row.Hash)" } }
            }
        }
    } catch { }   # missing/locked/headless-no-OutDir: just yields an empty map (nothing on disk)
    $script:DownloadLogIndex = $map
    return $map
}
# Invalidate the cached log index (call after a download appends a new row this session).
function Reset-DownloadLogIndex { $script:DownloadLogIndex = $null }
function Get-DownloadedBytes([string]$url) {
    if (-not $url) { return $null }
    $idx = Get-DownloadLogIndex
    if (-not $idx.ContainsKey($url)) { return $null }
    $rec = $idx[$url]
    $cands = [Collections.Generic.List[string]]::new()
    try {
        if ($rec.FileName) {
            $cands.Add((Join-Path $OutDir $rec.FileName))
            if ($rec.Hash) { $cands.Add((Join-Path $OutDir (Add-NameTag $rec.FileName (Get-DedupTag $rec.Hash $url)))) }
        }
    } catch { return $null }
    foreach ($p in $cands) {
        if (Test-Path -LiteralPath $p) { try { return [System.IO.File]::ReadAllBytes($p) } catch { } }
    }
    return $null
}

# ── TEXT-TYPE DETECTION ───────────────────────────────────────────────────────
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

# ── URLS / RAW FETCH ──────────────────────────────────────────────────────────
# Constructed download URL for a search item (repo/path/name under the REST base).
# An archive-entry result (from archive-search: carries InArchive + a precomputed
# EntryUrl of the repo/...zip!/entry form) is served straight from that EntryUrl, since
# its content lives inside an archive and can't be addressed by repo/path/name. This is
# the single chokepoint used by downloads, preview keys, and the previewable badge, so
# every one of those paths handles archive-entry results without further changes.
function Get-ItemUrl($item) {
    if ($item.PSObject.Properties['InArchive'] -and $item.InArchive -and
        $item.PSObject.Properties['EntryUrl'] -and "$($item.EntryUrl)") { return [string]$item.EntryUrl }
    $repo = if ($item.Repo) { $item.Repo } else { '' }
    $seg  = if ($item.Path) { "$($item.Path)/" } else { '' }
    return "$(Get-ArtBase)/$repo/$seg$($item.Name)"
}

# Name of the archive an item/finding came from (its content lives inside this archive
# file), or '' for a normal top-level artifact. Audit findings carry InArchive/ArchiveName;
# plain search items have neither, so they always return '' (never archive entries). The
# property guards keep this safe under Set-StrictMode.
function Get-ItemArchiveName($item) {
    if ($null -eq $item) { return '' }
    if ($item.PSObject.Properties['InArchive'] -and $item.InArchive -and
        $item.PSObject.Properties['ArchiveName']) { return [string]$item.ArchiveName }
    return ''
}

# True when a results item is a top-level archive the user can browse (open its tree).
# An archive-entry result (from archive-search) whose own name happens to look like an
# archive is NOT browsable - a nested sub-archive can't be listed - so it's handled as a
# plain downloadable file instead. Plain artifacts named *.zip/.jar/... are browsable.
function Test-ItemBrowsableArchive($item) {
    if ($null -eq $item) { return $false }
    if (Get-ItemArchiveName $item) { return $false }
    return (Get-IsArchive ([string]$item.Name))
}

# Fetch raw bytes for a url (no caching). $null on failure. In offline 'all' no request is made -
# the bytes come only from a previously-downloaded copy on disk (else $null).
function Get-FileBytes([string]$url) {
    if (Test-NetworkBlocked) { return (Get-DownloadedBytes $url) }
    $old = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'
    try {
        $resp = Invoke-WebRequest -Uri $url -Headers (Get-AuthHeaders) -UseBasicParsing -ErrorAction Stop
        if ($resp.RawContentStream) { return $resp.RawContentStream.ToArray() }
        if ($resp.Content -is [byte[]]) { return [byte[]]$resp.Content }
        return [Text.Encoding]::UTF8.GetBytes([string]$resp.Content)
    } catch { return $null }
    finally { $ProgressPreference = $old }
}

# ── ARCHIVE TREE-DATA ACCESSORS ───────────────────────────────────────────────
# Artifactory archives are listed via the UI tree-browser endpoint (the same call the
# web UI makes); these accessors read the returned node fields defensively. The
# INTERACTIVE archive browser lives in Archive.ps1; only the data layer is here.
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

# These accessors read node fields defensively: the display name lives under text
# (or name); a folder is flagged by folder/isFolder or implied by type; children
# holds the nested entries for a folder.
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

# Epoch-millis (as Artifactory reports archive-entry times) to a local datetime. Tolerant of
# an already-formatted value: a node reconstructed from the index carries its pre-formatted
# (or ISO) date string here, so a non-numeric date-looking input is passed through unchanged.
function Format-Epoch($ms) {
    $s = "$ms"
    if ($s -notmatch '^\d+$') { if ($s -match '\d{4}-\d{2}-\d{2}') { return $s }; return '' }
    try { return [DateTimeOffset]::FromUnixTimeMilliseconds([int64]$s).LocalDateTime.ToString('yyyy-MM-dd HH:mm') }
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

# Filename of the archive an internal entry lives in. The entry's download path has the
# form <...>/<archive>!/<internal-path>, so the segment just before the '!' separator is
# the containing archive. Returns '' if the node has no such path (not an archive entry).
function Get-EntryArchiveName($n) {
    $url = Get-EntryUrl $n
    if (-not $url) { return '' }
    $i = $url.IndexOf('!')
    if ($i -lt 0) { return '' }
    $before = $url.Substring(0, $i)
    return ($before -split '/')[-1]
}

# Internal (within-archive) path of a node, with the archive prefix stripped.
function Get-NodeInternalPath($n) {
    if ($null -eq $n) { return '' }
    $np = if ($n.PSObject.Properties['path'])        { "$($n.path)" }        else { '' }
    $ap = if ($n.PSObject.Properties['archivePath']) { "$($n.archivePath)" } else { '' }
    if ($ap -and $np.StartsWith($ap)) { return $np.Substring($ap.Length).TrimStart('/') }
    return $np
}

# Map a repo's rclass to the repoType string the UI tree-browser expects.
function Get-RepoTypeForUI([string]$repo) {
    switch ((Resolve-Repo $repo).Type.ToUpper()) {
        'LOCAL'   { return 'local'   }
        'REMOTE'  { return 'remote'  }
        'VIRTUAL' { return 'virtual' }
        'CACHE'   { return 'cached'  }
        default   { return 'local'   }
    }
}

# Build the treebrowser POST request (uri / body / headers / user-agent) without
# sending it. Shared by the synchronous Invoke-TreeBrowse and the background
# preview/audit workers (which can't call these helpers from their isolated runspace,
# so they need the request fully materialised on the main thread). A single POST
# returns the entire archive contents nested under each folder's 'children'.
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

# ── DOWNLOAD LOG (CSV) ────────────────────────────────────────────────────────
# Bulk-download progress hook. The TUI sets this to a Show-Popup wrapper; the headless
# engine sets a verbosity writer; left $null it's a no-op. Invoke-DedupDownload calls it
# through Report-DownloadProgress so it never references a UI primitive directly.
$script:DownloadProgress = $null
function Report-DownloadProgress([string[]]$lines) {
    if ($script:DownloadProgress) { & $script:DownloadProgress $lines }
}

# ── CSV ROW PRIMITIVES ────────────────────────────────────────────────────────
# Shared by the local index (Index.ps1) and the audit-match log (AuditEngine.ps1). All
# rows are RFC-4180 with EVERY field quoted and CR/LF stripped from values, so one record ==
# one line and a lazy [System.IO.File]::ReadLines streamer never has to buffer the file.
function Format-CsvRow([object[]]$fields) {
    $sb = [Text.StringBuilder]::new()
    for ($i = 0; $i -lt $fields.Count; $i++) {
        if ($i -gt 0) { [void]$sb.Append(',') }
        $v = ("$($fields[$i])" -replace "[`r`n]", ' ') -replace '"', '""'
        [void]$sb.Append('"').Append($v).Append('"')
    }
    return $sb.ToString()
}
# Parse one fully-quoted CSV line into a string list WITHOUT allocating an object per row
# (ConvertFrom-Csv is far heavier at millions of rows). Tolerant of a trailing newline.
function Read-CsvRow([string]$line) {
    $out = [Collections.Generic.List[string]]::new()
    $n = $line.Length; $i = 0
    $sb = [Text.StringBuilder]::new()
    while ($i -lt $n) {
        while ($i -lt $n -and $line[$i] -ne '"') { $i++ }   # skip to opening quote
        if ($i -ge $n) { break }
        $i++                                                 # past opening quote
        [void]$sb.Clear()
        while ($i -lt $n) {
            $ch = $line[$i]
            if ($ch -eq '"') {
                if ($i + 1 -lt $n -and $line[$i + 1] -eq '"') { [void]$sb.Append('"'); $i += 2; continue }
                $i++; break                                  # closing quote
            }
            [void]$sb.Append($ch); $i++
        }
        $out.Add($sb.ToString())
        if ($i -lt $n -and $line[$i] -eq ',') { $i++ }
    }
    return $out
}

# ── OUTPUT LAYOUT ──────────────────────────────────────────────────────────────
# Everything for one instance lives under output/<host>/ with three subfolders:
#   index/      the local index (CSV shards)        - Resolve-IndexPath (Index.ps1) points here
#   downloads/  saved files + download-log.csv       - $OutDir
#   audit/      <repo>-matches.csv match logs         - $AuditDir
# $OutDir stays owned by the launchers (a TUI param / a headless script var), so it is NOT
# declared here (declaring it would clobber the launcher value at load time). $OutDirExplicit
# records a user-supplied -OutDir/-o so Resolve-OutputPaths leaves it verbatim.
$script:OutputBase     = ''       # base 'output' dir; default ./output (override via Set-OutputBase)
$script:OutDirExplicit = $false   # user passed -OutDir/-o; keep it as given
$script:AuditDir       = ''       # <root>/audit, resolved per instance

function Set-OutputBase([string]$dir) { $script:OutputBase = $dir }
function Get-InstanceHostSafe {
    $hn = ''
    try { $hn = ([Uri]$BaseUrl).Host } catch { }
    if (-not $hn) { $hn = 'default' }
    return ($hn -replace '[^A-Za-z0-9._-]', '_')
}
function Get-OutputInstanceRoot {
    $base = if ($script:OutputBase) { $script:OutputBase } else { Join-Path (Get-Location).Path 'output' }
    return (Join-Path $base (Get-InstanceHostSafe))
}
# Resolve per-instance downloads ($OutDir) + audit ($AuditDir) dirs. Call after BaseUrl is
# known. An explicit -OutDir is kept; otherwise downloads default under the instance root.
# The index dir is resolved by Resolve-IndexPath (Index.ps1), sharing Get-OutputInstanceRoot.
function Resolve-OutputPaths {
    $root = Get-OutputInstanceRoot
    if (-not $script:OutDirExplicit) { $script:OutDir = Join-Path $root 'downloads' }
    $script:AuditDir = Join-Path $root 'audit'
}

# Append one row to a download/scrape log CSV in the folder the file was saved to
# (created with a header on first write). Every download — audit or not — is logged;
# non-audit downloads pass 'N/A' for severity/rule. Quoting is RFC-4180; the file is
# UTF-8 no-BOM. Failures are swallowed so logging never blocks a download.
#   -FileName  target csv name (default 'download-log.csv'; 'scrape-log.csv' for scrapes)
#   -Scrape    write the row with BLANK Timestamp and Hash (a scrape didn't download)
function Write-DownloadLog([string]$dir, [string]$name, [string]$repo, [string]$path, [string]$archive,
                           [long]$sizeBytes, [string]$modified, [string]$url,
                           [string]$severity, [string]$rule, [string]$hash = '',
                           [string]$fileName = 'download-log.csv', [switch]$Scrape) {
    try {
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $csv  = Join-Path $dir $fileName
        $q    = { param($v) '"' + ("$v" -replace '"','""') + '"' }
        # FileName is always the original Artifactory filename; Hash (its sha256) follows
        # so a bulk download saved under a disambiguated name can still be traced back.
        $cols = @('Timestamp','FileName','Hash','Repository','Path','Archive','SizeBytes','Modified','DownloadUrl','Severity','MatchedRule')
        $sz   = if ($sizeBytes -ge 0) { "$sizeBytes" } else { '' }
        $ts   = if ($Scrape) { '' } else { (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') }
        $hsh  = if ($Scrape) { '' } else { $hash }
        $row  = @($ts, $name, $hsh, $repo, $path, $archive, $sz, $modified, $url,
                  $(if ($severity) { $severity } else { 'N/A' }), $(if ($rule) { $rule } else { 'N/A' }))
        $new = -not (Test-Path -LiteralPath $csv)
        $sb  = [Text.StringBuilder]::new()
        if ($new) { [void]$sb.AppendLine((@($cols | ForEach-Object { & $q $_ }) -join ',')) }
        [void]$sb.AppendLine((@($row | ForEach-Object { & $q $_ }) -join ','))
        [System.IO.File]::AppendAllText($csv, $sb.ToString(), [Text.UTF8Encoding]::new($false))
    } catch { }
}

# ── DEDUP DOWNLOAD ENGINE ─────────────────────────────────────────────────────
function Add-NameTag([string]$name, [string]$tag) {
    return "$tag.$name"
}

# 7-char (uppercase) content tag for collision disambiguation: the first 7 hex of the
# file's checksum when known, else a deterministic MD5 of its identity string (so a given
# file always tags the same way regardless of what else is in the batch). $hash is
# '<algo>:<hex>', so drop the algorithm prefix before keeping hex digits (otherwise 'sha1:'
# would leak an 'a1').
function Get-DedupTag([string]$hash, [string]$fallback) {
    $hex = (("$hash" -split ':')[-1] -replace '[^0-9A-Fa-f]', '')
    if ($hex.Length -ge 7) { return $hex.Substring(0, 7).ToUpper() }
    $md5 = [Security.Cryptography.MD5]::Create()
    try {
        $h = $md5.ComputeHash([Text.Encoding]::UTF8.GetBytes("$fallback"))
        return ((($h | ForEach-Object { $_.ToString('x2') }) -join '').Substring(0, 7)).ToUpper()
    } finally { $md5.Dispose() }
}

# SHA-256 of a byte array as lowercase hex. Used to derive a content identity for items
# that have no storage checksum (notably archive entries), by hashing the bytes directly.
function Get-BytesSha256([byte[]]$bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '') }
    finally { $sha.Dispose() }
}

# Content hash of a just-saved file as '<algo>:<hex>', for logging a download whose hash
# wasn't known up front (archive entries have no storage checksum). Streams the file via
# Get-FileHash so a large download isn't read wholly into memory. '' on any failure.
function Get-FileSha256([string]$path) {
    try { return 'sha256:' + ((Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()) }
    catch { return '' }
}

# Fetch an entry's bytes for hashing/writing, reusing preview-cache bytes when held.
function Get-DedupBytes($e) {
    if ($script:MemFiles.ContainsKey([string]$e.Url)) { return $script:MemFiles[[string]$e.Url] }
    return Get-FileBytes ([string]$e.Url)
}

# Write $bytes to $dest. Returns $true on success.
function Save-DedupFile([string]$dest, [byte[]]$bytes) {
    try { [System.IO.File]::WriteAllBytes($dest, $bytes); return $true } catch { return $false }
}

# Log a download-log.csv row for $e (its original name + the content $hash) and mark it
# downloaded. Called once per entry even when several share one on-disk file.
function Write-DedupEntry($e, [string]$hash) {
    $sz = if ($e.Size -ge 0) { [long]$e.Size } else { -1 }
    Write-DownloadLog $OutDir ([string]$e.Name) ([string]$e.Repo) ([string]$e.Path) ([string]$e.Archive) `
                      $sz ([string]$e.Modified) ([string]$e.Url) ([string]$e.Sev) ([string]$e.Rule) ([string]$hash)
    Mark-Downloaded ([string]$e.VisitKey) ([string]$e.Url)
}

# Shared bulk-download engine for the results view and the audit view. Identical CONTENT is
# written to disk ONCE — the same bytes under different paths, repos or archives collapse to a
# single file — but a download-log.csv row is written for EVERY entry, so each listed
# occurrence stays individually recorded (mirroring the UI). Every entry is marked downloaded.
#
# Hashing is only done where it's needed to resolve a conflict: entries are grouped by
# filename first, and only files that SHARE a name are hashed (to tell duplicates apart from
# distinct content). A unique filename can't collide, so it's saved straight away — its hash
# is still computed from the bytes we download to write it, so the log records it. Distinct
# contents under one name each get a front hash tag (7F7C415.name) so neither clobbers the
# other. $entries are objects with:
#   .Ref .Name .Url .KnownHash .Repo .Path .Archive .Size(long,-1 ok) .Modified .Sev .Rule .VisitKey
# Returns @{ Files; Entries; Renamed; Failed; Identical }.
function Invoke-DedupDownload($entries) {
    $entries = @($entries | Where-Object { $_ })
    $total = $entries.Count
    try { if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null } } catch { }

    # Group by filename (case-insensitive), preserving first-seen order.
    $nameGroups = [Collections.Generic.List[object]]::new()
    $byName = @{}
    foreach ($e in $entries) {
        $nm = [string]$e.Name
        if ($byName.ContainsKey($nm)) { [void]$byName[$nm].Add($e) }
        else { $lst = [Collections.Generic.List[object]]::new(); [void]$lst.Add($e); $byName[$nm] = $lst; [void]$nameGroups.Add($lst) }
    }

    $files = 0; $renamed = 0; $logged = 0; $failed = 0; $gi = 0
    foreach ($grp in $nameGroups) {
        $gi++
        $members = @($grp)
        if ($members.Count -eq 1) {
            # Unique filename — no collision possible; save under its own name. Hash comes
            # from the storage checksum if known, else the bytes we just fetched (no extra
            # download, no separate hashing pass).
            $e = $members[0]
            Report-DownloadProgress @("Saving $gi / $($nameGroups.Count)", [string]$e.Name)
            $b = Get-DedupBytes $e
            if ($null -eq $b) { $failed++; continue }
            $h = if ("$($e.KnownHash)") { [string]$e.KnownHash } else { 'sha256:' + (Get-BytesSha256 $b) }
            if (Save-DedupFile (Join-Path $OutDir ([string]$e.Name)) $b) { Write-DedupEntry $e $h; $files++; $logged++ } else { $failed++ }
            continue
        }
        # Shared filename — hash each member (storage checksum if known, else the bytes) and
        # split into distinct-content sub-groups. Bytes fetched for hashing are kept for the
        # write so each copy is downloaded only once.
        $contents = [Collections.Generic.List[object]]::new()
        $byHash   = @{}
        $mi = 0
        foreach ($e in $members) {
            $mi++
            Report-DownloadProgress @("Hashing $gi / $($nameGroups.Count)", "$([string]$e.Name)  ($mi/$($members.Count))")
            $h = [string]$e.KnownHash
            $b = $null
            if (-not $h) { $b = Get-DedupBytes $e; if ($b) { $h = 'sha256:' + (Get-BytesSha256 $b) } }
            $key = if ($h) { 'h:' + $h.ToLower() } else { 'fb:' + [string]$e.Url }
            if ($byHash.ContainsKey($key)) { [void]$byHash[$key].Members.Add($e) }
            else {
                $c = [PSCustomObject]@{ Hash = $h; Key = $key; Bytes = $b; Members = [Collections.Generic.List[object]]::new() }
                [void]$c.Members.Add($e); $byHash[$key] = $c; [void]$contents.Add($c)
            }
        }
        $tagged = ($contents.Count -gt 1)   # >1 distinct content under one name -> disambiguate
        foreach ($c in $contents) {
            $primary  = $c.Members[0]
            $destName = if ($tagged) { Add-NameTag ([string]$primary.Name) (Get-DedupTag $c.Hash $c.Key) } else { [string]$primary.Name }
            Report-DownloadProgress @("Saving $gi / $($nameGroups.Count)", $destName)
            $b = if ($c.Bytes) { $c.Bytes } else { Get-DedupBytes $primary }
            if ($null -eq $b) { $failed += $c.Members.Count; continue }
            if (Save-DedupFile (Join-Path $OutDir $destName) $b) {
                $files++; if ($tagged) { $renamed++ }
                foreach ($e in $c.Members) { Write-DedupEntry $e $c.Hash; $logged++ }
            } else { $failed += $c.Members.Count }
        }
    }
    return [PSCustomObject]@{ Files = $files; Entries = $total; Renamed = $renamed; Failed = $failed; Identical = ($logged - $files) }
}

# Done-popup summary line for a bulk download: files written vs. entries, plus how many
# entries collapsed onto a shared file and how many names were tagged.
function Get-DedupDoneLine($res) {
    $extra = @()
    if ($res.Identical -gt 0) { $extra += "$($res.Identical) duplicate$(if ($res.Identical -ne 1){'s'}) merged" }
    if ($res.Renamed -gt 0)   { $extra += "$($res.Renamed) name-tagged" }
    if ($res.Failed -gt 0)    { $extra += "$($res.Failed) failed" }
    $tail = if ($extra.Count -gt 0) { ' (' + ($extra -join ', ') + ')' } else { '' }
    return "Done.  Saved $($res.Files) file$(if ($res.Files -ne 1){'s'}) from $($res.Entries) entr$(if ($res.Entries -ne 1){'ies'}else{'y'})$tail."
}
