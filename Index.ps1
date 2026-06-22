# Index.ps1 - the local repository-index engine of the ARTCA Artifactory tool.
#
# Turns the tool into a LOCAL-INDEX-BACKED browser: it persists what we learn about the
# instance to a per-instance DIRECTORY of PER-REPO CSV shards on disk and serves
# searching/browsing from it, so the server is hit only for previews and downloads. The
# layout (.artca-index/<host>/) is:
#   _repos.csv         -> manifest: <shard-stem>,<real-repo-key> (recovers the exact repo)
#   <stem>.csv         -> top-level artifacts:  path,name,size,modified  (repo = the shard)
#   <stem>.arc.csv     -> archive entries:      archDir,archName,internalPath,size,modified
#   _archives.csv      -> indexed archives:     repo,archDir,archName  (re-walk skip-set)
# Repo is the shard, so it is NOT repeated in rows; path/name + the absolute URLs are DERIVED
# (not stored) from the relative identity + the live base url, so shards stay small and are
# portable across base-url spellings. No hash (download-time concern) and no staleness
# handling (the index is an intentional point-in-time snapshot).
#
# SCALE: built for ~3M-artifact instances, so NOTHING is bulk-loaded into RAM. Cold start is
# trivial (no parse). Search STREAMS the shards (line-at-a-time, raw-substring pre-screen).
# Browsing warms $MetaCache (Api.ps1) on demand via Get-RepoIndexTable - per-repo shard
# tables loaded lazily and LRU-evicted, so the resident set is bounded by the repos in use,
# not the whole instance; an indexed page still fires ZERO metadata requests. New metadata
# fetched while browsing is written back through Update-IndexFromMeta. This file also hosts
# the archive-search feature (walk listable archives + match internal entries against the
# query) as one FEEDER of the same store. CSV (not JSONL) for the on-disk format; see the
# legacy JSONL migration in Convert-LegacyIndex.
#
# This is a HEADLESS component (no terminal/UI dependency): loaded by BOTH the TUI
# (StartTui.ps1) and the headless engine (StartAuditEngine.ps1, 'search' verb); needs
# Core.ps1 + Api.ps1 in scope. It reuses the background-walker / treebrowser-expansion /
# throttled-runspace PATTERNS proven out by the optional audit module but never depends on
# AuditEngine.ps1 being present.
#
# Definitions/$script:-state only; nothing here runs on its own. Load order among the
# component files does not matter (names bind at call time).
#
# File conventions: UTF-8 without BOM, LF endings; any non-ASCII glyph that affects
# execution is a numeric [char] escape (literal Unicode only in comments).

# == USER SETTINGS (persist across searches; toggled from the TUI / set by flags) ==
$script:ArcSearchEnabled = $false   # archive-search WALK off by default; [w] toggles in the TUI
$script:IndexEnabled     = $true    # local index on by default; [W] toggles in the TUI
$script:IndexPath        = ''       # resolved per instance by Resolve-IndexPath (host-scoped DIRECTORY of CSV shards)
$script:IndexPathExplicit = $false  # set when a path was supplied (flag), so Resolve leaves it alone

# == INDEX STATE ===============================================================
$script:IndexLoaded    = $false   # lightweight startup ran once this session (migration + skip-set load)
$script:IndexCount     = 0        # records WRITTEN this session (footer hint; NOT a disk total - we never scan to count)
$script:IndexPersisted = New-Object 'System.Collections.Generic.HashSet[string]'  # storage uris known on disk THIS SESSION (warmed-from-shard or written): a write-through dedupe guard, bounded by browse volume - no longer the whole instance
$script:IndexWroteTick = $false   # set when a write happened (drives the TUI '(writing)' hint)

# == PER-REPO SHARD CACHE (on-demand warm; bounds memory to the repos in use) ===
# repo -> @{ Table = @{ relKey -> @{Size;Modified} }; Rows = <int> }, most-recently-used last.
# Loaded lazily by Get-RepoIndexTable from <stem>.csv; whole repos are LRU-evicted once the
# combined row count exceeds the cap, so the resident set is bounded by the repos touched -
# not the whole instance. A single multi-million-row repo is the known residual limit.
$script:ShardCache        = [Collections.Specialized.OrderedDictionary]::new()
$script:ShardCacheRows    = 0
$script:ShardCacheMaxRows = 500000
$script:IndexManifest     = $null   # @{ ByRepo=@{repo->stem}; ByStem=@{stem->repo}; Used=@{stem->1} }, loaded once
$script:ArcIndexedLoaded  = $false  # _archives.csv has been read into ArcIndexedArchives this session
# Insertion order of MetaCache keys WE write (warm/walk/write-through), for bounded trimming
# during long walks. Prefetch's own writes are bounded by browse volume and not tracked here.
$script:MetaOrder         = [Collections.Generic.Queue[string]]::new()
$script:MetaCacheMax      = 200000
# Number of hash buckets per repo's archive-entry folder (<stem>.arc/<NN>.csv). More buckets
# -> smaller files + faster tree-view, but more files to open on search. Fixed per index.
$script:ArcBucketCount    = 256

# == ARCHIVE-SEARCH STATE ======================================================
$script:ArcSearchState   = 'idle'   # idle | walking | done
$script:ArcSearchQuery   = ''       # current query, lowercased, for Contains matching

# Matched result items, append-only so paging stays stable as matches stream in.
# Deduped by EntryUrl. ArcSearchDrained is the TUI's read cursor (only new rows drain).
$script:ArcSearchResults    = [Collections.Generic.List[object]]::new()
$script:ArcSearchResultKeys = New-Object 'System.Collections.Generic.HashSet[string]'
$script:ArcSearchDrained    = 0

# Session-durable index caches (NOT reset between searches - that's the whole point):
#   ArcIndexEntries   - every archive entry expanded/imported this session (name search + warm meta)
#   ArcIndexedArchives- canonical archive uris already fully indexed (skip on re-walk)
#   ArcAttempted      - archives whose expansion was tried this session (success OR fail)
$script:ArcIndexEntries    = [Collections.Generic.List[object]]::new()
$script:ArcIndexedArchives = New-Object 'System.Collections.Generic.HashSet[string]'
$script:ArcAttempted       = New-Object 'System.Collections.Generic.HashSet[string]'

# Skip-versions: by default the archive walk expands only the FIRST version encountered of
# each artifact (e.g. archive-1.0.0.jar but not archive-1.0.1.jar / archive-2.0.12.jar),
# skipping the rest's (expensive) treebrowser expansion. ArcVersionSeen holds the
# version-normalized filename keys (Get-ArcVersionKey) whose representative has been taken.
# Sticky session setting; the seen-set is seeded cross-session from _archives.csv so a re-walk
# won't pick a NEW version for an already-indexed artifact.
$script:ArcSkipVersions  = $true
$script:ArcVersionSeen   = New-Object 'System.Collections.Generic.HashSet[string]'

# Background storage walker (finds archive files) - same runspace pattern the audit
# full-walk uses, but emits ONLY archive files.
$script:ArcWalkPS     = $null
$script:ArcWalkHandle = $null
$script:ArcWalkCancel = $null
$script:ArcWalkOut    = $null
$script:ArcWalkReap   = [Collections.Generic.List[object]]::new()

# Archive-expansion work queue + worker pool + in-flight jobs + transient fetch cache.
$script:ArcQueue   = [Collections.Generic.Queue[object]]::new()
$script:ArcPool    = $null
$script:ArcJobs    = [Collections.Generic.List[object]]::new()
$script:ArcFetch   = [hashtable]::Synchronized(@{})
$script:ArcThrottle   = @{ MaxConcurrent = 3; MinIntervalMs = 150 }
$script:ArcLastLaunch = [DateTime]::MinValue
$script:ArcMaxWorkers = 20   # raised from 10: the tree now flattens in the worker, not the main thread

# Set when results/state change, so the TUI knows to redraw.
$script:ArcSearchDirty = $false

# == WORKER SCRIPTS (run in isolated runspaces; cannot see our functions) ==========
# Storage walker: recursive DFS over /api/storage/<repo>/<path> (a GET on a folder
# returns its 'children'), pushing the storage uri of every ARCHIVE file into a
# synchronized buffer. Non-archive files are never emitted (the extension set is passed
# in and the leaf check tests it inline). Back-pressure: pause while the buffer is full
# so a huge instance can't balloon memory. Mirrors AuditEngine's AuditWalkScript.
$script:ArcWalkScript = {
    param($artBase, $headers, $repos, $arcSet, $out, $cancel, $paceMs, $maxPending)
    $stack = New-Object 'System.Collections.Generic.Stack[object]'
    foreach ($r in $repos) { $stack.Push([PSCustomObject]@{ Repo = $r; Rel = '' }) }
    while ($stack.Count -gt 0) {
        if ($cancel.stop) { break }
        $node = $stack.Pop()
        $uri  = "$artBase/api/storage/$($node.Repo)$($node.Rel)"
        try {
            $info = Invoke-RestMethod -Uri $uri -Headers $headers -ErrorAction Stop
            if ($info.PSObject.Properties['children'] -and $info.children) {
                foreach ($c in @($info.children)) {
                    if ($null -eq $c) { continue }
                    $childRel = "$($node.Rel)$($c.uri)"
                    if ([bool]$c.folder) {
                        $stack.Push([PSCustomObject]@{ Repo = $node.Repo; Rel = $childRel })
                    } else {
                        # Leaf file: emit only when its extension is a known archive type.
                        $nm  = "$($c.uri)".TrimStart('/')
                        $dot = $nm.LastIndexOf('.')
                        $ext = if ($dot -ge 0 -and $dot -lt $nm.Length - 1) { $nm.Substring($dot + 1).ToLower() } else { '' }
                        if ($ext -and $arcSet.Contains($ext)) {
                            while (-not $cancel.stop -and $out.Count -ge $maxPending) { Start-Sleep -Milliseconds 100 }
                            $out.Add("$artBase/api/storage/$($node.Repo)$childRel")
                        }
                    }
                }
            }
        } catch { }   # denied / unreadable folders are skipped silently
        if ($paceMs -gt 0) { Start-Sleep -Milliseconds $paceMs }
    }
}

# Archive-expansion worker (C): POST the treebrowser request (one POST returns the entire archive
# contents nested under each folder's 'children'), then FLATTEN the tree to its file entries RIGHT
# HERE - projecting each to the three persisted primitives (internalPath/size/modified) and DROPPING
# the bulky nested tree. Only the compact entry list crosses back, so the main thread neither holds
# the deep tree nor walks it; that removes the per-archive main-thread stall that forced low arc
# concurrency, and lowers peak memory. RETRY/BACKOFF (B): a 429/503/timeout is retried up to 3x with
# jittered backoff before giving up. The node helpers + Get-WkError are injected ahead of this body
# by the dispatcher (Get-ArcNodeFns / $PvErrFn).
$script:ArcExpandScript = {
    param($key, $uri, $body, $headers, $ua, $cache, $alert)
    $attempt = 0
    while ($true) {
        try {
            $resp = Invoke-RestMethod -Uri $uri -Method Post -Body $body `
                        -ContentType 'application/json' -Headers $headers -UserAgent $ua -ErrorAction Stop
            $data = if ($resp.PSObject.Properties['data'] -and $resp.data) { @(@($resp.data) | Where-Object { $null -ne $_ }) } else { @() }
            # Iterative DFS (no recursion - archives can nest deeply): folders are expanded, non-folder
            # nodes (incl. unlistable sub-archives) become file entries. Children pushed in reverse so
            # they pop in document order (matches the recursive Add-ArcEntriesFromNodes order).
            $entries = [Collections.Generic.List[object]]::new()
            $stack = New-Object 'System.Collections.Generic.Stack[object]'
            for ($i = $data.Count - 1; $i -ge 0; $i--) { $stack.Push($data[$i]) }
            while ($stack.Count -gt 0) {
                $n = $stack.Pop()
                if ($null -eq $n) { continue }
                if (Get-NodeIsFolder $n) {
                    $kids = @(Get-NodeChildren $n)
                    for ($i = $kids.Count - 1; $i -ge 0; $i--) { $stack.Push($kids[$i]) }
                    continue
                }
                $ip = Get-NodeInternalPath $n
                if (-not $ip) { continue }
                $info = Get-NodeInfo $n
                $sz = -1; $mod = ''
                if ($info -and $info.PSObject.Properties['size']) { try { $sz = [long]$info.size } catch { $sz = -1 } }
                if ($info -and $info.PSObject.Properties['modificationTime'] -and "$($info.modificationTime)" -ne '') { $mod = Format-Epoch $info.modificationTime }
                $entries.Add([PSCustomObject]@{ InternalPath = "$ip"; Size = $sz; Modified = "$mod" })
            }
            $cache[$key] = [PSCustomObject]@{ Ok=$true; Entries=$entries; Error='' }
            break
        } catch {
            $we = Get-WkError $_
            if ($we.Code -eq 429 -or $we.Code -eq 503) { $alert.Message = "Server rate-limited an archive-search request (HTTP $($we.Code))."; $alert.At = [DateTime]::UtcNow }
            $transient = ($we.Code -eq 429 -or $we.Code -eq 503 -or $we.Code -eq 0 -or $we.Code -eq 502 -or $we.Code -eq 504)
            if ($transient -and $attempt -lt 3) {
                $attempt++
                Start-Sleep -Milliseconds ([int]([Math]::Pow(2, $attempt) * 200) + (Get-Random -Minimum 0 -Maximum 300))
                continue
            }
            $cache[$key] = [PSCustomObject]@{ Ok=$false; Entries=$null; Error=$we.Message }
            break
        }
    }
}

# Lazily build (once, then cache) an injectable scriptblock that re-declares the node helpers the
# expansion worker needs, sourced from the live Core.ps1 definitions so they never drift. Built at
# first dispatch (not load) to keep the "load order doesn't matter" invariant.
$script:ArcNodeFns = $null
function Get-ArcNodeFns {
    if ($null -eq $script:ArcNodeFns) {
        $defs = foreach ($fn in 'Get-NodeIsFolder','Get-NodeChildren','Get-NodeInfo','Get-NodeInternalPath','Format-Epoch') {
            $c = Get-Command $fn -CommandType Function -ErrorAction SilentlyContinue
            if ($c) { "function $fn {`n$($c.Definition)`n}" }
        }
        $script:ArcNodeFns = [scriptblock]::Create(($defs -join "`n"))
    }
    return $script:ArcNodeFns
}

# == REPO ENUMERATION ==========================================================
# Repos to walk: an explicit -Repos list wins; otherwise the repo-map keys that fall in
# the active repo-type scope (default LOCAL only - see Test-RepoTypeInScope, which also
# always drops virtual repos since they re-enumerate their backing keys). Widen the type
# scope with --repo-types. Mirrors Get-AuditWalkRepos.
function Get-ArcSearchWalkRepos {
    if ($Repos) { return @($Repos -split '[,\s]+' | Where-Object { $_ }) }
    Initialize-RepoMap
    return @($script:RepoMap.Keys | Where-Object { Test-RepoTypeInScope $_ })
}

# Archive-extension lookup passed to the walker runspace.
function Get-ArcExtSet {
    $hs = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($e in $script:ArchiveExts) { [void]$hs.Add($e) }
    return $hs
}

# == DERIVATION HELPERS (relative identity -> absolute urls; shared by load + walk) ==
# These rebuild the urls that the index no longer stores, using the LIVE base url. The
# live walk path uses them too, so a seeded-from-index entry and a freshly-walked one
# produce byte-identical dedupe keys.
function Get-ArcArchivePath([string]$p, [string]$n) {
    if ($p) { return "$p/$n" }
    return $n
}
function Get-ArcArchiveUri([string]$repo, [string]$archPath) {
    return "$(Get-ArtBase)/api/storage/$repo/$archPath"
}
# Version-normalized identity for skip-versions dedupe: collapse the version part of a
# Maven/Jenkins-style archive to a placeholder so siblings that differ only in version share a
# key. Strategy:
#   1. Strip the trailing archive extension (incl. compound .tar.gz/.tar.bz2) so the version's
#      internal dots aren't confused with the ext dot.
#   2. PRIMARY - Maven/Jenkins/Gradle layout puts each version in its own folder, so the archive's
#      parent directory IS the exact version. When that last path segment looks like a version
#      (starts with a digit) and appears as a coordinate token in the filename, replace exactly
#      that occurrence with '#'. This nails qualifier versions (1.0.0-rc243, 1.0-beta1+218,
#      1.0-alpha3+196) and hash builds (353.vf3b_9b_a_f1f7f7) WITHOUT touching classifiers, even
#      digit-bearing native ones (-linux-x86_64 / -aarch64).
#   3. FALLBACK (no usable version dir, e.g. flat/non-Maven layouts) - normalize each HYPHEN-
#      delimited token that STARTS with a digit (the numeric version, e.g. 2.17.1). Kept
#      conservative (no qualifier-chaining) so native-arch classifiers aren't over-merged; the
#      (?<=-) lookbehind never touches the FIRST token (artifactId), so 7zip-tool stays intact.
# Best-effort heuristic. Examples (with version dir): tekton-client-1.0.0-rc243.jar ->
# tekton-client-#.jar; netty-4.1.0-linux-x86_64.jar -> netty-#-linux-x86_64.jar (classifier kept).
function Get-ArcVersionKey([string]$repo, [string]$archDir, [string]$name) {
    $stem = $name; $ext = ''
    $m = [regex]::Match($stem, '\.[A-Za-z0-9]+$')
    if ($m.Success) { $ext = $m.Value; $stem = $stem.Substring(0, $stem.Length - $ext.Length) }
    if ($stem -match '\.tar$') { $ext = '.tar' + $ext; $stem = $stem.Substring(0, $stem.Length - 4) }
    $norm = $null
    $dirLast = ($archDir -split '/')[-1]
    if ($dirLast -and $dirLast -match '^\d') {
        $pat  = '(?<=^|-)' + [regex]::Escape($dirLast) + '(?=$|-)'
        $cand = [regex]::Replace($stem, $pat, '#')
        if ($cand -ne $stem) { $norm = $cand }
    }
    if ($null -eq $norm) { $norm = [regex]::Replace($stem, '(?<=-)\d[^-]*', '#') }
    return "$repo|$norm$ext"
}
function Get-ArcEntryUrl([string]$repo, [string]$archPath, [string]$internalPath) {
    return "$(Get-ArtBase)/$repo/$archPath!/$internalPath"
}
# Reconstruct a top-level artifact's storage uri from its relative identity - the inverse of
# Convert-UriToItem (Api.ps1). Used to rebuild $MetaCache keys when loading the compact
# relative top-level records.
function Get-StorageUriFor([string]$repo, [string]$path, [string]$name) {
    $rel = $repo
    if ($path) { $rel += "/$path" }
    $rel += "/$name"
    return "$(Get-ArtBase)/api/storage/$rel"
}
function Split-ArcInternalPath([string]$ip) {
    $s = "$ip".Trim('/')
    $slash = $s.LastIndexOf('/')
    if ($slash -ge 0) { return @{ Name = $s.Substring($slash + 1); Dir = $s.Substring(0, $slash) } }
    return @{ Name = $s; Dir = '' }
}

# == INDEX PATH ================================================================
# Resolve the index DIRECTORY once the base url is known: an explicit path (flag) is kept;
# otherwise it is the 'index' subfolder of the shared per-instance output root
# (output/<host>/index), alongside downloads/ and audit/ (see Get-OutputInstanceRoot, Core).
function Set-IndexPath([string]$path) {
    $script:IndexPath = $path
    $script:IndexPathExplicit = [bool]$path
}
function Resolve-IndexPath {
    if ($script:IndexPathExplicit -and $script:IndexPath) { return }
    $script:IndexPath = Join-Path (Get-OutputInstanceRoot) 'index'
}

# == CSV + SHARD + MANIFEST HELPERS ============================================
# CSV row read/write primitives (Format-CsvRow / Read-CsvRow) live in Core.ps1 now, shared
# with the audit-match logging. All shard rows are RFC-4180 with EVERY field quoted and CR/LF
# stripped from values, so one record == one line and the lazy streaming reader never buffers.
function Confirm-IndexDir {
    if (-not $script:IndexPath) { return $false }
    if (-not (Test-Path -LiteralPath $script:IndexPath)) {
        try { New-Item -ItemType Directory -Path $script:IndexPath -Force | Out-Null } catch { return $false }
    }
    return $true
}
# Manifest: stable shard-stem <-> real repo key, so rows can omit the repo and the exact key
# is still recoverable, and a sanitization collision between two repos can't share a shard.
function Get-IndexManifest {
    if ($null -ne $script:IndexManifest) { return $script:IndexManifest }
    $m = @{ ByRepo = @{}; ByStem = @{}; Used = @{} }
    $mf = Join-Path $script:IndexPath '_repos.csv'
    if ($script:IndexPath -and (Test-Path -LiteralPath $mf)) {
        try {
            foreach ($line in [System.IO.File]::ReadLines($mf)) {
                if (-not "$line".Trim()) { continue }
                $f = Read-CsvRow $line
                if ($f.Count -ge 2) { $m.ByStem[$f[0]] = $f[1]; $m.ByRepo[$f[1]] = $f[0]; $m.Used[$f[0]] = 1 }
            }
        } catch { }
    }
    $script:IndexManifest = $m
    return $m
}
# Resolve (creating + persisting if new) the shard stem for a repo. Sanitize, then
# de-collide with a numeric suffix so distinct repos never share a shard file.
function Get-IndexStem([string]$repo) {
    $m = Get-IndexManifest
    if ($m.ByRepo.ContainsKey($repo)) { return $m.ByRepo[$repo] }
    $base = ($repo -replace '[^A-Za-z0-9._-]', '_'); if (-not $base) { $base = 'repo' }
    $stem = $base; $k = 1
    while ($m.Used.ContainsKey($stem)) { $k++; $stem = "${base}_$k" }
    $m.ByRepo[$repo] = $stem; $m.ByStem[$stem] = $repo; $m.Used[$stem] = 1
    if (Confirm-IndexDir) {
        $line = Format-CsvRow @($stem, $repo)
        try { [System.IO.File]::AppendAllText((Join-Path $script:IndexPath '_repos.csv'),
                  ($line + "`n"), [Text.UTF8Encoding]::new($false)) } catch { }
    }
    return $stem
}
function Get-ArtifactShardPath([string]$repo) { Join-Path $script:IndexPath ((Get-IndexStem $repo) + '.csv') }
# Archive entries live in a per-repo FOLDER of hash-bucket CSVs (<stem>.arc/<NN>.csv) instead
# of one giant <stem>.arc.csv: an archive's entries all land in one bucket, so opening its tree
# view reads only that bucket (~total/N rows) instead of the whole repo's entries, and each
# file stays bounded. Search reads the N buckets sequentially. Bucket = a deterministic hash of
# the archive's repo-relative path (FNV-1a, so it's stable across runs - .NET GetHashCode is
# not). N is fixed per index; '{0:x2}' is a MINIMUM width (never truncates a larger N).
function Get-ArchiveDirPath([string]$repo)    { Join-Path $script:IndexPath ((Get-IndexStem $repo) + '.arc') }
function Get-ArcBucket([string]$s) {
    $h = [uint64]2166136261
    foreach ($ch in $s.ToCharArray()) {
        $h = $h -bxor [uint64][int]$ch
        $h = ($h * [uint64]16777619) -band [uint64]4294967295   # FNV-1a, low 32 bits
    }
    return [int]($h % [uint64]$script:ArcBucketCount)
}
function Get-ArchiveBucketPath([string]$repo, [string]$archDir, [string]$archName) {
    $b = Get-ArcBucket (Get-ArcArchivePath $archDir $archName)
    Join-Path (Get-ArchiveDirPath $repo) (('{0:x2}' -f $b) + '.csv')
}
function Confirm-ArchiveDir([string]$repo) {
    $d = Get-ArchiveDirPath $repo
    if (-not (Test-Path -LiteralPath $d)) {
        try { New-Item -ItemType Directory -Path $d -Force | Out-Null } catch { return $false }
    }
    return $true
}
# Existing bucket files for a repo (for streaming search over all archive entries).
function Get-ArchiveBucketFiles([string]$repo) {
    $d = Get-ArchiveDirPath $repo
    if (-not (Test-Path -LiteralPath $d)) { return @() }
    return @(Get-ChildItem -LiteralPath $d -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like '*.csv' } | ForEach-Object { $_.FullName })
}
# All repos that have a shard on disk (for an unfiltered streaming search).
function Get-IndexedRepos {
    $m = Get-IndexManifest
    return @($m.ByRepo.Keys)
}

# == INDEX RECORDS =============================================================
# An in-memory archive-entry record. archDir/archName are the containing archive's
# repo-relative dir + filename; ArchiveUri + EntryUrl are derived from them + the entry's
# within-archive path, so they always match the reconstruct-on-load form.
function New-ArcIndexEntry([string]$repo, [string]$archDir, [string]$archName, [string]$internalPath, $size, [string]$modified) {
    $sz = -1; if ("$size" -match '^-?\d+$') { $sz = [long]$size }
    $archPath = Get-ArcArchivePath $archDir $archName
    $sp = Split-ArcInternalPath $internalPath
    return [PSCustomObject]@{
        ArchiveRepo=$repo; ArchivePath=$archDir; ArchiveName=$archName
        ArchiveUri=(Get-ArcArchiveUri $repo $archPath)
        Name=$sp.Name; Path=$sp.Dir; InternalPath=([string]$internalPath)
        EntryUrl=(Get-ArcEntryUrl $repo $archPath $internalPath)
        Size=$sz; Modified=$modified
    }
}

# Result item shaped like Convert-UriToItem output PLUS the archive fields the display /
# download / preview layers read (InArchive/ArchiveName via Get-ItemArchiveName; EntryUrl
# via the archive-aware Get-ItemUrl). Uri = EntryUrl so visited/identity keying works.
function New-ArcResultItem($e) {
    return [PSCustomObject]@{
        Name        = [string]$e.Name
        Repo        = [string]$e.ArchiveRepo
        Path        = [string]$e.Path
        Uri         = [string]$e.EntryUrl
        FileType    = (Get-Ext ([string]$e.Name))
        Size        = $(if ($e.Size -ge 0) { [long]$e.Size } else { '' })
        Modified    = [string]$e.Modified
        Hash        = ''
        InArchive   = $true
        ArchiveName = [string]$e.ArchiveName
        EntryUrl    = [string]$e.EntryUrl
    }
}

# Build a top-level result item from a known storage uri, warmed from $MetaCache.
function New-IndexResultItem([string]$uri) {
    $it = Convert-UriToItem $uri
    Apply-Meta @($it)
    return $it
}

# Add a result item for an archive entry whose name matches the live query, deduped by
# EntryUrl. Returns $true when it was newly added.
function Add-ArcSearchMatch($e) {
    $url = [string]$e.EntryUrl
    if (-not $url -or -not $script:ArcSearchResultKeys.Add($url)) { return $false }
    $script:ArcSearchResults.Add((New-ArcResultItem $e))
    $script:ArcSearchDirty = $true
    return $true
}

function Test-ArcNameMatches([string]$name) {
    if (-not $script:ArcSearchQuery) { return $false }
    return ([string]$name).ToLower().Contains($script:ArcSearchQuery)
}

# == INDEX LOAD / SAVE (CSV SHARDS) ============================================
# Startup is now LIGHTWEIGHT: no bulk preload of the instance into RAM (that's the whole
# point at 3M artifacts). It only migrates older on-disk formats if present ((1) a legacy
# single-file JSONL index, (2) flat <stem>.arc.csv archive shards -> per-repo bucket folders)
# and loads the small _archives.csv re-walk skip-set. Per-page metadata is warmed on demand by
# Warm-IndexMeta; search streams the shards. $path is the index DIRECTORY.
function Import-Index([string]$path) {
    if ($script:IndexLoaded) { return }
    $script:IndexLoaded = $true
    if (-not $path) { return }
    Convert-LegacyIndex
    Convert-FlatArchiveShards
    Ensure-ArcIndexedLoaded
}

# One-time migration of flat per-repo archive shards (<stem>.arc.csv, from the first CSV
# layout) into per-repo bucket folders (<stem>.arc/<NN>.csv). Streams each flat file, routes
# every row to its archive's bucket (buffered + chunk-flushed so memory stays bounded on a
# multi-million-row file), then renames the flat file .migrated. Rows are copied verbatim, so
# they keep their exact size/modified. Idempotent across runs via the rename.
function Convert-FlatArchiveShards {
    if (-not $script:IndexPath -or -not (Test-Path -LiteralPath $script:IndexPath)) { return }
    $flat = @(Get-ChildItem -LiteralPath $script:IndexPath -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like '*.arc.csv' })
    foreach ($file in $flat) {
        # Disambiguate from an artifact shard whose repo stem happens to end in '.arc' (so
        # <stem>.csv also matches *.arc.csv): archive rows have 5 fields, artifact rows 4.
        # Peek via an explicitly-disposed StreamReader, NOT a `break` out of lazy ReadLines
        # (that leaves the file handle open, so the later Move-Item rename fails).
        $isArc = $false; $rdr = $null
        try {
            $rdr = [System.IO.StreamReader]::new($file.FullName, [Text.UTF8Encoding]::new($false))
            while ($null -ne ($pk = $rdr.ReadLine())) {
                if (-not "$pk".Trim()) { continue }
                $isArc = ((Read-CsvRow $pk).Count -ge 5); break
            }
        } catch { $isArc = $false } finally { if ($rdr) { $rdr.Dispose() } }
        if (-not $isArc) { continue }
        $stem = $file.Name.Substring(0, $file.Name.Length - '.arc.csv'.Length)
        $arcDir = Join-Path $script:IndexPath ($stem + '.arc')
        if (-not (Test-Path -LiteralPath $arcDir)) {
            try { New-Item -ItemType Directory -Path $arcDir -Force | Out-Null } catch { continue }
        }
        $buf = @{}            # bucketPath -> StringBuilder
        $buffered = 0
        try {
            foreach ($line in [System.IO.File]::ReadLines($file.FullName)) {
                if (-not "$line".Trim()) { continue }
                $f = Read-CsvRow $line
                if ($f.Count -lt 3) { continue }
                $bp = Join-Path $arcDir (('{0:x2}' -f (Get-ArcBucket (Get-ArcArchivePath $f[0] $f[1]))) + '.csv')
                if (-not $buf.ContainsKey($bp)) { $buf[$bp] = [Text.StringBuilder]::new() }
                [void]$buf[$bp].Append($line).Append("`n")
                $buffered++
                if ($buffered -ge 100000) { Save-ArcBucketBuffer $buf; $buffered = 0 }
            }
            Save-ArcBucketBuffer $buf
            Move-Item -LiteralPath $file.FullName -Destination ($file.FullName + '.migrated') -Force
        } catch { }
    }
}
# Flush a bucketPath -> StringBuilder map to disk (append) and clear each builder. Keeps the
# flat-shard migration's resident memory bounded to one chunk regardless of total file size.
function Save-ArcBucketBuffer($buf) {
    foreach ($bp in @($buf.Keys)) {
        $sb = $buf[$bp]
        if ($sb.Length -gt 0) {
            try { [System.IO.File]::AppendAllText($bp, $sb.ToString(), [Text.UTF8Encoding]::new($false)) } catch { }
            [void]$sb.Clear()
        }
    }
}

# One-time migration of the pre-sharding single-file index (.artca-index/<host>.jsonl) into
# the new per-repo CSV shards. Runs only when the legacy file exists and the new dir is empty
# of shards; the legacy file is renamed .migrated afterwards so it never runs twice.
function Convert-LegacyIndex {
    if (-not $script:IndexPath) { return }
    $legacy = $script:IndexPath.TrimEnd('\','/') + '.jsonl'
    if (-not (Test-Path -LiteralPath $legacy)) { return }
    $lines = @()
    try { $lines = [System.IO.File]::ReadAllLines($legacy) } catch { return }
    foreach ($line in $lines) {
        if (-not "$line".Trim()) { continue }
        $o = $null
        try { $o = $line | ConvertFrom-Json } catch { continue }
        if ($null -eq $o) { continue }
        if ($o.PSObject.Properties['e']) {
            $repo = [string]$o.r; $dir = [string]$o.p; $name = [string]$o.n
            $entries = [Collections.Generic.List[object]]::new()
            foreach ($en in @($o.e)) {
                if ($null -eq $en) { continue }
                $entries.Add((New-ArcIndexEntry $repo $dir $name ([string]$en.i) $en.s ([string]$en.m)))
            }
            Save-IndexArchive $repo $dir $name $entries
        } elseif ($o.PSObject.Properties['u']) {
            $it = Convert-UriToItem ([string]$o.u)
            [void](Write-IndexArtifactRow ([string]$it.Repo) ([string]$it.Path) ([string]$it.Name) $o.s ([string]$o.m))
        } elseif ($o.PSObject.Properties['r'] -and $o.PSObject.Properties['n']) {
            $p = if ($o.PSObject.Properties['p']) { [string]$o.p } else { '' }
            [void](Write-IndexArtifactRow ([string]$o.r) $p ([string]$o.n) $o.s ([string]$o.m))
        }
    }
    try { Move-Item -LiteralPath $legacy -Destination ($legacy + '.migrated') -Force } catch { }
}

# Load the small _archives.csv into the in-session skip-set so re-walks / re-opens of an
# archive indexed in a PRIOR session don't re-expand it (the old Import-Index filled this
# from the whole-instance preload; now it's a tiny dedicated file).
function Ensure-ArcIndexedLoaded {
    if ($script:ArcIndexedLoaded) { return }
    $script:ArcIndexedLoaded = $true
    if (-not $script:IndexPath) { return }
    $af = Join-Path $script:IndexPath '_archives.csv'
    if (-not (Test-Path -LiteralPath $af)) { return }
    try {
        foreach ($line in [System.IO.File]::ReadLines($af)) {
            if (-not "$line".Trim()) { continue }
            $f = Read-CsvRow $line
            if ($f.Count -lt 3) { continue }
            $au = Get-ArcArchiveUri $f[0] (Get-ArcArchivePath $f[1] $f[2])
            [void]$script:ArcIndexedArchives.Add($au); [void]$script:ArcAttempted.Add($au)
            # Seed the skip-versions set so a re-walk won't pick a NEW version of an artifact
            # already indexed in a prior session (harmless when skip-versions is off).
            [void]$script:ArcVersionSeen.Add((Get-ArcVersionKey $f[0] $f[1] $f[2]))
        }
    } catch { }
}

# Append one top-level artifact row to its repo shard (path,name,size,modified). Size
# normalized to a number ('' when unknown). Low-level; callers handle the dedupe guard.
# WRITES (D): in buffered mode ($IndexWriteBuffered, set by the headless build) rows accumulate in a
# per-shard StringBuilder and are flushed in batches (threshold or lifecycle) - one file-open per
# ~hundreds of rows instead of per row, which matters once the parallel pipeline writes 100s/sec.
# The low-volume TUI write-through leaves the flag off and writes immediately (no loss on a crash).
function Write-IndexArtifactRow([string]$repo, [string]$path, [string]$name, $size, [string]$modified) {
    if (-not (Confirm-IndexDir)) { return $false }
    $sz = ''
    if ("$size" -ne '' -and "$size" -ne '?') { try { $sz = [long]$size } catch { $sz = "$size" } }
    $line = Format-CsvRow @($path, $name, $sz, $modified)
    $sp = Get-ArtifactShardPath $repo
    if ($script:IndexWriteBuffered) {
        $sb = $script:ShardWriteBuf[$sp]
        if ($null -eq $sb) { $sb = [Text.StringBuilder]::new(); $script:ShardWriteBuf[$sp] = $sb; $script:ShardWriteBufRows[$sp] = 0 }
        [void]$sb.Append($line).Append("`n")
        $script:ShardWriteBufRows[$sp]++
        $script:IndexCount++
        if ([int]$script:ShardWriteBufRows[$sp] -ge $script:ShardWriteFlushRows) { Flush-IndexShardBuf $sp }
        return $true
    }
    try {
        [System.IO.File]::AppendAllText($sp, ($line + "`n"), [Text.UTF8Encoding]::new($false))
        $script:IndexCount++
        return $true
    } catch { return $false }
}

# Per-shard write buffers (D): path -> StringBuilder, path -> row count. Flushed by threshold (in
# Write-IndexArtifactRow), periodically (the build loop), and fully on Stop-IndexBuild.
$script:IndexWriteBuffered  = $false
$script:ShardWriteBuf       = @{}
$script:ShardWriteBufRows   = @{}
$script:ShardWriteFlushRows = 256

# Flush one shard's buffer to disk (append, no-BOM UTF-8/LF) and reset its row count.
function Flush-IndexShardBuf([string]$sp) {
    $sb = $script:ShardWriteBuf[$sp]
    if ($null -eq $sb -or $sb.Length -eq 0) { return }
    try { [System.IO.File]::AppendAllText($sp, $sb.ToString(), [Text.UTF8Encoding]::new($false)) } catch { }
    [void]$sb.Clear()
    $script:ShardWriteBufRows[$sp] = 0
}

# Flush every shard buffer (lifecycle/periodic).
function Flush-IndexWrites {
    foreach ($sp in @($script:ShardWriteBuf.Keys)) { Flush-IndexShardBuf $sp }
}

# Append one archive's entries to its repo arc bucket (one CSV row per entry) and record the
# archive in _archives.csv so it's skipped on re-walk. Empty archive -> a single marker row
# with a blank internal path, so it isn't re-walked. All of one archive's rows go to a single
# bucket (keyed by archive path), so a tree-view reads just that bucket. Gated on the index.
function Save-IndexArchive([string]$arcRepo, [string]$arcDir, [string]$arcName, $entries) {
    if (-not $script:IndexEnabled -or -not (Confirm-IndexDir) -or -not (Confirm-ArchiveDir $arcRepo)) { return }
    try {
        $sb = [Text.StringBuilder]::new()
        $cnt = 0
        foreach ($e in @($entries)) {
            if ($null -eq $e) { continue }   # $entries may be $null (empty-list unroll) -> @($null) yields one null
            $sz = $(if ($e.Size -ge 0) { [long]$e.Size } else { -1 })
            [void]$sb.Append((Format-CsvRow @($arcDir, $arcName, [string]$e.InternalPath, $sz, [string]$e.Modified))).Append("`n")
            $cnt++
        }
        if ($cnt -eq 0) { [void]$sb.Append((Format-CsvRow @($arcDir, $arcName, '', -1, ''))).Append("`n") }   # empty-archive marker
        [System.IO.File]::AppendAllText((Get-ArchiveBucketPath $arcRepo $arcDir $arcName), $sb.ToString(), [Text.UTF8Encoding]::new($false))
        $arcLine = Format-CsvRow @($arcRepo, $arcDir, $arcName)
        [System.IO.File]::AppendAllText((Join-Path $script:IndexPath '_archives.csv'),
            ($arcLine + "`n"), [Text.UTF8Encoding]::new($false))
        $script:IndexCount += $cnt
        $script:IndexWroteTick = $true
    } catch { }
}

# Write-through: persist top-level metadata that just landed in $MetaCache (size/modified)
# for items not yet on disk this session. Archive-entry items are skipped (their content is
# persisted as an archive group via Save-IndexArchive). Routed to the per-repo shard. Cheap
# when there is nothing new (set lookups). Returns the number of records newly written.
function Update-IndexFromMeta($items) {
    if (-not $script:IndexEnabled -or -not $script:IndexPath) { return 0 }
    $wrote = 0
    foreach ($it in @($items)) {
        if ($null -eq $it) { continue }
        if (Get-ItemArchiveName $it) { continue }
        $u = [string]$it.Uri
        if (-not $u -or $script:IndexPersisted.Contains($u) -or -not $script:MetaCache.ContainsKey($u)) { continue }
        $m = $script:MetaCache[$u]
        $hasSize = ("$($m.Size)" -ne '' -and "$($m.Size)" -ne '?')
        $hasMod  = ($m.PSObject.Properties['Modified'] -and "$($m.Modified)" -ne '')
        if (-not $hasSize -and -not $hasMod) { continue }
        [void]$script:IndexPersisted.Add($u)
        $sz = ''
        if ($hasSize) { $sz = $m.Size }
        if (Write-IndexArtifactRow ([string]$it.Repo) ([string]$it.Path) ([string]$it.Name) $sz ([string]$m.Modified)) { $wrote++ }
    }
    if ($wrote -gt 0) { $script:IndexWroteTick = $true }
    return $wrote
}

# == LOCAL SEARCH ==============================================================
# Name-match (case-insensitive Contains, like the REST quick-search) over the local index:
# both top-level artifacts and archive entries. Returns result items for the caller to
# merge with the live REST results (deduped by .Uri). Metadata is served from $MetaCache.
# STREAMS the on-disk shards (line-at-a-time, never buffering a shard). A raw-substring
# pre-screen on the lowercased line rejects the vast majority of rows before any parse; only
# survivors are parsed and the NAME re-checked (the pre-screen also matches path text). Size/
# modified are filled from the row, so results display without a $MetaCache round-trip. Honors
# the -Repos scope (only those shards) when set; otherwise every shard in the manifest.
# Windowed streaming search over the local index, so the whole result set is reachable in chunks
# without ever building it all at once. Matches are taken in stable shard order; this returns the
# window [skip, skip+take) by match position (take <= 0 = no limit, used by the headless search
# verb which writes a complete CSV). Dedup is left to the caller's URI-keyed merge (top-level Uri
# and archive EntryUrl are both the item's .Uri), so windows stay aligned by raw match position.
# -WantTotal (or take <= 0) scans to the end and sets $script:IndexSearchTotal to the full match
# count (for "showing N of T"); a plain windowed call stops once the window is built (fast paging).
# NOTE: the line read uses an explicit enumerator in try/finally because PowerShell does NOT
# dispose a `foreach ($line in [IO.File]::ReadLines())` enumerator when broken out of early -
# that would leak a shard read handle and block Compress-Index's replace.
$script:IndexSearchTotal = 0
# The chunk/window size the interactive TUI loads at a time (and auto-tops-up past).
$script:IndexSearchMax   = 5000

# Index-scan progress hook (mirrors Core's $DownloadProgress). The TUI sets this to a Show-Popup
# wrapper so the initial offline search shows live progress while Search-Index streams the shards;
# left $null (headless) it's a no-op. Report-IndexProgress time-throttles so callers can call it
# liberally from the hot row loop without flooding the renderer.
$script:IndexProgress     = $null
$script:IndexProgressLast = [DateTime]::MinValue
function Report-IndexProgress([string[]]$lines) {
    if (-not $script:IndexProgress) { return }
    if (([DateTime]::UtcNow - $script:IndexProgressLast).TotalMilliseconds -lt 80) { return }
    $script:IndexProgressLast = [DateTime]::UtcNow
    & $script:IndexProgress $lines
}

function Search-Index([string]$query, [int]$skip = 0, [int]$take = 0, [switch]$WantTotal) {
    $q = "$query".ToLower()
    $script:IndexSearchTotal = 0
    if (-not $q -or -not $script:IndexPath) { return @() }
    # Explicit -Repos wins; otherwise the indexed repos narrowed to the active type scope
    # (default LOCAL only), so an index built wider (--repo-types) still browses local-only by
    # default. Test-RepoTypeInScope is graceful when the repo map is unavailable (offline /
    # anonymous-denied): types read as '?' and pass through, leaving the index as the source of truth.
    $repos   = if ($Repos) { @($Repos -split '[,\s]+' | Where-Object { $_ }) }
               else        { @(Get-IndexedRepos | Where-Object { Test-RepoTypeInScope $_ }) }
    $out     = [Collections.Generic.List[object]]::new()
    $matched = 0
    $limit   = if ($take -gt 0) { $skip + $take } else { [int]::MaxValue }
    $scanAll = ([bool]$WantTotal -or $take -le 0)   # keep counting past the window for the total
    # Progress: only when the hook is set (TUI) AND search is index-served (offline). The scan
    # blocks the UI, so we redraw a popup as repos/rows stream by. Cheap when off (one bool/row).
    $reposArr   = @($repos)
    $nrepo      = $reposArr.Count
    $ridx       = 0
    $scanned    = 0
    $reportProg = ($null -ne $script:IndexProgress) -and (Test-SearchLocalOnly)
    :scan foreach ($repo in $reposArr) {
        $ridx++
        if ($reportProg) { Report-IndexProgress @('Loading offline index', "repo $ridx of $nrepo", "$matched match(es) $([char]0x00B7) $scanned rows scanned") }
        # Top-level artifact shard: path,name,size,modified.
        $sp = Get-ArtifactShardPath $repo
        if (Test-Path -LiteralPath $sp) {
            $en = [System.IO.File]::ReadLines($sp).GetEnumerator()
            try {
                while ($en.MoveNext()) {
                    if (-not $scanAll -and $matched -ge $limit) { break scan }   # window built; stop
                    if ($reportProg) {
                        $scanned++
                        if (($scanned % 20000) -eq 0) { Report-IndexProgress @('Loading offline index', "repo $ridx of $nrepo", "$matched match(es) $([char]0x00B7) $scanned rows scanned") }
                    }
                    $line = $en.Current
                    if (-not $line -or -not $line.ToLower().Contains($q)) { continue }
                    $f = Read-CsvRow $line
                    if ($f.Count -lt 2 -or -not $f[1].ToLower().Contains($q)) { continue }
                    if ($matched -ge $skip -and $matched -lt $limit) {
                        $u  = Get-StorageUriFor $repo $f[0] $f[1]
                        $it = Convert-UriToItem $u
                        if ($f.Count -ge 3 -and "$($f[2])" -ne '') { $it.Size = $f[2] }
                        if ($f.Count -ge 4) { $it.Modified = $f[3] }
                        $out.Add($it)
                    }
                    $matched++
                }
            } catch { } finally { $en.Dispose() }
        }
        # Archive-entry buckets: archDir,archName,internalPath,size,modified.
        foreach ($ap in (Get-ArchiveBucketFiles $repo)) {
            $en = [System.IO.File]::ReadLines($ap).GetEnumerator()
            try {
                while ($en.MoveNext()) {
                    if (-not $scanAll -and $matched -ge $limit) { break scan }
                    if ($reportProg) {
                        $scanned++
                        if (($scanned % 20000) -eq 0) { Report-IndexProgress @('Loading offline index', "repo $ridx of $nrepo", "$matched match(es) $([char]0x00B7) $scanned rows scanned") }
                    }
                    $line = $en.Current
                    if (-not $line -or -not $line.ToLower().Contains($q)) { continue }
                    $f = Read-CsvRow $line
                    if ($f.Count -lt 3 -or -not $f[2]) { continue }
                    $nm = (Split-ArcInternalPath $f[2]).Name
                    if (-not $nm.ToLower().Contains($q)) { continue }
                    if ($matched -ge $skip -and $matched -lt $limit) {
                        $sz = if ($f.Count -ge 4) { $f[3] } else { -1 }
                        $md = if ($f.Count -ge 5) { $f[4] } else { '' }
                        $e  = New-ArcIndexEntry $repo $f[0] $f[1] $f[2] $sz $md
                        $out.Add((New-ArcResultItem $e))
                    }
                    $matched++
                }
            } catch { } finally { $en.Dispose() }
        }
    }
    if ($scanAll) { $script:IndexSearchTotal = $matched }   # full count (window calls don't clobber it)
    return @($out.ToArray())
}

# Seed the archive-search result list from already-indexed archive entries for the current
# query (instant matches, no walking) - including PRIOR sessions, by streaming the on-disk
# arc shards. Add-ArcSearchMatch dedupes by EntryUrl, so this safely overlaps with entries
# walked later this session. Used by the archive-search WALK feature.
function Search-ArcIndex {
    if (-not $script:ArcSearchQuery -or -not $script:IndexPath) { return }
    foreach ($repo in (Get-ArcSearchWalkRepos)) {
        foreach ($ap in (Get-ArchiveBucketFiles $repo)) {
            try {
                foreach ($line in [System.IO.File]::ReadLines($ap)) {
                    if (-not $line -or -not $line.ToLower().Contains($script:ArcSearchQuery)) { continue }
                    $f = Read-CsvRow $line
                    if ($f.Count -lt 3 -or -not $f[2]) { continue }
                    $nm = (Split-ArcInternalPath $f[2]).Name
                    if (-not (Test-ArcNameMatches $nm)) { continue }
                    $sz = if ($f.Count -ge 4) { $f[3] } else { -1 }
                    $md = if ($f.Count -ge 5) { $f[4] } else { '' }
                    [void](Add-ArcSearchMatch (New-ArcIndexEntry $repo $f[0] $f[1] $f[2] $sz $md))
                }
            } catch { }
        }
    }
}

# == ON-DEMAND WARM + BOUNDED CACHES ===========================================
# relKey for a top-level artifact within its repo shard: path + '/' + name (path may be '').
function Get-IndexRelKey([string]$path, [string]$name) {
    if ($path) { return "$path/$name" }
    return $name
}
# Load (and cache) a repo's whole artifact shard as a hashtable relKey -> @{Size;Modified}.
# Whole repos are LRU-evicted once the combined resident row count exceeds the cap, so memory
# is bounded by the repos in use - not the instance. A single multi-million-row repo is the
# known residual limit (its one table can still be large). Most-recently-used is kept last.
function Get-RepoIndexTable([string]$repo) {
    if ($script:ShardCache.Contains($repo)) {
        $entry = $script:ShardCache[$repo]
        $script:ShardCache.Remove($repo); $script:ShardCache[$repo] = $entry   # touch -> MRU
        return $entry.Table
    }
    $table = @{}
    $sp = Get-ArtifactShardPath $repo
    if (Test-Path -LiteralPath $sp) {
        try {
            foreach ($line in [System.IO.File]::ReadLines($sp)) {
                if (-not $line) { continue }
                $f = Read-CsvRow $line
                if ($f.Count -lt 2) { continue }
                # Last-wins: a later row supersedes an earlier one for the same key (pre-compaction dups).
                $table[(Get-IndexRelKey $f[0] $f[1])] = [PSCustomObject]@{
                    Size     = $(if ($f.Count -ge 3) { $f[2] } else { '' })
                    Modified = $(if ($f.Count -ge 4) { $f[3] } else { '' })
                }
            }
        } catch { }
    }
    $script:ShardCache[$repo] = [PSCustomObject]@{ Table = $table; Rows = $table.Count }
    $script:ShardCacheRows += $table.Count
    while ($script:ShardCacheRows -gt $script:ShardCacheMaxRows -and $script:ShardCache.Count -gt 1) {
        $lru = @($script:ShardCache.Keys)[0]
        $script:ShardCacheRows -= [int]$script:ShardCache[$lru].Rows
        $script:ShardCache.Remove($lru)
    }
    return $table
}
# Warm $MetaCache from the on-disk shards for the given (display) items, so an indexed page
# fires ZERO metadata requests without ever bulk-loading the instance. Only top-level items
# are handled (archive-entry items already carry their own size/modified). A warmed uri is
# marked IndexPersisted so Update-IndexFromMeta won't re-append it. Returns count warmed.
function Warm-IndexMeta($items) {
    if (-not $script:IndexEnabled -or -not $script:IndexPath) { return 0 }
    $warmed = 0
    foreach ($it in @($items)) {
        if ($null -eq $it) { continue }
        $u = [string]$it.Uri
        if (-not $u -or $script:MetaCache.ContainsKey($u)) { continue }
        if (Get-ItemArchiveName $it) { continue }
        # Index-search results already carry size/modified from their shard row (Search-Index),
        # so seed the cache directly - no need to rebuild the whole repo shard table (the simple->
        # detailed hang). REST-search items have empty size/modified and still take the table path.
        if ("$($it.Size)" -ne '' -or "$($it.Modified)" -ne '') {
            $script:MetaCache[$u] = [PSCustomObject]@{ Size = $it.Size; Modified = $it.Modified; Hash = '' }
            $script:MetaOrder.Enqueue($u)
            [void]$script:IndexPersisted.Add($u)
            $warmed++
            continue
        }
        $table = Get-RepoIndexTable ([string]$it.Repo)
        $rk = Get-IndexRelKey ([string]$it.Path) ([string]$it.Name)
        if (-not $table.ContainsKey($rk)) { continue }
        $m = $table[$rk]
        $script:MetaCache[$u] = [PSCustomObject]@{ Size = $m.Size; Modified = $m.Modified; Hash = '' }
        $script:MetaOrder.Enqueue($u)
        [void]$script:IndexPersisted.Add($u)   # already on disk - don't write-through again
        $warmed++
    }
    if ($warmed -gt 0) { Limit-MetaCache @($items | ForEach-Object { if ($_) { [string]$_.Uri } }) }
    return $warmed
}
# Bound $MetaCache during long sessions/walks by evicting our oldest-written keys (tracked in
# MetaOrder), never evicting a uri in $protect (the current page). Locks SyncRoot because the
# prefetch pool writes to $MetaCache from worker threads. Prefetch's own writes aren't in
# MetaOrder but are bounded by browse volume, so this is enough to cap the unbounded path
# (archive/warm writes during a full walk).
function Limit-MetaCache([string[]]$protect) {
    if ($script:MetaCache.Count -le $script:MetaCacheMax) { return }
    $keep = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($p in @($protect)) { if ($p) { [void]$keep.Add($p) } }
    $sr = $script:MetaCache.SyncRoot
    [System.Threading.Monitor]::Enter($sr)
    try {
        while ($script:MetaCache.Count -gt $script:MetaCacheMax -and $script:MetaOrder.Count -gt 0) {
            $k = $script:MetaOrder.Dequeue()
            if ($keep.Contains($k)) { continue }
            if ($script:MetaCache.ContainsKey($k)) { $script:MetaCache.Remove($k) }
        }
    } finally { [System.Threading.Monitor]::Exit($sr) }
}

# == WALK ======================================================================
function Start-ArcSearchWalk {
    Stop-ArcSearchWalk
    $repos = Get-ArcSearchWalkRepos
    if (@($repos).Count -eq 0) { return $false }
    $script:ArcWalkOut = [Collections.ArrayList]::Synchronized([Collections.ArrayList]::new())
    $cancel = [hashtable]::Synchronized(@{ stop = $false })
    $ps = [PowerShell]::Create()
    [void]$ps.AddScript($script:ArcWalkScript).
        AddArgument((Get-ArtBase)).AddArgument((Get-AuthHeaders)).AddArgument(@($repos)).
        AddArgument((Get-ArcExtSet)).AddArgument($script:ArcWalkOut).AddArgument($cancel).
        AddArgument(0).AddArgument(5000)
    $script:ArcWalkCancel = $cancel
    $script:ArcWalkPS     = $ps
    $script:ArcWalkHandle = $ps.BeginInvoke()
    return $true
}

# Drain discovered archive uris (bounded per tick), skip ones already indexed/attempted,
# and enqueue an expansion job for the rest (treebrowser request built up front).
function Step-ArcSearchWalk {
    if ($null -eq $script:ArcWalkOut) { return }
    $batch = @()
    $sr = $script:ArcWalkOut.SyncRoot
    [System.Threading.Monitor]::Enter($sr)
    try {
        $n = [Math]::Min(200, $script:ArcWalkOut.Count)
        if ($n -gt 0) {
            $batch = $script:ArcWalkOut.GetRange(0, $n).ToArray()
            $script:ArcWalkOut.RemoveRange(0, $n)
        }
    } finally { [System.Threading.Monitor]::Exit($sr) }
    foreach ($uri in $batch) { Add-ArcExpandJob ([string]$uri) }
    Receive-ArcWalk
}

function Receive-ArcWalk {
    if ($script:ArcWalkReap.Count -eq 0) { return }
    $still = [Collections.Generic.List[object]]::new()
    foreach ($j in $script:ArcWalkReap) {
        if ($j.Handle.IsCompleted) { try { [void]$j.PS.EndInvoke($j.Handle) } catch { }; try { $j.PS.Dispose() } catch { } }
        else { $still.Add($j) }
    }
    $script:ArcWalkReap = $still
}

function Test-ArcSearchWalkActive {
    $running = ($null -ne $script:ArcWalkHandle -and -not $script:ArcWalkHandle.IsCompleted)
    $pending = ($null -ne $script:ArcWalkOut -and $script:ArcWalkOut.Count -gt 0)
    return ($running -or $pending)
}

function Stop-ArcSearchWalk {
    if ($script:ArcWalkCancel) { $script:ArcWalkCancel.stop = $true }
    if ($script:ArcWalkPS) { $script:ArcWalkReap.Add([PSCustomObject]@{ PS=$script:ArcWalkPS; Handle=$script:ArcWalkHandle }) }
    $script:ArcWalkPS = $null; $script:ArcWalkHandle = $null; $script:ArcWalkCancel = $null; $script:ArcWalkOut = $null
    Receive-ArcWalk
}

# == EXPANSION =================================================================
# Build + enqueue an archive-expansion job from a discovered archive storage uri. The
# canonical archive uri (Get-ArcArchiveUri) is the dedupe/index key, so the in-session skip
# and the reconstructed-on-load key are derived the same way. The treebrowser POST is
# materialised on the main thread (it needs Resolve-Repo / Get-RepoTypeForUI).
function Add-ArcExpandJob([string]$arcUri) {
    if (-not $arcUri -or (Test-NetworkBlocked)) { return }   # offline 'all' issues no expansions
    $item = Convert-UriToItem $arcUri
    $repo = [string]$item.Repo
    $archPath = Get-ArcArchivePath ([string]$item.Path) ([string]$item.Name)
    $canon = Get-ArcArchiveUri $repo $archPath
    if ($script:ArcIndexedArchives.Contains($canon) -or -not $script:ArcAttempted.Add($canon)) { return }
    # Skip-versions: only expand the first version of each artifact seen this session (the
    # seen-set is also seeded from prior runs via Ensure-ArcIndexedLoaded). Placed after the
    # indexed/attempted guard so an already-attempted archive can't consume a version slot twice.
    if ($script:ArcSkipVersions) {
        $vk = Get-ArcVersionKey $repo ([string]$item.Path) ([string]$item.Name)
        if (-not $script:ArcVersionSeen.Add($vk)) { return }   # a version of this artifact already taken
    }
    $tbr = Get-TreeBrowseRequest $repo (Get-RepoTypeForUI $repo) `
               ([string](Resolve-Repo $repo).PackageType) $archPath ([string]$item.Name)
    $script:ArcQueue.Enqueue(@{
        Key=$canon; ArcUri=$canon; ArcRepo=$repo; ArcPath=[string]$item.Path; ArcName=[string]$item.Name
        Uri=$tbr.Uri; Body=$tbr.Body; Headers=$tbr.Headers; Ua=$tbr.Ua
    })
}

# Throttled dispatch of expansion jobs (mirrors Dispatch-AuditWork).
function Dispatch-ArcExpand {
    $maxc = [Math]::Max(1, [Math]::Min($script:ArcMaxWorkers, [int]$script:ArcThrottle.MaxConcurrent))
    $iv   = [int]$script:ArcThrottle.MinIntervalMs
    while ($script:ArcJobs.Count -lt $maxc -and $script:ArcQueue.Count -gt 0) {
        if ($iv -gt 0 -and ([DateTime]::UtcNow - $script:ArcLastLaunch).TotalMilliseconds -lt $iv) { break }
        $rec = $script:ArcQueue.Dequeue()
        if ($null -eq $script:ArcPool) {
            $script:ArcPool = [RunspaceFactory]::CreateRunspacePool(1, $script:ArcMaxWorkers)
            $script:ArcPool.Open()
        }
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $script:ArcPool
        [void]$ps.AddScript($script:PvErrFn)        # define Get-WkError in the worker scope
        [void]$ps.AddScript((Get-ArcNodeFns))       # define the node helpers the worker flattens with
        [void]$ps.AddScript($script:ArcExpandScript).
            AddArgument($rec.Key).AddArgument($rec.Uri).AddArgument($rec.Body).
            AddArgument($rec.Headers).AddArgument($rec.Ua).AddArgument($script:ArcFetch).AddArgument($script:Alert)
        $script:ArcJobs.Add([PSCustomObject]@{ PS=$ps; Handle=$ps.BeginInvoke(); Rec=$rec })
        $script:ArcLastLaunch = [DateTime]::UtcNow
        if ($iv -gt 0) { break }   # paced: one launch per tick
    }
}

function Receive-ArcExpand {
    if ($script:ArcJobs.Count -eq 0) { return }
    $still = [Collections.Generic.List[object]]::new()
    foreach ($j in $script:ArcJobs) {
        if ($j.Handle.IsCompleted) {
            try { [void]$j.PS.EndInvoke($j.Handle) } catch { }
            try { $j.PS.Dispose() } catch { }
            Complete-ArcExpand $j.Rec
        } else { $still.Add($j) }
    }
    $script:ArcJobs = $still
}

# Single recursive pass over a (possibly nested) treebrowser node list -> this archive's index
# entry records: folders are recursed; non-folder nodes (incl. unlistable sub-archives) become file
# entries. One pass, no intermediate flat-node list. At 3M scale it deliberately does NOT accumulate
# into a session-wide list or warm $MetaCache per entry - a full walk would make both unbounded.
# Used by manual browsing (Save-BrowsedArchive), which holds the whole tree on the main thread; the
# BACKGROUND expansion now flattens inside its worker (ArcExpandScript) and Complete-ArcExpand just
# persists those compact records.
function Build-ArcIndexEntries([string]$repo, [string]$archDir, [string]$archName, $nodes) {
    $entries = [Collections.Generic.List[object]]::new()
    Add-ArcEntriesFromNodes $repo $archDir $archName $nodes $entries
    return ,$entries   # comma-wrap so an EMPTY list isn't unrolled to $null on return
}
function Add-ArcEntriesFromNodes([string]$repo, [string]$archDir, [string]$archName, $nodes, $acc) {
    foreach ($n in @($nodes)) {
        if ($null -eq $n) { continue }
        if (Get-NodeIsFolder $n) { Add-ArcEntriesFromNodes $repo $archDir $archName (Get-NodeChildren $n) $acc; continue }
        $internalPath = Get-NodeInternalPath $n
        if (-not $internalPath) { continue }
        $info = Get-NodeInfo $n
        $sz   = -1; $mod = ''
        if ($info -and $info.PSObject.Properties['size']) { try { $sz = [long]$info.size } catch { $sz = -1 } }
        if ($info -and $info.PSObject.Properties['modificationTime'] -and "$($info.modificationTime)" -ne '') { $mod = Format-Epoch $info.modificationTime }
        $acc.Add((New-ArcIndexEntry $repo $archDir $archName $internalPath $sz $mod))
    }
}

# Process a finished expansion (C). The worker already flattened the tree to compact
# {InternalPath;Size;Modified} entries, so the bulky tree never reaches the main thread. Persist the
# archive group and mark it indexed. ONLY when a live query is set (interactive arc-search) do we
# build full result records to test name matches; the headless index build has no query, so it skips
# straight to persisting. A failed expansion is left attempted-but-unindexed (not persisted).
function Complete-ArcExpand($rec) {
    $key = [string]$rec.Key
    $res = $null
    if ($script:ArcFetch.ContainsKey($key)) { $res = $script:ArcFetch[$key]; [void]$script:ArcFetch.Remove($key) }
    if ($null -eq $res -or -not $res.Ok) { $script:ArcSearchDirty = $true; return }

    $entries = @($res.Entries)
    if ($script:ArcSearchQuery) {
        foreach ($t in $entries) {
            if ($null -eq $t) { continue }
            $e = New-ArcIndexEntry $rec.ArcRepo $rec.ArcPath $rec.ArcName ([string]$t.InternalPath) $t.Size ([string]$t.Modified)
            if (Test-ArcNameMatches ([string]$e.Name)) { [void](Add-ArcSearchMatch $e) }
        }
    }
    [void]$script:ArcIndexedArchives.Add($key)
    Save-IndexArchive $rec.ArcRepo $rec.ArcPath $rec.ArcName $entries
    $script:ArcSearchDirty = $true
}

# Index an archive's contents when its tree is opened in the archive browser (the same
# indexing the [w] walk does, but triggered by manual browsing). Idempotent: an archive
# already indexed/attempted this session - including one loaded from a prior index - is
# skipped, so re-opening it costs nothing and never duplicates rows. $item is the archive
# file (a top-level browsable archive); $nodes is its treebrowser node list.
function Save-BrowsedArchive([object]$item, $nodes) {
    if (-not $script:IndexEnabled -or $null -eq $item) { return }
    $repo = [string]$item.Repo; $archDir = [string]$item.Path; $archName = [string]$item.Name
    $archPath = Get-ArcArchivePath $archDir $archName
    $canon = Get-ArcArchiveUri $repo $archPath
    if ($script:ArcIndexedArchives.Contains($canon) -or -not $script:ArcAttempted.Add($canon)) { return }
    $entries = Build-ArcIndexEntries $repo $archDir $archName $nodes
    [void]$script:ArcIndexedArchives.Add($canon)
    Save-IndexArchive $repo $archDir $archName $entries
}

# == TREE RECONSTRUCTION (serve the archive tree view from the index) ==========
# Ensure a folder node exists for $dir and all its ancestors in a reconstructed archive
# tree, linking each new folder into its parent's children. $childrenOf maps a dir path
# ('' = root) to its children list; $folderNodes maps a dir path to its node. Ancestors
# are created root-first, so a parent's children list always exists when a child is added.
function Confirm-ArcTreeDir([string]$dir, [hashtable]$childrenOf, [hashtable]$folderNodes) {
    if ($childrenOf.ContainsKey($dir)) { return }
    $cur = ''
    foreach ($seg in ($dir -split '/')) {
        if (-not $seg) { continue }
        $parent = $cur
        $cur = if ($cur) { "$cur/$seg" } else { $seg }
        if (-not $childrenOf.ContainsKey($cur)) {
            $kids = [Collections.Generic.List[object]]::new()
            $node = [PSCustomObject]@{ text = $seg; folder = $true; children = $kids; path = $cur; archivePath = '' }
            $childrenOf[$cur] = $kids
            $folderNodes[$cur] = $node
            $childrenOf[$parent].Add($node)
        }
    }
}

# Reconstruct the treebrowser-shaped tree for an archive purely from its indexed entries,
# so Show-ArchiveTree can open it WITHOUT a treebrowser request. Returns the same
# @{ Ok; Nodes; Error } shape as Get-ArchiveTree / the preview cache. Synthetic nodes carry
# exactly the fields the Core node accessors read (text/folder/children/path/archivePath/
# repoKey/downloadPath/tabs.info), so download urls, names, sizes and dates resolve as for a
# live tree. Sub-archives are flat file leaves (matching both the index and the tree view).
function Build-ArchiveTreeFromIndex($item) {
    $repo    = [string]$item.Repo
    $archDir = [string]$item.Path
    $archName= [string]$item.Name
    $archPath= Get-ArcArchivePath $archDir $archName
    # STREAM this archive's rows out of its single bucket (only ~total/N rows, not the whole
    # repo's archive entries). Rows are archDir,archName,internalPath,size,modified; match on
    # (archDir,archName) since a bucket holds several archives; a blank internalPath is the
    # empty-archive marker (no entry). Duplicate archive groups (pre-compaction) just re-add
    # identical entries, deduped by InternalPath below.
    $entries = [Collections.Generic.List[object]]::new()
    $ap = Get-ArchiveBucketPath $repo $archDir $archName
    if (Test-Path -LiteralPath $ap) {
        $seenIp = New-Object 'System.Collections.Generic.HashSet[string]'
        try {
            foreach ($line in [System.IO.File]::ReadLines($ap)) {
                if (-not $line) { continue }
                $f = Read-CsvRow $line
                if ($f.Count -lt 3 -or $f[0] -ne $archDir -or $f[1] -ne $archName) { continue }
                if (-not $f[2] -or -not $seenIp.Add($f[2])) { continue }
                $sz = if ($f.Count -ge 4) { $f[3] } else { -1 }
                $md = if ($f.Count -ge 5) { $f[4] } else { '' }
                $entries.Add((New-ArcIndexEntry $repo $f[0] $f[1] $f[2] $sz $md))
            }
        } catch { }
    }

    $childrenOf  = @{ '' = [Collections.Generic.List[object]]::new() }
    $folderNodes = @{}
    foreach ($e in $entries) {
        $dir = [string]$e.Path
        if ($dir) { Confirm-ArcTreeDir $dir $childrenOf $folderNodes }
        $internalPath = [string]$e.InternalPath
        $fnode = [PSCustomObject]@{
            text = [string]$e.Name; folder = $false; path = $internalPath; archivePath = ''
            repoKey = $repo; downloadPath = "$archPath!/$internalPath"
            tabs = @([PSCustomObject]@{ info = [PSCustomObject]@{ size = $e.Size; modificationTime = [string]$e.Modified } })
        }
        $childrenOf[$dir].Add($fnode)
    }
    # Get-NodeChildren only accepts an [Array], so finalize every folder's children (built as
    # a List for incremental Add) into a real array.
    foreach ($dir in @($folderNodes.Keys)) { $folderNodes[$dir].children = @($childrenOf[$dir].ToArray()) }
    return [PSCustomObject]@{ Ok = $true; Nodes = @($childrenOf[''].ToArray()); Error = '' }
}

# == PUMP / DRAIN ==============================================================
# One engine tick: reap finished expansions, extend the walk, dispatch new expansions,
# and detect completion. Safe to call every UI poll; cheap when idle.
function Invoke-ArcSearchPump {
    if ($script:ArcSearchState -ne 'walking') { return }
    Receive-ArcExpand
    Step-ArcSearchWalk
    Dispatch-ArcExpand
    if ($script:ArcQueue.Count -eq 0 -and $script:ArcJobs.Count -eq 0 -and -not (Test-ArcSearchWalkActive)) {
        $script:ArcSearchState = 'done'; $script:ArcSearchDirty = $true
    }
}

# Return archive-search result items added since the caller last drained (so the TUI
# appends only new rows). Advances the read cursor.
function Receive-ArcSearchResults {
    $out = @()
    if ($script:ArcSearchDrained -lt $script:ArcSearchResults.Count) {
        $out = @($script:ArcSearchResults.GetRange($script:ArcSearchDrained,
                    $script:ArcSearchResults.Count - $script:ArcSearchDrained))
        $script:ArcSearchDrained = $script:ArcSearchResults.Count
    }
    return $out
}

# == LIFECYCLE =================================================================
# Begin archive-search WALK for a query: abort any prior walk, reset the per-search result
# list, import the on-disk index once, seed instant matches from already-indexed archives,
# then start the background walk (the durable index caches are intentionally kept).
function Start-ArcSearch([string]$query, $restItems) {
    Stop-ArcSearch
    $script:ArcSearchQuery   = ([string]$query).ToLower()
    $script:ArcSearchResults = [Collections.Generic.List[object]]::new()
    $script:ArcSearchResultKeys = New-Object 'System.Collections.Generic.HashSet[string]'
    $script:ArcSearchDrained = 0
    $script:ArcSearchDirty   = $true
    if (-not $script:ArcSearchQuery) { $script:ArcSearchState = 'done'; return }
    if ($script:IndexEnabled) { Import-Index $script:IndexPath }
    Search-ArcIndex
    # Offline 'all': the walk hits the server (storage walk + treebrowser expansions), so it's
    # skipped - archive matches come only from what's already in the index (Search-ArcIndex above).
    if (Test-NetworkBlocked) { $script:ArcSearchState = 'done'; return }
    if (@(Get-ArcSearchWalkRepos).Count -eq 0) { $script:ArcSearchState = 'done'; return }
    $script:ArcSearchState = 'walking'
    [void](Start-ArcSearchWalk)
}

# Abort in-flight walk + expansions and clear pending work, leaving the index caches and
# any results found so far intact.
function Stop-ArcSearch {
    Stop-ArcSearchWalk
    foreach ($j in $script:ArcJobs) {
        try { [void]$j.PS.Stop() } catch { }
        try { $j.PS.Dispose() }    catch { }
    }
    $script:ArcJobs.Clear()
    $script:ArcQueue.Clear()
    $script:ArcFetch.Clear()
    if ($script:ArcPool) {
        try { $script:ArcPool.Close() }   catch { }
        try { $script:ArcPool.Dispose() } catch { }
        $script:ArcPool = $null
    }
    if ($script:ArcSearchState -eq 'walking') { $script:ArcSearchState = 'idle' }
}

# Hard reset: stop, and discard the in-memory index caches too. Used for testing / a fully
# clean slate (normal new-query flow uses Start-ArcSearch, which keeps the caches).
function Reset-ArcSearch {
    Stop-ArcSearch
    $script:ArcSearchState   = 'idle'; $script:ArcSearchQuery = ''
    $script:ArcSearchResults = [Collections.Generic.List[object]]::new()
    $script:ArcSearchResultKeys = New-Object 'System.Collections.Generic.HashSet[string]'
    $script:ArcSearchDrained = 0
    $script:ArcIndexEntries    = [Collections.Generic.List[object]]::new()
    $script:ArcIndexedArchives = New-Object 'System.Collections.Generic.HashSet[string]'
    $script:ArcAttempted       = New-Object 'System.Collections.Generic.HashSet[string]'
    $script:ArcVersionSeen     = New-Object 'System.Collections.Generic.HashSet[string]'
    $script:IndexPersisted     = New-Object 'System.Collections.Generic.HashSet[string]'
    $script:IndexLoaded        = $false
    $script:ArcIndexedLoaded   = $false
    $script:IndexManifest      = $null
    $script:ShardCache         = [Collections.Specialized.OrderedDictionary]::new()
    $script:ShardCacheRows     = 0
    $script:MetaOrder          = [Collections.Generic.Queue[string]]::new()
    $script:IndexCount         = 0
}

# == HEADLESS INDEX BUILDER ====================================================
# Build the local index non-interactively (StartIndex.ps1): a background storage walk emits
# EVERY file uri; a throttled metadata-fetch pool GETs each file's /api/storage record and
# persists path,name,size,modified to the per-repo shard (Write-IndexArtifactRow). Archive
# files are ALSO routed to the existing arc-expansion engine (Add-ArcExpandJob -> Complete-
# ArcExpand -> Save-IndexArchive) so their internal entries are indexed too - one walk feeds
# both. Location mode skips the walk and seeds jobs straight from a search's result items.
# Mirrors the arc-search engine's runspace/throttle patterns; reuses Get-ArcSearchWalkRepos.

# PARALLEL DEPTH-FIRST walk over /api/storage/<repo>/<path> emitting the storage uri of every FILE
# (A). Multiple of these run concurrently, sharing one ConcurrentStack of folders + a single-element
# int[] active-counter, so discovery is no longer the serial bottleneck that starves the metadata
# workers. A STACK (LIFO = depth-first, like the original serial walk) is deliberate: it dives to
# file-rich leaves fast and keeps the in-memory frontier small - a FIFO queue would enumerate an
# entire wide top layer (e.g. a Maven group root's 1000+ dirs) before surfacing any file AND let the
# frontier balloon. Each walker: claim a slot (Increment active BEFORE pop), GET the folder, push
# child folders + emit child files, release the slot. Termination is collective: a walker that finds
# the stack empty AND active==0 (nobody else holds a folder that could push children) exits.
# Increment-before-pop makes that test race-free - a walker about to take work is always counted, so
# active==0 truly means no more folders can appear. Back-pressure: pause while the output buffer is
# full so a huge instance can't balloon memory.
$script:IndexWalkScript = {
    param($artBase, $headers, $folderStack, $out, $cancel, $active, $paceMs, $maxPending)
    # $active is a synchronized hashtable { n } used as a shared atomic counter via Monitor on its
    # SyncRoot. NOTE: do NOT use [Interlocked]::Increment([ref]$arr[0]) here - PowerShell boxes a COPY
    # of an array element for [ref], so Interlocked silently updates the copy and the real counter
    # never moves (which made every walker but one exit instantly - a near-serial walk). Monitor on a
    # synchronized hashtable is the working cross-runspace primitive used elsewhere in this file.
    $lock = $active.SyncRoot
    while ($true) {
        if ($cancel.stop) { break }
        [System.Threading.Monitor]::Enter($lock); $active.n++; [System.Threading.Monitor]::Exit($lock)   # claim a slot before pop (race-free)
        $node = $null
        if (-not $folderStack.TryPop([ref]$node)) {
            [System.Threading.Monitor]::Enter($lock); $active.n--; $a = $active.n; [System.Threading.Monitor]::Exit($lock)
            # Stack empty right now: if no walker holds a slot, no more children can appear -> done.
            if ($a -eq 0 -and $folderStack.IsEmpty) { break }
            Start-Sleep -Milliseconds 10
            continue
        }
        try {
            $uri = "$artBase/api/storage/$($node.Repo)$($node.Rel)"
            try {
                $info = Invoke-RestMethod -Uri $uri -Headers $headers -ErrorAction Stop
                if ($info.PSObject.Properties['children'] -and $info.children) {
                    foreach ($c in @($info.children)) {
                        if ($null -eq $c) { continue }
                        $childRel = "$($node.Rel)$($c.uri)"
                        if ([bool]$c.folder) { $folderStack.Push([PSCustomObject]@{ Repo = $node.Repo; Rel = $childRel }) }
                        else {
                            while (-not $cancel.stop -and $out.Count -ge $maxPending) { Start-Sleep -Milliseconds 100 }
                            [void]$out.Add("$artBase/api/storage/$($node.Repo)$childRel")
                        }
                    }
                }
            } catch { }   # denied/unreadable folders are skipped silently
        } finally { [System.Threading.Monitor]::Enter($lock); $active.n--; [System.Threading.Monitor]::Exit($lock) }
        if ($paceMs -gt 0) { Start-Sleep -Milliseconds $paceMs }
    }
}

# Metadata worker LOOP (E): runs for the whole build in its own runspace. Pulls a uri from the
# input queue, GETs its /api/storage record (size + lastModified; no checksums - the index stores
# no hash), pushes a {Uri;Ok;Size;Modified} record to the output queue, repeats until Cancel. It
# idle-parks while its ordinal is >= the live Target (the AIMD throttle, B). No per-file PowerShell
# object is created/disposed - one loop replaces that churn.
# RETRY/BACKOFF (B): a transient failure (429/503/timeout/502/504) is retried up to 3x with jittered
# exponential backoff instead of dropping the file - the old single-try path silently lost a file on
# any blip, which got worse the harder we push concurrency. A 429/503 also stamps $ctl.LastThrottle
# so the main-thread AIMD controller (Step-IdxAimd) can back the Target down. Non-transient errors
# (404/403/...) fail fast - retrying them is pointless.
$script:IdxMetaWorkerScript = {
    param($inQ, $outQ, $ctl, $headers, $ordinal)
    while (-not $ctl.Cancel) {
        if ($ordinal -ge [int]$ctl.Target) { Start-Sleep -Milliseconds 25; continue }   # parked above target
        $uri = $null
        if (-not $inQ.TryDequeue([ref]$uri)) { Start-Sleep -Milliseconds 15; continue }  # input empty: wait
        $attempt = 0
        while ($true) {
            try {
                $info = Invoke-RestMethod -Uri ([string]$uri) -Headers $headers -TimeoutSec 60 -ErrorAction Stop
                $sz = ''; $mod = ''
                if ($info.PSObject.Properties['size'])         { $sz  = $info.size }
                if ($info.PSObject.Properties['lastModified']) { $mod = "$($info.lastModified)" }
                $outQ.Enqueue([PSCustomObject]@{ Uri = [string]$uri; Ok = $true; Size = $sz; Modified = $mod })
                break
            } catch {
                $code = 0
                try { if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode } } catch { }
                $throttle  = ($code -eq 429 -or $code -eq 503)
                $transient = ($throttle -or $code -eq 0 -or $code -eq 502 -or $code -eq 504)   # 0 = timeout / conn reset
                if ($throttle) { $ctl.LastThrottle = [DateTime]::UtcNow }   # signal the AIMD controller
                if ($transient -and $attempt -lt 3) {
                    $attempt++
                    Start-Sleep -Milliseconds ([int]([Math]::Pow(2, $attempt) * 150) + (Get-Random -Minimum 0 -Maximum 250))
                    continue
                }
                $outQ.Enqueue([PSCustomObject]@{ Uri = [string]$uri; Ok = $false; Size = ''; Modified = '' })
                break
            }
        }
        $d = [int]$ctl.Delay
        if ($d -gt 0) { Start-Sleep -Milliseconds $d }
    }
}

# == INDEX-BUILD STATE =========================================================
$script:IdxBuildState = 'idle'    # idle | building | done
$script:IdxBuildArchives = $false # also expand+index listable archives
$script:IdxEnq  = 0               # files dispatched for metadata
$script:IdxDone = 0               # files persisted (or failed)
$script:IdxSeen = New-Object 'System.Collections.Generic.HashSet[string]'  # uris dispatched this run (intra-run dedupe)
$script:IdxResume  = $false       # (F) --resume: skip the metadata GET for files already in the shards
$script:IdxSkipped = 0            # files skipped this run because they were already indexed (resume)

# Parallel discovery walk (A): a pool of $IdxWalkConcurrency walker runspaces share $IdxWalkFolderStack
# (a ConcurrentStack of {Repo;Rel} folders, seeded with repo roots - LIFO for depth-first descent)
# and $IdxWalkActive (a synchronized hashtable { n } used as a Monitor-guarded atomic active-walker
# counter for collective termination). $IdxWalkers holds the {PS;Handle} of each. $IdxWalkOut is the
# bounded output buffer the main thread drains (Step-IndexWalk).
$script:IdxWalkConcurrency = 8    # aggressive default; overridden by --walkers
$script:IdxWalkPool   = $null
$script:IdxWalkers    = [Collections.Generic.List[object]]::new()
$script:IdxWalkCancel = $null
$script:IdxWalkFolderStack = $null
$script:IdxWalkActive  = $null
$script:IdxWalkOut = $null; $script:IdxWalkReap = [Collections.Generic.List[object]]::new()

# Worker-loop metadata pool (E): a FIXED set of long-lived runspaces pull file uris from a shared
# ConcurrentQueue (input) and push {Uri;Ok;Size;Modified} records to another (output). The main
# thread feeds input (Add-IndexFile) and drains output (Drain-IdxMeta), writing the rows itself so
# shard appends stay serialized. $IdxCtl is the shared control block every worker reads each loop:
#   Cancel - stop the loops; Target - how many workers may be active (the AIMD throttle knob, B);
#   Delay  - per-request politeness sleep (ms). This replaces the old per-file [PowerShell]::Create()
#   /BeginInvoke/EndInvoke/Dispose churn (one object per file) with N loops that run for the build.
$script:IdxMetaQueue = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()   # input: file uris
$script:IdxOutQueue  = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()   # output: result records
$script:IdxCtl       = [hashtable]::Synchronized(@{ Cancel = $false; Target = 0; Delay = 0; LastThrottle = [DateTime]::MinValue })
$script:IdxMetaPool  = $null
$script:IdxWorkers   = [Collections.Generic.List[object]]::new()   # the long-lived worker {PS;Handle}
$script:IdxThrottle  = @{ MaxConcurrent = 32; MinIntervalMs = 0 }   # aggressive default: 32 metadata workers
$script:IdxMaxWorkers = 100   # ceiling for --workers / the metadata runspace pool
# AIMD adaptive throttle (B): the main thread nudges $IdxCtl.Target (active worker count) - halving
# it when a worker reports a 429/503 (multiplicative decrease) and creeping it back toward the full
# pool after a quiet spell (additive increase). Lets the aggressive defaults run hot but yield fast
# if the server pushes back, instead of hammering it. Workers above Target idle-park (they aren't
# destroyed), so this is just moving a number.
$script:IdxAimdMaxTarget  = 0                   # pool size = Target ceiling; set in Start-IdxMetaPool
$script:IdxAimdReactedTo  = [DateTime]::MinValue # the LastThrottle stamp we've already reacted to
$script:IdxAimdLastChange = [DateTime]::MinValue # rate-limits how often AIMD adjusts
# Back-pressure cap: when the metadata queue OR the archive-expansion queue reaches this, the
# walk drain pauses so the walk's own bounded buffer fills and the walker sleeps. Without this
# the storage walk (fast: folder GETs) outruns the per-file metadata + archive-tree workers
# (slow: network + heavy main-thread processing) and the queues + in-flight trees grow without
# bound, ballooning memory on a large instance.
$script:IdxQueueCap  = 8000

# Launch the PARALLEL file walk over the in-scope repos (an explicit -Repos list, else non-virtual
# repo keys - same selection as the arc walk). A pool of $IdxWalkConcurrency walker runspaces share
# one folder queue (seeded with repo roots) + the atomic active-counter. Returns $false when there's
# nothing to walk.
function Start-IndexWalk {
    Stop-IndexWalk
    $repos = Get-ArcSearchWalkRepos
    if (@($repos).Count -eq 0) { return $false }
    $k = [Math]::Max(1, [int]$script:IdxWalkConcurrency)
    $script:IdxWalkOut    = [Collections.ArrayList]::Synchronized([Collections.ArrayList]::new())
    $script:IdxWalkCancel = [hashtable]::Synchronized(@{ stop = $false })
    $script:IdxWalkFolderStack = [System.Collections.Concurrent.ConcurrentStack[object]]::new()
    foreach ($r in @($repos)) { $script:IdxWalkFolderStack.Push([PSCustomObject]@{ Repo = $r; Rel = '' }) }
    $script:IdxWalkActive = [hashtable]::Synchronized(@{ n = 0 })   # atomic active-walker counter (Monitor-guarded)
    $script:IdxWalkPool = [RunspaceFactory]::CreateRunspacePool($k, $k)
    $script:IdxWalkPool.Open()
    $artBase = Get-ArtBase; $headers = Get-AuthHeaders
    for ($i = 0; $i -lt $k; $i++) {
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $script:IdxWalkPool
        [void]$ps.AddScript($script:IndexWalkScript).
            AddArgument($artBase).AddArgument($headers).AddArgument($script:IdxWalkFolderStack).
            AddArgument($script:IdxWalkOut).AddArgument($script:IdxWalkCancel).
            AddArgument($script:IdxWalkActive).AddArgument(0).AddArgument(5000)
        $script:IdxWalkers.Add([PSCustomObject]@{ PS = $ps; Handle = $ps.BeginInvoke() })
    }
    return $true
}

# Route a discovered file uri: always queue a metadata fetch; if it's a listable archive and
# archive-indexing is on, ALSO enqueue an arc expansion (the reused engine indexes its entries).
function Add-IndexFile([string]$uri) {
    if (-not $uri -or -not $script:IdxSeen.Add($uri)) { return }
    # Resume (F): if this file's row is already in its repo shard (from a prior run), skip the
    # metadata GET - the expensive part. We still fall through to archive routing below, because the
    # archive's INTERNAL entries may not have been expanded yet (Add-ArcExpandJob has its own skip-set).
    $skipMeta = $false
    if ($script:IdxResume) {
        $it = Convert-UriToItem $uri
        $rk = Get-IndexRelKey ([string]$it.Path) ([string]$it.Name)
        if ((Get-RepoIndexTable ([string]$it.Repo)).ContainsKey($rk)) { $skipMeta = $true; $script:IdxSkipped++ }
    }
    if (-not $skipMeta) {
        $script:IdxMetaQueue.Enqueue($uri)
        $script:IdxEnq++   # counted as it enters the input queue; completion is IdxEnq == IdxDone (all drained)
    }
    if ($script:IdxBuildArchives) {
        $nm  = ($uri -split '/')[-1]
        $dot = $nm.LastIndexOf('.')
        $ext = if ($dot -ge 0 -and $dot -lt $nm.Length - 1) { $nm.Substring($dot + 1).ToLower() } else { '' }
        if ($ext -and (Get-ArcExtSet).Contains($ext)) { Add-ArcExpandJob $uri }
    }
}

# Seed jobs from a result-set (location mode): each item's metadata, plus archive expansion
# for any listable-archive item when archive-indexing is on.
function Add-IndexItems($items) {
    foreach ($it in @($items)) {
        if ($null -eq $it) { continue }
        Add-IndexFile ([string]$it.Uri)
    }
}

# Drain the walk buffer (bounded per tick) and route each uri.
function Step-IndexWalk {
    if ($null -eq $script:IdxWalkOut) { return }
    # Back-pressure: while downstream queues are saturated, stop draining so the walk's own
    # bounded buffer fills and the walker pauses. Bounds total in-memory work (queues +
    # in-flight archive trees) regardless of instance size.
    if ($script:IdxMetaQueue.Count -ge $script:IdxQueueCap -or $script:ArcQueue.Count -ge $script:IdxQueueCap) {
        Receive-IndexWalk; return
    }
    $batch = @()
    $sr = $script:IdxWalkOut.SyncRoot
    [System.Threading.Monitor]::Enter($sr)
    try {
        $n = [Math]::Min(300, $script:IdxWalkOut.Count)
        if ($n -gt 0) {
            $batch = $script:IdxWalkOut.GetRange(0, $n).ToArray()
            $script:IdxWalkOut.RemoveRange(0, $n)
        }
    } finally { [System.Threading.Monitor]::Exit($sr) }
    foreach ($uri in $batch) { Add-IndexFile ([string]$uri) }
    Receive-IndexWalk
}

function Receive-IndexWalk {
    if ($script:IdxWalkReap.Count -eq 0) { return }
    $still = [Collections.Generic.List[object]]::new()
    foreach ($j in $script:IdxWalkReap) {
        if ($j.Handle.IsCompleted) { try { [void]$j.PS.EndInvoke($j.Handle) } catch { }; try { $j.PS.Dispose() } catch { } }
        else { $still.Add($j) }
    }
    $script:IdxWalkReap = $still
}

function Test-IndexWalkActive {
    $running = $false
    foreach ($w in $script:IdxWalkers) { if (-not $w.Handle.IsCompleted) { $running = $true; break } }
    $pending = ($null -ne $script:IdxWalkOut -and $script:IdxWalkOut.Count -gt 0)
    return ($running -or $pending)
}

function Stop-IndexWalk {
    if ($script:IdxWalkCancel) { $script:IdxWalkCancel.stop = $true }
    foreach ($w in $script:IdxWalkers) {
        try { [void]$w.PS.Stop() } catch { }
        try { $w.PS.Dispose() }    catch { }
    }
    $script:IdxWalkers.Clear()
    if ($script:IdxWalkPool) {
        try { $script:IdxWalkPool.Close() }   catch { }
        try { $script:IdxWalkPool.Dispose() } catch { }
        $script:IdxWalkPool = $null
    }
    $script:IdxWalkCancel = $null; $script:IdxWalkOut = $null
    $script:IdxWalkFolderStack = $null; $script:IdxWalkActive = $null
    Receive-IndexWalk
}

# Launch the fixed worker-loop pool once at build start. N = the configured concurrency (--workers,
# capped at $IdxMaxWorkers); Target starts at N (all active) and AIMD (B) lowers it under throttling.
# The workers live until Stop-IndexBuild. Mirrors nothing per-tick - the pump just feeds + drains.
function Start-IdxMetaPool {
    $n = [Math]::Max(1, [Math]::Min($script:IdxMaxWorkers, [int]$script:IdxThrottle.MaxConcurrent))
    $script:IdxCtl.Cancel = $false
    $script:IdxCtl.Target = $n
    $script:IdxCtl.Delay  = [Math]::Max(0, [int]$script:IdxThrottle.MinIntervalMs)
    $script:IdxCtl.LastThrottle = [DateTime]::MinValue
    $script:IdxAimdMaxTarget  = $n   # AIMD may lower Target to 1 and ramp it back up to here
    $script:IdxAimdReactedTo  = [DateTime]::MinValue
    $script:IdxAimdLastChange = [DateTime]::MinValue
    if ($null -eq $script:IdxMetaPool) {
        $script:IdxMetaPool = [RunspaceFactory]::CreateRunspacePool($n, $n)
        $script:IdxMetaPool.Open()
    }
    $headers = Get-AuthHeaders
    for ($i = 0; $i -lt $n; $i++) {
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $script:IdxMetaPool
        [void]$ps.AddScript($script:IdxMetaWorkerScript).
            AddArgument($script:IdxMetaQueue).AddArgument($script:IdxOutQueue).
            AddArgument($script:IdxCtl).AddArgument($headers).AddArgument($i)
        $script:IdxWorkers.Add([PSCustomObject]@{ PS = $ps; Handle = $ps.BeginInvoke() })
    }
}

# Drain finished metadata results (bounded per tick so the pump stays responsive) and persist each
# as a top-level shard row. Runs on the main thread, so shard appends stay serialized.
function Drain-IdxMeta {
    $res = $null
    $n = 0
    while ($n -lt 2000 -and $script:IdxOutQueue.TryDequeue([ref]$res)) {
        if ($res -and $res.Ok) {
            $it = Convert-UriToItem ([string]$res.Uri)
            [void](Write-IndexArtifactRow ([string]$it.Repo) ([string]$it.Path) ([string]$it.Name) $res.Size ([string]$res.Modified))
        }
        $script:IdxDone++
        $n++
    }
}

# One engine tick: reap + dispatch metadata fetches and (reused) archive expansions, extend
# the walk, and detect completion. Safe to call in a tight loop; cheap when idle.
# AIMD controller (B): runs on the main thread, ~once/0.75s. Halves Target on a fresh 429/503 signal
# (multiplicative decrease); after ~8s with no throttle, creeps Target back up by 1 toward the full
# pool (additive increase). Cheap and idempotent; safe to call every pump tick.
function Step-IdxAimd {
    $now = [DateTime]::UtcNow
    if (($now - $script:IdxAimdLastChange).TotalMilliseconds -lt 750) { return }   # at most ~once/0.75s
    $lt  = [DateTime]$script:IdxCtl.LastThrottle
    $cur = [int]$script:IdxCtl.Target
    if ($lt -gt $script:IdxAimdReactedTo) {
        $script:IdxCtl.Target    = [Math]::Max(1, [int][Math]::Floor($cur / 2.0))
        $script:IdxAimdReactedTo = $lt
        $script:IdxAimdLastChange = $now
    } elseif (($now - $lt).TotalSeconds -ge 8 -and $cur -lt $script:IdxAimdMaxTarget) {
        $script:IdxCtl.Target     = [Math]::Min($script:IdxAimdMaxTarget, $cur + 1)
        $script:IdxAimdLastChange = $now
    }
}

function Invoke-IndexBuildPump {
    if ($script:IdxBuildState -ne 'building') { return }
    if ($script:IdxBuildArchives) { Receive-ArcExpand }
    Step-IndexWalk        # feeds the input queue via Add-IndexFile (back-pressured)
    Drain-IdxMeta         # drains worker results -> shard rows
    Step-IdxAimd          # adjust worker concurrency to server pushback
    if ($script:IdxBuildArchives) { Dispatch-ArcExpand }
    $arcBusy = $script:IdxBuildArchives -and ($script:ArcQueue.Count -gt 0 -or $script:ArcJobs.Count -gt 0)
    # Done when: no more discovery, input queue empty, every fed file has produced+drained a result
    # (IdxEnq counted at enqueue, IdxDone at drain), and the archive tail is idle.
    if (-not (Test-IndexWalkActive) -and $script:IdxMetaQueue.Count -eq 0 -and
        $script:IdxEnq -eq $script:IdxDone -and -not $arcBusy) {
        $script:IdxBuildState = 'done'
    }
}

# Begin a build. $items seeds location mode (no walk); pass $null + (Start the walk) for full.
function Start-IndexBuild([bool]$full, [bool]$archives, $items) {
    Stop-IndexBuild
    $script:IdxBuildArchives = $archives
    $script:IdxEnq = 0; $script:IdxDone = 0; $script:IdxSkipped = 0
    $script:IdxSeen = New-Object 'System.Collections.Generic.HashSet[string]'
    $script:IdxMetaQueue = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
    $script:IdxOutQueue  = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
    $script:ShardWriteBuf = @{}; $script:ShardWriteBufRows = @{}; $script:IndexWriteBuffered = $true   # buffer writes (D)
    if ($archives) { Ensure-ArcIndexedLoaded }   # skip archives already indexed in a prior run
    $script:IdxBuildState = 'building'
    Start-IdxMetaPool   # launch the fixed worker-loop pool (full + location both feed it)
    if ($full) {
        if (-not (Start-IndexWalk)) { $script:IdxBuildState = 'done'; Stop-IndexBuild; return $false }
    } else {
        Add-IndexItems $items
    }
    return $true
}

# Abort the build: stop the walk, drain/dispose the metadata pool, and clean the reused arc
# pool. Index caches (skip-set etc.) are left intact.
function Stop-IndexBuild {
    Stop-IndexWalk
    $script:IdxCtl.Cancel = $true   # signal the worker loops to exit
    foreach ($w in $script:IdxWorkers) {
        try { [void]$w.PS.Stop() } catch { }   # Stop() (not EndInvoke) so a worker mid-GET can't wedge us
        try { $w.PS.Dispose() }    catch { }
    }
    $script:IdxWorkers.Clear()
    if ($script:IdxMetaPool) {
        try { $script:IdxMetaPool.Close() }   catch { }
        try { $script:IdxMetaPool.Dispose() } catch { }
        $script:IdxMetaPool = $null
    }
    # Fresh queues for the next build (ConcurrentQueue has no Clear() on .NET Framework).
    $script:IdxMetaQueue = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
    $script:IdxOutQueue  = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
    Flush-IndexWrites                      # (D) persist any buffered top-level rows before we stop
    $script:IndexWriteBuffered = $false    # the TUI write-through (if any) goes back to immediate writes
    if ($script:IdxBuildArchives) { Stop-ArcSearch }   # clean the reused arc-expansion pool
    if ($script:IdxBuildState -eq 'building') { $script:IdxBuildState = 'idle' }
}

# == INDEX-BUILD DRIVER (shared by StartIndex + audit --populate-index) =========
# Verbosity for the build driver, set by whichever launcher calls it (StartIndex from -v; the audit
# launcher forwards its own verbosity when auto-populating). Lives here so the driver is self-contained
# and callable from either launcher (the audit launcher does NOT load StartIndex.ps1).
$script:IndexVerbosity = 1
function Write-IdxV([int]$level, [string]$msg) { if ($script:IndexVerbosity -ge $level) { Write-Host $msg } }
function Format-Eta([int]$seconds) {
    if ($seconds -lt 0) { $seconds = 0 }
    if ($seconds -lt 60)    { return "${seconds}s" }
    if ($seconds -lt 3600)  { return ('{0}m {1}s' -f [int][Math]::Floor($seconds / 60), ($seconds % 60)) }
    if ($seconds -lt 86400) { return ('{0}h {1}m' -f [int][Math]::Floor($seconds / 3600), [int][Math]::Floor(($seconds % 3600) / 60)) }
    return ('{0}d {1}h' -f [int][Math]::Floor($seconds / 86400), [int][Math]::Floor(($seconds % 86400) / 3600))
}

# Drive a configured index build to completion. Preconditions the CALLER sets: $BaseUrl (trimmed) +
# auth, $Repos / repo-type scope, $IndexPath (resolved), $IndexVerbosity. Applies the index throttle
# DEFAULTS (workers 50, walkers 20, arc-workers 15, delay 0) when a value is <=0 (delay <0). Used by
# StartIndex's Invoke-IndexBuildCore AND the audit launcher's --populate-index auto-build, so the
# defaults + drive logic live in exactly one place.
function Invoke-IndexBuildRun {
    param([bool]$Full, [bool]$Archives, [string]$Query = '', [bool]$AllVersions = $false, [bool]$Resume = $false,
          [int]$Workers = 0, [int]$Walkers = 0, [int]$ArcWorkers = 0, [int]$DelayMs = -1)

    $script:IndexEnabled = $true
    $script:IdxThrottle.MaxConcurrent = if ($Workers -gt 0)    { [Math]::Max(1, [Math]::Min(100, $Workers)) }    else { 50 }
    $script:IdxWalkConcurrency        = if ($Walkers -gt 0)    { [Math]::Max(1, [Math]::Min(32,  $Walkers)) }    else { 20 }
    $script:ArcThrottle.MaxConcurrent = if ($ArcWorkers -gt 0) { [Math]::Max(1, [Math]::Min(20,  $ArcWorkers)) } else { 15 }
    $d = if ($DelayMs -ge 0) { $DelayMs } else { 0 }
    $script:IdxThrottle.MinIntervalMs = $d; $script:ArcThrottle.MinIntervalMs = $d
    $script:ArcSkipVersions = -not $AllVersions
    $script:IdxResume = $Resume

    $scopeLabel = if ($Full) { 'entire instance' } else { "search: $Query" }
    $arcLabel   = if ($Archives) { ' (+ listable archives)' } else { '' }
    Write-IdxV 1 "Building index for $scopeLabel$arcLabel"
    Write-IdxV 2 "  index dir: $($script:IndexPath)"
    Write-IdxV 5 ("  settings: archives=$Archives skip-versions=$($script:ArcSkipVersions) resume=$($script:IdxResume) workers=$($script:IdxThrottle.MaxConcurrent) walkers=$($script:IdxWalkConcurrency) arc-workers=$($script:ArcThrottle.MaxConcurrent) delay=$($script:IdxThrottle.MinIntervalMs)ms queue-cap=$($script:IdxQueueCap) repos='$($script:Repos)' repo-types='$($script:RepoTypeScope -join ",")'")

    if ($Full) {
        $walkRepos = @(Get-ArcSearchWalkRepos)
        if ($walkRepos.Count -eq 0) {
            Write-IdxV 1 'Nothing to index: no readable repositories (anonymous access may be denied /api/repositories; try -r/--repos).'
            return
        }
        $repoPreview = (@($walkRepos | Select-Object -First 12) -join ', ')
        if ($walkRepos.Count -gt 12) { $repoPreview += ', ...' }
        Write-IdxV 3 "  walking $($walkRepos.Count) repo(s): $repoPreview"
        if (-not (Start-IndexBuild $true $Archives $null)) { Write-IdxV 1 'Nothing to index.'; return }
    } else {
        Write-IdxV 1 "Searching for '$Query'..."
        $res = Search-Artifacts $Query
        if ($res.Error) { throw "Search failed: $($res.Error)" }
        Write-IdxV 2 "  $($res.Total) result(s) from the REST quick-search"
        [void](Start-IndexBuild $false $Archives $res.Items)
    }

    $start = [DateTime]::UtcNow; $lastTick = [DateTime]::MinValue; $lastGc = [DateTime]::UtcNow; $lastFlush = [DateTime]::UtcNow
    $arcBase = $script:ArcIndexedArchives.Count
    while ($script:IdxBuildState -ne 'done') {
        Invoke-IndexBuildPump
        if (([DateTime]::UtcNow - $lastGc).TotalSeconds -ge 20) { [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers(); $lastGc = [DateTime]::UtcNow }
        if (([DateTime]::UtcNow - $lastFlush).TotalSeconds -ge 5) { Flush-IndexWrites; $lastFlush = [DateTime]::UtcNow }
        if ($script:IndexVerbosity -ge 2 -and ([DateTime]::UtcNow - $lastTick).TotalSeconds -ge 1) {
            $done    = $script:IdxDone + $script:IdxSkipped
            $denom   = $script:IdxSeen.Count
            $walking = Test-IndexWalkActive
            $arcBusy = $Archives -and ($script:ArcQueue.Count -gt 0 -or $script:ArcJobs.Count -gt 0)
            $elapsed = ([DateTime]::UtcNow - $start).TotalSeconds
            $rate    = if ($elapsed -gt 0) { $done / $elapsed } else { 0 }
            $pct     = if ($denom -gt 0) { [int][Math]::Floor($done * 100.0 / $denom) } else { 0 }
            $status =
                if ($walking)                              { '(walking - discovered total still rising)' }
                elseif ($done -lt $denom -and $rate -gt 0) { 'ETA ' + (Format-Eta ([int][Math]::Ceiling(($denom - $done) / $rate))) }
                elseif ($arcBusy) {
                    $arcLeft  = $script:ArcQueue.Count + $script:ArcJobs.Count
                    $arcDone2 = $script:ArcIndexedArchives.Count - $arcBase
                    $arcRate  = if ($elapsed -gt 0) { $arcDone2 / $elapsed } else { 0 }
                    $arcEta   = if ($arcRate -gt 0) { ', ETA ' + (Format-Eta ([int][Math]::Ceiling($arcLeft / $arcRate))) } else { '' }
                    "(expanding archives $arcDone2/$($arcDone2 + $arcLeft)$arcEta)"
                }
                else { '' }
            $rateStr = if ($rate -gt 0) { ' | {0:0.0} files/s' -f $rate } else { '' }
            $arc  = if ($Archives -and $script:IndexVerbosity -ge 4) { " | archives expanded=$($script:ArcIndexedArchives.Count)" } else { '' }
            $dbg  = if ($script:IndexVerbosity -ge 5) {
                $aq = if ($Archives) { " | arc-expand queued=$($script:ArcQueue.Count) active=$($script:ArcJobs.Count)" } else { '' }
                "  [meta-fetch queued=$($script:IdxMetaQueue.Count) workers=$($script:IdxCtl.Target)/$($script:IdxWorkers.Count)$aq]"
            } else { '' }
            $skip = if ($script:IdxSkipped -gt 0) { " | $($script:IdxSkipped) already-indexed skipped" } else { '' }
            Write-Host ("  ...metadata fetched for $done/$denom discovered files ($pct%), $($script:IndexCount) index rows$rateStr$skip $status$arc$dbg".TrimEnd())
            $lastTick = [DateTime]::UtcNow
        }
        Start-Sleep -Milliseconds 100
    }
    Stop-IndexBuild

    $secs = [int]([DateTime]::UtcNow - $start).TotalSeconds
    $skipNote = if ($script:IdxSkipped -gt 0) { " ($($script:IdxSkipped) already-indexed file(s) skipped via --resume)" } else { '' }
    Write-IdxV 1 ''
    Write-IdxV 1 ("Index build complete in ${secs}s: metadata fetched for $($script:IdxDone) file(s)$skipNote, $($script:IndexCount) index row(s) written this run (top-level + archive entries).")
    if ($Archives) { Write-IdxV 1 ("  archives expanded (incl. prior runs): $($script:ArcIndexedArchives.Count)") }
    Write-IdxV 2 "  index: $($script:IndexPath)"
}

# == HEADLESS RESULTS WRITER ===================================================
# Write the combined search results (REST + archive matches) to a CSV. Columns:
# Name,Repo,Path,Archive,Url,Size,Modified. UTF-8 no-BOM, RFC-4180 quoting.
function Write-ArcSearchResults([string]$file, $items) {
    $rows = @($items | Where-Object { $_ })
    try {
        $dir = Split-Path -Parent $file
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $q    = { param($v) '"' + ("$v" -replace '"','""') + '"' }
        $cols = @('Name','Repo','Path','Archive','Url','Size','Modified')
        $sb   = [Text.StringBuilder]::new()
        [void]$sb.AppendLine((@($cols | ForEach-Object { & $q $_ }) -join ','))
        foreach ($it in $rows) {
            $sz  = if ("$($it.Size)" -match '^\d+$') { "$($it.Size)" } else { '' }
            $row = @([string]$it.Name, [string]$it.Repo, [string]$it.Path, (Get-ItemArchiveName $it),
                     (Get-ItemUrl $it), $sz, [string]$it.Modified)
            [void]$sb.AppendLine((@($row | ForEach-Object { & $q $_ }) -join ','))
        }
        [System.IO.File]::WriteAllText($file, $sb.ToString(), [Text.UTF8Encoding]::new($false))
    } catch { }
}

# == COMPACTION ================================================================
# Write-through is append-only, so re-browsing across sessions can leave duplicate rows for a
# key (artifact rel-key, or an archive entry). Compaction streams ONE shard file, keeps the
# LAST row per key (last-wins, matching the read-side dedupe), and rewrites it atomically
# (temp + move). Streaming + a single output writer keeps memory at O(distinct keys in that
# one file). Returns @{ Before; After } row counts, or $null if there was nothing to do.
function Compress-IndexShardFile([string]$path, [switch]$Archive) {
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    $order = [Collections.Generic.List[string]]::new()    # first-seen key order, for stable output
    $last  = @{}                                           # key -> raw line (last wins)
    $before = 0
    try {
        $sep = [char]0
        foreach ($line in [System.IO.File]::ReadLines($path)) {
            if (-not "$line".Trim()) { continue }
            $before++
            $f = Read-CsvRow $line
            $key = $null
            if ($Archive) {
                if ($f.Count -ge 3) { $key = "$($f[0])$sep$($f[1])$sep$($f[2])" }   # archDir|archName|internalPath
            } elseif ($f.Count -ge 2) {
                $key = Get-IndexRelKey $f[0] $f[1]
            }
            if ($null -eq $key) { continue }
            if (-not $last.ContainsKey($key)) { $order.Add($key) }
            $last[$key] = $line
        }
    } catch { return $null }
    if ($order.Count -eq $before) { return @{ Before = $before; After = $before } }   # no dups
    $tmp = $path + '.tmp'
    try {
        $sb = [Text.StringBuilder]::new()
        foreach ($k in $order) { [void]$sb.Append($last[$k]).Append("`n") }
        [System.IO.File]::WriteAllText($tmp, $sb.ToString(), [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $tmp -Destination $path -Force
    } catch { try { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } catch { }; return $null }
    return @{ Before = $before; After = $order.Count }
}
# Compact a repo's shards: the artifact shard, or (with -Archive) every arc bucket. Aggregates
# @{ Before; After } across files; $null when there was nothing on disk. Not auto-run (a
# multi-million-row rewrite is slow); call it explicitly when shards have grown dup-heavy.
function Compress-IndexShard([string]$repo, [switch]$Archive) {
    if (-not $Archive) { return Compress-IndexShardFile (Get-ArtifactShardPath $repo) }
    $before = 0; $after = 0; $any = $false
    foreach ($bp in (Get-ArchiveBucketFiles $repo)) {
        $r = Compress-IndexShardFile $bp -Archive
        if ($r) { $any = $true; $before += $r.Before; $after += $r.After }
    }
    if (-not $any) { return $null }
    return @{ Before = $before; After = $after }
}
# Compact every shard (artifact + all archive buckets) of every repo; _archives.csv /
# _repos.csv are left as-is (idempotent on read). Returns total rows reclaimed.
function Compress-Index {
    $reclaimed = 0
    foreach ($repo in (Get-IndexedRepos)) {
        foreach ($arc in @($false, $true)) {
            $r = if ($arc) { Compress-IndexShard $repo -Archive } else { Compress-IndexShard $repo }
            if ($r) { $reclaimed += ($r.Before - $r.After) }
        }
    }
    return $reclaimed
}

# Sentinel so the launchers can detect that the index/archive-search engine is loaded.
function Invoke-ArcSearch { }
