# Prefetch.ps1 — part of the ARTCA Artifactory TUI (see StartTui.ps1).
#
# This file holds function and $script:-state definitions only; nothing here runs
# on its own. It is loaded two ways:
#   · dot-sourced automatically by StartTui.ps1 when the tool is run as a file, or
#   · pasted directly into the PowerShell console (paste the component files first,
#     then StartTui.ps1 last) to run the tool without executing the .ps1 files.
# Load order among the component files does not matter.
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
        $m = [PSCustomObject]@{ Size = ''; Modified = ''; Hash = '' }
        if ($info.PSObject.Properties['size'])         { $m.Size     = $info.size }
        if ($info.PSObject.Properties['lastModified']) { $m.Modified = "$($info.lastModified)" }
        # Content identity, recorded as '<algo>:<hex>'. Artifactory often leaves sha256
        # blank (only sha1/md5 populated), so fall back through the strongest available.
        if ($info.PSObject.Properties['checksums'] -and $info.checksums) {
            foreach ($algo in 'sha256','sha1','md5') {
                if ($info.checksums.PSObject.Properties[$algo] -and "$($info.checksums.$algo)") {
                    $m.Hash = "${algo}:" + ("$($info.checksums.$algo)").ToLower(); break
                }
            }
        }
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
    if (Test-NetworkBlocked) { return }   # offline 'all': metadata comes only from the index warm
    if ($null -eq $Items) { return }
    Receive-Prefetch
    $headers = Get-AuthHeaders
    foreach ($it in $Items) {
        if (-not $it) { continue }
        $u = $it.Uri
        if ($script:MetaCache.ContainsKey($u) -or $script:PfQueued.ContainsKey($u)) { continue }
        if ($null -eq $script:PfPool) {
            # Ceiling kept modest: each open worker runspace is a near-complete
            # engine copy (tens of MB in PS 5.1), and metadata fetches are short,
            # so a handful of concurrent requests fills the current page about as
            # fast as ten would while holding far less memory.
            $script:PfPool = [RunspaceFactory]::CreateRunspacePool(1, 4)
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
                $m = [PSCustomObject]@{ Size = ''; Modified = ''; Hash = '' }
                if ($info.PSObject.Properties['size'])         { $m.Size     = $info.size }
                if ($info.PSObject.Properties['lastModified']) { $m.Modified = "$($info.lastModified)" }
                # Content identity '<algo>:<hex>', strongest available (sha256 is often blank).
                if ($info.PSObject.Properties['checksums'] -and $info.checksums) {
                    foreach ($algo in 'sha256','sha1','md5') {
                        if ($info.checksums.PSObject.Properties[$algo] -and "$($info.checksums.$algo)") {
                            $m.Hash = "${algo}:" + ("$($info.checksums.$algo)").ToLower(); break
                        }
                    }
                }
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
    if (Test-NetworkBlocked) { return }   # offline 'all': no background metadata fetches
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

# Bound on resolved preview entries kept in $PreviewCache. Each entry can hold a
# file's bytes (up to the 512 KB cap, or larger if the user opted in via [y]) or
# an archive's node listing; without a cap the cache grows for the whole session
# as the user skims pages, pinning tens of MB that will never be looked at again.
# Restrict-PreviewCache (below) trims it to this many entries. Insertion order is
# tracked main-thread-side in $PvOrder so the oldest, off-screen entries are the
# ones evicted; $PvOrderSet mirrors it for O(1) membership tests.
$script:PreviewCap = 48
$script:PvOrder    = [Collections.Generic.List[string]]::new()
$script:PvOrderSet = New-Object 'System.Collections.Generic.HashSet[string]'

function Get-FilePreviewKey([string]$url) { "F|$url" }
function Get-ArcPreviewKey([string]$uri)  { "A|$uri" }

# Offline 'all' preview seeding: with the background pools disabled, populate $PreviewCache for
# this page's items from what's already on disk so the preview pane renders without any request.
# Files -> bytes from the session cache or a previously-downloaded copy (Get-DownloadedBytes);
# browsable archives -> the tree reconstructed from the local index (Build-ArchiveTreeFromIndex).
# Anything not on disk / not indexed is cached as a clear "offline" miss so the pane stops saying
# "Loading...". Cheap + idempotent (skips keys already cached); safe to call per render. No-op
# unless network is blocked. Cache shape mirrors the pool workers' { Ok; Bytes; Nodes; Error }.
function Warm-OfflinePreviews([object[]]$Items) {
    if (-not (Test-NetworkBlocked) -or $null -eq $Items) { return }
    foreach ($it in $Items) {
        if (-not $it) { continue }
        if (Test-ItemBrowsableArchive $it) {
            $k = Get-ArcPreviewKey ([string]$it.Uri)
            if ($script:PreviewCache.ContainsKey($k)) { continue }
            $tree = $null
            if (Get-Command Build-ArchiveTreeFromIndex -ErrorAction SilentlyContinue) {
                $canon = Get-ArcArchiveUri ([string]$it.Repo) (Get-ArcArchivePath ([string]$it.Path) ([string]$it.Name))
                if ($script:ArcIndexedArchives.Contains($canon)) { $tree = Build-ArchiveTreeFromIndex $it }
            }
            $script:PreviewCache[$k] = if ($tree -and $tree.Ok) {
                [PSCustomObject]@{ Ok = $true; Bytes = $null; Nodes = $tree.Nodes; Error = '' }
            } else {
                [PSCustomObject]@{ Ok = $false; Bytes = $null; Nodes = $null; Error = 'Offline: archive listing not in the local index.' }
            }
        } else {
            $u = Get-ItemUrl $it
            $k = Get-FilePreviewKey $u
            if ($script:PreviewCache.ContainsKey($k)) { continue }
            $bytes = if ($script:MemFiles.ContainsKey($u)) { $script:MemFiles[$u] } else { Get-DownloadedBytes $u }
            $script:PreviewCache[$k] = if ($null -ne $bytes) {
                [PSCustomObject]@{ Ok = $true; Bytes = $bytes; Nodes = $null; Error = '' }
            } else {
                [PSCustomObject]@{ Ok = $false; Bytes = $null; Nodes = $null; Error = 'Offline: file content not on disk (download it while online to preview).' }
            }
        }
    }
}


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
    if (Test-NetworkBlocked) { return }   # offline 'all': previews seeded from disk (Warm-OfflinePreviews)
    if ($null -eq $Requests) { return }
    Receive-PreviewPrefetch
    foreach ($rq in $Requests) {
        if (-not $rq) { continue }
        $k = $rq.Key
        if ($script:PreviewCache.ContainsKey($k) -or $script:PvQueued.ContainsKey($k)) { continue }
        if ($null -eq $script:PvPool) {
            # Modest ceiling for the same reason as the metadata pool (see there):
            # the highlighted row plus its nearest neighbours warm fast enough with
            # a few workers, and the lookahead trickle covers the rest of the page.
            $script:PvPool = [RunspaceFactory]::CreateRunspacePool(1, 3)
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

# Trim the resolved-preview cache to $PreviewCap entries, evicting oldest-first
# but never a key in $Keep (the on-screen page/window), so what the user is
# looking at is always retained and only off-screen history is reclaimed. The
# cache is written by background workers, so keys they added since the last call
# are reconciled into the order tracker first; the .Keys snapshot is taken under
# the sync root because enumerating a synchronized hashtable while a worker is
# adding to it can otherwise throw. Call from the main thread.
#
# Order note: a plain hashtable doesn't preserve insertion order, so keys added
# between two calls reconcile in arbitrary (hash) order *relative to each other*.
# Because this runs on every render/tick, those batches are one page at a time,
# and the keep-set protects the whole current page — so eviction only ever reaches
# keys from earlier batches (older pages), which is correct oldest-page-first. The
# arbitrary order applies only within a batch, where the keys are either all kept
# or all evictable, so it never changes which page is dropped.
function Restrict-PreviewCache([hashtable]$Keep) {
    $snapshot = $null
    $sr = $script:PreviewCache.SyncRoot
    [System.Threading.Monitor]::Enter($sr)
    try { $snapshot = @($script:PreviewCache.Keys) } finally { [System.Threading.Monitor]::Exit($sr) }

    foreach ($k in $snapshot) {
        if (-not $script:PvOrderSet.Contains($k)) {
            [void]$script:PvOrderSet.Add($k); $script:PvOrder.Add($k)
        }
    }
    if ($script:PvOrder.Count -le $script:PreviewCap) { return }

    $keep    = if ($Keep) { $Keep } else { @{} }
    $evictBy = $script:PvOrder.Count - $script:PreviewCap
    $kept    = [Collections.Generic.List[string]]::new()
    foreach ($k in $script:PvOrder) {
        if ($evictBy -gt 0 -and -not $keep.ContainsKey($k)) {
            [void]$script:PreviewCache.Remove($k)   # synchronized: atomic
            [void]$script:PvOrderSet.Remove($k)
            $evictBy--
        } else {
            $kept.Add($k)
        }
    }
    $script:PvOrder = $kept
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
    if (Test-NetworkBlocked) { return }   # offline 'all': no background preview fetches
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
        # Clamp the cursor into range first: a stale/out-of-range selRow (e.g. right after
        # hiding rows shrinks the page) would otherwise index past the array or onto a $null.
        if ($selRow -lt 0) { $selRow = 0 }
        if ($selRow -ge $pageItems.Count) { $selRow = $pageItems.Count - 1 }
        $order = [Collections.Generic.List[int]]::new()
        $order.Add($selRow)
        $max = [Math]::Max($selRow, $pageItems.Count - 1 - $selRow)
        for ($d = 1; $d -le $max; $d++) {
            if ($selRow + $d -lt $pageItems.Count) { $order.Add($selRow + $d) }
            if ($selRow - $d -ge 0)                { $order.Add($selRow - $d) }
        }
        foreach ($idx in $order) {
            if ($idx -lt 0 -or $idx -ge $pageItems.Count) { continue }
            $it = $pageItems[$idx]
            if ($null -eq $it) { continue }
            $rq = Get-ItemPreviewRequest $it
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

# ── POOL LIFECYCLE ────────────────────────────────────────────────────────────
# Each open worker runspace in a pool is a near-complete engine copy (tens of MB
# of working set in PS 5.1), and under fast skimming the pools grow to their
# ceiling and then sit open for the rest of the session. These helpers release a
# pool when its view no longer needs it: simple view warms nothing, leaving
# preview mode frees the preview pool, and pausing on a fully-warmed page frees
# both. Any in-flight pooled jobs are aborted first (aborting a mid-flight fetch
# just frees a slot); the cancel flag / cache are untouched. Both pools reopen
# lazily on next use (Start-Prefetch / Start-PreviewPrefetch), so teardown is
# always safe — the only cost is a one-time pool-open (~tens of ms) on the next
# page that needs it, invisible next to the network fetch it precedes.

function Close-MetaPool {
    foreach ($j in $script:PfJobs) {
        try { [void]$j.PS.Stop() } catch { }
        try { $j.PS.Dispose() }    catch { }
    }
    $script:PfJobs.Clear(); $script:PfQueued.Clear()
    if ($script:PfPool) {
        try { $script:PfPool.Close() }   catch { }
        try { $script:PfPool.Dispose() } catch { }
        $script:PfPool = $null
    }
}

function Close-PreviewPool {
    foreach ($j in $script:PvJobs) {
        try { [void]$j.PS.Stop() } catch { }
        try { $j.PS.Dispose() }    catch { }
    }
    $script:PvJobs.Clear(); $script:PvQueued.Clear()
    if ($script:PvPool) {
        try { $script:PvPool.Close() }   catch { }
        try { $script:PvPool.Dispose() } catch { }
        $script:PvPool = $null
    }
}

function Close-PrefetchPools { Close-MetaPool; Close-PreviewPool }

