# AuditEngine.ps1 - headless audit engine of the ARTCA Artifactory tool.
#
# The OPTIONAL credential/secret audit, ENGINE half: severity model, ruleset,
# classification, background concurrency, the full-instance walker, findings, the
# mode launchers, and the headless download-set builder. NO terminal/UI dependency,
# so it is loaded by BOTH the TUI (alongside AuditView.ps1) and the non-interactive
# engine (StartAuditEngine.ps1). Needs Core.ps1 + Api.ps1 in scope.
#
# Definitions only; nothing here runs on its own. Loaded by dot-source (file mode)
# or pasted before a launcher. The view half (AuditView.ps1) adds the interactive
# results view, audit menu, on-demand preview, passive mode, and severity colours.
#
# File conventions: UTF-8 without BOM, LF endings; any non-ASCII glyph that affects
# execution is a numeric [char] escape (literal Unicode only in comments).
# ── SEVERITY MODEL ────────────────────────────────────────────────────────────
# Severities, most to least severe: Critical > High > Medium > Low > Informational.
# Colours are unchanged from the old tiers (Critical=red, High=yellow, Medium=green,
# Low=blue); Informational is purple and is used for synthetic, non-match findings
# (oversize text files, Tier-2 skipped) so they're visible but clearly the lowest tier.
# Keys are stored capitalised (e.g. 'Critical'); the switches lower-case before
# matching, so case never matters.

function Get-AuditRank([string]$sev) {
    switch ("$sev".ToLower()) {
        'critical' { 5 } 'high' { 4 } 'medium' { 3 } 'low' { 2 } 'informational' { 1 } default { 0 }
    }
}

# On-screen colour for a severity. Built at call time so it never touches the ANSI
# vars at load (they may not exist yet in paste mode). Empty on a non-VT host, where
# Get-AuditLetter differentiates instead.
function Get-AuditColor([string]$sev) {
    if (-not $script:Vt) { return '' }
    $e = [char]27
    switch ("$sev".ToLower()) {
        'critical'      { "$e[38;5;203m" }   # red
        'high'          { "$e[38;5;221m" }   # yellow
        'medium'        { "$e[38;5;113m" }   # green
        'low'           { "$e[38;5;75m"  }   # blue
        'informational' { "$e[38;5;135m" }   # purple
        default         { '' }
    }
}

# Single-letter severity tag, so the marker is distinguishable without colour
# (ISE / plain cmd) and for the CSV: C/H/M/L/I.
function Get-AuditLetter([string]$sev) {
    switch ("$sev".ToLower()) {
        'critical' { 'C' } 'high' { 'H' } 'medium' { 'M' } 'low' { 'L' } 'informational' { 'I' } default { '?' }
    }
}

# Name of the synthetic rule for readable text files skipped only because they
# exceed the content-scan cap. Lowest severity, default-excluded in the view.
$script:AuditOversizeRule = 'SkippedOversizeText'

# Synthetic rule for files that would have had a Tier-2 content scan but were skipped
# because the audit is running Tier-1 only. Lowest severity, default-excluded — so the
# candidates are still visible without being pulled into the download set.
$script:AuditSkippedRule = 'SkippedTier2'

# ── RULESET ───────────────────────────────────────────────────────────────────
# === USER-EDITABLE RULES =======================================================
# To tune the audit, edit the blocks below. Every rule has an Enabled flag — set
# it to $false to switch a rule off without deleting it; add your own by copying
# the shape of a nearby entry. Three kinds:
#
#   Discard  — { Loc='ext'|'name'|'path'; Match='exact'|'contains'|'regex';
#               Values=@(...); Enabled=$bool }
#              A hit drops the file from the audit entirely (noise suppression).
#   Meta     — { Name; Sev=Critical|High|Medium|Low; Loc='ext'|'name'|'path';
#               Match='exact'|'contains'|'endswith'|'regex'; Values=@(...); Enabled }
#              A "Tier 1" finding decided from filename/extension/path alone — no
#              download. (.ext values are bare, no dot: 'kdbx' not '.kdbx'.)
#   Content  — keyed by name => { Sev; Patterns=@(regex,...); Enabled }
#              A "Tier 2" finding: regex run over the file's decoded text. Reached
#              only when a Relay rule routes a file to it (so we fetch text only
#              for relevant file types).
#   Relay    — { Loc='ext'|'name'; Match; Values=@(...); Rules=@(content-rule-names) }
#              "files of THIS type get their text scanned with THESE content rules."
#
# NOTE: ShareName rules from Snaffler (C$, ADMIN$, print$, SCCM shares) are omitted
# — they are SMB concepts with no Artifactory analogue. Path values use forward
# slashes (Artifactory paths), matched case-insensitively.

function Get-AuditRuleDefs {
    # ---- DISCARD (noise suppression; checked first) ---------------------------
    $discard = @(
        @{ Loc='ext'; Match='exact'; Enabled=$true; Values=@(
            'bmp','eps','gif','ico','jfi','jfif','jif','jpe','jpeg','jpg','png','psd',
            'svg','tif','tiff','webp','xcf','ttf','otf','lock','css','less','admx',
            'adml','xsd','nse','xsl') }
        @{ Loc='name'; Match='exact'; Enabled=$true; Values=@(
            'jmxremote.password.template','sceregvl.inf',
            # Snaffler PostMatch discards (known-benign tooling):
            'credentialprovider.idl','pspasswd64.exe','pspasswd.exe','psexec.exe','psexec64.exe') }
        @{ Loc='path'; Match='contains'; Enabled=$true; Values=@(
            'node_modules','vendor/bundle','vendor/cache','lib/ruby','lib/site-packages',
            'usr/share/doc','puppet/share/doc','doc/openssl','anaconda3/lib/test',
            'windowspowershell/modules','reference assemblies/microsoft/framework/.netframework',
            'dotnet/sdk','dotnet/shared','modules/microsoft.powershell.security','windows/assembly',
            # Windows system dirs (rare in repos, cheap to keep):
            'winsxs','syswow64','system32','systemapps','windows/servicing','/servicing/',
            'microsoft.net/framework','windows/immersivecontrolpanel','windows/diagnostics',
            'windows/debug','chocolatey/helpers','sources/sxs','wsuscontent',
            # Snaffler PostMatch path discards:
            'windows kits/10','git/mingw64','git/usr/lib',
            'programdata/microsoft/netframework/breadcrumbstore','mssqlserver/mssql/binn/templates') }
        @{ Loc='path'; Match='regex'; Enabled=$true; Values=@('python\d*/lib') }
    )

    # ---- META: Tier-1 findings (name / extension / path) ----------------------
    $meta = @(
        # ----- BLACK -----
        @{ Name='WinHashes';        Sev='Critical'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('NTDS.DIT','SYSTEM','SAM','SECURITY') }
        @{ Name='NixLocalHashes';   Sev='Critical'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('shadow','pwd.db','passwd') }
        @{ Name='MemDumpByName';    Sev='Critical'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('MEMORY.DMP','hiberfil.sys','lsass.dmp','lsass.exe.dmp') }
        @{ Name='NetDeviceConfig';  Sev='Critical'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('running-config.cfg','startup-config.cfg','running-config','startup-config') }
        @{ Name='CyberArkConfigs';  Sev='Critical'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('Psmapp.cred','psmgw.cred','backup.key','MasterReplicationUser.pass','RecPrv.key',
                    'ReplicationUser.pass','Server.key','VaultEmergency.pass','VaultUser.pass','Vault.ini',
                    'PADR.ini','PARAgent.ini','CACPMScanner.exe.config','PVConfiguration.xml') }
        @{ Name='PasswordManagers'; Sev='Critical'; Loc='ext';  Match='exact'; Enabled=$true;
           Values=@('kdbx','kdb','psafe3','kwallet','keychain','agilekeychain','cred') }
        @{ Name='SSHKeysByName';    Sev='Critical'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('id_rsa','id_dsa','id_ecdsa','id_ed25519') }
        @{ Name='SSHKeysByExt';     Sev='Critical'; Loc='ext';  Match='exact'; Enabled=$true;
           Values=@('ppk') }
        @{ Name='SSHFilesByPath';   Sev='Critical'; Loc='path'; Match='contains'; Enabled=$true;
           Values=@('/.ssh/') }
        @{ Name='RemoteAccessName'; Sev='Critical'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('mobaxterm.ini','mobaxterm backup.zip','confCons.xml') }
        @{ Name='CloudApiKeysName'; Sev='Critical'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('.tugboat') }
        @{ Name='CloudApiKeysPath'; Sev='Critical'; Loc='path'; Match='contains'; Enabled=$true;
           Values=@('/.aws/','doctl/config.yaml') }
        # ----- RED -----
        @{ Name='HtpasswdEtc';      Sev='High'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('.htpasswd','accounts.v4') }
        @{ Name='MediaWikiConfig';  Sev='High'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('LocalSettings.php') }
        @{ Name='RubyConfig';       Sev='High'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('database.yml','.secret_token.rb','knife.rb','carrierwave.rb','omniauth.rb') }
        @{ Name='JenkinsConfig';    Sev='High'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('jenkins.plugins.publish_over_ssh.BapSshPublisherPlugin.xml','credentials.xml') }
        @{ Name='FtpServerConfig';  Sev='High'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('proftpdpasswd','filezilla.xml') }
        @{ Name='FtpClientConfig';  Sev='High'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('recentservers.xml','sftp-config.json') }
        @{ Name='DbMgmtConfig';     Sev='High'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('SqlStudio.bin','.mysql_history','.psql_history','.pgpass',
                    '.dbeaver-data-sources.xml','credentials-config.json','dbvis.xml','robomongo.json') }
        @{ Name='GitCredentials';   Sev='High'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('.git-credentials') }
        @{ Name='PasswordFiles';    Sev='High'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('passwords.txt','pass.txt','accounts.txt','passwords.doc','pass.doc','accounts.doc',
                    'passwords.xls','pass.xls','accounts.xls','passwords.docx','pass.docx','accounts.docx',
                    'passwords.xlsx','pass.xlsx','accounts.xlsx','secrets.txt','secrets.doc','secrets.xls',
                    'secrets.docx','secrets.xlsx','BitlockerLAPSPasswords.csv') }
        @{ Name='InfraAsCode';      Sev='High'; Loc='ext';  Match='exact'; Enabled=$true;
           Values=@('cscfg','ucs','tfvars') }
        @{ Name='VmDisks';          Sev='High'; Loc='ext';  Match='exact'; Enabled=$true;
           Values=@('vmdk','vdi','vhd','vhdx') }
        @{ Name='MemDumpByExt';     Sev='High'; Loc='ext';  Match='exact'; Enabled=$true;
           Values=@('dmp') }
        @{ Name='CyberArkByExt';    Sev='High'; Loc='ext';  Match='exact'; Enabled=$true;
           Values=@('pass') }
        @{ Name='DomainJoinPath';   Sev='High'; Loc='path'; Match='contains'; Enabled=$true;
           Values=@('control/customsettings.ini') }
        @{ Name='SccmBootVarPath';  Sev='High'; Loc='path'; Match='regex'; Enabled=$true;
           Values=@('reminst/smstemp/.*\.var','sms/data/variables.dat','sms/data/policy.xml') }
        # ----- YELLOW -----
        @{ Name='Databases';        Sev='Medium'; Loc='ext'; Match='exact'; Enabled=$true;
           Values=@('mdf','sdf','sqldump','bak') }
        @{ Name='DeployImages';     Sev='Medium'; Loc='ext'; Match='exact'; Enabled=$true;
           Values=@('wim','ova','ovf') }
        @{ Name='KerberosByExt';    Sev='Medium'; Loc='ext'; Match='exact'; Enabled=$true;
           Values=@('keytab','ccache') }
        @{ Name='KerberosByName';   Sev='Medium'; Loc='name'; Match='regex'; Enabled=$true;
           Values=@('^krb5cc_.*') }
        @{ Name='PacketCapture';    Sev='Medium'; Loc='ext'; Match='exact'; Enabled=$true;
           Values=@('pcap','cap','pcapng') }
        @{ Name='RemoteAccessExt';  Sev='Medium'; Loc='ext'; Match='exact'; Enabled=$true;
           Values=@('rdg','rtsz','rtsx','ovpn','tvopt','sdtid') }
        @{ Name='DefenderConfig';   Sev='Medium'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('SensorConfiguration.json','mdatp_managed.json') }
        @{ Name='DomainJoinName';   Sev='Medium'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('customsettings.ini') }
        # ----- GREEN (informational) -----
        @{ Name='NameContainsSecret'; Sev='Low'; Loc='name'; Match='contains'; Enabled=$true;
           Values=@('passw','secret','credential','thycotic','cyberark') }
        @{ Name='ShellHistory';       Sev='Low'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('.bash_history','.zsh_history','.sh_history','zhistory','.irb_history','ConsoleHost_History.txt') }
        @{ Name='ShellRcFiles';       Sev='Low'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('.netrc','_netrc','.exports','.functions','.extra','.npmrc','.env','.bashrc','.profile','.zshrc') }
    )

    # ---- CONTENT: Tier-2 findings (regex over decoded text) -------------------
    # Single-quoted strings keep backslashes literal; embedded single quotes are
    # doubled. Char classes simplified to ['"] (Snaffler over-escaped them).
    $content = [ordered]@{
        'InlinePrivateKey' = @{ Sev='High'; Enabled=$true; Patterns=@(
            '-----BEGIN( RSA| OPENSSH| DSA| EC| PGP)? PRIVATE KEY( BLOCK)?-----') }
        'AwsKeys' = @{ Sev='High'; Enabled=$true; Patterns=@(
            'aws[_\-\.]?key',
            '(\s|[''"^=])(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z2-7]{12,16}(\s|[''"]|$)') }
        'SlackTokens' = @{ Sev='High'; Enabled=$true; Patterns=@(
            '(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})',
            'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}') }
        'PassOrKeyInCode' = @{ Sev='High'; Enabled=$true; Patterns=@(
            'passw?o?r?d\s*=\s*[''"][^''"]....',
            'api[Kk]ey\s*=\s*[''"][^''"]....',
            'passw?o?r?d?>\s*[^\s<]+\s*<',
            'passw?o?r?d?>.{3,2000}</pass',
            '[\s]+-passw?o?r?d?',
            'api[kK]ey>\s*[^\s<]+\s*<',
            '[_\-\.]oauth\s*=\s*[''"][^''"]....',
            'client_secret\s*=*\s*',
            '<ExtendedMatchKey>ClientAuth',
            'GIUserPassword') }
        'SqlAccountCreation' = @{ Sev='High'; Enabled=$true; Patterns=@(
            'CREATE (USER|LOGIN) .{0,200} (IDENTIFIED BY|WITH PASSWORD)') }
        'DbConnStringPw' = @{ Sev='Medium'; Enabled=$true; Patterns=@(
            'connectionstring.{1,200}passw') }
        'S3UriPrefix' = @{ Sev='Medium'; Enabled=$true; Patterns=@(
            's3[a]?:\/\/[a-zA-Z0-9\-\+\/]{2,16}') }
        'CSharpDbConnRed' = @{ Sev='High'; Enabled=$true; Patterns=@(
            'Data Source=.+(;|)Password=.+(;|)','Password=.+(;|)Data Source=.+(;|)') }
        'CSharpDbConnYellow' = @{ Sev='Medium'; Enabled=$true; Patterns=@(
            'Data Source=.+Integrated Security=(SSPI|true)','Integrated Security=(SSPI|true);.*Data Source=.+') }
        'CSharpViewstateKeys' = @{ Sev='High'; Enabled=$true; Patterns=@(
            'validationkey\s*=\s*[''"][^''"]....','decryptionkey\s*=\s*[''"][^''"]....') }
        'CmdCredentials' = @{ Sev='High'; Enabled=$true; Patterns=@(
            'passwo?r?d\s*=\s*[''"][^''"]....','schtasks.{1,300}(/rp\s|/p\s)','net user ',
            'psexec .{0,100} -p ','net use .{0,300} /user:','cmdkey ') }
        'PsCredentials' = @{ Sev='High'; Enabled=$true; Patterns=@(
            '-SecureString','-AsPlainText','\[Net.NetworkCredential\]::new\(') }
        'JavaDbConnStrings' = @{ Sev='High'; Enabled=$true; Patterns=@(
            '\.getConnection\("jdbc:','passwo?r?d\s*=\s*[''"][^''"]....') }
        'PhpDbConnStrings' = @{ Sev='High'; Enabled=$true; Patterns=@(
            'mysql_connect\s*\(.*\$.*\)','mysql_pconnect\s*\(.*\$.*\)','mysql_change_user\s*\(.*\$.*\)',
            'pg_connect\s*\(.*\$.*\)','pg_pconnect\s*\(.*\$.*\)') }
        'PerlDbConnStrings' = @{ Sev='High'; Enabled=$true; Patterns=@('DBI\-\>connect\(') }
        'PyDbConnStrings' = @{ Sev='High'; Enabled=$true; Patterns=@(
            'mysql\.connector\.connect\(','psycopg2\.connect\(') }
        'RubyDbConnStrings' = @{ Sev='High'; Enabled=$true; Patterns=@('DBI\.connect\(') }
        'NetConfigCreds' = @{ Sev='High'; Enabled=$true; Patterns=@(
            'NVRAM config last updated','enable password \.','simple-bind authenticated encrypt',
            'pac key [0-7] ','snmp-server community\s.+\sRW') }
        'UnattendXml' = @{ Sev='High'; Enabled=$true; Patterns=@(
            '(?s)<AdministratorPassword>.{0,30}<Value>.*<\/Value>',
            '(?s)<AutoLogon>.{0,30}<Value>.*<\/Value>') }
        'FirefoxLogins' = @{ Sev='High'; Enabled=$true; Patterns=@(
            '"encryptedPassword":"[A-Za-z0-9+/=]+"') }
        'RdpPasswords' = @{ Sev='High'; Enabled=$true; Patterns=@('password 51:b') }
    }

    # ---- RELAY: route file types to content rules -----------------------------
    $genericCode = @('AwsKeys','InlinePrivateKey','PassOrKeyInCode','SlackTokens','SqlAccountCreation','DbConnStringPw')
    $relay = @(
        @{ Loc='ext'; Match='exact'; Enabled=$true;
           Values=@('yaml','yml','toml','xml','json','config','ini','inf','cnf','conf','properties',
                    'env','dist','txt','sql','log','sqlite','sqlite3','fdb','tfvars');
           Rules=($genericCode + 'NetConfigCreds') }
        @{ Loc='ext'; Match='exact'; Enabled=$true;
           Values=@('aspx','ashx','asmx','asp','cshtml','cs','ascx','config');
           Rules=($genericCode + @('CSharpDbConnRed','CSharpDbConnYellow','CSharpViewstateKeys')) }
        @{ Loc='ext'; Match='exact'; Enabled=$true; Values=@('jsp','do','java','cfm');
           Rules=($genericCode + 'JavaDbConnStrings') }
        @{ Loc='ext'; Match='exact'; Enabled=$true; Values=@('js','cjs','mjs','ts','tsx','ls','es6','es');
           Rules=$genericCode }
        @{ Loc='ext'; Match='exact'; Enabled=$true; Values=@('php','phtml','inc','php3','php5','php7');
           Rules=($genericCode + 'PhpDbConnStrings') }
        @{ Loc='ext'; Match='exact'; Enabled=$true; Values=@('py');    Rules=($genericCode + 'PyDbConnStrings') }
        @{ Loc='ext'; Match='exact'; Enabled=$true; Values=@('rb');    Rules=($genericCode + 'RubyDbConnStrings') }
        @{ Loc='ext'; Match='exact'; Enabled=$true; Values=@('pl');    Rules=($genericCode + 'PerlDbConnStrings') }
        @{ Loc='ext'; Match='exact'; Enabled=$true; Values=@('psd1','psm1','ps1');
           Rules=($genericCode + @('PsCredentials','CmdCredentials')) }
        @{ Loc='ext'; Match='exact'; Enabled=$true; Values=@('bat','cmd'); Rules=($genericCode + 'CmdCredentials') }
        @{ Loc='ext'; Match='exact'; Enabled=$true; Values=@('vbs','vbe','wsf','wsc','hta');
           Rules=($genericCode + @('CmdCredentials','CSharpDbConnRed','CSharpDbConnYellow')) }
        @{ Loc='ext'; Match='exact'; Enabled=$true; Values=@('sh','bash','zsh');
           Rules=@('AwsKeys','InlinePrivateKey','PassOrKeyInCode','SlackTokens','SqlAccountCreation') }
        @{ Loc='ext'; Match='exact'; Enabled=$true; Values=@('pem'); Rules=@('InlinePrivateKey') }
        @{ Loc='ext'; Match='exact'; Enabled=$true; Values=@('rdp'); Rules=@('RdpPasswords') }
        @{ Loc='name'; Match='exact'; Enabled=$true; Values=@('unattend.xml','Autounattend.xml'); Rules=@('UnattendXml') }
        @{ Loc='name'; Match='exact'; Enabled=$true; Values=@('logins.json'); Rules=@('FirefoxLogins') }
        @{ Loc='name'; Match='exact'; Enabled=$true;
           Values=@('ConsoleHost_history.txt','ConsoleHost_History.txt');
           Rules=($genericCode + @('PsCredentials','CmdCredentials')) }
        @{ Loc='name'; Match='contains'; Enabled=$true; Values=@('cisco','router','firewall','switch');
           Rules=@('NetConfigCreds') }
        @{ Loc='name'; Match='endswith'; Enabled=$true; Values=@('_rsa','_dsa','_ed25519','_ecdsa');
           Rules=@('InlinePrivateKey') }
    )

    return @{ Discard=$discard; Meta=$meta; Content=$content; Relay=$relay }
}
# === END USER-EDITABLE RULES ===================================================

# ── COMPILED RULESET ──────────────────────────────────────────────────────────
# Built once from Get-AuditRuleDefs: disabled rules dropped, content patterns
# precompiled, extension/name lookups turned into hashsets for O(1) tests. Cached
# in $script:AuditRules.
$script:AuditRules = $null

function Build-AuditRegex([string]$pat) {
    return [regex]::new($pat, ([Text.RegularExpressions.RegexOptions]'IgnoreCase, Compiled, CultureInvariant'))
}

function Get-AuditRuleSet {
    if ($script:AuditRules) { return $script:AuditRules }
    $defs = Get-AuditRuleDefs

    # Content rules: name -> { Sev; Regexes=[regex[]] } for enabled rules only.
    $content = @{}
    foreach ($name in $defs.Content.Keys) {
        $c = $defs.Content[$name]
        if (-not $c.Enabled) { continue }
        $rx = @(); foreach ($p in $c.Patterns) { $rx += (Build-AuditRegex $p) }
        $content[$name] = @{ Sev = $c.Sev; Regexes = $rx }
    }

    # Compile meta/discard/relay value matchers. exact/contains/endswith use a
    # lowercased hashset or substring list; regex compiles a regex array.
    $compileSet = {
        param($rule)
        $out = @{ Loc=$rule.Loc; Match=$rule.Match }
        if ($rule.ContainsKey('Name'))  { $out.Name  = $rule.Name }
        if ($rule.ContainsKey('Sev'))   { $out.Sev   = $rule.Sev }
        if ($rule.ContainsKey('Rules')) { $out.Rules = @($rule.Rules) }
        if ($rule.Match -eq 'regex') {
            $rx = @(); foreach ($v in $rule.Values) { $rx += (Build-AuditRegex $v) }
            $out.Regexes = $rx
        } elseif ($rule.Match -eq 'exact') {
            $hs = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            foreach ($v in $rule.Values) { [void]$hs.Add($v) }
            $out.Set = $hs
        } else {   # contains / endswith
            $out.Values = @($rule.Values | ForEach-Object { $_.ToLower() })
        }
        return $out
    }

    $discard = @(); foreach ($d in $defs.Discard) { if ($d.Enabled) { $discard += (& $compileSet $d) } }
    $meta    = @(); foreach ($m in $defs.Meta)    { if ($m.Enabled) { $meta    += (& $compileSet $m) } }
    $relay   = @(); foreach ($r in $defs.Relay)   { if ($r.Enabled) { $relay   += (& $compileSet $r) } }

    $script:AuditRules = @{ Discard=$discard; Meta=$meta; Content=$content; Relay=$relay }
    return $script:AuditRules
}

# Test a compiled value-matcher against the relevant field. $name/$ext are already
# the file's name and lowercased extension; $pathL is the lowercased path used for
# path matches. Returns $true on a hit.
function Test-AuditMatcher($m, [string]$name, [string]$ext, [string]$pathL) {
    switch ($m.Loc) {
        'ext'  { if ($m.Match -eq 'exact') { return $m.Set.Contains($ext) } }
        'name' {
            switch ($m.Match) {
                'exact'    { return $m.Set.Contains($name) }
                'contains' { $nl = $name.ToLower(); foreach ($v in $m.Values) { if ($nl.Contains($v)) { return $true } }; return $false }
                'endswith' { $nl = $name.ToLower(); foreach ($v in $m.Values) { if ($nl.EndsWith($v)) { return $true } }; return $false }
                'regex'    { foreach ($rx in $m.Regexes) { if ($rx.IsMatch($name)) { return $true } }; return $false }
            }
        }
        'path' {
            switch ($m.Match) {
                'contains' { foreach ($v in $m.Values) { if ($pathL.Contains($v)) { return $true } }; return $false }
                'regex'    { foreach ($rx in $m.Regexes) { if ($rx.IsMatch($pathL)) { return $true } }; return $false }
            }
        }
    }
    return $false
}

# ── CLASSIFICATION ────────────────────────────────────────────────────────────
# Metadata pass (no I/O): given a file's name + repo-relative path, decide whether
# it is discarded, which Tier-1 findings it earns, and which content rules its text
# should be scanned with if/when fetched. Returns:
#   @{ Discard=$bool; Findings=@(@{Rule;Sev}); ContentRules=@(name,...) }
function Test-AuditMeta([string]$name, [string]$path) {
    $rs    = Get-AuditRuleSet
    $ext   = (Get-Ext $name).ToLower()
    # Normalise the path the way the path patterns expect: forward slashes, wrapped
    # in slashes so '/.ssh/' and bare segment matches both work, lowercased.
    $pathL = ('/' + ("$path" -replace '\\','/').Trim('/') + '/').ToLower()

    foreach ($d in $rs.Discard) {
        if (Test-AuditMatcher $d $name $ext $pathL) { return @{ Discard=$true; Findings=@(); ContentRules=@() } }
    }

    $findings = [Collections.Generic.List[object]]::new()
    foreach ($m in $rs.Meta) {
        if (Test-AuditMatcher $m $name $ext $pathL) { $findings.Add(@{ Rule=$m.Name; Sev=$m.Sev }) }
    }

    $crules = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($r in $rs.Relay) {
        if (Test-AuditMatcher $r $name $ext $pathL) { foreach ($cn in $r.Rules) { [void]$crules.Add($cn) } }
    }
    return @{ Discard=$false; Findings=@($findings.ToArray()); ContentRules=@($crules) }
}

# Extract a single-line preview snippet centred on a regex match: $AuditPreviewWindow TOTAL context
# chars split evenly each side of the match (40 -> 20 left + match + 20 right; odd windows put the
# spare char on the right). The match itself sits between the context. Whitespace is collapsed to
# single spaces (CR/LF/TAB -> space) so the snippet is one CSV record and readable, and the result is
# hard-capped so one enormous match span can't bloat the row (truncation marked with '...').
function Get-AuditSnippet([string]$text, [int]$idx, [int]$len, [int]$window) {
    if ($window -lt 0) { $window = 0 }
    if ($len -lt 0)    { $len = 0 }
    $half   = [int][Math]::Floor($window / 2)
    $start  = [Math]::Max(0, $idx - $half)
    $mStart = [Math]::Min($text.Length, $idx)
    $mEnd   = [Math]::Min($text.Length, $idx + $len)
    $end    = [Math]::Min($text.Length, $mEnd + ($window - $half))
    if ($mStart -lt $start) { $mStart = $start }
    if ($end -lt $mEnd)     { $end = $mEnd }
    # Keep the three parts separate so the renderer can show the EXACT match in white and the surrounding
    # context grey. Whitespace is collapsed in each part (CR/LF/TAB -> space); only the outer edges trim.
    $norm  = { param($x) ($x -replace '[\r\n\t]+', ' ') -replace ' {2,}', ' ' }
    $pre   = (& $norm $text.Substring($start, $mStart - $start)).TrimStart()
    $match =  & $norm $text.Substring($mStart, $mEnd - $mStart)
    $post  = (& $norm $text.Substring($mEnd, $end - $mEnd)).TrimEnd()
    $mMax = $window + 120
    if ($match.Length -gt $mMax) { $match = $match.Substring(0, $mMax) + '...' }
    return @{ Pre = $pre; Match = $match; Post = $post; Text = ($pre + $match + $post) }
}

# Encode an array of strings as a compact, single-line JSON array (no external dependency, so it's
# deterministic and avoids ConvertTo-Json's formatting/unicode-escaping quirks). Only ", \, and control
# chars need escaping; everything else (incl. UTF-8) passes through, which is safe in the no-BOM UTF-8
# log. Stays one physical line, so the CSV record-per-line invariant holds.
function ConvertTo-AuditJsonArray($items) {
    # An empty @() unwraps to $null when passed positionally; @($null) would then become a 1-element
    # array holding a blank string. Drop nulls so an empty input yields '[]', not '[""]'.
    $items = @($items | Where-Object { $null -ne $_ })
    $sb = [Text.StringBuilder]::new()
    [void]$sb.Append('[')
    $first = $true
    foreach ($it in $items) {
        # Snippets are {Text;Rule;Sev} objects in memory but persist as bare strings in the CSV; accept
        # either (extract .Text from an object) so the match log stays unlabelled as before.
        $s = if ($it -is [string]) { $it } elseif ($it.PSObject.Properties['Text']) { [string]$it.Text } else { [string]$it }
        if (-not $first) { [void]$sb.Append(',') }
        $first = $false
        [void]$sb.Append('"')
        foreach ($ch in $s.ToCharArray()) {
            $code = [int]$ch
            if     ($ch -eq '"')    { [void]$sb.Append('\"') }
            elseif ($ch -eq '\')    { [void]$sb.Append('\\') }
            elseif ($code -lt 0x20) { [void]$sb.Append('\u'); [void]$sb.Append($code.ToString('x4')) }
            else                    { [void]$sb.Append($ch) }
        }
        [void]$sb.Append('"')
    }
    [void]$sb.Append(']')
    return $sb.ToString()
}

# Parse a MatchedContentPreview cell back to a string array (for the consolidation merge). Empty / '[]'
# / malformed -> empty array. @() wrapping normalises PS 5.1's single-element unwrap.
function ConvertFrom-AuditJsonArray([string]$json) {
    $t = "$json".Trim()
    if ($t -eq '' -or $t -eq '[]') { return @() }
    try { return @($t | ConvertFrom-Json) } catch { return @() }
}

# Content pass: run the named content rules' regexes over decoded text, enumerating EVERY occurrence
# (not just the first) so we can report the true instance count and collect up to $AuditPreviewMax
# preview snippets. Returns @{ Findings=@(@{Rule;Sev}...); Count=<total occurrences>; Snippets=@(...) }.
# Counting removes the old IsMatch+break short-circuit, so a content rule now scans the whole file for
# all hits - negligible for sparse secret patterns; $AuditPreviewCountCeil bounds the pathological tail.
function Test-AuditContent([string]$text, [string[]]$contentRules) {
    if (-not $text -or $null -eq $contentRules -or $contentRules.Count -eq 0) {
        return @{ Findings=@(); Count=0; Snippets=@(); SevCounts=@{} }
    }
    $rs    = Get-AuditRuleSet
    $win   = [int]$script:AuditPreviewWindow
    $capN  = [int]$script:AuditPreviewMax
    $ceil  = [int]$script:AuditPreviewCountCeil
    $out   = [Collections.Generic.List[object]]::new()
    # Snippets carry the producing rule + its severity (known here, discarded otherwise) so the level-5
    # output can colour each preview by its rule WITHOUT any later lookup or content re-read. SevCounts
    # tallies occurrences per severity for the 'N more matches' breakdown.
    $snips = [Collections.Generic.List[object]]::new()
    $sevCounts = @{}
    $total = 0
    foreach ($cn in $contentRules) {
        if (-not $rs.Content.ContainsKey($cn)) { continue }
        $c = $rs.Content[$cn]
        $ruleHit = $false
        foreach ($rx in $c.Regexes) {
            $m = $rx.Match($text)
            $iter = 0
            while ($m.Success) {
                $ruleHit = $true
                $total++
                $sevCounts[$c.Sev] = 1 + $(if ($sevCounts.ContainsKey($c.Sev)) { $sevCounts[$c.Sev] } else { 0 })
                if ($snips.Count -lt $capN) {
                    $sp = Get-AuditSnippet $text $m.Index $m.Length $win
                    [void]$snips.Add([PSCustomObject]@{ Pre=$sp.Pre; Match=$sp.Match; Post=$sp.Post; Text=$sp.Text; Rule=$cn; Sev=$c.Sev })
                }
                $iter++
                if ($iter -ge $ceil) { break }   # safety ceiling: don't scan a regex-bomb forever
                $m = $m.NextMatch()               # .NET guarantees forward progress (incl. zero-width)
            }
        }
        if ($ruleHit) { $out.Add(@{ Rule=$cn; Sev=$c.Sev }) }
    }
    return @{ Findings=@($out.ToArray()); Count=$total; Snippets=@($snips.ToArray()); SevCounts=$sevCounts }
}

# Reduce a set of @{Rule;Sev} findings to the single highest-severity finding (for the marker) and a
# combined rule label. Returns $null when empty. Count defaults to the number of matched rules (Tier-1
# meta matches: N rules -> N) but a caller can override it with the true occurrence count (Tier-2
# content: total regex hits), and pass the preview snippets to carry into the finding/match log.
function Resolve-AuditFindings($findings, $snippets = @(), [int]$countOverride = -1, $sevCounts = $null) {
    $findings = @($findings)
    if ($findings.Count -eq 0) { return $null }
    $best = $findings[0]; $bestRank = Get-AuditRank $best.Sev
    foreach ($f in $findings) { $rk = Get-AuditRank $f.Sev; if ($rk -gt $bestRank) { $best = $f; $bestRank = $rk } }
    $rules = @($findings | ForEach-Object { $_.Rule } | Select-Object -Unique)
    $cnt   = if ($countOverride -ge 0) { $countOverride } else { $findings.Count }
    # Per-severity counts: supplied by the caller (Tier-2 occurrence tally) or derived here (Tier-1:
    # one count per matched meta rule, by its severity). Sum equals Count.
    $sc = if ($null -ne $sevCounts) { $sevCounts } else {
        $h = @{}; foreach ($f in $findings) { $s = [string]$f.Sev; $h[$s] = 1 + $(if ($h.ContainsKey($s)) { $h[$s] } else { 0 }) }; $h
    }
    return @{ Sev=$best.Sev; Rule=$best.Rule; Rank=$bestRank; AllRules=($rules -join ', '); Count=$cnt; Snippets=@($snippets); SevCounts=$sc }
}

# ── ENGINE STATE ──────────────────────────────────────────────────────────────
# Content-scan size cap. Automatic modes (location/full) scan larger files than
# the 0.5 MB interactive preview cap; passive mode reuses the preview cap (see the
# caller). Files of readable text type above the active cap are surfaced under the
# synthetic oversize rule instead of being scanned.
$script:AuditCap = 2097152   # 2 MB for automatic audits

# Content-match preview (snippet) settings. AuditPreviewMax = max snippets stored per finding/file
# (and merged into audit-log.csv's MatchedContentPreview JSON array); AuditPreviewWindow = TOTAL
# context characters captured around each match, split evenly each side (40 -> 20 left + match + 20
# right). AuditPreviewCountCeil bounds per-regex occurrence enumeration so a pathological pattern can't
# wedge the main-thread scan (MatchCount saturates rather than scanning millions of hits). Set per run
# by the headless launcher (--preview-count/--preview-window); NOT reset by Reset-AuditEngine.
$script:AuditPreviewMax       = 10
$script:AuditPreviewWindow    = 40
$script:AuditPreviewCountCeil = 100000

$script:AuditState   = 'idle'   # idle | passive | running | paused | done | cancelled
$script:AuditMode    = ''       # passive | location | full
$script:AuditScope   = ''       # human-readable description of what's being audited
$script:AuditDirty   = $false   # set when flags/findings/state change (drives redraw)

# User setting (toggled from the audit menu; persists across runs, NOT reset by
# Reset-AuditEngine): when on, a listable archive is expanded via the treebrowser and
# every internal entry is audited; when off, the archive is classified as a plain
# file (name/path/content only), with no internal structure pulled. Default off.
$script:AuditWalkArchives = $false

# User setting (toggled from the audit menu; persists, NOT reset by Reset-AuditEngine):
# when on, files routed by a relay rule are downloaded and scanned with content regexes
# (Tier 2). When off, the audit is Tier-1 only — name/extension/path metadata checks
# with NO file content fetched. Default off (Tier-1 only).
$script:AuditTier2 = $false

# When on (default), Tier-1 surfaces synthetic "skipped" findings (SkippedTier2 for a relay-eligible
# file with no Tier-1 match; SkippedOversizeText for a too-big readable file) so the TUI can show
# what a Tier-2 pass would cover. These are default-EXCLUDED and never written to any CSV, so the
# headless launcher turns this OFF (Initialize-AuditRunConfig): at multi-million scale holding one
# finding object per relay-eligible file is pure memory waste. NOT reset by Reset-AuditEngine.
$script:AuditEmitSkipped = $true

# ── TIER-2 WORKLIST (Phase A writer) ──────────────────────────────────────────
# The two-phase Tier-2 flow: a Tier-1 pass writes a worklist of every relay-eligible file (one Tier-2
# would content-inspect) THROUGH to disk, and a later/continued pass (Phase B, Start-AuditTier2List)
# streams it back, content-scans each, and checkpoints a resumable cursor. When $AuditTier2ListPath is
# set, Add-AuditRecord's Tier-1 branch appends a row here. Buffered (StringBuilder flushed by row
# threshold) so millions of appends don't open/close the file per row - mirrors the index's
# ShardWriteBuf. Schema: repo,path,name,archive,size,modified,url (url = content download url; the
# !/ form for archive entries; non-empty archive marks an archive-internal entry). NOT reset by
# Reset-AuditEngine; cleared explicitly at phase transitions.
$script:AuditTier2ListPath  = ''
$script:AuditTier2ListBuf   = $null
$script:AuditTier2ListRows  = 0
$script:AuditTier2ListTotal = 0     # rows written this run (reported by the launcher)
$script:AuditTier2ListFlush = 512

function Open-AuditTier2List([string]$path) {
    $script:AuditTier2ListPath  = $path
    $script:AuditTier2ListBuf   = [Text.StringBuilder]::new()
    $script:AuditTier2ListRows  = 0
    $script:AuditTier2ListTotal = 0
    $dir = Split-Path -Parent $path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { try { New-Item -ItemType Directory -Path $dir -Force | Out-Null } catch { } }
    # Fresh worklist (truncate) + header, no-BOM UTF-8/LF. Drop any stale progress cursor so a later
    # resume of THIS rebuilt list starts at row 0 (a leftover cursor would skip the wrong rows).
    try { Remove-Item -LiteralPath (Get-AuditT2CursorPath $path) -Force -ErrorAction SilentlyContinue } catch { }
    try { [System.IO.File]::WriteAllText($path, (Format-CsvRow @('repo','path','name','archive','size','modified','url')) + "`n", [Text.UTF8Encoding]::new($false)) } catch { }
}
function Write-AuditTier2ListRow($rec) {
    if (-not $script:AuditTier2ListPath -or $null -eq $script:AuditTier2ListBuf) { return }
    $arch = if ($rec.IsArchiveEntry) { [string]$rec.ArchiveName } else { '' }
    $sz   = if ($rec.KnownSize -ge 0) { [long]$rec.KnownSize } else { -1 }
    [void]$script:AuditTier2ListBuf.Append((Format-CsvRow @(
        [string]$rec.Repo, [string]$rec.Path, [string]$rec.Name, $arch, $sz, [string]$rec.KnownModified, [string]$rec.Url))).Append("`n")
    $script:AuditTier2ListRows++; $script:AuditTier2ListTotal++
    if ($script:AuditTier2ListRows -ge $script:AuditTier2ListFlush) { Flush-AuditTier2List }
}
function Flush-AuditTier2List {
    if ($null -eq $script:AuditTier2ListBuf -or $script:AuditTier2ListBuf.Length -eq 0) { return }
    try { [System.IO.File]::AppendAllText($script:AuditTier2ListPath, $script:AuditTier2ListBuf.ToString(), [Text.UTF8Encoding]::new($false)) } catch { }
    [void]$script:AuditTier2ListBuf.Clear(); $script:AuditTier2ListRows = 0
}
function Close-AuditTier2List {
    Flush-AuditTier2List
    $script:AuditTier2ListPath = ''; $script:AuditTier2ListBuf = $null; $script:AuditTier2ListRows = 0
}

# Marker map read by the base row renderers: key -> highest raw severity. Synchronized
# only so a stale read during a write can't throw; written on the main thread.
$script:AuditFlags   = [hashtable]::Synchronized(@{})

# Findings (main-thread): the ordered list plus a key->object index for dedupe/merge.
$script:AuditFindings    = [Collections.Generic.List[object]]::new()
$script:AuditFindingIdx  = @{}
# These per-item dedup sets grow with the CATALOGUE size (artifact count), not the match count, so
# at multi-million scale they must be cheap: we store a 128-bit hash of each key/identity rather
# than the full string (a full storage uri averages ~90 chars - ~1.3 GB of strings across the three
# sets at 2M items). The hash is a ValueTuple of two independent 64-bit FNV-1a lanes (Get-AuditHash128);
# collision probability at 2-3M is ~1e-26, so it never drops an artifact. ValueTuple has structural
# equality, so the HashSet needs no comparer (the IgnoreCase semantics of the path set live in
# Get-AuditPathHash, which lowercases before hashing).
$script:AuditSeen        = New-Object 'System.Collections.Generic.HashSet[System.ValueTuple[System.UInt64,System.UInt64]]'  # key hashes already enqueued
$script:AuditDecided     = New-Object 'System.Collections.Generic.HashSet[System.ValueTuple[System.UInt64,System.UInt64]]'  # key hashes fully scanned (drives the passive * / ? glyph)
# Content-identity dedup. The same file in one repo can be reached under more than one
# differently-formatted storage uri (the walker's constructed uri vs a search-result uri;
# trailing-slash / encoding variants) — which the uri-keyed AuditSeen above can't collapse,
# producing identical findings in pairs. The identity is repo + path + filename, so a file
# with the same path and name in a DIFFERENT (unrelated) repo is treated as distinct and
# kept, as is a different path. Archive entries qualify the identity with their archive name
# so same-named entries in different archives aren't merged. (The other pair source — a
# virtual repo re-listing a backing repo's artifacts — is cut off in Get-AuditWalkRepos,
# which skips virtual repos.) Stored as 128-bit hashes of the lowercased identity (was an
# OrdinalIgnoreCase string set — see Get-AuditPathHash).
$script:AuditSeenPath    = New-Object 'System.Collections.Generic.HashSet[System.ValueTuple[System.UInt64,System.UInt64]]'
function Get-AuditPathIdentity($rec) {
    $base = "$($rec.Repo)|$($rec.Path)|$($rec.Name)"
    if ($rec.IsArchiveEntry) { return "$($rec.ArchiveName)!$base" }
    return $base
}

# 128-bit hash of a string, packed into a ValueTuple used as the element type of the per-item dedup
# sets so they hold 16 bytes/entry instead of a whole string. It is a NON-cryptographic distribution
# hash (MD5 here only as a fast, built-in 128-bit mixer for hashtable keys — not a security control),
# split into two UInt64 lanes. MD5 sidesteps PS 5.1's lack of unchecked 64-bit integer arithmetic
# (a manual FNV multiply overflows UInt64 -> promotes to Double and throws on the mask). The single
# instance is reused on the MAIN THREAD only (all set Add/Contains/Remove are main-thread; the
# worker runspaces key $AuditFetch by string and never call this). Ordinal (UTF-8 bytes).
$script:AuditHasher = [System.Security.Cryptography.MD5]::Create()
function Get-AuditHash128([string]$s) {
    $b = $script:AuditHasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($s))
    return [System.ValueTuple[System.UInt64,System.UInt64]]::new(
        [System.BitConverter]::ToUInt64($b, 0), [System.BitConverter]::ToUInt64($b, 8))
}
# Hash of a work record's uri key (ordinal).
function Get-AuditKeyHash([string]$key) { return (Get-AuditHash128 $key) }
# Hash of a work record's path-identity, lowercased to preserve the set's old IgnoreCase semantics.
function Get-AuditPathHash($rec) { return (Get-AuditHash128 ((Get-AuditPathIdentity $rec).ToLower())) }

# ── AUDIT-MATCH LOG (audit/<repo>-matches.csv) ─────────────────────────────────
# Every rule match (passive / location / full) is recorded for logging, the way scrape mode
# writes scrape-log.csv - but split per repo and WRITTEN THROUGH as matches are found.
# Dedupe is by a repo|path|name|archive identity (reconstructable from a logged row), held in
# $AuditMatchesPersisted, which loads any prior runs' identities once (Ensure-AuditMatchesLoaded)
# so re-running an audit doesn't duplicate rows. Synthetic findings (skipped/oversize) aren't
# real matches and are not logged.
#   NOTE: this is a LOG + dedupe cache, NOT a request-saving content cache. A matches-only file
#   cannot represent files that were scanned and came up CLEAN, so it can't safely let a
#   re-audit skip Tier-2 content fetches (that would risk missing content that now matches, or
#   under-reporting a file whose prior match was Tier-1-only). A real Tier-2 skip cache would
#   need to record scanned-clean files plus the scan tier - a separate, larger structure.
$script:AuditMatchesPersisted = New-Object 'System.Collections.Generic.HashSet[string]'
$script:AuditMatchesLoaded    = $false

function Get-AuditMatchIdentity([string]$repo, [string]$path, [string]$name, [string]$archive) {
    $z = [char]0
    return "$repo$z$path$z$name$z$archive"
}
# Normalize a comma-joined rule label to a stable, order-independent form (sorted, unique).
function Get-AuditRulesNorm([string]$rules) {
    return ((@("$rules" -split '\s*,\s*') | Where-Object { $_ } | Sort-Object -Unique) -join ',')
}
# Dedupe key for a logged row: identity PLUS the finding's current severity + normalized rule set.
# Keying on the (sev,rules) STATE - not the identity alone - lets a Tier-1 match and its later Tier-2
# UPGRADE both persist (two rows for one identity), so the consolidated audit-log can recover the
# merged Tier-1+Tier-2 truth even across resumed runs; re-running the same audit still dedupes because
# the final state's signature is already present.
function Get-AuditMatchSignature([string]$repo, [string]$path, [string]$name, [string]$archive, [string]$sev, [string]$rules) {
    $z = [char]0
    return (Get-AuditMatchIdentity $repo $path $name $archive) + $z + $sev + $z + (Get-AuditRulesNorm $rules)
}
function Get-AuditMatchFile([string]$repo) {
    $safe = ($repo -replace '[^A-Za-z0-9._-]', '_'); if (-not $safe) { $safe = 'unknown' }
    return "$safe-matches.csv"
}
# Load prior runs' match identities so re-logging dedupes across sessions. Reads every
# *-matches.csv in the audit dir; columns are the Write-DownloadLog set
# (Timestamp,FileName,Hash,Repository,Path,Archive,...) -> FileName=1, Repository=3, Path=4,
# Archive=5. Needs Core's Read-CsvRow (always loaded with the audit engine).
function Ensure-AuditMatchesLoaded {
    if ($script:AuditMatchesLoaded) { return }
    $script:AuditMatchesLoaded = $true
    if (-not $script:AuditDir -or -not (Test-Path -LiteralPath $script:AuditDir)) { return }
    foreach ($file in (Get-ChildItem -LiteralPath $script:AuditDir -File -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -like '*-matches.csv' })) {
        $first = $true
        try {
            foreach ($line in [System.IO.File]::ReadLines($file.FullName)) {
                if ($first) { $first = $false; continue }   # header
                if (-not "$line".Trim()) { continue }
                $f = Read-CsvRow $line
                if ($f.Count -lt 11) { continue }
                # Seed the (identity, severity, rules) signature - cols: FileName=1, Repository=3,
                # Path=4, Archive=5, Severity=9, MatchedRule=10 - so prior runs' rows (incl. upgrades)
                # don't re-log.
                [void]$script:AuditMatchesPersisted.Add((Get-AuditMatchSignature $f[3] $f[4] $f[1] $f[5] $f[9] $f[10]))
            }
        } catch { }
    }
}
# Append a finding to its repo's audit/<repo>-matches.csv (scrape-style: blank Timestamp + Hash).
# Written through once per (identity, severity, rule-set) STATE - this session AND prior runs - so a
# Tier-1 match and its later Tier-2 upgrade BOTH land on disk (consolidation merges them by identity),
# while re-running the same audit re-logs nothing. Real matches only. Cheap no-op when no audit dir.
function Save-AuditMatch($f, [int]$matchCount = 0, [string]$contentPreview = '[]') {
    if (-not $script:AuditDir -or $null -eq $f) { return }
    $rule = [string]$f.Rule
    if ($rule -eq $script:AuditOversizeRule -or $rule -eq $script:AuditSkippedRule) { return }
    Ensure-AuditMatchesLoaded
    $repo = if ([string]$f.Repo) { [string]$f.Repo } else { 'unknown' }
    $arch = if ($f.InArchive) { [string]$f.ArchiveName } else { '' }
    $sig  = Get-AuditMatchSignature $repo ([string]$f.Path) ([string]$f.Name) $arch ([string]$f.Sev) ([string]$f.AllRules)
    if (-not $script:AuditMatchesPersisted.Add($sig)) { return }
    $sz = if ($f.Size -ge 0) { [long]$f.Size } else { -1 }
    Write-DownloadLog $script:AuditDir ([string]$f.Name) $repo ([string]$f.Path) $arch `
        $sz ([string]$f.Modified) ([string]$f.Url) ([string]$f.Sev) ([string]$f.AllRules) '' (Get-AuditMatchFile $repo) -Scrape `
        -matchCount $matchCount -contentPreview $contentPreview
}

# Build the single definitive audit-log.csv by consolidating EVERY per-repo <repo>-matches.csv: group
# all rows by repo|path|name|archive identity and merge each group into one row - the UNION of all
# MatchedRule tokens and the HIGHEST severity seen (so a file's Tier-1 row + its Tier-2 upgrade row
# collapse to the merged Tier-1+Tier-2 label). Because matches.csv is cumulative + write-through, this
# is complete across resumed/split runs and crash-safe. Overwrites $outFile (one clean file, no append
# duplicates). Size/Modified/Url come from the highest-severity row. Returns the row count written.
function Build-AuditLogFromMatches([string]$outFile) {
    if (-not $script:AuditDir -or -not (Test-Path -LiteralPath $script:AuditDir)) { return 0 }
    $byId = @{}   # identity -> @{ Repo;Path;Name;Archive;Url;Size;Modified;Rank;Sev; Rules=HashSet }
    foreach ($file in (Get-ChildItem -LiteralPath $script:AuditDir -File -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -like '*-matches.csv' })) {
        $first = $true
        try {
            foreach ($line in [System.IO.File]::ReadLines($file.FullName)) {
                if ($first) { $first = $false; continue }   # header
                if (-not "$line".Trim()) { continue }
                $r = Read-CsvRow $line
                if ($r.Count -lt 11) { continue }
                # cols: FileName=1 Repository=3 Path=4 Archive=5 SizeBytes=6 Modified=7 DownloadUrl=8 Severity=9
                #       MatchedRule=10  MatchCount=11  MatchedContentPreview=12  (11/12 absent on pre-feature rows)
                $id   = Get-AuditMatchIdentity $r[3] $r[4] $r[1] $r[5]
                $rank = Get-AuditRank $r[9]
                $e = $byId[$id]
                if ($null -eq $e) {
                    $e = @{ Repo=$r[3]; Path=$r[4]; Name=$r[1]; Archive=$r[5]; Url=$r[8]; Size=$r[6]; Modified=$r[7]
                            Rank=$rank; Sev=$r[9]; Rules=(New-Object 'System.Collections.Generic.HashSet[string]')
                            MatchCount=0; Snippets=(New-Object 'System.Collections.Generic.List[string]')
                            SnipSeen=(New-Object 'System.Collections.Generic.HashSet[string]') }
                    $byId[$id] = $e
                } elseif ($rank -gt $e.Rank) {
                    # Higher-severity row wins for severity + the representative size/modified/url.
                    $e.Rank = $rank; $e.Sev = $r[9]; $e.Url = $r[8]; $e.Size = $r[6]; $e.Modified = $r[7]
                }
                foreach ($t in (@("$($r[10])" -split '\s*,\s*') | Where-Object { $_ })) { [void]$e.Rules.Add($t) }
                # MatchCount: SUM per-row contributions (each Tier-1 row + each Tier-2 upgrade row carries
                # its own tier's instance count), so the total is correct across split/resumed runs.
                if ($r.Count -ge 12 -and "$($r[11])" -match '^\d+$') { $e.MatchCount += [int]$r[11] }
                # MatchedContentPreview: union the rows' snippet arrays (order-preserved, deduped), capped.
                if ($r.Count -ge 13) {
                    foreach ($sn in (ConvertFrom-AuditJsonArray ([string]$r[12]))) {
                        if (-not "$sn") { continue }   # skip blanks (e.g. legacy/empty cells)
                        if ($e.Snippets.Count -ge $script:AuditPreviewMax) { break }
                        if ($e.SnipSeen.Add([string]$sn)) { [void]$e.Snippets.Add([string]$sn) }
                    }
                }
            }
        } catch { }
    }
    # Overwrite the destination so re-runs don't accumulate; then append one merged row per identity.
    try { Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue } catch { }
    $dir  = Split-Path -Parent $outFile
    $name = Split-Path -Leaf $outFile
    $n = 0
    foreach ($e in ($byId.Values | Sort-Object @{Expression={$_.Rank};Descending=$true}, @{Expression={$_.Repo}}, @{Expression={$_.Path}}, @{Expression={$_.Name}})) {
        $rules = ((@($e.Rules) | Sort-Object) -join ', ')
        $sz = -1; if ("$($e.Size)" -match '^\d+$') { $sz = [long]$e.Size }
        Write-DownloadLog $dir ([string]$e.Name) ([string]$e.Repo) ([string]$e.Path) ([string]$e.Archive) `
            $sz ([string]$e.Modified) ([string]$e.Url) ([string]$e.Sev) $rules '' $name -Scrape `
            -matchCount ([int]$e.MatchCount) -contentPreview (ConvertTo-AuditJsonArray $e.Snippets)
        $n++
    }
    return $n
}

# Exclude filter: compiled glob terms ('*.xml', '*testing*', ...). A finding whose
# Name matches any term is auto-excluded from the bulk download (rendered dim with an
# 'x', like a manual exclude). Applied to findings as they arrive AND on demand to the
# existing list when the user edits the filter. Reset by 'include all'.
$script:AuditExcludes = @()   # array of @{ Text; Rx=[regex] }

# Storage uris we've already asked the metadata prefetch to warm, so a denied/empty
# fetch isn't re-requested every render (MetaCache only holds successes).
$script:AuditMetaTried = New-Object 'System.Collections.Generic.HashSet[string]'

# Work queue + worker pool + in-flight jobs.
$script:AuditQueue   = [Collections.Generic.Queue[object]]::new()
$script:AuditPool    = $null
$script:AuditJobs    = [Collections.Generic.List[object]]::new()
$script:AuditFetch   = [hashtable]::Synchronized(@{})   # key -> worker result (drained+dropped by pump)
# Archive entries awaiting classification: a finished expansion can yield thousands
# of entries; rather than classify them all in one tick (which froze the UI), they
# queue here as @{ Node; ArcName } and are drained a bounded number per pump tick.
$script:AuditPendingNodes = [Collections.Generic.Queue[object]]::new()

# Throttle (read live by the dispatcher; adjustable from the view). Two knobs:
#   MinIntervalMs  - delay between request launches, 0..5000 ms (+/- in the view)
#   MaxConcurrent  - number of parallel workers, 1..10 (w fewer / W more in the view)
# Defaults to a moderate pace (3 workers, 150 ms) so an automatic audit makes steady
# progress out of the box; the user dials it up or down from the audit view.
$script:AuditThrottle = @{ MaxConcurrent = 3; MinIntervalMs = 150 }
$script:AuditLastLaunch = [DateTime]::MinValue
$script:AuditMaxWorkers = 50   # ceiling for the w/W worker control (and the runspace pool); the
                               # headless audit defaults to 15 workers, so the pool must allow >10

# Delay ladder for the +/- controls: increments are small near 0 and grow toward
# 5000 ms, so fine control where it matters and coarse steps at the slow end.
$script:AuditDelayLadder = @(0,10,25,50,75,100,150,200,300,400,500,750,1000,1500,2000,3000,4000,5000)

# Move the inter-request delay one rung along the ladder ($dir +1 slower, -1 faster),
# snapping from the current value to the nearest rung first.
function Step-AuditDelay([int]$dir) {
    $ladder = $script:AuditDelayLadder
    $cur = [int]$script:AuditThrottle.MinIntervalMs
    $idx = 0; $best = [int]::MaxValue
    for ($i = 0; $i -lt $ladder.Count; $i++) {
        $d = [Math]::Abs($ladder[$i] - $cur); if ($d -lt $best) { $best = $d; $idx = $i }
    }
    $idx = [Math]::Max(0, [Math]::Min($ladder.Count - 1, $idx + $dir))
    $script:AuditThrottle.MinIntervalMs = $ladder[$idx]
}
# Full-audit only: the instance walker is deferred until the first resume, so a
# paused automatic audit issues NO requests (not even enumeration) until the user
# adjusts the throttle and presses resume.
$script:AuditWalkPending = $false

# Progress + rate metrics.
$script:AuditEnq      = 0    # accepted for audit (not discarded/dup); grows during full walk
# Known denominator for the progress display when the total IS known up front (the Tier-2 worklist
# feeder sets it to the rows remaining this run). 0 = unknown (index/full walk discover incrementally),
# in which case the display falls back to $AuditEnq. Reset by Reset-AuditEngine.
$script:AuditEnqTotal = 0
$script:AuditDone     = 0    # fully processed
$script:AuditLaunched = 0    # content workers started (~requests)
$script:AuditBytes    = 0L   # content bytes scanned
$script:AuditRate     = @{ QPS = 0.0; FPS = 0.0; BPS = 0.0 }
$script:AuditRateSnap = @{ At = [DateTime]::UtcNow; Done = 0; Launched = 0; Bytes = 0L }
$script:AuditStartedAt = [DateTime]::UtcNow

# ── WORKER ────────────────────────────────────────────────────────────────────
# Fetches a file's size (only if unknown and a storage uri is supplied) then, when
# within the cap, its content decoded to capped text. Writes a transient result to
# the synchronized fetch cache; the pump classifies it and immediately drops it, so
# no file content is retained. Get-WkError (from Prefetch.ps1's $PvErrFn) is injected
# ahead of this body by the dispatcher.
$script:AuditWkScript = {
    param($key, $storageUri, $downloadUrl, $headers, $cap, $knownSize, $cache, $alert)
    $old = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'
    try {
        $size = [int64]$knownSize
        $modified = ''
        # Hit the storage API whenever we have a storage uri, to capture lastModified
        # (ISO) for the Modified column — and the size when it isn't already known.
        # A failure only aborts when the size is still unknown (we can't safely
        # download then); if the size is known we proceed and just leave Modified blank.
        if ($storageUri) {
            try {
                $info = Invoke-RestMethod -Uri $storageUri -Headers $headers -ErrorAction Stop
                if ($size -lt 0 -and $info.PSObject.Properties['size']) { $size = [int64]$info.size }
                if ($info.PSObject.Properties['lastModified'])           { $modified = "$($info.lastModified)" }
            } catch {
                $we = Get-WkError $_
                if ($we.Code -eq 429 -or $we.Code -eq 503) { $alert.Message = "Server rate-limited an audit request (HTTP $($we.Code))."; $alert.At = [DateTime]::UtcNow }
                if ($size -lt 0) {
                    $cache[$key] = [PSCustomObject]@{ Ok=$false; Size=-1; Modified=''; Text=$null; TooBig=$false; Error=$we.Message }
                    return
                }
            }
        }
        if ($size -ge 0 -and $size -gt $cap) {
            $cache[$key] = [PSCustomObject]@{ Ok=$true; Size=$size; Modified=$modified; Text=$null; TooBig=$true; Error='' }
            return
        }
        $resp  = Invoke-WebRequest -Uri $downloadUrl -Headers $headers -UseBasicParsing -ErrorAction Stop
        $bytes = if ($resp.RawContentStream) { $resp.RawContentStream.ToArray() }
                 elseif ($resp.Content -is [byte[]]) { [byte[]]$resp.Content }
                 else { [Text.Encoding]::UTF8.GetBytes([string]$resp.Content) }
        $full = $bytes.Length
        $len  = if ($full -gt $cap) { $cap } else { $full }
        $start = 0
        if ($len -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { $start = 3 }
        $text = [Text.Encoding]::UTF8.GetString($bytes, $start, $len - $start)
        if ($size -lt 0) { $size = $full }
        # NOTE: Modified comes only from the storage API ($info.lastModified, ISO 8601)
        # so it always renders in the same yyyy-MM-dd form as the search view. We do NOT
        # read the HTTP Last-Modified header here — that's RFC 1123 ("Fri, 28 Aug ...")
        # and would mix formats. Findings whose size was already known (storage call
        # skipped above) get their Modified from the MetaCache warm in the view instead.
        $cache[$key] = [PSCustomObject]@{ Ok=$true; Size=$size; Modified=$modified; Text=$text; TooBig=$false; Error='' }
    } catch {
        $we = Get-WkError $_
        if ($we.Code -eq 429 -or $we.Code -eq 503) { $alert.Message = "Server rate-limited an audit request (HTTP $($we.Code))."; $alert.At = [DateTime]::UtcNow }
        $cache[$key] = [PSCustomObject]@{ Ok=$false; Size=-1; Modified=''; Text=$null; TooBig=$false; Error=$we.Message }
    } finally { $ProgressPreference = $old }
}

# Archive-expansion worker: POST the treebrowser request and return the node tree.
# Get-WkError is injected ahead of this body by the dispatcher.
$script:AuditArcScript = {
    param($key, $uri, $body, $headers, $ua, $cache, $alert)
    try {
        $resp = Invoke-RestMethod -Uri $uri -Method Post -Body $body `
                    -ContentType 'application/json' -Headers $headers -UserAgent $ua -ErrorAction Stop
        $data = if ($resp.PSObject.Properties['data'] -and $resp.data) { @(@($resp.data) | Where-Object { $null -ne $_ }) } else { @() }
        $cache[$key] = [PSCustomObject]@{ Ok=$true; Nodes=$data; Error='' }
    } catch {
        $we = Get-WkError $_
        if ($we.Code -eq 429 -or $we.Code -eq 503) { $alert.Message = "Server rate-limited an audit request (HTTP $($we.Code))."; $alert.At = [DateTime]::UtcNow }
        $cache[$key] = [PSCustomObject]@{ Ok=$false; Nodes=@(); Error=$we.Message }
    }
}

# ── FINDINGS ──────────────────────────────────────────────────────────────────
# Add or merge a finding for a work record. $resolved is from Resolve-AuditFindings
# (highest severity + rule label). Merges into an existing entry (raising severity,
# combining rule names) so a file that matches both a meta and a content rule shows
# once at its top severity. Updates the marker flag and marks the view dirty.
function Add-AuditFinding($rec, $resolved, [long]$size = -1, [string]$modified = '') {
    if ($null -eq $resolved) { return }
    $key = $rec.Key
    # This resolution's own contribution: the instance count (Tier-1 meta rules matched, or Tier-2
    # content occurrences) and its preview snippets. Accumulated into the live finding for display, but
    # written to the match log PER ROW (not accumulated) so the additive consolidation stays correct
    # across split/resumed runs - see Save-AuditMatch / Build-AuditLogFromMatches.
    $rCount = if ($resolved.ContainsKey('Count')) { [int]$resolved.Count } else { 1 }
    $rSnips = if ($resolved.ContainsKey('Snippets')) { @($resolved.Snippets) } else { @() }
    $rSevC  = if ($resolved.ContainsKey('SevCounts') -and $resolved.SevCounts) { $resolved.SevCounts } else { @{} }
    if ($script:AuditFindingIdx.ContainsKey($key)) {
        $f = $script:AuditFindingIdx[$key]
        if ($resolved.Rank -gt $f.Rank) { $f.Sev = $resolved.Sev; $f.Rank = $resolved.Rank; $f.Rule = $resolved.Rule }
        $merged = @($f.AllRules -split ', ') + @($resolved.AllRules -split ', ')
        $f.AllRules = (@($merged | Where-Object { $_ } | Select-Object -Unique) -join ', ')
        if ($size -ge 0 -and $f.Size -lt 0) { $f.Size = $size }
        if (-not $f.Modified) {
            if ($modified)          { $f.Modified = $modified }
            elseif ($rec.KnownModified) { $f.Modified = [string]$rec.KnownModified }
        }
        $f.MatchCount += $rCount
    } else {
        $f = [PSCustomObject]@{
            Key=$key; Name=$rec.Name; Repo=$rec.Repo; Path=$rec.Path; Uri=$rec.Uri; Url=$rec.Url
            Size=$(if ($size -ge 0) { $size } elseif ($rec.KnownSize -ge 0) { [long]$rec.KnownSize } else { [long]-1 })
            Modified=$(if ($modified) { $modified } elseif ($rec.KnownModified) { [string]$rec.KnownModified } else { '' })
            FileType=(Get-Ext $rec.Name)
            Sev=$resolved.Sev; Rank=$resolved.Rank; Rule=$resolved.Rule; AllRules=$resolved.AllRules
            # Oversize text findings are excluded by default; so is anything matching the
            # active exclude filter (e.g. '*.xml'). Manual [x]/[i] still override per row.
            Included=(($resolved.Rule -ne $script:AuditOversizeRule) -and ($resolved.Rule -ne $script:AuditSkippedRule) -and -not (Test-AuditExcluded ([string]$rec.Name)))
            InArchive=[bool]$rec.IsArchiveEntry; ArchiveName=$rec.ArchiveName
            # Snippets are {Text;Rule;Sev} objects; MatchSev tallies all matched instances per severity
            # (Tier-1 meta + Tier-2 content) for the 'N more matches' breakdown.
            MatchCount=$rCount; Snippets=(New-Object 'System.Collections.Generic.List[object]'); MatchSev=@{}
        }
        $script:AuditFindings.Add($f)
        $script:AuditFindingIdx[$key] = $f
    }
    # Accumulate this resolution's per-severity instance counts onto the finding.
    foreach ($sk in $rSevC.Keys) { $f.MatchSev[$sk] = [int]$rSevC[$sk] + $(if ($f.MatchSev.ContainsKey($sk)) { [int]$f.MatchSev[$sk] } else { 0 }) }
    # Accumulate preview snippets on the live finding, bounded by $AuditPreviewMax.
    foreach ($sn in $rSnips) {
        if ($f.Snippets.Count -ge $script:AuditPreviewMax) { break }
        [void]$f.Snippets.Add($sn)
    }
    # Marker = highest raw severity seen for this key.
    $cur = if ($script:AuditFlags.ContainsKey($key)) { $script:AuditFlags[$key] } else { '' }
    if ((Get-AuditRank $resolved.Sev) -ge (Get-AuditRank $cur)) { $script:AuditFlags[$key] = $f.Sev }
    # Write-through to audit/<repo>-matches.csv (real matches only; deduped per identity). The row carries
    # THIS resolution's instance count + snippets (not the finding's running total), so Tier-1 and the
    # later Tier-2 upgrade each contribute a distinct row that the consolidation SUMs / unions.
    Save-AuditMatch $f $rCount (ConvertTo-AuditJsonArray $rSnips)
    $script:AuditDirty = $true
}

# Build a normalized work record from a search-results item.
function New-AuditWorkItem($item) {
    $known = -1
    $kmod  = ''
    $u = [string]$item.Uri
    if ($script:MetaCache.ContainsKey($u)) {
        $mc = $script:MetaCache[$u]
        if ("$($mc.Size)" -ne '')     { try { $known = [long]$mc.Size } catch { $known = -1 } }
        if ($mc.PSObject.Properties['Modified'] -and "$($mc.Modified)" -ne '') { $kmod = "$($mc.Modified)" }
    }
    if ($known -lt 0 -and "$($item.Size)" -ne '' -and "$($item.Size)" -ne '?') {
        try { $known = [long]$item.Size } catch { $known = -1 }
    }
    if (-not $kmod -and $item.PSObject.Properties['Modified'] -and "$($item.Modified)" -ne '') { $kmod = "$($item.Modified)" }
    return @{
        Key=$u; Name=[string]$item.Name; Repo=[string]$item.Repo; Path=[string]$item.Path
        Uri=$u; Url=(Get-ItemUrl $item); KnownSize=$known; KnownModified=$kmod
        IsArchiveEntry=$false; ArchiveName=''
        IsArchive=(Get-IsArchive ([string]$item.Name))
    }
}

# Build a normalized work record from an archive-tree node (an internal entry).
function New-AuditWorkNode($n, [string]$arcName) {
    $url  = Get-EntryUrl $n
    $info = Get-NodeInfo $n
    $known = -1
    $kmod  = ''
    if ($info -and $info.PSObject.Properties['size']) { try { $known = [long]$info.size } catch { $known = -1 } }
    # Archive-tree node info reports its date as 'modificationTime' (epoch millis) — NOT
    # the storage API's 'lastModified' (ISO). Reading the wrong field left KnownModified
    # empty, so the findings Modified column never filled for archive entries (size, from
    # 'size' above, worked — hence the column looked selectively broken). Prefer the
    # archive field; fall back to lastModified in case a node carries the storage shape.
    if ($info -and $info.PSObject.Properties['modificationTime'] -and "$($info.modificationTime)" -ne '') { $kmod = "$($info.modificationTime)" }
    elseif ($info -and $info.PSObject.Properties['lastModified'] -and "$($info.lastModified)" -ne '')     { $kmod = "$($info.lastModified)" }
    return @{
        Key=$url; Name=(Get-NodeName $n); Repo=$(if ($n.PSObject.Properties['repoKey']) { "$($n.repoKey)" } else { '' })
        Path=(Get-NodeInternalPath $n); Uri=''; Url=$url; KnownSize=$known; KnownModified=$kmod
        IsArchiveEntry=$true; ArchiveName=$arcName
        IsArchive=$false   # nested sub-archives can't be listed (treated as plain files)
    }
}

# Build a normalized work record from an index archive-entry result item (the shape
# New-ArcResultItem returns: Name/Repo/Path + InArchive/ArchiveName/EntryUrl + Size/Modified).
# Used by the index-backed audit feeder: the archive's entries are already in the index, so we
# audit them directly without a live treebrowser expansion. Size/Modified come from the index row,
# so no metadata request is made; the content fetch (Tier 2) uses EntryUrl as the download url and
# leaves Uri blank (no storage call). Mirrors New-AuditWorkNode but reads a flat result item.
function New-AuditWorkArcItem($it) {
    $known = -1
    if ("$($it.Size)" -match '^-?\d+$') { try { $known = [long]$it.Size } catch { $known = -1 } }
    return @{
        Key=[string]$it.EntryUrl; Name=[string]$it.Name; Repo=[string]$it.Repo
        Path=[string]$it.Path; Uri=''; Url=[string]$it.EntryUrl
        KnownSize=$known; KnownModified=[string]$it.Modified
        IsArchiveEntry=$true; ArchiveName=[string]$it.ArchiveName
        IsArchive=$false
    }
}

# ── ENQUEUE ───────────────────────────────────────────────────────────────────
# Classify a work record's metadata immediately (no I/O); record any Tier-1 finding
# now and, when content rules apply, queue it for a background content fetch. Returns
# nothing; updates state/metrics. Deduped by key via $AuditSeen.
function Add-AuditRecord($rec) {
    if (-not $rec.Key) { return }
    $kh = Get-AuditKeyHash $rec.Key
    if ($script:AuditSeen.Contains($kh)) { return }
    [void]$script:AuditSeen.Add($kh)
    $m = Test-AuditMeta $rec.Name $rec.Path
    if ($m.Discard) { [void]$script:AuditDecided.Add($kh); return }
    # Drop a re-encounter of the same file (same repo + path + name) reached under a
    # differently-formatted uri; the same path + name in a different repo is a distinct
    # file and kept, as is a different path. See $AuditSeenPath.
    if (-not $script:AuditSeenPath.Add((Get-AuditPathHash $rec))) {
        [void]$script:AuditDecided.Add($kh); return
    }
    $script:AuditEnq++
    if ($m.Findings.Count -gt 0) { Add-AuditFinding $rec (Resolve-AuditFindings $m.Findings) }
    # An archive (and not a nested sub-archive) is also expanded: its tree is fetched
    # as a throttled job and every internal entry audited. The archive file itself is
    # "decided" only once that expansion completes. Disabled when the user has turned
    # off "Walk through listable archives" — then it's classified as a plain file.
    $expand = ($rec.IsArchive -and -not $rec.IsArchiveEntry -and $script:AuditWalkArchives)
    # Content (Tier 2) fetch only when enabled; Tier-1-only audits skip it and decide
    # the file on its metadata findings alone.
    $doContent = ($m.ContentRules.Count -gt 0 -and $script:AuditTier2)
    if ($doContent) {
        $rec.Kind          = 'file'
        $rec.ContentRules  = $m.ContentRules
        $rec.HasMetaFinding = ($m.Findings.Count -gt 0)
        $rec.Previewable    = (Get-IsPreviewable $rec.Name)
        $script:AuditQueue.Enqueue($rec)   # decided once its content fetch completes
    } elseif (-not $expand) {
        # Tier-1 pass over a relay-eligible file (has content rules) but Tier-2 is OFF: this is a
        # file Tier-2 WOULD content-inspect. When a worklist is open (Phase A of the two-phase
        # Tier-2 flow) write it through to disk for a later/continued Tier-2 pass - EVERY relay file,
        # including ones that already earned a Tier-1 finding (so Phase B can still content-enrich
        # them). Streamed, not retained.
        if ($script:AuditTier2ListPath -and $m.ContentRules.Count -gt 0) { Write-AuditTier2ListRow $rec }
        # Otherwise (no worklist), optionally surface the synthetic skipped finding so the TUI can
        # show what Tier-2 would cover. Default-excluded, never written to a CSV; suppressed headless
        # ($AuditEmitSkipped off) since at multi-million scale one per relay file is pure memory waste.
        elseif ($script:AuditEmitSkipped -and $m.ContentRules.Count -gt 0 -and $m.Findings.Count -eq 0) {
            Add-AuditFinding $rec @{ Sev='Informational'; Rank=1; Rule=$script:AuditSkippedRule; AllRules=$script:AuditSkippedRule; Count=1 }
        }
        $script:AuditDone++
        [void]$script:AuditDecided.Add($kh)
    }
    if ($expand) { Add-AuditArchiveJob $rec }
}

# Queue an archive-expansion job: a treebrowser POST (built up front so the worker
# just sends it) whose result is flattened into per-entry work. Deduped by a
# distinct "ARC|<uri>" key so it can't collide with the archive file's own record.
function Add-AuditArchiveJob($rec) {
    $akey = Get-AuditKeyHash "ARC|$($rec.Uri)"
    if ($script:AuditSeen.Contains($akey)) { return }
    [void]$script:AuditSeen.Add($akey)
    $archPath = if ($rec.Path) { "$($rec.Path)/$($rec.Name)" } else { [string]$rec.Name }
    $tbr = Get-TreeBrowseRequest $rec.Repo (Get-RepoTypeForUI $rec.Repo) `
               ([string](Resolve-Repo $rec.Repo).PackageType) $archPath ([string]$rec.Name)
    $script:AuditEnq++
    $script:AuditQueue.Enqueue(@{
        Kind='archive'; Key=$akey; ArcName=[string]$rec.Name
        Uri=$tbr.Uri; Body=$tbr.Body; Headers=$tbr.Headers; Ua=$tbr.Ua
    })
}

# Flatten a (possibly nested) treebrowser node list to its file entries: folders are
# recursed; sub-archives can't be listed so they're emitted as plain file entries.
function Get-AuditFlatEntries($nodes, $acc) {
    foreach ($n in @($nodes)) {
        if ($null -eq $n) { continue }
        if (Get-NodeIsFolder $n) { Get-AuditFlatEntries (Get-NodeChildren $n) $acc }
        else { $acc.Add($n) }
    }
}

function Add-AuditWork($items) {
    foreach ($it in @($items)) { if ($it) { Add-AuditRecord (New-AuditWorkItem $it) } }
    $script:AuditDirty = $true
}
function Add-AuditWorkNodes($nodes, [string]$arcName) {
    foreach ($n in @($nodes)) { if ($n) { Add-AuditRecord (New-AuditWorkNode $n $arcName) } }
    $script:AuditDirty = $true
}

# ── DISPATCH / REAP ───────────────────────────────────────────────────────────
function Receive-AuditJobs {
    if ($script:AuditJobs.Count -eq 0) { return }
    $still = [Collections.Generic.List[object]]::new()
    foreach ($j in $script:AuditJobs) {
        if ($j.Handle.IsCompleted) {
            try { [void]$j.PS.EndInvoke($j.Handle) } catch { }
            try { $j.PS.Dispose() } catch { }
            if ($j.Kind -eq 'archive') { Complete-ArchiveJob $j.Rec } else { Complete-AuditJob $j.Rec }
        } else { $still.Add($j) }
    }
    $script:AuditJobs = $still
}

# Process a finished archive expansion: flatten its tree to file entries and enqueue
# each for auditing (name/path now, content if it's previewable text). Drops the
# cached tree afterwards so nothing is retained.
function Complete-ArchiveJob($rec) {
    $key = $rec.Key
    $res = $null
    if ($script:AuditFetch.ContainsKey($key)) { $res = $script:AuditFetch[$key]; [void]$script:AuditFetch.Remove($key) }
    $script:AuditDone++
    [void]$script:AuditDecided.Add((Get-AuditKeyHash $key))
    if ($res -and $res.Ok) {
        $entries = [Collections.Generic.List[object]]::new()
        Get-AuditFlatEntries $res.Nodes $entries
        # Queue for incremental classification (see Step-AuditEntries) rather than
        # processing a whole archive's worth of entries in this one tick.
        foreach ($e in $entries) { $script:AuditPendingNodes.Enqueue(@{ Node=$e; ArcName=$rec.ArcName }) }
    }
    $script:AuditDirty = $true
}

# Classify a bounded batch of pending archive entries per tick, so a huge archive's
# entries trickle into the findings list instead of arriving in one UI-freezing burst.
function Step-AuditEntries {
    $n = 0
    while ($script:AuditPendingNodes.Count -gt 0 -and $n -lt 300) {
        $p = $script:AuditPendingNodes.Dequeue()
        Add-AuditRecord (New-AuditWorkNode $p.Node $p.ArcName)
        $n++
    }
    if ($n -gt 0) { $script:AuditDirty = $true }
}

# Process one finished content fetch: run the content rules over the fetched text,
# add/merge findings (or the synthetic oversize finding), then DROP the cached text.
function Complete-AuditJob($rec) {
    $key = $rec.Key
    $res = $null
    if ($script:AuditFetch.ContainsKey($key)) { $res = $script:AuditFetch[$key]; [void]$script:AuditFetch.Remove($key) }
    $script:AuditDone++
    [void]$script:AuditDecided.Add((Get-AuditKeyHash $key))
    if ($null -eq $res) { return }
    if ($res.Ok -and $res.Text) {
        $cf = Test-AuditContent $res.Text $rec.ContentRules
        if (@($cf.Findings).Count -gt 0) {
            Add-AuditFinding $rec (Resolve-AuditFindings $cf.Findings $cf.Snippets $cf.Count $cf.SevCounts) $res.Size $res.Modified
            $script:AuditBytes += [long]$res.Text.Length
            return
        }
        $script:AuditBytes += [long]$res.Text.Length
    }
    # No content hit. If it's a readable text file skipped only for size, and it has
    # no other finding, surface it under the synthetic oversize rule (default-excluded).
    # Suppressed when $AuditEmitSkipped is off (headless): never written to any CSV.
    if ($script:AuditEmitSkipped -and $res.Ok -and $res.TooBig -and $rec.Previewable -and -not $script:AuditFindingIdx.ContainsKey($key)) {
        Add-AuditFinding $rec @{ Sev='Informational'; Rank=1; Rule=$script:AuditOversizeRule; AllRules=$script:AuditOversizeRule; Count=1 } $res.Size $res.Modified
    }
}

function Dispatch-AuditWork {
    $maxc  = [Math]::Max(1, [Math]::Min($script:AuditMaxWorkers, [int]$script:AuditThrottle.MaxConcurrent))
    $iv    = [int]$script:AuditThrottle.MinIntervalMs
    $headers = Get-AuthHeaders
    while ($script:AuditJobs.Count -lt $maxc -and $script:AuditQueue.Count -gt 0) {
        if ($iv -gt 0 -and ([DateTime]::UtcNow - $script:AuditLastLaunch).TotalMilliseconds -lt $iv) { break }
        $rec = $script:AuditQueue.Dequeue()
        if ($null -eq $script:AuditPool) {
            $script:AuditPool = [RunspaceFactory]::CreateRunspacePool(1, $script:AuditMaxWorkers)
            $script:AuditPool.Open()
        }
        $kind = if ($rec.ContainsKey('Kind')) { $rec.Kind } else { 'file' }
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $script:AuditPool
        [void]$ps.AddScript($script:PvErrFn)   # define Get-WkError in the worker scope
        if ($kind -eq 'archive') {
            [void]$ps.AddScript($script:AuditArcScript).
                AddArgument($rec.Key).AddArgument($rec.Uri).AddArgument($rec.Body).
                AddArgument($rec.Headers).AddArgument($rec.Ua).AddArgument($script:AuditFetch).AddArgument($script:Alert)
        } else {
            $cap = if ($rec.ContainsKey('Cap')) { [long]$rec.Cap } else { [long]$script:AuditCapActive }
            [void]$ps.AddScript($script:AuditWkScript).
                AddArgument($rec.Key).AddArgument($rec.Uri).AddArgument($rec.Url).
                AddArgument($headers).AddArgument($cap).
                AddArgument([long]$rec.KnownSize).AddArgument($script:AuditFetch).AddArgument($script:Alert)
        }
        $script:AuditJobs.Add([PSCustomObject]@{ PS=$ps; Handle=$ps.BeginInvoke(); Key=$rec.Key; Rec=$rec; Kind=$kind })
        $script:AuditLastLaunch = [DateTime]::UtcNow
        $script:AuditLaunched++
        if ($iv -gt 0) { break }   # paced: one launch per tick
    }
}

function Update-AuditMetrics {
    $now = [DateTime]::UtcNow
    $dt  = ($now - $script:AuditRateSnap.At).TotalSeconds
    if ($dt -ge 0.75) {
        $script:AuditRate = @{
            QPS = [Math]::Round(($script:AuditLaunched - $script:AuditRateSnap.Launched) / $dt, 1)
            FPS = [Math]::Round(($script:AuditDone     - $script:AuditRateSnap.Done)     / $dt, 1)
            BPS = [long](($script:AuditBytes - $script:AuditRateSnap.Bytes) / $dt)
        }
        $script:AuditRateSnap = @{ At=$now; Done=$script:AuditDone; Launched=$script:AuditLaunched; Bytes=$script:AuditBytes }
    }
}

# One engine tick: reap finished work, extend the full-audit walk, dispatch new
# workers (unless paused), refresh metrics, and detect completion. Safe to call
# every UI poll; cheap when idle.
function Invoke-AuditPump {
    if ($script:AuditState -eq 'idle' -or $script:AuditState -eq 'done' -or $script:AuditState -eq 'cancelled') { return }
    Receive-AuditJobs
    # While paused: reap only — no enumeration, no fetching. The full-audit walker is
    # launched here on the first unpaused tick so a paused audit stays silent.
    if ($script:AuditState -ne 'paused') {
        if ($script:AuditWalkPending) { $script:AuditWalkPending = $false; [void](Start-AuditWalk) }
        Step-AuditWalk
        Step-AuditIndexWalk
        Step-AuditTier2List
        Step-AuditEntries
        Dispatch-AuditWork
    }
    Update-AuditMetrics
    if ($script:AuditState -eq 'running' -and $script:AuditQueue.Count -eq 0 -and
        $script:AuditJobs.Count -eq 0 -and $script:AuditPendingNodes.Count -eq 0 -and
        -not (Test-AuditWalkActive) -and -not (Test-AuditIndexWalkActive) -and -not (Test-AuditTier2ListActive)) {
        $script:AuditState = 'done'; $script:AuditDirty = $true
    }
}

# Active cap for the current run (set by the mode launchers; passive uses the
# preview cap, automatic modes use the larger audit cap).
$script:AuditCapActive = $script:AuditCap

# ── LIFECYCLE ─────────────────────────────────────────────────────────────────
function Suspend-AuditEngine { if ($script:AuditState -eq 'running') { $script:AuditState = 'paused'; $script:AuditDirty = $true } }
function Resume-AuditEngine  { if ($script:AuditState -eq 'paused')  { $script:AuditState = 'running'; $script:AuditDirty = $true } }

# Abort in-flight workers and clear pending work, leaving findings intact. Used by
# cancel (-> show findings so far) and when tearing down.
function Stop-AuditWork {
    $script:AuditWalkPending = $false
    Stop-AuditWalk
    Stop-AuditIndexWalk
    Stop-AuditTier2List
    foreach ($j in $script:AuditJobs) {
        try { [void]$j.PS.Stop() } catch { }
        try { $j.PS.Dispose() }    catch { }
    }
    $script:AuditJobs.Clear()
    $script:AuditQueue.Clear()
    $script:AuditPendingNodes.Clear()
    $script:AuditFetch.Clear()
    if ($script:AuditPool) {
        try { $script:AuditPool.Close() }   catch { }
        try { $script:AuditPool.Dispose() } catch { }
        $script:AuditPool = $null
    }
}

# Full teardown back to idle, discarding findings and markers. Call when leaving
# audit entirely (e.g. on a new search) so stale markers don't linger.
function Reset-AuditEngine {
    Stop-AuditWork
    $script:AuditState = 'idle'; $script:AuditMode = ''; $script:AuditScope = ''
    $script:AuditFindings = [Collections.Generic.List[object]]::new()
    $script:AuditFindingIdx = @{}
    $script:AuditSeen = New-Object 'System.Collections.Generic.HashSet[System.ValueTuple[System.UInt64,System.UInt64]]'
    $script:AuditSeenPath = New-Object 'System.Collections.Generic.HashSet[System.ValueTuple[System.UInt64,System.UInt64]]'
    $script:AuditDecided = New-Object 'System.Collections.Generic.HashSet[System.ValueTuple[System.UInt64,System.UInt64]]'
    $script:AuditMetaTried = New-Object 'System.Collections.Generic.HashSet[string]'
    $script:AuditExcludes = @()
    $script:AuditFlags.Clear()
    $script:AuditSortCount = -1; $script:AuditSortDirty = $true
    $script:AuditEnq = 0; $script:AuditEnqTotal = 0; $script:AuditDone = 0; $script:AuditLaunched = 0; $script:AuditBytes = 0L
    $script:AuditRate = @{ QPS=0.0; FPS=0.0; BPS=0L }
    $script:AuditRateSnap = @{ At=[DateTime]::UtcNow; Done=0; Launched=0; Bytes=0L }
    $script:AuditDirty = $true
}

# ── FULL-AUDIT WALKER (no AQL) ────────────────────────────────────────────────
# Enumerate the whole instance using ONLY the endpoints the tool already relies on:
# repository keys come from /api/repositories (as Initialize-RepoMap uses), then a
# recursive walk of /api/storage/<repo>/<path> (the same storage endpoint used for
# per-item metadata; a GET on a folder returns its 'children'). Anonymous-readable
# repos only. A background runspace does the walking and pushes discovered file
# storage-uris into a synchronized buffer; Step-AuditWalk drains them on the main
# thread and classifies/enqueues. Back-pressure: the walker pauses while the buffer
# is full so a huge instance can't balloon memory.
$script:AuditWalkPS     = $null
$script:AuditWalkHandle = $null
$script:AuditWalkCancel = $null
$script:AuditWalkOut    = $null
$script:AuditWalkReap   = [Collections.Generic.List[object]]::new()

$script:AuditWalkScript = {
    param($artBase, $headers, $repos, $out, $cancel, $paceMs, $maxPending)
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
                    if ([bool]$c.folder) { $stack.Push([PSCustomObject]@{ Repo = $node.Repo; Rel = $childRel }) }
                    else {
                        while (-not $cancel.stop -and $out.Count -ge $maxPending) { Start-Sleep -Milliseconds 100 }
                        $out.Add("$artBase/api/storage/$($node.Repo)$childRel")
                    }
                }
            }
        } catch { }   # denied/!readable folders are skipped silently
        if ($paceMs -gt 0) { Start-Sleep -Milliseconds $paceMs }
    }
}

# Repos to walk: an explicit -Repos list wins; otherwise the keys from the repo
# map (populated by Initialize-RepoMap). Empty when anonymous access is denied the
# repositories listing and no -Repos was given.
function Get-AuditWalkRepos {
    if ($Repos) { return @($Repos -split '[,\s]+' | Where-Object { $_ }) }
    Initialize-RepoMap
    # Restrict to the active repo-type scope (default LOCAL only). The audit hunts for the
    # organisation's OWN leaked credentials, which live in the artifacts it published to its
    # LOCAL repos — not in the third-party files proxied into REMOTE/CACHE repos. Virtual repos
    # are always excluded (Test-RepoTypeInScope): they aggregate other repos, so walking them
    # re-enumerates the same artifacts under their backing keys (duplicate findings + wasted
    # requests). Widen the type scope with --repo-types; an explicit -Repos list above is
    # honoured as given. If the repo map is empty (anonymous denied /api/repositories) this
    # yields nothing, exactly as before.
    return @($script:RepoMap.Keys | Where-Object { Test-RepoTypeInScope $_ })
}

function Start-AuditWalk {
    Stop-AuditWalk
    $repos = Get-AuditWalkRepos
    if (@($repos).Count -eq 0) { return $false }
    $script:AuditWalkOut = [Collections.ArrayList]::Synchronized([Collections.ArrayList]::new())
    $cancel = [hashtable]::Synchronized(@{ stop = $false })
    $ps = [PowerShell]::Create()
    [void]$ps.AddScript($script:AuditWalkScript).
        AddArgument((Get-ArtBase)).AddArgument((Get-AuthHeaders)).AddArgument(@($repos)).
        AddArgument($script:AuditWalkOut).AddArgument($cancel).AddArgument(0).AddArgument(5000)
    $script:AuditWalkCancel = $cancel
    $script:AuditWalkPS     = $ps
    $script:AuditWalkHandle = $ps.BeginInvoke()
    return $true
}

# Drain discovered uris (bounded per tick so the UI stays responsive) and enqueue.
function Step-AuditWalk {
    if ($null -eq $script:AuditWalkOut) { return }
    $batch = @()
    $sr = $script:AuditWalkOut.SyncRoot
    [System.Threading.Monitor]::Enter($sr)
    try {
        $n = [Math]::Min(300, $script:AuditWalkOut.Count)
        if ($n -gt 0) {
            # GetRange returns a live VIEW over the list, which RemoveRange then
            # invalidates; .ToArray() copies the elements out first.
            $batch = $script:AuditWalkOut.GetRange(0, $n).ToArray()
            $script:AuditWalkOut.RemoveRange(0, $n)
        }
    } finally { [System.Threading.Monitor]::Exit($sr) }
    foreach ($uri in $batch) { Add-AuditRecord (New-AuditWorkItem (Convert-UriToItem $uri)) }
    if (@($batch).Count -gt 0) { $script:AuditDirty = $true }
    Receive-AuditWalk
}

function Receive-AuditWalk {
    if ($script:AuditWalkReap.Count -eq 0) { return }
    $still = [Collections.Generic.List[object]]::new()
    foreach ($j in $script:AuditWalkReap) {
        if ($j.Handle.IsCompleted) { try { [void]$j.PS.EndInvoke($j.Handle) } catch { }; try { $j.PS.Dispose() } catch { } }
        else { $still.Add($j) }
    }
    $script:AuditWalkReap = $still
}

# Active while the walker runspace is still running OR undrained uris remain.
function Test-AuditWalkActive {
    $running = ($null -ne $script:AuditWalkHandle -and -not $script:AuditWalkHandle.IsCompleted)
    $pending = ($null -ne $script:AuditWalkOut -and $script:AuditWalkOut.Count -gt 0)
    return ($running -or $pending)
}

function Stop-AuditWalk {
    if ($script:AuditWalkCancel) { $script:AuditWalkCancel.stop = $true }
    if ($script:AuditWalkPS) { $script:AuditWalkReap.Add([PSCustomObject]@{ PS=$script:AuditWalkPS; Handle=$script:AuditWalkHandle }) }
    $script:AuditWalkPS = $null; $script:AuditWalkHandle = $null; $script:AuditWalkCancel = $null; $script:AuditWalkOut = $null
    Receive-AuditWalk
}

# ── INDEX-BACKED FEEDER (no discovery) ────────────────────────────────────────
# The headless 'index' mode sources its work ONLY from the local index (the per-repo CSV shards +
# archive buckets Index.ps1 maintains) instead of a live /api/storage walk or REST search. The
# index already carries size/modified, so Tier-1 classification fires ZERO requests; only Tier-2
# content scanning hits the server. Mirrors the full-walk pattern (Step-/Test-AuditWalk) but reads
# local files on the main thread, advancing a bounded number of rows per pump tick so a huge index
# trickles into findings instead of arriving in one burst. Dependency direction is allowed: this
# optional module CALLS INTO the core Index.ps1 (Get-IndexedRepos / Get-ArtifactShardPath /
# Get-ArchiveBucketFiles / New-ArcIndexEntry / ...); Index.ps1 never depends back on audit.
$script:AuditIdxActive    = $false   # feeder has rows left to stream
$script:AuditIdxRepos     = $null    # [List] repo keys still to process
$script:AuditIdxRepoPos   = 0        # index into AuditIdxRepos
$script:AuditIdxRepo      = ''       # current repo key (for building records)
$script:AuditIdxFiles     = $null    # [List] of @{ Path; IsArc } for the current repo (shard then buckets)
$script:AuditIdxFilePos   = 0        # index into AuditIdxFiles
$script:AuditIdxEnum      = $null    # live ReadLines enumerator for the current file
$script:AuditIdxEnumIsArc = $false   # is the current file an archive bucket (vs the artifact shard)?
# Back-pressure: stop feeding while the Tier-2 backlog (queued + in-flight content fetches) is
# this deep, so memory stays bounded on a Tier-2 run. Tier-1-only never queues, so it streams freely.
$script:AuditIdxQueueCap  = 2000

# Open the next on-disk shard/bucket enumerator. Advances within the current repo's file list, then
# to the next repo (building its file list: artifact shard first, then each arc bucket). Returns
# $true when an enumerator was opened, $false when every repo is exhausted (and clears the active
# flag). Missing/unreadable files are skipped.
function Open-AuditIdxNextFile {
    while ($true) {
        if ($null -ne $script:AuditIdxFiles -and $script:AuditIdxFilePos -lt $script:AuditIdxFiles.Count) {
            $entry = $script:AuditIdxFiles[$script:AuditIdxFilePos]; $script:AuditIdxFilePos++
            if (Test-Path -LiteralPath $entry.Path) {
                try {
                    $script:AuditIdxEnum      = [System.IO.File]::ReadLines($entry.Path).GetEnumerator()
                    $script:AuditIdxEnumIsArc = [bool]$entry.IsArc
                    return $true
                } catch { continue }
            }
            continue
        }
        if ($null -eq $script:AuditIdxRepos -or $script:AuditIdxRepoPos -ge $script:AuditIdxRepos.Count) {
            $script:AuditIdxActive = $false
            return $false
        }
        $repo = $script:AuditIdxRepos[$script:AuditIdxRepoPos]; $script:AuditIdxRepoPos++
        $script:AuditIdxRepo = $repo
        $files = [Collections.Generic.List[object]]::new()
        $files.Add(@{ Path = (Get-ArtifactShardPath $repo); IsArc = $false })
        foreach ($ap in (Get-ArchiveBucketFiles $repo)) { $files.Add(@{ Path = $ap; IsArc = $true }) }
        $script:AuditIdxFiles   = $files
        $script:AuditIdxFilePos = 0
    }
}

# Drain a bounded batch of index rows per tick and enqueue each for auditing. Top-level shard rows
# (path,name,size,modified) rebuild a storage item the way Search-Index does; arc-bucket rows
# (archDir,archName,internalPath,size,modified) rebuild an archive-entry item. Honors the Tier-2
# back-pressure cap. Uses an explicit enumerator disposed on advance (the ReadLines/break leak
# caveat), so a read handle is never leaked between files.
function Step-AuditIndexWalk {
    if (-not $script:AuditIdxActive) { return }
    if (($script:AuditQueue.Count + $script:AuditJobs.Count) -ge $script:AuditIdxQueueCap) { return }
    $n = 0
    while ($n -lt 300) {
        if ($null -eq $script:AuditIdxEnum) {
            if (-not (Open-AuditIdxNextFile)) { break }
        }
        $moved = $false
        try { $moved = $script:AuditIdxEnum.MoveNext() } catch { $moved = $false }
        if (-not $moved) {
            try { $script:AuditIdxEnum.Dispose() } catch { }
            $script:AuditIdxEnum = $null
            continue
        }
        $line = $script:AuditIdxEnum.Current
        $n++
        if (-not "$line".Trim()) { continue }
        $f = Read-CsvRow $line
        if ($script:AuditIdxEnumIsArc) {
            # archDir,archName,internalPath,size,modified (blank internalPath = empty-archive marker)
            if ($f.Count -lt 3 -or -not $f[2]) { continue }
            $sz = if ($f.Count -ge 4) { $f[3] } else { -1 }
            $md = if ($f.Count -ge 5) { $f[4] } else { '' }
            $e  = New-ArcIndexEntry $script:AuditIdxRepo $f[0] $f[1] $f[2] $sz $md
            Add-AuditRecord (New-AuditWorkArcItem (New-ArcResultItem $e))
        } else {
            # path,name,size,modified
            if ($f.Count -lt 2 -or -not $f[1]) { continue }
            $it = Convert-UriToItem (Get-StorageUriFor $script:AuditIdxRepo $f[0] $f[1])
            if ($f.Count -ge 3 -and "$($f[2])" -ne '') { $it.Size = $f[2] }
            if ($f.Count -ge 4) { $it.Modified = $f[3] }
            Add-AuditRecord (New-AuditWorkItem $it)
        }
    }
    if ($n -gt 0) { $script:AuditDirty = $true }
}

# Active while the feeder still has shards/rows to stream.
function Test-AuditIndexWalkActive { return [bool]$script:AuditIdxActive }

# Tear down the feeder: dispose the live enumerator and clear state.
function Stop-AuditIndexWalk {
    if ($null -ne $script:AuditIdxEnum) {
        try { $script:AuditIdxEnum.Dispose() } catch { }
        $script:AuditIdxEnum = $null
    }
    $script:AuditIdxActive  = $false
    $script:AuditIdxRepos   = $null
    $script:AuditIdxFiles   = $null
    $script:AuditIdxRepoPos = 0
    $script:AuditIdxFilePos = 0
    $script:AuditIdxRepo    = ''
}

# ── TIER-2 WORKLIST FEEDER (Phase B, resumable) ───────────────────────────────
# Stream a Phase-A worklist (repo,path,name,archive,size,modified,url) back in, building a work record
# per row and feeding it to Add-AuditRecord with Tier-2 ON so the existing fetch pool content-scans it.
# Resumable via a progress cursor: a sidecar (<worklist>.progress) holds the count of fully-committed
# rows. Batch-drain keeps the cursor correct despite out-of-order worker completion - a batch is only
# committed once the queue + in-flight jobs have fully drained, then the next batch is read. On EOF the
# worklist + sidecar are deleted. Memory: one batch of records + in-flight fetch content (dropped by
# Complete-AuditJob) + findings (matches only).
$script:AuditT2Active    = $false
$script:AuditT2Enum      = $null     # ReadLines enumerator over the worklist (positioned past header + cursor)
$script:AuditT2Path      = ''        # worklist path
$script:AuditT2Cursor    = 0         # rows committed (persisted to the sidecar)
$script:AuditT2Batch     = 0         # rows read into the current in-flight batch (not yet committed)
$script:AuditT2BatchSize = 1000

function Get-AuditT2CursorPath([string]$path) { return "$path.progress" }
function Read-AuditT2Cursor([string]$path) {
    $cp = Get-AuditT2CursorPath $path
    if (Test-Path -LiteralPath $cp) {
        try { $t = (Get-Content -LiteralPath $cp -Raw).Trim(); if ($t -match '^\d+$') { return [int]$t } } catch { }
    }
    return 0
}
function Save-AuditT2Cursor {
    if (-not $script:AuditT2Path) { return }
    $cp  = Get-AuditT2CursorPath $script:AuditT2Path
    $tmp = "$cp.tmp"
    try {
        [System.IO.File]::WriteAllText($tmp, [string]$script:AuditT2Cursor, [Text.UTF8Encoding]::new($false))
        [System.IO.File]::Copy($tmp, $cp, $true); Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    } catch { }
}

# Build a work record from a worklist row (array from Read-CsvRow: repo,path,name,archive,size,modified,url).
# Archive entries get the New-AuditWorkArcItem shape; top-level rows key off the storage uri (so a Tier-2
# finding merges with Phase A's same-keyed Tier-1 finding) but leave Uri blank so the worker skips the
# storage call (size/modified are known) and fetches only content from url.
function New-AuditWorkFromListRow($f) {
    if ($f.Count -lt 3) { return $null }
    $repo = [string]$f[0]; $path = [string]$f[1]; $name = [string]$f[2]
    $arch = if ($f.Count -ge 4) { [string]$f[3] } else { '' }
    $known = -1; if ($f.Count -ge 5 -and "$($f[4])" -match '^-?\d+$') { $known = [long]$f[4] }
    $mod  = if ($f.Count -ge 6) { [string]$f[5] } else { '' }
    $url  = if ($f.Count -ge 7) { [string]$f[6] } else { '' }
    if ($arch) {
        return @{
            Key=$url; Name=$name; Repo=$repo; Path=$path; Uri=''; Url=$url
            KnownSize=$known; KnownModified=$mod; IsArchiveEntry=$true; ArchiveName=$arch; IsArchive=$false
        }
    }
    return @{
        Key=(Get-StorageUriFor $repo $path $name); Name=$name; Repo=$repo; Path=$path; Uri=''; Url=$url
        KnownSize=$known; KnownModified=$mod; IsArchiveEntry=$false; ArchiveName=''
        IsArchive=(Get-IsArchive $name)
    }
}

# Start consuming a worklist. -KeepFindings (inline -2 continuation) clears ONLY the dedup seen-sets and
# resets the progress counters, keeping findings/idx/flags/matches so Tier-2 merges into Phase A's
# findings; without it (standalone --tier2-resume) the engine is fully reset. Returns $false if the
# worklist is missing/empty.
function Start-AuditTier2List([string]$path, [switch]$KeepFindings) {
    if (-not $path -or -not (Test-Path -LiteralPath $path)) { return $false }
    if ($KeepFindings) {
        Stop-AuditWork   # abort any in-flight Phase-A work, keep findings
        $script:AuditSeen     = New-Object 'System.Collections.Generic.HashSet[System.ValueTuple[System.UInt64,System.UInt64]]'
        $script:AuditSeenPath = New-Object 'System.Collections.Generic.HashSet[System.ValueTuple[System.UInt64,System.UInt64]]'
        $script:AuditEnq = 0; $script:AuditDone = 0; $script:AuditLaunched = 0; $script:AuditBytes = 0L
        $script:AuditRateSnap = @{ At=[DateTime]::UtcNow; Done=0; Launched=0; Bytes=0L }
    } else {
        Reset-AuditEngine
    }
    $script:AuditTier2 = $true
    $script:AuditMode = 'tier2-list'; $script:AuditScope = "worklist: $path"
    $script:AuditCapActive = $script:AuditCap
    $script:AuditStartedAt = [DateTime]::UtcNow
    $script:AuditT2Path   = $path
    $script:AuditT2Cursor = Read-AuditT2Cursor $path
    $script:AuditT2Batch  = 0
    # Known progress total: the worklist row count is known up front (unlike the streaming index
    # walk), so count it once (cheap sequential pass, no parse) and expose the rows still to do this
    # run as the progress denominator instead of letting it grow a batch at a time.
    $rows = 0
    try { foreach ($ln in [System.IO.File]::ReadLines($path)) { $rows++ } } catch { }
    $script:AuditEnqTotal = [Math]::Max(0, ($rows - 1) - $script:AuditT2Cursor)   # minus the header, minus committed
    # Open the reader, skip the header + already-committed rows.
    $script:AuditT2Enum = [System.IO.File]::ReadLines($path).GetEnumerator()
    $skip = 1 + $script:AuditT2Cursor   # header + committed data rows
    $n = 0
    while ($n -lt $skip) { if (-not $script:AuditT2Enum.MoveNext()) { break }; $n++ }
    $script:AuditT2Active = $true
    $script:AuditState = 'paused'
    return $true
}

# One feeder tick: commit the drained batch (advance + persist the cursor), then read + enqueue the next.
function Step-AuditTier2List {
    if (-not $script:AuditT2Active) { return }
    # Wait until the current batch has fully drained so the cursor only advances past completed rows.
    if (($script:AuditQueue.Count + $script:AuditJobs.Count) -gt 0) { return }
    if ($script:AuditT2Batch -gt 0) {
        $script:AuditT2Cursor += $script:AuditT2Batch
        $script:AuditT2Batch = 0
        Save-AuditT2Cursor
    }
    $read = 0
    while ($read -lt $script:AuditT2BatchSize) {
        if (-not $script:AuditT2Enum.MoveNext()) { break }
        $line = $script:AuditT2Enum.Current
        $read++
        if (-not "$line".Trim()) { continue }
        $rec = New-AuditWorkFromListRow (Read-CsvRow $line)
        if ($rec) { Add-AuditRecord $rec }
    }
    if ($read -eq 0) {
        # EOF: nothing left and the last batch already committed above -> done. Drop the files.
        $script:AuditT2Active = $false
        $p = $script:AuditT2Path
        Stop-AuditTier2List
        if ($p) {
            try { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue } catch { }
            try { Remove-Item -LiteralPath (Get-AuditT2CursorPath $p) -Force -ErrorAction SilentlyContinue } catch { }
        }
        return
    }
    $script:AuditT2Batch = $read
    $script:AuditDirty = $true
}

function Test-AuditTier2ListActive { return [bool]$script:AuditT2Active }

# Tear down the feeder (dispose the reader). Does NOT delete the worklist/cursor - only full completion
# (the EOF path in Step-AuditTier2List) does, so an interrupted run stays resumable.
function Stop-AuditTier2List {
    if ($null -ne $script:AuditT2Enum) {
        try { $script:AuditT2Enum.Dispose() } catch { }
        $script:AuditT2Enum = $null
    }
    $script:AuditT2Active = $false
    $script:AuditT2Path   = ''
    $script:AuditT2Batch  = 0
}

# ── MODE LAUNCHERS ────────────────────────────────────────────────────────────
function Start-AuditPassive {
    if ($script:AuditState -ne 'passive') { Reset-AuditEngine }
    $script:AuditMode = 'passive'; $script:AuditScope = 'current view (background)'
    $script:AuditCapActive = $script:PreviewLimit   # passive matches the preview cap
    $script:AuditStartedAt = [DateTime]::UtcNow
    $script:AuditState = 'passive'
}

# Automatic audits START PAUSED so the user can set the throttle before any
# requests fire, then press resume. Metadata/Tier-1 findings (no I/O) are still
# computed up front and shown; only the content fetching waits for resume.
function Start-AuditLocation([string]$label, $items) {
    Reset-AuditEngine
    Initialize-RepoMap   # so archive-expansion treebrowser requests get the right repo type
    $script:AuditMode = 'location'; $script:AuditScope = $label
    $script:AuditCapActive = $script:AuditCap
    $script:AuditStartedAt = [DateTime]::UtcNow
    Add-AuditWork $items
    $script:AuditState = 'paused'
}

function Start-AuditLocationNodes([string]$label, $nodes, [string]$arcName) {
    Reset-AuditEngine
    $script:AuditMode = 'location'; $script:AuditScope = $label
    $script:AuditCapActive = $script:AuditCap
    $script:AuditStartedAt = [DateTime]::UtcNow
    Add-AuditWorkNodes $nodes $arcName
    $script:AuditState = 'paused'
}

function Start-AuditFull {
    Reset-AuditEngine
    Initialize-RepoMap   # so archive-expansion treebrowser requests get the right repo type
    $script:AuditMode = 'full'; $script:AuditScope = 'entire instance'
    $script:AuditCapActive = $script:AuditCap
    $script:AuditStartedAt = [DateTime]::UtcNow
    if (@(Get-AuditWalkRepos).Count -eq 0) {
        $script:AuditState = 'done'   # nothing to enumerate (no repos / denied)
        return
    }
    $script:AuditWalkPending = $true  # walker launches on first resume
    $script:AuditState = 'paused'
}

# Best-effort total-rows estimate for an index audit: the sum of line counts across each in-scope repo's
# artifact shard + archive buckets (the same files Step-AuditIndexWalk streams). No server queries (the
# index is on disk), counted in .NET via Linq over ReadLines (no PowerShell-level per-byte loop), so it
# stays fast at scale. Slightly OVER the audited count because the walk dedupes repeats - good enough
# for a progress denominator. Returns 0 if nothing is countable.
function Get-AuditIndexRowCount($repos) {
    $total = 0L
    foreach ($repo in @($repos)) {
        $files = [Collections.Generic.List[string]]::new()
        $files.Add((Get-ArtifactShardPath $repo))
        foreach ($ap in (Get-ArchiveBucketFiles $repo)) { $files.Add($ap) }
        foreach ($path in $files) {
            if (-not (Test-Path -LiteralPath $path)) { continue }
            try { $total += [long][System.Linq.Enumerable]::Count([System.IO.File]::ReadLines($path)) } catch { }
        }
    }
    return [long]$total
}

# Index-backed audit: source work ONLY from the local index (no discovery). Scope is the indexed
# repos narrowed to the active repo-type scope (default LOCAL only), or an explicit -Repos list.
# Starts paused like the other automatic modes (the headless pump resumes immediately); the feeder
# (Step-AuditIndexWalk) streams the shards on each tick. Returns $false when there's nothing to
# audit (no in-scope indexed repos) so the launcher can report it.
function Start-AuditIndex {
    Reset-AuditEngine
    Initialize-RepoMap   # populate the repo map so Test-RepoTypeInScope can filter to local (graceful if denied)
    $script:AuditMode = 'index'; $script:AuditScope = 'local index'
    $script:AuditCapActive = $script:AuditCap
    $script:AuditStartedAt = [DateTime]::UtcNow
    $repos = if ($Repos) { @($Repos -split '[,\s]+' | Where-Object { $_ }) }
             else        { @(Get-IndexedRepos | Where-Object { Test-RepoTypeInScope $_ }) }
    if (@($repos).Count -eq 0) {
        $script:AuditState = 'done'
        return $false
    }
    $list = [Collections.Generic.List[object]]::new()
    foreach ($rk in $repos) { $list.Add($rk) }
    $script:AuditIdxRepos     = $list
    # Known total up front: the index is already on disk, so count the rows we're about to stream (no
    # server queries). Drives a (mostly) correct done/total + ETA from the first tick; slightly over the
    # audited count because the walk dedupes repeats. Tier-2 later overrides this with its worklist size.
    $script:AuditEnqTotal     = Get-AuditIndexRowCount $repos
    $script:AuditIdxRepoPos   = 0
    $script:AuditIdxRepo      = ''
    $script:AuditIdxFiles     = $null
    $script:AuditIdxFilePos   = 0
    $script:AuditIdxEnum      = $null
    $script:AuditIdxEnumIsArc = $false
    $script:AuditIdxActive    = $true
    $script:AuditState = 'paused'
    return $true
}
# ── FINDINGS SORTING ──────────────────────────────────────────────────────────
# Sorted view of the findings: downloaded last of all, then excluded, then highest
# severity, then repo/path/name. Re-sort only when the count changed OR an exclusion or
# download toggled (both set AuditSortDirty; a download also marks the key visited),
# AND either the audit isn't actively running or it's been a beat since the last sort
# — so a fast scan doesn't re-sort thousands of rows every frame (the cause of the
# navigation lag / periodic freezes). When paused or done it sorts immediately.
$script:AuditSortCount = -1
$script:AuditSorted    = @()
$script:AuditSortAt    = [DateTime]::MinValue
$script:AuditSortDirty = $true    # set when Included flags change (no count change)
function Get-AuditSortedFindings {
    $changed = ($script:AuditFindings.Count -ne $script:AuditSortCount) -or $script:AuditSortDirty
    $stale   = (([DateTime]::UtcNow - $script:AuditSortAt).TotalMilliseconds -ge 750)
    if ($changed -and ($stale -or $script:AuditState -ne 'running')) {
        $script:AuditSorted = @($script:AuditFindings |
            Sort-Object @{ Expression = { (Test-Visited $_.Key) } },
                        @{ Expression = { -not $_.Included } },
                        @{ Expression = { $_.Rank }; Descending = $true },
                        @{ Expression = { $_.Repo } }, @{ Expression = { $_.Path } },
                        @{ Expression = { $_.Name } })
        $script:AuditSortCount = $script:AuditFindings.Count
        $script:AuditSortAt    = [DateTime]::UtcNow
        $script:AuditSortDirty = $false
    }
    return $script:AuditSorted
}
# ── EXCLUDE FILTER ────────────────────────────────────────────────────────────
# Glob terms ('*.xml', '*testing*', 'pass?.txt') matched against a finding's Name.
# '*' = any run, '?' = one char; matching is case-insensitive and anchored to the
# whole name. A match excludes the finding from the bulk download (dim + 'x').
function ConvertTo-AuditGlobRegex([string]$glob) {
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

# Parse a user-entered filter string (terms separated by commas or whitespace) into
# the compiled exclude set held in $script:AuditExcludes.
function Set-AuditExcludes([string]$terms) {
    $out = @()
    foreach ($t in @("$terms" -split '[,\s]+')) {
        if (-not $t) { continue }
        $rx = ConvertTo-AuditGlobRegex $t
        if ($rx) { $out += @{ Text = $t; Rx = $rx } }
    }
    $script:AuditExcludes = @($out)
}

# True if a name matches any active exclude term.
function Test-AuditExcluded([string]$name) {
    if (@($script:AuditExcludes).Count -eq 0) { return $false }
    foreach ($e in $script:AuditExcludes) { if ($e.Rx.IsMatch("$name")) { return $true } }
    return $false
}
# Sentinel so the base files can detect that audit is loaded (see StartTui.ps1).
function Invoke-Audit { }

# == HEADLESS DOWNLOAD-SET BUILDER ==============================================
# The non-UI core of the bulk download, shared by the TUI's Save-AuditFindingSet
# wrapper (which adds the confirm prompt + done popup) and the non-interactive
# engine. Get-AuditIncludedCandidates is the default "download all" selection.
function Get-AuditIncludedCandidates {
    return @(Get-AuditSortedFindings | Where-Object { $_.Included -and -not (Test-Visited $_.Key) })
}

function Get-AuditDownloadEntries($candidates) {
    return @(@($candidates | Where-Object { $_ }) | ForEach-Object {
        $kh = ''
        if (-not $_.InArchive -and $_.Uri -and $script:MetaCache.ContainsKey($_.Uri)) {
            $m = $script:MetaCache[$_.Uri]; if ($m.PSObject.Properties['Hash']) { $kh = [string]$m.Hash }
        }
        [PSCustomObject]@{
            Ref = $_; Name = [string]$_.Name; Url = [string]$_.Url; KnownHash = $kh
            Repo = [string]$_.Repo; Path = [string]$_.Path
            Archive = $(if ($_.InArchive) { [string]$_.ArchiveName } else { '' })
            Size = $(if ($_.Size -ge 0) { [long]$_.Size } else { [long]-1 })
            Modified = [string]$_.Modified; Sev = [string]$_.Sev; Rule = [string]$_.AllRules; VisitKey = [string]$_.Key
        }
    })
}

function Invoke-AuditDownloadSet($candidates) {
    $entries = Get-AuditDownloadEntries $candidates
    $res = Invoke-DedupDownload $entries
    $script:AuditSortDirty = $true
    return $res
}
