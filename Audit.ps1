# Audit.ps1 — OPTIONAL credential-audit component of the ARTCA Artifactory TUI.
#
# This file holds function and $script:-state definitions only; nothing here runs
# on its own. It is loaded two ways:
#   · dot-sourced automatically by StartTui.ps1 when the tool is run as a file, IF
#     this file is present beside the others, or
#   · pasted directly into the PowerShell console alongside the other component
#     files (before StartTui.ps1) to enable audit mode without the .ps1 files.
#
# When this file is ABSENT the tool runs exactly as before: the base files gate
# every reference to audit behind $script:AuditAvailable (set $false by StartTui
# and flipped true only once Invoke-Audit — the sentinel below — is defined).
#
# It ports the SnaffCon/Snaffler default ruleset (filename/extension/path = "Tier
# 1", file-content regex = "Tier 2") to classify Artifactory artifacts by severity
# and surface likely exposed credentials/secrets for review and cleanup.
#
# File conventions follow the rest of the codebase: UTF-8 without BOM, LF endings,
# and any non-ASCII glyph that affects execution is a numeric [char] escape.

# ── SEVERITY MODEL ────────────────────────────────────────────────────────────
# Severities, most to least severe: red > yellow > green > blue. The names are just
# the colour each is shown in, so key, label and on-screen colour all agree.
#
# Historical note: these tiers are ported from Snaffler, whose ruleset names them
# black > red > yellow > green. Black is unreadable on a dark terminal, so the tool
# always displayed each one step down the colour scale (black->red, red->yellow,
# yellow->green, green->blue). The keys have now simply been renamed to the colour
# they're shown in, dropping the old indirection; the ordering is unchanged (what
# Snaffler calls "black", the most severe, is our "red").

function Get-AuditRank([string]$sev) {
    switch ("$sev".ToLower()) {
        'red'  { 4 } 'yellow' { 3 } 'green' { 2 } 'blue' { 1 } default { 0 }
    }
}

# On-screen colour for a severity. Built at call time so it never touches the ANSI
# vars at load (they may not exist yet in paste mode). Empty on a non-VT host, where
# Get-AuditLetter differentiates instead.
function Get-AuditColor([string]$sev) {
    if (-not $script:Vt) { return '' }
    $e = [char]27
    switch ("$sev".ToLower()) {
        'red'    { "$e[38;5;203m" }
        'yellow' { "$e[38;5;221m" }
        'green'  { "$e[38;5;113m" }
        'blue'   { "$e[38;5;75m"  }
        default  { '' }
    }
}

# Single-letter severity tag, so the marker is distinguishable without colour
# (ISE / plain cmd) and for the CSV: R/Y/G/B.
function Get-AuditLetter([string]$sev) {
    switch ("$sev".ToLower()) {
        'red'  { 'R' } 'yellow' { 'Y' } 'green' { 'G' } 'blue' { 'B' } default { '?' }
    }
}

# Name of the synthetic rule for readable text files skipped only because they
# exceed the content-scan cap. Lowest severity, default-excluded in the view.
$script:AuditOversizeRule = 'TextFileAboveSizeLimit'

# ── RULESET ───────────────────────────────────────────────────────────────────
# === USER-EDITABLE RULES =======================================================
# To tune the audit, edit the blocks below. Every rule has an Enabled flag — set
# it to $false to switch a rule off without deleting it; add your own by copying
# the shape of a nearby entry. Three kinds:
#
#   Discard  — { Loc='ext'|'name'|'path'; Match='exact'|'contains'|'regex';
#               Values=@(...); Enabled=$bool }
#              A hit drops the file from the audit entirely (noise suppression).
#   Meta     — { Name; Sev=red|yellow|green|blue; Loc='ext'|'name'|'path';
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
        @{ Name='WinHashes';        Sev='red'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('NTDS.DIT','SYSTEM','SAM','SECURITY') }
        @{ Name='NixLocalHashes';   Sev='red'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('shadow','pwd.db','passwd') }
        @{ Name='MemDumpByName';    Sev='red'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('MEMORY.DMP','hiberfil.sys','lsass.dmp','lsass.exe.dmp') }
        @{ Name='NetDeviceConfig';  Sev='red'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('running-config.cfg','startup-config.cfg','running-config','startup-config') }
        @{ Name='CyberArkConfigs';  Sev='red'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('Psmapp.cred','psmgw.cred','backup.key','MasterReplicationUser.pass','RecPrv.key',
                    'ReplicationUser.pass','Server.key','VaultEmergency.pass','VaultUser.pass','Vault.ini',
                    'PADR.ini','PARAgent.ini','CACPMScanner.exe.config','PVConfiguration.xml') }
        @{ Name='PasswordManagers'; Sev='red'; Loc='ext';  Match='exact'; Enabled=$true;
           Values=@('kdbx','kdb','psafe3','kwallet','keychain','agilekeychain','cred') }
        @{ Name='SSHKeysByName';    Sev='red'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('id_rsa','id_dsa','id_ecdsa','id_ed25519') }
        @{ Name='SSHKeysByExt';     Sev='red'; Loc='ext';  Match='exact'; Enabled=$true;
           Values=@('ppk') }
        @{ Name='SSHFilesByPath';   Sev='red'; Loc='path'; Match='contains'; Enabled=$true;
           Values=@('/.ssh/') }
        @{ Name='RemoteAccessName'; Sev='red'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('mobaxterm.ini','mobaxterm backup.zip','confCons.xml') }
        @{ Name='CloudApiKeysName'; Sev='red'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('.tugboat') }
        @{ Name='CloudApiKeysPath'; Sev='red'; Loc='path'; Match='contains'; Enabled=$true;
           Values=@('/.aws/','doctl/config.yaml') }
        # ----- RED -----
        @{ Name='HtpasswdEtc';      Sev='yellow'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('.htpasswd','accounts.v4') }
        @{ Name='MediaWikiConfig';  Sev='yellow'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('LocalSettings.php') }
        @{ Name='RubyConfig';       Sev='yellow'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('database.yml','.secret_token.rb','knife.rb','carrierwave.rb','omniauth.rb') }
        @{ Name='JenkinsConfig';    Sev='yellow'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('jenkins.plugins.publish_over_ssh.BapSshPublisherPlugin.xml','credentials.xml') }
        @{ Name='FtpServerConfig';  Sev='yellow'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('proftpdpasswd','filezilla.xml') }
        @{ Name='FtpClientConfig';  Sev='yellow'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('recentservers.xml','sftp-config.json') }
        @{ Name='DbMgmtConfig';     Sev='yellow'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('SqlStudio.bin','.mysql_history','.psql_history','.pgpass',
                    '.dbeaver-data-sources.xml','credentials-config.json','dbvis.xml','robomongo.json') }
        @{ Name='GitCredentials';   Sev='yellow'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('.git-credentials') }
        @{ Name='PasswordFiles';    Sev='yellow'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('passwords.txt','pass.txt','accounts.txt','passwords.doc','pass.doc','accounts.doc',
                    'passwords.xls','pass.xls','accounts.xls','passwords.docx','pass.docx','accounts.docx',
                    'passwords.xlsx','pass.xlsx','accounts.xlsx','secrets.txt','secrets.doc','secrets.xls',
                    'secrets.docx','secrets.xlsx','BitlockerLAPSPasswords.csv') }
        @{ Name='InfraAsCode';      Sev='yellow'; Loc='ext';  Match='exact'; Enabled=$true;
           Values=@('cscfg','ucs','tfvars') }
        @{ Name='VmDisks';          Sev='yellow'; Loc='ext';  Match='exact'; Enabled=$true;
           Values=@('vmdk','vdi','vhd','vhdx') }
        @{ Name='MemDumpByExt';     Sev='yellow'; Loc='ext';  Match='exact'; Enabled=$true;
           Values=@('dmp') }
        @{ Name='CyberArkByExt';    Sev='yellow'; Loc='ext';  Match='exact'; Enabled=$true;
           Values=@('pass') }
        @{ Name='DomainJoinPath';   Sev='yellow'; Loc='path'; Match='contains'; Enabled=$true;
           Values=@('control/customsettings.ini') }
        @{ Name='SccmBootVarPath';  Sev='yellow'; Loc='path'; Match='regex'; Enabled=$true;
           Values=@('reminst/smstemp/.*\.var','sms/data/variables.dat','sms/data/policy.xml') }
        # ----- YELLOW -----
        @{ Name='Databases';        Sev='green'; Loc='ext'; Match='exact'; Enabled=$true;
           Values=@('mdf','sdf','sqldump','bak') }
        @{ Name='DeployImages';     Sev='green'; Loc='ext'; Match='exact'; Enabled=$true;
           Values=@('wim','ova','ovf') }
        @{ Name='KerberosByExt';    Sev='green'; Loc='ext'; Match='exact'; Enabled=$true;
           Values=@('keytab','ccache') }
        @{ Name='KerberosByName';   Sev='green'; Loc='name'; Match='regex'; Enabled=$true;
           Values=@('^krb5cc_.*') }
        @{ Name='PacketCapture';    Sev='green'; Loc='ext'; Match='exact'; Enabled=$true;
           Values=@('pcap','cap','pcapng') }
        @{ Name='RemoteAccessExt';  Sev='green'; Loc='ext'; Match='exact'; Enabled=$true;
           Values=@('rdg','rtsz','rtsx','ovpn','tvopt','sdtid') }
        @{ Name='DefenderConfig';   Sev='green'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('SensorConfiguration.json','mdatp_managed.json') }
        @{ Name='DomainJoinName';   Sev='green'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('customsettings.ini') }
        # ----- GREEN (informational) -----
        @{ Name='NameContainsSecret'; Sev='blue'; Loc='name'; Match='contains'; Enabled=$true;
           Values=@('passw','secret','credential','thycotic','cyberark') }
        @{ Name='ShellHistory';       Sev='blue'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('.bash_history','.zsh_history','.sh_history','zhistory','.irb_history','ConsoleHost_History.txt') }
        @{ Name='ShellRcFiles';       Sev='blue'; Loc='name'; Match='exact'; Enabled=$true;
           Values=@('.netrc','_netrc','.exports','.functions','.extra','.npmrc','.env','.bashrc','.profile','.zshrc') }
    )

    # ---- CONTENT: Tier-2 findings (regex over decoded text) -------------------
    # Single-quoted strings keep backslashes literal; embedded single quotes are
    # doubled. Char classes simplified to ['"] (Snaffler over-escaped them).
    $content = [ordered]@{
        'InlinePrivateKey' = @{ Sev='yellow'; Enabled=$true; Patterns=@(
            '-----BEGIN( RSA| OPENSSH| DSA| EC| PGP)? PRIVATE KEY( BLOCK)?-----') }
        'AwsKeys' = @{ Sev='yellow'; Enabled=$true; Patterns=@(
            'aws[_\-\.]?key',
            '(\s|[''"^=])(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z2-7]{12,16}(\s|[''"]|$)') }
        'SlackTokens' = @{ Sev='yellow'; Enabled=$true; Patterns=@(
            '(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})',
            'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}') }
        'PassOrKeyInCode' = @{ Sev='yellow'; Enabled=$true; Patterns=@(
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
        'SqlAccountCreation' = @{ Sev='yellow'; Enabled=$true; Patterns=@(
            'CREATE (USER|LOGIN) .{0,200} (IDENTIFIED BY|WITH PASSWORD)') }
        'DbConnStringPw' = @{ Sev='green'; Enabled=$true; Patterns=@(
            'connectionstring.{1,200}passw') }
        'S3UriPrefix' = @{ Sev='green'; Enabled=$true; Patterns=@(
            's3[a]?:\/\/[a-zA-Z0-9\-\+\/]{2,16}') }
        'CSharpDbConnRed' = @{ Sev='yellow'; Enabled=$true; Patterns=@(
            'Data Source=.+(;|)Password=.+(;|)','Password=.+(;|)Data Source=.+(;|)') }
        'CSharpDbConnYellow' = @{ Sev='green'; Enabled=$true; Patterns=@(
            'Data Source=.+Integrated Security=(SSPI|true)','Integrated Security=(SSPI|true);.*Data Source=.+') }
        'CSharpViewstateKeys' = @{ Sev='yellow'; Enabled=$true; Patterns=@(
            'validationkey\s*=\s*[''"][^''"]....','decryptionkey\s*=\s*[''"][^''"]....') }
        'CmdCredentials' = @{ Sev='yellow'; Enabled=$true; Patterns=@(
            'passwo?r?d\s*=\s*[''"][^''"]....','schtasks.{1,300}(/rp\s|/p\s)','net user ',
            'psexec .{0,100} -p ','net use .{0,300} /user:','cmdkey ') }
        'PsCredentials' = @{ Sev='yellow'; Enabled=$true; Patterns=@(
            '-SecureString','-AsPlainText','\[Net.NetworkCredential\]::new\(') }
        'JavaDbConnStrings' = @{ Sev='yellow'; Enabled=$true; Patterns=@(
            '\.getConnection\("jdbc:','passwo?r?d\s*=\s*[''"][^''"]....') }
        'PhpDbConnStrings' = @{ Sev='yellow'; Enabled=$true; Patterns=@(
            'mysql_connect\s*\(.*\$.*\)','mysql_pconnect\s*\(.*\$.*\)','mysql_change_user\s*\(.*\$.*\)',
            'pg_connect\s*\(.*\$.*\)','pg_pconnect\s*\(.*\$.*\)') }
        'PerlDbConnStrings' = @{ Sev='yellow'; Enabled=$true; Patterns=@('DBI\-\>connect\(') }
        'PyDbConnStrings' = @{ Sev='yellow'; Enabled=$true; Patterns=@(
            'mysql\.connector\.connect\(','psycopg2\.connect\(') }
        'RubyDbConnStrings' = @{ Sev='yellow'; Enabled=$true; Patterns=@('DBI\.connect\(') }
        'NetConfigCreds' = @{ Sev='yellow'; Enabled=$true; Patterns=@(
            'NVRAM config last updated','enable password \.','simple-bind authenticated encrypt',
            'pac key [0-7] ','snmp-server community\s.+\sRW') }
        'UnattendXml' = @{ Sev='yellow'; Enabled=$true; Patterns=@(
            '(?s)<AdministratorPassword>.{0,30}<Value>.*<\/Value>',
            '(?s)<AutoLogon>.{0,30}<Value>.*<\/Value>') }
        'FirefoxLogins' = @{ Sev='yellow'; Enabled=$true; Patterns=@(
            '"encryptedPassword":"[A-Za-z0-9+/=]+"') }
        'RdpPasswords' = @{ Sev='yellow'; Enabled=$true; Patterns=@('password 51:b') }
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

# Content pass: run the named content rules' regexes over decoded text. Returns an
# array of @{Rule;Sev} for those that match.
function Test-AuditContent([string]$text, [string[]]$contentRules) {
    if (-not $text -or $null -eq $contentRules -or $contentRules.Count -eq 0) { return @() }
    $rs = Get-AuditRuleSet
    $out = [Collections.Generic.List[object]]::new()
    foreach ($cn in $contentRules) {
        if (-not $rs.Content.ContainsKey($cn)) { continue }
        $c = $rs.Content[$cn]
        foreach ($rx in $c.Regexes) {
            if ($rx.IsMatch($text)) { $out.Add(@{ Rule=$cn; Sev=$c.Sev }); break }
        }
    }
    return @($out.ToArray())
}

# Reduce a set of @{Rule;Sev} findings to the single highest-severity finding (for
# the marker) and a combined rule label. Returns $null when empty.
function Resolve-AuditFindings($findings) {
    $findings = @($findings)
    if ($findings.Count -eq 0) { return $null }
    $best = $findings[0]; $bestRank = Get-AuditRank $best.Sev
    foreach ($f in $findings) { $rk = Get-AuditRank $f.Sev; if ($rk -gt $bestRank) { $best = $f; $bestRank = $rk } }
    $rules = @($findings | ForEach-Object { $_.Rule } | Select-Object -Unique)
    return @{ Sev=$best.Sev; Rule=$best.Rule; Rank=$bestRank; AllRules=($rules -join ', '); Count=$findings.Count }
}

# ── ENGINE STATE ──────────────────────────────────────────────────────────────
# Content-scan size cap. Automatic modes (location/full) scan larger files than
# the 0.5 MB interactive preview cap; passive mode reuses the preview cap (see the
# caller). Files of readable text type above the active cap are surfaced under the
# synthetic oversize rule instead of being scanned.
$script:AuditCap = 2097152   # 2 MB for automatic audits

$script:AuditState   = 'idle'   # idle | passive | running | paused | done | cancelled
$script:AuditMode    = ''       # passive | location | full
$script:AuditScope   = ''       # human-readable description of what's being audited
$script:AuditDirty   = $false   # set when flags/findings/state change (drives redraw)

# User setting (toggled from the audit menu; persists across runs, NOT reset by
# Reset-AuditEngine): when on, a listable archive is expanded via the treebrowser and
# every internal entry is audited; when off, the archive is classified as a plain
# file (name/path/content only), with no internal structure pulled.
$script:AuditWalkArchives = $true

# User setting (toggled from the audit menu; persists, NOT reset by Reset-AuditEngine):
# when on, files routed by a relay rule are downloaded and scanned with content regexes
# (Tier 2). When off, the audit is Tier-1 only — name/extension/path metadata checks
# with NO file content fetched.
$script:AuditTier2 = $true

# Marker map read by the base row renderers: key -> highest raw severity. Synchronized
# only so a stale read during a write can't throw; written on the main thread.
$script:AuditFlags   = [hashtable]::Synchronized(@{})

# Findings (main-thread): the ordered list plus a key->object index for dedupe/merge.
$script:AuditFindings    = [Collections.Generic.List[object]]::new()
$script:AuditFindingIdx  = @{}
$script:AuditSeen        = New-Object 'System.Collections.Generic.HashSet[string]'  # keys already enqueued
$script:AuditDecided     = New-Object 'System.Collections.Generic.HashSet[string]'  # keys fully scanned (drives the passive * / ? glyph)

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
#   MaxConcurrent  - number of parallel workers, 1..5 (w cycles in the view)
# Defaults to a moderate pace (3 workers, 150 ms) so an automatic audit makes steady
# progress out of the box; the user dials it up or down from the audit view.
$script:AuditThrottle = @{ MaxConcurrent = 3; MinIntervalMs = 150 }
$script:AuditLastLaunch = [DateTime]::MinValue
$script:AuditMaxWorkers = 5   # ceiling for the w-key cycle (and the runspace pool)

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
        if ($size -lt 0 -and $storageUri) {
            try {
                $info = Invoke-RestMethod -Uri $storageUri -Headers $headers -ErrorAction Stop
                if ($info.PSObject.Properties['size'])         { $size     = [int64]$info.size }
                if ($info.PSObject.Properties['lastModified']) { $modified = "$($info.lastModified)" }
            } catch {
                $we = Get-WkError $_
                if ($we.Code -eq 429 -or $we.Code -eq 503) { $alert.Message = "Server rate-limited an audit request (HTTP $($we.Code))."; $alert.At = [DateTime]::UtcNow }
                $cache[$key] = [PSCustomObject]@{ Ok=$false; Size=-1; Modified=''; Text=$null; TooBig=$false; Error=$we.Message }
                return
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
    } else {
        $f = [PSCustomObject]@{
            Key=$key; Name=$rec.Name; Repo=$rec.Repo; Path=$rec.Path; Uri=$rec.Uri; Url=$rec.Url
            Size=$(if ($size -ge 0) { $size } elseif ($rec.KnownSize -ge 0) { [long]$rec.KnownSize } else { [long]-1 })
            Modified=$(if ($modified) { $modified } elseif ($rec.KnownModified) { [string]$rec.KnownModified } else { '' })
            FileType=(Get-Ext $rec.Name)
            Sev=$resolved.Sev; Rank=$resolved.Rank; Rule=$resolved.Rule; AllRules=$resolved.AllRules
            # Oversize text findings are excluded by default; so is anything matching the
            # active exclude filter (e.g. '*.xml'). Manual [x]/[i] still override per row.
            Included=(($resolved.Rule -ne $script:AuditOversizeRule) -and -not (Test-AuditExcluded ([string]$rec.Name)))
            InArchive=[bool]$rec.IsArchiveEntry; ArchiveName=$rec.ArchiveName
        }
        $script:AuditFindings.Add($f)
        $script:AuditFindingIdx[$key] = $f
    }
    # Marker = highest raw severity seen for this key.
    $cur = if ($script:AuditFlags.ContainsKey($key)) { $script:AuditFlags[$key] } else { '' }
    if ((Get-AuditRank $resolved.Sev) -ge (Get-AuditRank $cur)) { $script:AuditFlags[$key] = $f.Sev }
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
    if ($info -and $info.PSObject.Properties['lastModified'] -and "$($info.lastModified)" -ne '') { $kmod = "$($info.lastModified)" }
    return @{
        Key=$url; Name=(Get-NodeName $n); Repo=$(if ($n.PSObject.Properties['repoKey']) { "$($n.repoKey)" } else { '' })
        Path=(Get-NodeInternalPath $n); Uri=''; Url=$url; KnownSize=$known; KnownModified=$kmod
        IsArchiveEntry=$true; ArchiveName=$arcName
        IsArchive=$false   # nested sub-archives can't be listed (treated as plain files)
    }
}

# ── ENQUEUE ───────────────────────────────────────────────────────────────────
# Classify a work record's metadata immediately (no I/O); record any Tier-1 finding
# now and, when content rules apply, queue it for a background content fetch. Returns
# nothing; updates state/metrics. Deduped by key via $AuditSeen.
function Add-AuditRecord($rec) {
    if (-not $rec.Key -or $script:AuditSeen.Contains($rec.Key)) { return }
    [void]$script:AuditSeen.Add($rec.Key)
    $m = Test-AuditMeta $rec.Name $rec.Path
    if ($m.Discard) { [void]$script:AuditDecided.Add($rec.Key); return }
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
        $script:AuditDone++
        [void]$script:AuditDecided.Add($rec.Key)
    }
    if ($expand) { Add-AuditArchiveJob $rec }
}

# Queue an archive-expansion job: a treebrowser POST (built up front so the worker
# just sends it) whose result is flattened into per-entry work. Deduped by a
# distinct "ARC|<uri>" key so it can't collide with the archive file's own record.
function Add-AuditArchiveJob($rec) {
    $akey = "ARC|$($rec.Uri)"
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
    [void]$script:AuditDecided.Add($key)
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
    [void]$script:AuditDecided.Add($key)
    if ($null -eq $res) { return }
    if ($res.Ok -and $res.Text) {
        $cf = Test-AuditContent $res.Text $rec.ContentRules
        if (@($cf).Count -gt 0) {
            Add-AuditFinding $rec (Resolve-AuditFindings $cf) $res.Size $res.Modified
            $script:AuditBytes += [long]$res.Text.Length
            return
        }
        $script:AuditBytes += [long]$res.Text.Length
    }
    # No content hit. If it's a readable text file skipped only for size, and it has
    # no other finding, surface it under the synthetic oversize rule (default-excluded).
    if ($res.Ok -and $res.TooBig -and $rec.Previewable -and -not $script:AuditFindingIdx.ContainsKey($key)) {
        Add-AuditFinding $rec @{ Sev='blue'; Rank=1; Rule=$script:AuditOversizeRule; AllRules=$script:AuditOversizeRule; Count=1 } $res.Size $res.Modified
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
            $script:AuditPool = [RunspaceFactory]::CreateRunspacePool(1, 10)
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
        Step-AuditEntries
        Dispatch-AuditWork
    }
    Update-AuditMetrics
    if ($script:AuditState -eq 'running' -and $script:AuditQueue.Count -eq 0 -and
        $script:AuditJobs.Count -eq 0 -and $script:AuditPendingNodes.Count -eq 0 -and
        -not (Test-AuditWalkActive)) {
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
    $script:AuditSeen = New-Object 'System.Collections.Generic.HashSet[string]'
    $script:AuditDecided = New-Object 'System.Collections.Generic.HashSet[string]'
    $script:AuditMetaTried = New-Object 'System.Collections.Generic.HashSet[string]'
    $script:AuditExcludes = @()
    $script:AuditFlags.Clear()
    $script:AuditSortCount = -1; $script:AuditSortDirty = $true
    $script:AuditEnq = 0; $script:AuditDone = 0; $script:AuditLaunched = 0; $script:AuditBytes = 0L
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
    return @($script:RepoMap.Keys)
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

# Called each frame by the base results loop while passive auditing: enqueue the
# current page (nearest-first), pump, and report whether the view should redraw.
function Invoke-AuditPassiveTick($pageItems, [int]$selRow) {
    if ($script:AuditState -ne 'passive') { return $false }
    Add-AuditWork (Get-AuditNearOrder $pageItems $selRow)
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
    }
    Invoke-AuditPump
    $d = $script:AuditDirty; $script:AuditDirty = $false
    return $d
}

# One-column status glyph for a file key, used by the base row renderers:
#   coloured '!'  a finding (severity colour, remapped)
#   grey '?'      passive mode: not yet scanned (or still in flight)
#   grey '*'      passive mode: scanned, nothing found
#   ''            not auditing this view
# The '?'/'*' progress glyphs appear only while a PASSIVE audit is running, so it's
# obvious the engine is working through the current view; after a one-shot
# location/full audit only the '!' findings mark the rows.
function Get-AuditMarker([string]$key) {
    if (-not $key) { return '' }
    if ($script:AuditFlags.ContainsKey($key)) {
        $col = Get-AuditColor $script:AuditFlags[$key]
        return "${col}!${R}"   # $col/$R empty on a non-VT host -> plain '!'
    }
    if ($script:AuditState -eq 'passive') {
        $g = if ($script:AuditDecided.Contains($key)) { '*' } else { '?' }
        return "${DM}$g${R}"
    }
    return ''
}

# ── FINDINGS SORTING ──────────────────────────────────────────────────────────
# Sorted view of the findings: included first / excluded last, then highest severity,
# then repo/path/name. Re-sort only when the count changed OR an exclusion toggled,
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
            Sort-Object @{ Expression = { -not $_.Included } },
                        @{ Expression = { $_.Rank }; Descending = $true },
                        @{ Expression = { $_.Repo } }, @{ Expression = { $_.Path } },
                        @{ Expression = { $_.Name } })
        $script:AuditSortCount = $script:AuditFindings.Count
        $script:AuditSortAt    = [DateTime]::UtcNow
        $script:AuditSortDirty = $false
    }
    return $script:AuditSorted
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
    # Fixed-width rate values so the line doesn't jitter as the numbers change.
    $qps = '{0,6:0.0}' -f [double]$script:AuditRate.QPS
    $fps = '{0,6:0.0}' -f [double]$script:AuditRate.FPS
    $bps = ((Format-Size $script:AuditRate.BPS) + '/s').PadLeft(11)
    $rate = "${DM}$qps req/s  $fps files/s  $bps${R}"
    $l1 = "  ${DM}Audit:${R} $(Trunc $script:AuditScope ([Math]::Max(8,$w-40)))   $st   $prog"
    $l2 = "  $rate   $thr"
    return @($l1, $l2)
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

    if ((Test-Visited $f.Key) -or (Test-Downloaded ([string]$f.Url))) {
        $L.Add("${DM}Downloaded - content cleared from memory.${R}")
        $L.Add("${DM}Press [d] to download again.${R}")
        return $L.ToArray()
    }
    $url   = [string]$f.Url
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
function Save-AuditFinding($f) {
    try {
        if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
    } catch { return "${RD}${BD}Download failed:${R} cannot create ${CY}$OutDir${R}" }
    $dest = Join-Path $OutDir $f.Name
    $old = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'
    try {
        Invoke-WebRequest -Uri $f.Url -Headers (Get-AuthHeaders) -OutFile $dest -ErrorAction Stop
        $len = -1; try { $len = (Get-Item $dest).Length } catch { }
        Write-DownloadLog $OutDir $f.Name $f.Repo $f.Path $len $f.Modified $f.Url $f.Sev $f.AllRules
        Mark-Downloaded $f.Key $f.Url
        $sz = if ($len -ge 0) { ' (' + (Format-Size $len) + ')' } else { '' }
        return "${BD}Saved${R} to ${CY}$dest${R}$sz"
    } catch {
        try { if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Force } } catch { }
        return "${RD}${BD}Download failed:${R} $(Get-HttpErrorDetail $_)"
    } finally { $ProgressPreference = $old }
}

# Confirm + download all INCLUDED findings, warning with count + total size first.
function Save-AuditIncluded {
    $inc = @(Get-AuditSortedFindings | Where-Object { $_.Included -and -not (Test-Visited $_.Key) })
    $total = $inc.Count
    if ($total -eq 0) { Show-Popup @('Nothing to download.', '', 'press any key'); [void](Read-Key); return }
    $bytes = 0L; $haveAll = $true
    foreach ($f in $inc) { if ($f.Size -ge 0) { $bytes += [long]$f.Size } else { $haveAll = $false } }
    $szStr = if ($haveAll) { Format-Size $bytes } else { "$(Format-Size $bytes)+ (some sizes unknown)" }
    $ok = Confirm-Prompt @(
        "${BD}Download $total flagged file$(if ($total -ne 1){'s'})?${R}",
        "Total size: ${CY}$szStr${R}",
        "Into: ${CY}$OutDir${R}",
        "${DM}Each file and its download URL is logged to download-log.csv there.${R}")
    if (-not $ok) { return }
    $done = 0; $fail = 0; $i = 0
    foreach ($f in $inc) {
        $i++
        Show-Popup @("Downloading $i / $total", $f.Name)
        $res = Save-AuditFinding $f
        if ($res -like '*Download failed*') { $fail++ } else { $done++ }
    }
    Show-Popup @("Done.  Saved $done, failed $fail.", "Into $OutDir", '', 'press any key')
    [void](Read-Key)
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

# Re-apply the current exclude set across every finding: matches are excluded, the
# rest are left as-is (so manual [x] toggles on non-matching rows are preserved).
function Update-AuditExclusions {
    foreach ($f in $script:AuditFindings) {
        if (Test-AuditExcluded ([string]$f.Name)) { $f.Included = $false }
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
    if (-not $url -or (Test-Downloaded $url)) { return $null }
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
        $order = [Collections.Generic.List[int]]::new(); $order.Add($selRow)
        $max = [Math]::Max($selRow, $items.Count - 1 - $selRow)
        for ($d = 1; $d -le $max; $d++) {
            if ($selRow + $d -lt $items.Count) { $order.Add($selRow + $d) }
            if ($selRow - $d -ge 0)            { $order.Add($selRow - $d) }
        }
        foreach ($idx in $order) {
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
    $notice = if ($script:AuditState -eq 'paused') {
        @{ Message = "${YL}Paused - set delay with ${LB}+/-${RB} (0-5000ms) and workers with ${LB}w${RB} (1-5), then ${LB}p${RB} to start.${R}"; At = [DateTime]::UtcNow }
    } else { @{ Message = ''; At = [DateTime]::MinValue } }
    $pendingKey = $null

    while ($true) {
        $active = ($script:AuditState -eq 'running' -or $script:AuditState -eq 'paused')
        $list   = @(Get-AuditSortedFindings)
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
        $gap   = [Math]::Max(0, $w - $title.Length)
        $L.Add("${HB}${BD}${MG}${title}${R}${HB}$(' ' * $gap)${R}")
        $L.Add("$DM$(HR $w)$R")
        foreach ($sl in (Get-AuditStatusLines $w)) { $L.Add($sl) }
        if ($notice.Message -and ([DateTime]::UtcNow - $notice.At).TotalSeconds -lt 8) {
            $L.Add("  $(Trunc $notice.Message ($w - 4))")
        }

        # Column geometry.
        $rightW = if ($preview) { [Math]::Max(28, [int]($w * 0.42)) } else { 0 }
        $colW   = if ($preview) { $w - $rightW - 3 } else { $w }
        $numW = 4; $sevW = 4; $typeW = 5; $sizeW = 9; $modW = 10
        # Preview keeps the compact set (# Sev Name Type Size Modified Rule) since the
        # right pane carries repo/path/etc.; the full table adds the same detail columns
        # the regular search view shows (Repo / RType / PType / Path). The matched-rule
        # column is always shown; Name (and Path, when shown) absorb the remaining width.
        $repoW = 0; $rtypeW = 0; $ptypeW = 0; $pathW = 0
        if ($preview) {
            $ruleW = [Math]::Min(16, [Math]::Max(8, [int]($colW * 0.20)))
            $fixed = $numW + $sevW + $typeW + $sizeW + $modW + $ruleW + 14
            $nameW = [Math]::Max(10, $colW - $fixed)
        } else {
            $ruleW  = [Math]::Min(26, [Math]::Max(12, [int]($colW * 0.22)))
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
        $bodyH = [Math]::Max(4, (Get-Height) - $L.Count - 3)
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
            $msg = if ($active) { 'Scanning... findings will appear here.' } else { 'No findings.' }
            $leftLines.Add("  ${DM}$msg${R}")
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
                $modd = Format-AuditModified ([string]$f.Modified)
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
                    if ($pathW -gt 0) { $cells += "${DM}$(Clip ([string]$f.Path) $pathW)${R}" }
                }
                $mark = if ($excluded) { "${DM}x${R} " } elseif ($downloaded) { "${DM}.${R} " } elseif ($sels) { "${BD}${YL}>${R} " } else { '  ' }
                $line = "$mark$($cells -join ' ')"
                if ($sels) { $line = Highlight-Row $line $colW }
                $leftLines.Add($line)
            }
        }

        if (-not $preview) {
            foreach ($ll in $leftLines) {
                if ($ll -eq $script:HeaderRuleTag) { $L.Add("  ${DM}$(HR ($w - 2))${R}") } else { $L.Add($ll) }
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
            $nav.Add("${BD}${LB}d${RB}${R}${DM} download${R}")
            $nav.Add("${BD}${LB}x${RB}${R}${DM} $(if ($cur -and $cur.Included) { 'exclude' } else { 'include' })${R}")
            $nav.Add("${BD}${LB}a${RB}${R}${DM} download all${R}")
            $nav.Add("${BD}${LB}f${RB}${R}${DM} filter$(if (@($script:AuditExcludes).Count -gt 0) { " ($(@($script:AuditExcludes).Count))" })${R}")
            $nav.Add("${BD}${LB}i${RB}${R}${DM} include all${R}")
            $nav.Add("${BD}${LB}v${RB}${R}${DM} $(if ($preview) { 'preview off' } else { 'preview on' })${R}")
            if ($preview -and $cur) {
                $pst = Get-AuditPreviewability ([string]$cur.Name) ([string]$cur.Url) ([long]$cur.Size)
                if ($pst -eq 'large-gated')     { $nav.Add("${BD}${LB}y${RB}${R}${DM} preview large${R}") }
                elseif ($pst -eq 'force-gated') { $nav.Add("${BD}${LB}y${RB}${R}${DM} force preview${R}") }
            }
            if ($preview -and $script:PvScrollMax -gt 0) { $nav.Add("${BD}${LB}Shift+$([char]0x2191)$([char]0x2193)${RB}${R}${DM} scroll${R}") }
        }
        if ($active) {
            $nav.Add("${BD}${LB}p${RB}${R}${DM} $(if ($script:AuditState -eq 'paused') { 'resume' } else { 'pause' })${R}")
            $nav.Add("${BD}${LB}c${RB}${R}${DM} cancel${R}")
            $nav.Add("${BD}${LB}+/-${RB}${R}${DM} delay $($script:AuditThrottle.MinIntervalMs)ms${R}")
            $nav.Add("${BD}${LB}w${RB}${R}${DM} workers $($script:AuditThrottle.MaxConcurrent)${R}")
        }
        $nav.Add("${BD}${LB}q${RB}${R}${DM} back${R}")
        $L.Add((Join-Justified $nav.ToArray() $w))
        Show-Frame $L.ToArray()

        # Input: poll while the engine is active OR while metadata/preview fetches are
        # still in flight, so the Modified column and preview badges/pane fill in live;
        # otherwise block on a keypress.
        $busy = $active -or ($script:PfQueued.Count -gt 0) -or ($script:PvQueued.Count -gt 0)
        if ($pendingKey) { $key = $pendingKey; $pendingKey = $null }
        elseif ($busy -and $script:CanRawKey) {
            $key = Read-KeyTimeout 150
            if ($null -eq $key) {
                if ($active) { Invoke-AuditPump }
                Receive-Prefetch; Receive-PreviewPrefetch; Receive-PreviewLookahead
                $script:AuditDirty = $false; continue
            }
        } else { $key = Read-Key }

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
            '^v$' {
                if ($preview) { $mode = 'results'; Stop-AuditPreviewWarm } else { $mode = 'results-preview' }
                $script:AuditPvKey = ''; $lastWarmKey = ''
            }
            '^(x| )$' {
                if ($cur) {
                    $cur.Included = (-not $cur.Included); $script:AuditSortDirty = $true
                    # Excluding drops the row to the back; advance to the next row so the
                    # cursor doesn't follow the excluded item down there.
                    if (-not $cur.Included) { $sel = [Math]::Min($sel + 1, [Math]::Max(0, $total - 1)) }
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
            '^(d|enter|o)$' {
                if ($cur) {
                    Show-Popup @('Downloading', $cur.Name)
                    $notice = @{ Message = (Save-AuditFinding $cur); At = [DateTime]::UtcNow }
                    $script:AuditPvKey = ''
                }
            }
            '^y$' {
                # Opt the selected file into a large/force preview, but only when it's
                # actually gated (and thus within the 5 MB ceiling); re-warm so the
                # content is fetched and the badge/pane update.
                if ($preview -and $cur) {
                    $st = Get-AuditPreviewability ([string]$cur.Name) ([string]$cur.Url) ([long]$cur.Size)
                    if ($st -eq 'large-gated' -or $st -eq 'force-gated') {
                        [void]$script:PreviewOK.Add([string]$cur.Url)
                        $script:AuditPvKey = ''; $lastWarmKey = ''
                    }
                }
            }
            '^a$' { Save-AuditIncluded }
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
            '^w$'      { $script:AuditThrottle.MaxConcurrent = ($script:AuditThrottle.MaxConcurrent % $script:AuditMaxWorkers) + 1 }
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
        $tierLine  = if ($script:AuditTier2) { 't  Analysis: Tier 1 + 2 (metadata + file content)' }
                     else                    { 't  Analysis: Tier 1 only (metadata: name / ext / path)' }
        Show-Popup @(
            'Audit mode  (credential / secret discovery)',
            '',
            $passiveLine,
            "2  Location  - $($ctx.LocationLabel)",
            '3  Full      - scan the entire Artifactory instance',
            '',
            $tierLine,
            '   (Tier 1 only = no file contents downloaded or scanned)',
            "w  Walk through listable archives: $walkState",
            '   (off = scan archives as plain files, no internal expansion)',
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

# Sentinel so the base files can detect that audit is loaded (see StartTui.ps1).
function Invoke-Audit { }

