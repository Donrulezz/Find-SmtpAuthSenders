<#PSScriptInfo

.VERSION 1.0.0

.GUID cef00cb4-ccd6-44f5-95b4-bcd9a9a96a72

.AUTHOR mailpassed.com

.COMPANYNAME mailpassed.com

.COPYRIGHT (c) 2026 mailpassed.com. MIT License.

.TAGS SMTP SMTPAUTH ExchangeOnline Exchange Microsoft365 Office365 BasicAuth OAuth Printer ScanToEmail Report

.LICENSEURI https://github.com/Donrulezz/Find-SmtpAuthSenders/blob/main/LICENSE

.PROJECTURI https://mailpassed.com/m365-smtp/find-smtp-auth-senders

.ICONURI

.EXTERNALMODULEDEPENDENCIES ExchangeOnlineManagement, Microsoft.Graph.Authentication

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES
1.0.0 (25 Oct 2026): first release. Settings, 180-day usage report, sign-in IPs and the admin center CSV, with a verdict per account.

#>

<#
.SYNOPSIS
    Finds every account, printer, scanner and app that sends mail through Microsoft 365 SMTP AUTH,
    before Microsoft turns Basic authentication for SMTP AUTH off by default (end of December 2026).

.DESCRIPTION
    READ-ONLY: this script changes nothing in your tenant. It combines up to four sources:

      1. SMTP AUTH settings (always): the tenant setting (Get-TransportConfig) and every mailbox
         (Get-EXOCASMailbox). An empty mailbox value means "use the tenant setting".
      2. -IncludeUsageReport: the Microsoft 365 email app usage report (Microsoft Graph
         getEmailAppUsageUserDetail, last 180 days) - which users sent with an "SMTP App".
         Needs the Reports.Read.All permission and a role such as Reports Reader.
      3. -IncludeSignInLogs: Entra ID sign-in logs with client app "Authenticated SMTP" - user,
         IP address (helps you find the physical device) and last time seen. Needs AuditLog.Read.All
         and Entra ID P1 or P2.
      4. -AdminCenterCsv: the CSV you export from Exchange admin center > Reports > Mail flow >
         SMTP AUTH clients report. It is the only source that shows Basic auth (TlsAuthLogin)
         versus OAuth (XOAUTH2).

    It writes SmtpAuthSenders-<date>.csv and SmtpAuthSenders-<date>.html with a verdict per account.

.EXAMPLE
    .\Find-SmtpAuthSenders.ps1
    Settings only: who is allowed to use SMTP AUTH.

.EXAMPLE
    .\Find-SmtpAuthSenders.ps1 -IncludeUsageReport -IncludeSignInLogs -AdminCenterCsv .\smtpauth.csv
    Everything: settings, 180 days of usage, sign-in IPs and Basic-vs-OAuth from the admin center export.

.NOTES
    Version 1.0, 25 Oct 2026. Free to use and share (MIT license).
    Requires: ExchangeOnlineManagement module (Install-Module ExchangeOnlineManagement).
    For -IncludeUsageReport / -IncludeSignInLogs also: Microsoft.Graph.Authentication module.
    Step-by-step fixes per device (relay connector, Direct Send, OAuth): https://mailpassed.com/m365-smtp
#>
[CmdletBinding()]
param(
    [switch]$IncludeUsageReport,
    [switch]$IncludeSignInLogs,
    [string]$AdminCenterCsv,
    [ValidateRange(1, 30)][int]$SignInDays = 30,
    [string]$OutputFolder = (Get-Location).Path,
    [switch]$SkipConnect
)

$FixUrl = 'https://mailpassed.com/m365-smtp'

function Get-NormalizedAddress([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    return $Value.Trim().ToLowerInvariant()
}

function Get-EffectiveSmtpAuth($MailboxValue, $TenantDisabled) {
    # SmtpClientAuthenticationDisabled: $true = blocked, $false = allowed, $null = use the tenant setting.
    if ($null -eq $MailboxValue -or "$MailboxValue" -eq '') {
        if ($TenantDisabled) { return [pscustomobject]@{ Allowed = $false; Source = 'tenant' } }
        return [pscustomobject]@{ Allowed = $true; Source = 'tenant' }
    }
    $blocked = ("$MailboxValue" -eq 'True')
    return [pscustomobject]@{ Allowed = (-not $blocked); Source = 'mailbox' }
}

function Find-CsvColumn($Headers, [string[]]$Patterns) {
    foreach ($p in $Patterns) {
        $hit = $Headers | Where-Object { $_ -match $p } | Select-Object -First 1
        if ($hit) { return $hit }
    }
    return $null
}

function ConvertFrom-UsageReport($Rows) {
    # Graph usage CSV: "User Principal Name" plus one column per app, including "SMTP App".
    $result = @{}
    if (-not $Rows) { return $result }
    $headers = $Rows[0].PSObject.Properties.Name
    $upnCol = Find-CsvColumn $headers @('^User Principal Name$', 'Principal')
    $smtpCol = Find-CsvColumn $headers @('^SMTP App$', '^SMTP')
    if (-not $upnCol -or -not $smtpCol) {
        Write-Warning "Usage report columns not recognised (found: $($headers -join ', '))."
        return $result
    }
    $concealed = 0
    foreach ($r in $Rows) {
        $v = "$($r.$smtpCol)".Trim()
        if ($v -eq '' -or $v -match '^(No|False|0)$') { continue }
        $upn = Get-NormalizedAddress $r.$upnCol
        if (-not $upn) { continue }
        if ($upn -notmatch '@') { $concealed++ }
        $result[$upn] = $true
    }
    if ($concealed -gt 0) {
        Write-Warning ("$concealed users in the usage report have hidden names. To see them: Microsoft 365 admin center > Settings > " +
            "Org settings > Reports > untick 'Display concealed user, group, and site names in all reports', then run again.")
    }
    return $result
}

function ConvertFrom-SignIns($Events) {
    $result = @{}
    foreach ($e in $Events) {
        $upn = Get-NormalizedAddress $e.userPrincipalName
        if (-not $upn) { continue }
        if (-not $result.ContainsKey($upn)) {
            $result[$upn] = [pscustomobject]@{ Count = 0; Ips = New-Object System.Collections.Generic.List[string]; Last = $null; Failures = 0 }
        }
        $s = $result[$upn]
        $s.Count++
        if ($e.ipAddress -and -not $s.Ips.Contains([string]$e.ipAddress)) { $s.Ips.Add([string]$e.ipAddress) }
        $when = $null
        if ($e.createdDateTime) { $when = [datetime]$e.createdDateTime }
        if ($when -and ($null -eq $s.Last -or $when -gt $s.Last)) { $s.Last = $when }
        if ($e.status -and $e.status.errorCode -and [int]$e.status.errorCode -ne 0) { $s.Failures++ }
    }
    return $result
}

function ConvertFrom-AdminCenterCsv($Rows) {
    # Exchange admin center SMTP AUTH clients report export. Column names vary by export, so detect them.
    $result = @{}
    if (-not $Rows) { return $result }
    $headers = $Rows[0].PSObject.Properties.Name
    $senderCol = Find-CsvColumn $headers @('sender', 'user', 'address', 'mail')
    $protoCol = Find-CsvColumn $headers @('protocol', 'auth', 'method')
    $countCol = Find-CsvColumn $headers @('message', 'count', 'volume')
    if (-not $senderCol -or -not $protoCol) {
        Write-Warning "Admin center CSV columns not recognised (found: $($headers -join ', ')). Skipping it."
        return $result
    }
    Write-Verbose "Admin center CSV: sender='$senderCol' protocol='$protoCol' count='$countCol'"
    foreach ($r in $Rows) {
        $addr = Get-NormalizedAddress $r.$senderCol
        if (-not $addr) { continue }
        if (-not $result.ContainsKey($addr)) { $result[$addr] = [pscustomobject]@{ Basic = $false; OAuth = $false; Messages = 0 } }
        $p = "$($r.$protoCol)"
        if ($p -match 'AuthLogin|Basic|LOGIN|PLAIN') { $result[$addr].Basic = $true }
        if ($p -match 'XOAUTH2|OAuth') { $result[$addr].OAuth = $true }
        if ($countCol) { $n = 0; if ([int]::TryParse("$($r.$countCol)", [ref]$n)) { $result[$addr].Messages += $n } }
    }
    return $result
}

function Get-Verdict($Row) {
    if ($Row.AdminCenterBasic) { return 'BREAKS end of Dec 2026: sends with Basic auth (admin center report)' }
    if ($Row.SignInCount -gt 0 -and -not $Row.AdminCenterOAuth) { return 'CHECK: sends with SMTP AUTH (sign-in logs). Basic auth will stop end of Dec 2026' }
    if ($Row.UsedSmtpApp -and -not $Row.AdminCenterOAuth) { return 'CHECK: used an SMTP app in the last 180 days. Basic auth will stop end of Dec 2026' }
    if ($Row.AdminCenterOAuth) { return 'OK: OAuth' }
    if ($Row.SmtpAuthAllowed -eq $true) { return 'Allowed but no use seen: you can switch SMTP AUTH off for this mailbox' }
    if ($Row.SmtpAuthAllowed -eq $false) { return 'OK: SMTP AUTH off' }
    return 'Not a mailbox in this tenant: check the sender'
}

function Merge-SmtpAuthFindings($TenantDisabled, $Mailboxes, $Usage, $SignIns, $AdminCenter) {
    # $Mailboxes: objects with UserPrincipalName, PrimarySmtpAddress, RecipientTypeDetails, SmtpClientAuthenticationDisabled.
    $rows = @{}
    $alias = @{}   # any known address -> row key
    foreach ($m in $Mailboxes) {
        $key = Get-NormalizedAddress $m.UserPrincipalName
        if (-not $key) { $key = Get-NormalizedAddress $m.PrimarySmtpAddress }
        if (-not $key) { continue }
        $eff = Get-EffectiveSmtpAuth $m.SmtpClientAuthenticationDisabled $TenantDisabled
        $rows[$key] = [pscustomobject]@{
            Account = $key; PrimarySmtpAddress = Get-NormalizedAddress $m.PrimarySmtpAddress; Type = "$($m.RecipientTypeDetails)"
            SmtpAuthAllowed = $eff.Allowed; SettingFrom = $eff.Source; UsedSmtpApp = $false
            SignInCount = 0; SignInIps = ''; LastSignIn = $null; AdminCenterBasic = $false; AdminCenterOAuth = $false; Messages = 0; Verdict = ''
        }
        $alias[$key] = $key
        $p = Get-NormalizedAddress $m.PrimarySmtpAddress
        if ($p) { $alias[$p] = $key }
    }
    $getRow = {
        param($addr)
        if ($alias.ContainsKey($addr)) { return $rows[$alias[$addr]] }
        $rows[$addr] = [pscustomobject]@{
            Account = $addr; PrimarySmtpAddress = ''; Type = 'not found as a mailbox'; SmtpAuthAllowed = $null; SettingFrom = ''
            UsedSmtpApp = $false; SignInCount = 0; SignInIps = ''; LastSignIn = $null; AdminCenterBasic = $false; AdminCenterOAuth = $false; Messages = 0; Verdict = ''
        }
        $alias[$addr] = $addr
        return $rows[$addr]
    }
    if ($Usage) { foreach ($u in $Usage.Keys) { (& $getRow $u).UsedSmtpApp = $true } }
    if ($SignIns) {
        foreach ($k in $SignIns.Keys) {
            $r = & $getRow $k; $s = $SignIns[$k]
            $r.SignInCount = $s.Count; $r.SignInIps = ($s.Ips -join ' '); $r.LastSignIn = $s.Last
        }
    }
    if ($AdminCenter) {
        foreach ($k in $AdminCenter.Keys) {
            $r = & $getRow $k; $a = $AdminCenter[$k]
            $r.AdminCenterBasic = $a.Basic; $r.AdminCenterOAuth = $a.OAuth; $r.Messages = $a.Messages
        }
    }
    foreach ($r in $rows.Values) { $r.Verdict = Get-Verdict $r }
    $order = @{ 'BREAKS' = 0; 'CHECK:' = 1; 'Not a ' = 2; 'Allowe' = 3; 'OK: OA' = 4; 'OK: SM' = 5 }
    return $rows.Values | Sort-Object @{ Expression = { $order[$_.Verdict.Substring(0, 6)] } }, Account
}

function ConvertTo-HtmlReport($Rows, $TenantDisabled, $Sources) {
    $enc = { param($t) [System.Net.WebUtility]::HtmlEncode("$t") }
    $breaks = @($Rows | Where-Object { $_.Verdict -like 'BREAKS*' -or $_.Verdict -like 'CHECK*' }).Count
    $allowed = @($Rows | Where-Object { $_.SmtpAuthAllowed -eq $true }).Count
    $tenant = 'allowed'
    if ($TenantDisabled) { $tenant = 'off' }
    $yesNo = { param($v) if ($null -eq $v) { 'n/a' } elseif ($v) { 'Yes' } else { 'No' } }
    $trs = foreach ($r in $Rows) {
        $allowedText = & $yesNo $r.SmtpAuthAllowed
        if ($r.SettingFrom) { $allowedText += " ($($r.SettingFrom))" }
        $cls = 'ok'
        if ($r.Verdict -like 'BREAKS*') { $cls = 'bad' } elseif ($r.Verdict -like 'CHECK*' -or $r.Verdict -like 'Not a*') { $cls = 'warn' }
        $last = ''
        if ($r.LastSignIn) { $last = $r.LastSignIn.ToString('yyyy-MM-dd') }
        "<tr class='$cls'><td>$(& $enc $r.Account)</td><td>$(& $enc $r.Type)</td><td>$(& $enc $allowedText)</td>" +
        "<td>$(& $yesNo $r.UsedSmtpApp)</td><td>$(& $enc $r.SignInCount) $(& $enc $r.SignInIps) $last</td><td>$(& $enc $r.Messages)</td><td>$(& $enc $r.Verdict)</td></tr>"
    }
    $date = (Get-Date).ToString('d MMM yyyy')
    return @"
<!doctype html><html><head><meta charset="utf-8"><title>SMTP AUTH senders - $date</title><style>
body{font-family:Segoe UI,Arial,sans-serif;margin:28px;color:#0f172a;font-size:14px}table{border-collapse:collapse;width:100%}
td,th{border:1px solid #e2e8f0;padding:6px 8px;text-align:left;vertical-align:top}th{background:#f1f5f9}
tr.bad td{background:#fef2f2}tr.warn td{background:#fffbeb}.muted{color:#64748b}</style></head><body>
<h1>Microsoft 365 SMTP AUTH senders</h1>
<p class="muted">$date &middot; sources: $(& $enc ($Sources -join ', ')) &middot; read-only scan</p>
<p><b>$breaks</b> account(s) need action before Microsoft turns Basic authentication for SMTP AUTH off by default at the end of December 2026.
<b>$allowed</b> account(s) are allowed to use SMTP AUTH. Tenant-wide SMTP AUTH: <b>$tenant</b>.</p>
<p>How to move each printer, scanner or app (SMTP relay connector, Direct Send or OAuth): <a href="$FixUrl">$FixUrl</a></p>
<table><tr><th>Account</th><th>Type</th><th>SMTP AUTH allowed</th><th>SMTP app (180 days)</th><th>Sign-ins / IPs / last</th><th>Messages</th><th>Verdict</th></tr>
$($trs -join "`n")
</table></body></html>
"@
}

function Invoke-Main {
    $ErrorActionPreference = 'Stop'
    $sources = New-Object System.Collections.Generic.List[string]
    if (-not $SkipConnect) {
        if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
            throw 'Install the ExchangeOnlineManagement module first: Install-Module ExchangeOnlineManagement -Scope CurrentUser'
        }
        Import-Module ExchangeOnlineManagement
        Connect-ExchangeOnline -ShowBanner:$false
    }
    Write-Host 'Reading SMTP AUTH settings...'
    $tenantDisabled = [bool](Get-TransportConfig).SmtpClientAuthenticationDisabled
    # UserPrincipalName, PrimarySmtpAddress and RecipientTypeDetails are in the default (Minimum) property set.
    $mbx = Get-EXOMailbox -ResultSize Unlimited | Select-Object UserPrincipalName, PrimarySmtpAddress, RecipientTypeDetails
    $cas = @{}
    Get-EXOCASMailbox -ResultSize Unlimited -Properties SmtpClientAuthenticationDisabled | ForEach-Object {
        $cas[(Get-NormalizedAddress $_.PrimarySmtpAddress)] = $_.SmtpClientAuthenticationDisabled
    }
    foreach ($m in $mbx) {
        $m | Add-Member -NotePropertyName SmtpClientAuthenticationDisabled -NotePropertyValue $cas[(Get-NormalizedAddress $m.PrimarySmtpAddress)] -Force
    }
    $sources.Add("settings ($(@($mbx).Count) mailboxes)")

    $usage = $null; $signIns = $null; $admin = $null
    if ($IncludeUsageReport -or $IncludeSignInLogs) {
        if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
            throw 'Install the Microsoft Graph module first: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
        }
        Import-Module Microsoft.Graph.Authentication
        $scopes = @()
        if ($IncludeUsageReport) { $scopes += 'Reports.Read.All' }
        if ($IncludeSignInLogs) { $scopes += 'AuditLog.Read.All' }
        if (-not $SkipConnect) { Connect-MgGraph -Scopes $scopes -NoWelcome }
    }
    if ($IncludeUsageReport) {
        Write-Host 'Reading the 180-day email app usage report...'
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("emailappusage-" + [guid]::NewGuid().ToString('N') + '.csv')
        Invoke-MgGraphRequest -Method GET -Uri "v1.0/reports/getEmailAppUsageUserDetail(period='D180')" -OutputFilePath $tmp
        $usage = ConvertFrom-UsageReport (Import-Csv $tmp)
        Remove-Item $tmp -ErrorAction SilentlyContinue
        $sources.Add("usage report ($($usage.Count) SMTP app users)")
    }
    if ($IncludeSignInLogs) {
        Write-Host "Reading $SignInDays days of 'Authenticated SMTP' sign-ins..."
        $since = (Get-Date).ToUniversalTime().AddDays(-$SignInDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $uri = 'v1.0/auditLogs/signIns?$filter=' + [uri]::EscapeDataString("clientAppUsed eq 'Authenticated SMTP' and createdDateTime ge $since") + '&$top=999'
        $events = New-Object System.Collections.Generic.List[object]
        while ($uri) {
            $page = Invoke-MgGraphRequest -Method GET -Uri $uri
            foreach ($v in $page.value) { $events.Add([pscustomobject]@{ userPrincipalName = $v.userPrincipalName; ipAddress = $v.ipAddress; createdDateTime = $v.createdDateTime; status = [pscustomobject]@{ errorCode = $v.status.errorCode } }) }
            $uri = $page.'@odata.nextLink'
        }
        $signIns = ConvertFrom-SignIns $events
        $sources.Add("sign-in logs ($($events.Count) events)")
    }
    if ($AdminCenterCsv) {
        $admin = ConvertFrom-AdminCenterCsv (Import-Csv $AdminCenterCsv)
        $sources.Add("admin center report ($($admin.Count) senders)")
    }

    $rows = Merge-SmtpAuthFindings $tenantDisabled $mbx $usage $signIns $admin
    $stamp = (Get-Date).ToString('yyyy-MM-dd')
    $csv = Join-Path $OutputFolder "SmtpAuthSenders-$stamp.csv"
    $html = Join-Path $OutputFolder "SmtpAuthSenders-$stamp.html"
    $rows | Select-Object Account, PrimarySmtpAddress, Type, SmtpAuthAllowed, SettingFrom, UsedSmtpApp, SignInCount, SignInIps, LastSignIn, AdminCenterBasic, AdminCenterOAuth, Messages, Verdict |
        Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
    ConvertTo-HtmlReport $rows $tenantDisabled $sources | Out-File -FilePath $html -Encoding utf8
    $need = @($rows | Where-Object { $_.Verdict -like 'BREAKS*' -or $_.Verdict -like 'CHECK*' }).Count
    Write-Host ''
    Write-Host "$need account(s) need action before end of December 2026. Report: $html"
    Write-Host "Fix guides per device: $FixUrl"
}

# Dot-sourcing (". .\Find-SmtpAuthSenders.ps1") only loads the functions, for testing.
if ($MyInvocation.InvocationName -ne '.') { Invoke-Main }
