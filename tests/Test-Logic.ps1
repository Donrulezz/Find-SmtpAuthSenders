$ErrorActionPreference = 'Stop'
# Offline tests: sample data only, no tenant needed. Run: powershell -File .\tests\Test-Logic.ps1
$script = Join-Path $PSScriptRoot '..\Find-SmtpAuthSenders.ps1'
$errs = $null; $tokens = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($script, [ref]$tokens, [ref]$errs)
if ($errs.Count) { $errs | ForEach-Object { Write-Output "PARSE ERROR: $($_.Message) at line $($_.Extent.StartLineNumber)" }; exit 1 }
Write-Output 'parse ok'
$nonAscii = (Get-Content $script -Raw).ToCharArray() | Where-Object { [int]$_ -gt 127 }
Write-Output "non-ascii chars: $(@($nonAscii).Count)"

. $script
$fail = 0
function Check($name, $cond) { if ($cond) { Write-Output "PASS $name" } else { Write-Output "FAIL $name"; $script:fail++ } }

# Effective setting
Check 'null mailbox + tenant allowed = allowed' ((Get-EffectiveSmtpAuth $null $false).Allowed -eq $true)
Check 'null mailbox + tenant off = blocked' ((Get-EffectiveSmtpAuth $null $true).Allowed -eq $false)
Check 'mailbox false overrides tenant off' ((Get-EffectiveSmtpAuth $false $true).Allowed -eq $true)
Check 'mailbox true = blocked' ((Get-EffectiveSmtpAuth $true $false).Allowed -eq $false)

# Usage report (Graph CSV shape)
$usageRows = @(
  [pscustomobject]@{ 'Report Refresh Date' = '2026-10-24'; 'User Principal Name' = 'Scanner@contoso.com'; 'SMTP App' = 'Yes'; 'IMAP4 App' = '' },
  [pscustomobject]@{ 'Report Refresh Date' = '2026-10-24'; 'User Principal Name' = 'alice@contoso.com'; 'SMTP App' = ''; 'IMAP4 App' = 'Yes' },
  [pscustomobject]@{ 'Report Refresh Date' = '2026-10-24'; 'User Principal Name' = 'wp-forms@contoso.com'; 'SMTP App' = 'Yes'; 'IMAP4 App' = '' })
$usage = ConvertFrom-UsageReport $usageRows
Check 'usage finds 2 SMTP users' ($usage.Count -eq 2 -and $usage.ContainsKey('scanner@contoso.com'))

# Sign-ins
$events = @(
  [pscustomobject]@{ userPrincipalName = 'scanner@contoso.com'; ipAddress = '203.0.113.25'; createdDateTime = '2026-10-20T08:00:00Z'; status = [pscustomobject]@{ errorCode = 0 } },
  [pscustomobject]@{ userPrincipalName = 'scanner@contoso.com'; ipAddress = '203.0.113.25'; createdDateTime = '2026-10-22T08:00:00Z'; status = [pscustomobject]@{ errorCode = 0 } },
  [pscustomobject]@{ userPrincipalName = 'erp@contoso.com'; ipAddress = '198.51.100.7'; createdDateTime = '2026-10-21T08:00:00Z'; status = [pscustomobject]@{ errorCode = 50126 } })
$signIns = ConvertFrom-SignIns $events
Check 'sign-ins grouped' ($signIns['scanner@contoso.com'].Count -eq 2 -and $signIns['scanner@contoso.com'].Ips.Count -eq 1)
Check 'sign-in failure counted' ($signIns['erp@contoso.com'].Failures -eq 1)

# Admin center CSV with unknown header names
$csvPath = Join-Path $env:TEMP 'smtpauth-test.csv'
@'
Sender address,Authentication protocol,TLS version,Message count
wp-forms@contoso.com,XOAUTH2,TLS1.2,40
erp@contoso.com,TlsAuthLogin,TLS1.2,120
scanner@contoso.com,TlsAuthLogin,TLS1.0,15
'@ | Set-Content -Path $csvPath -Encoding UTF8
$admin = ConvertFrom-AdminCenterCsv (Import-Csv $csvPath)
Check 'admin csv: erp basic' ($admin['erp@contoso.com'].Basic -eq $true -and $admin['erp@contoso.com'].Messages -eq 120)
Check 'admin csv: wp oauth' ($admin['wp-forms@contoso.com'].OAuth -eq $true -and $admin['wp-forms@contoso.com'].Basic -eq $false)

# Merge
$mbx = @(
  [pscustomobject]@{ UserPrincipalName = 'scanner@contoso.com'; PrimarySmtpAddress = 'scanner@contoso.com'; RecipientTypeDetails = 'SharedMailbox'; SmtpClientAuthenticationDisabled = $false },
  [pscustomobject]@{ UserPrincipalName = 'alice@contoso.onmicrosoft.com'; PrimarySmtpAddress = 'alice@contoso.com'; RecipientTypeDetails = 'UserMailbox'; SmtpClientAuthenticationDisabled = $null },
  [pscustomobject]@{ UserPrincipalName = 'wp-forms@contoso.com'; PrimarySmtpAddress = 'wp-forms@contoso.com'; RecipientTypeDetails = 'UserMailbox'; SmtpClientAuthenticationDisabled = $false },
  [pscustomobject]@{ UserPrincipalName = 'bob@contoso.com'; PrimarySmtpAddress = 'bob@contoso.com'; RecipientTypeDetails = 'UserMailbox'; SmtpClientAuthenticationDisabled = $true })
$rows = @(Merge-SmtpAuthFindings $false $mbx $usage $signIns $admin)
$rows | Format-Table Account, Type, SmtpAuthAllowed, SettingFrom, UsedSmtpApp, SignInCount, AdminCenterBasic, Verdict -AutoSize | Out-String -Width 250 | Write-Output
$by = @{}; foreach ($r in $rows) { $by[$r.Account] = $r }
Check 'scanner BREAKS' ($by['scanner@contoso.com'].Verdict -like 'BREAKS*')
Check 'erp (not a mailbox) BREAKS via admin csv' ($by['erp@contoso.com'].Verdict -like 'BREAKS*' -and $by['erp@contoso.com'].Type -eq 'not found as a mailbox')
Check 'wp-forms OK OAuth' ($by['wp-forms@contoso.com'].Verdict -eq 'OK: OAuth')
Check 'alice inherits tenant allowed, no use' ($by['alice@contoso.onmicrosoft.com'].SettingFrom -eq 'tenant' -and $by['alice@contoso.onmicrosoft.com'].Verdict -like 'Allowed but no use*')
Check 'bob OK off' ($by['bob@contoso.com'].Verdict -eq 'OK: SMTP AUTH off')
Check 'BREAKS sorted first' ($rows[0].Verdict -like 'BREAKS*')
Check 'alias: primary smtp alice@contoso.com maps to UPN row' ((@($rows | Where-Object { $_.Account -eq 'alice@contoso.com' })).Count -eq 0)

# Settings-only run (no optional sources)
$rows2 = @(Merge-SmtpAuthFindings $true $mbx $null $null $null)
Check 'settings-only: 4 rows' ($rows2.Count -eq 4)

# HTML
$html = ConvertTo-HtmlReport $rows $false @('test')
Check 'html has verdict + fix link' ($html -match 'BREAKS end of Dec 2026' -and $html -match 'mailpassed.com/m365-smtp')
$out = Join-Path $env:TEMP 'smtpauth-test.html'; $html | Out-File $out -Encoding utf8
Write-Output "html written: $out"
Write-Output "FAILURES: $fail"
