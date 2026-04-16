<#
.SYNOPSIS
    Extracts and analyzes SSL/TLS certificate expirations for Azure Front Door profiles.

.DESCRIPTION
    This script extracts certificate information from Azure Front Door deployments, supporting
    both Classic and Standard/Premium Front Door profiles. It displays certificate expiration
    dates with status indicators, shows provisioning and validation states, reports classic-to-
    Standard/Premium migration links when present, and can export results to CSV and, when
    the ImportExcel module is installed, to XLSX for reporting.

    The script supports three execution modes:
    - Single Front Door mode: Process a single Front Door by name in the current subscription
    - Subscription mode: Scan all Front Door profiles in the current or specified subscription
    - Tenant mode: Scan all Front Door profiles across all accessible subscriptions in the tenant

    Default Azure Front Door hostnames (*.azurefd.net) are skipped automatically.

.PARAMETER ScanFrontDoor
    The name of a single Front Door profile to inspect. Requires -ResourceGroupName.

.PARAMETER ResourceGroupName
    The name of the resource group containing the Front Door profile.

.PARAMETER ScanSubscription
    Scan all Front Door profiles in the specified subscription (name or ID, or empty for current).

.PARAMETER ScanTenant
    Switch to enable scanning all Front Door profiles across all accessible subscriptions.

.PARAMETER FrontDoorType
    Filter by Front Door type: All (default), StandardPremium, or Classic.

.PARAMETER ExportCsvPath
    Optional path to export results as CSV. When ImportExcel is installed and ExportXlsxPath
    is not specified, a companion XLSX is also written.

.PARAMETER ExportXlsxPath
    Optional path to export results as XLSX (requires ImportExcel).

.PARAMETER GridView
    Display results in an interactive GridView window.

.PARAMETER WarningDays
    Days before expiration to show warning indicators (default 30).

.PARAMETER ThrottleLimit
    Parallelism for ARM API calls (auto-calculated based on CPU count).

.PARAMETER TlsThrottleLimit
    Parallelism for TLS certificate checks (auto-calculated, higher for network-bound ops).

.PARAMETER TlsTimeoutMs
    Timeout in milliseconds for TLS certificate fetch operations (default 5000).

.PARAMETER RestRetryCount
    Maximum attempts for transient Azure REST API failures (default 3).

.PARAMETER TlsRetryCount
    Maximum attempts for transient live TLS probe failures (default 2).

.PARAMETER RetryBaseDelayMs
    Base delay in milliseconds for exponential retry backoff (default 500).

.EXAMPLE
    .\get-frontdoor-certs.ps1 -ScanFrontDoor "my-fd" -ResourceGroupName "my-rg"

.EXAMPLE
    .\get-frontdoor-certs.ps1 -ScanSubscription "Production"

.EXAMPLE
    .\get-frontdoor-certs.ps1 -ScanTenant -ExportCsvPath "C:\Reports\all-certs.csv"

.LINK
    https://github.com/formicalab/AFDCerts
#>

#Requires -PSEdition Core
using module Az.Accounts

[CmdletBinding(DefaultParameterSetName = 'SingleFrontDoor')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'SingleFrontDoor')]
    [string]$ScanFrontDoor,

    [Parameter(Mandatory = $true, ParameterSetName = 'SingleFrontDoor')]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true, ParameterSetName = 'ScanSubscription')]
    [AllowEmptyString()]
    [string]$ScanSubscription,

    [Parameter(Mandatory = $true, ParameterSetName = 'ScanTenant')]
    [switch]$ScanTenant,

    [Parameter(ParameterSetName = 'ScanSubscription')]
    [Parameter(ParameterSetName = 'ScanTenant')]
    [ValidateSet('All', 'StandardPremium', 'Classic')]
    [string]$FrontDoorType = 'All',

    [string]$ExportCsvPath,
    [string]$ExportXlsxPath,
    [switch]$GridView,

    [int]$WarningDays = 30,

    [ValidateRange(1, 64)]
    [int]$ThrottleLimit = [Math]::Min([Math]::Max([System.Environment]::ProcessorCount * 4, 8), 32),

    [ValidateRange(1, 256)]
    [int]$TlsThrottleLimit = [Math]::Min([Math]::Max([System.Environment]::ProcessorCount * 8, 16), 64),

    [ValidateRange(1000, 30000)]
    [int]$TlsTimeoutMs = 5000,

    [ValidateRange(1, 10)]
    [int]$RestRetryCount = 3,

    [ValidateRange(1, 5)]
    [int]$TlsRetryCount = 2,

    [ValidateRange(100, 5000)]
    [int]$RetryBaseDelayMs = 500
)

Set-StrictMode -Version 1
$ErrorActionPreference = 'Stop'

$script:ApiVersion = '2025-04-15'
$script:ClassicApiVersion = '2021-06-01'

# Resolve process-wide proxy once; use IsBypassed for a robust "no proxy" check.
$script:ProxyUri = $null
$proxyTestUri = [Uri]"https://management.azure.com"
$systemProxy = [System.Net.WebRequest]::GetSystemWebProxy()
if ($systemProxy -and -not $systemProxy.IsBypassed($proxyTestUri)) {
    $detectedProxy = $systemProxy.GetProxy($proxyTestUri)
    if ($detectedProxy -and $detectedProxy.Host -ne $proxyTestUri.Host) {
        $script:ProxyUri = $detectedProxy
    }
}
if ($script:ProxyUri) {
    Write-Host "Proxy detected: $($script:ProxyUri)" -ForegroundColor Cyan
    Write-Host "  Classic Front Door TLS probes will use HTTP CONNECT tunnel" -ForegroundColor Gray
} else {
    Write-Host "No proxy detected - using direct connections" -ForegroundColor Gray
}

#region Shared helpers (usable in main scope and runspaces via dot-source)

# Keep helper bodies in a single here-string so ForEach-Object -Parallel runspaces
# can dot-source them without duplicating ~700 lines.
$script:HelperSource = @'
function Get-HttpStatusCodeFromException {
    param([AllowNull()][System.Exception]$Exception)
    if (-not $Exception) { return $null }
    $cur = $Exception
    while ($cur) {
        foreach ($p in 'StatusCode', 'Response') {
            $prop = $cur.PSObject.Properties[$p]
            if ($prop) {
                try {
                    if ($p -eq 'StatusCode' -and $null -ne $prop.Value) { return [int]$prop.Value }
                    if ($p -eq 'Response' -and $prop.Value -and $prop.Value.StatusCode) { return [int]$prop.Value.StatusCode }
                } catch { }
            }
        }
        if (-not $cur.InnerException -or $cur.InnerException -eq $cur) { break }
        $cur = $cur.InnerException
    }
    return $null
}

function Get-ExceptionMessageSummary {
    param([AllowNull()][System.Exception]$Exception, [string]$PrefixMessage)
    $parts = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($PrefixMessage)) { $parts.Add($PrefixMessage) }
    $cur = $Exception
    while ($cur) {
        $m = [string]$cur.Message
        if (-not [string]::IsNullOrWhiteSpace($m) -and -not $parts.Contains($m)) { $parts.Add($m) }
        if (-not $cur.InnerException -or $cur.InnerException -eq $cur) { break }
        $cur = $cur.InnerException
    }
    if ($parts.Count -eq 0) { return $null }
    return ($parts -join ' ')
}

function Test-IsTransientRestFailure {
    param([AllowNull()][System.Exception]$Exception)
    if (-not $Exception) { return $false }
    $code = Get-HttpStatusCodeFromException -Exception $Exception
    if ($null -ne $code) { return $code -in 408, 409, 429, 500, 502, 503, 504 }
    $msg = Get-ExceptionMessageSummary -Exception $Exception
    return $msg -match 'timed out|timeout|temporar|throttl|too many requests|connection.+(reset|aborted|closed)|remote party closed|EOF|unexpected end'
}

function Test-IsTransientTlsFailure {
    param([AllowNull()][System.Exception]$Exception, [string]$FailureMessage)
    $msg = Get-ExceptionMessageSummary -Exception $Exception -PrefixMessage $FailureMessage
    if ([string]::IsNullOrWhiteSpace($msg)) { return $false }
    return $msg -match 'timed out|timeout|temporar|connection.+(reset|aborted|closed)|remote party closed|EOF|unexpected end|network.+unreachable|host.+unreachable|Proxy CONNECT failed: HTTP/\d\.\d (429|502|503|504)'
}

function Get-RetryDelayMilliseconds {
    param([int]$Attempt, [int]$BaseDelayMs)
    return [int][Math]::Min([Math]::Round($BaseDelayMs * [Math]::Pow(2, [Math]::Max($Attempt - 1, 0))), 10000)
}

function Invoke-WithRetry {
    param(
        [Parameter(Mandatory)][scriptblock]$Action,
        [Parameter(Mandatory)][ValidateSet('Rest','Tls')][string]$Category,
        [Parameter(Mandatory)][int]$MaxAttempts,
        [Parameter(Mandatory)][int]$BaseDelayMs
    )
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try { return & $Action }
        catch {
            $ex = $_.Exception
            $transient = if ($Category -eq 'Rest') {
                Test-IsTransientRestFailure -Exception $ex
            } else {
                Test-IsTransientTlsFailure -Exception $ex -FailureMessage $ex.Message
            }
            if (-not $transient -or $attempt -ge $MaxAttempts) { throw }
            Start-Sleep -Milliseconds (Get-RetryDelayMilliseconds -Attempt $attempt -BaseDelayMs $BaseDelayMs)
        }
    }
}

function Test-IsDefaultAzureFrontDoorHostname {
    param([string]$HostName)
    if ([string]::IsNullOrWhiteSpace($HostName)) { return $false }
    return $HostName.EndsWith('.azurefd.net', [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-CertificateFromDomain {
    param(
        [Parameter(Mandatory)][string]$DomainName,
        [Uri]$ProxyUri,
        [Parameter(Mandatory)][int]$TimeoutMs
    )
    $tcp = $null; $ssl = $null; $net = $null; $reader = $null; $writer = $null
    try {
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $tcp.SendTimeout = $TimeoutMs
        $tcp.ReceiveTimeout = $TimeoutMs
        if ($ProxyUri) {
            $tcp.Connect($ProxyUri.Host, $ProxyUri.Port)
            $net = $tcp.GetStream()
            $writer = [System.IO.StreamWriter]::new($net, [System.Text.Encoding]::ASCII)
            $writer.AutoFlush = $true
            $reader = [System.IO.StreamReader]::new($net, [System.Text.Encoding]::ASCII)
            $writer.WriteLine("CONNECT ${DomainName}:443 HTTP/1.1")
            $writer.WriteLine("Host: ${DomainName}:443")
            $writer.WriteLine("")
            $response = $reader.ReadLine()
            if ($response -notmatch '^HTTP/\d\.\d 200') { throw "Proxy CONNECT failed: $response" }
            while ($true) { $line = $reader.ReadLine(); if ([string]::IsNullOrEmpty($line)) { break } }
            $ssl = [System.Net.Security.SslStream]::new($net, $false, { param($s,$c,$ch,$e) return $true })
        } else {
            $tcp.Connect($DomainName, 443)
            $ssl = [System.Net.Security.SslStream]::new($tcp.GetStream(), $false, { param($s,$c,$ch,$e) return $true })
        }
        $ssl.AuthenticateAsClient($DomainName)
        $cert = $ssl.RemoteCertificate
        if ($cert) { return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cert) }
        return $null
    }
    finally {
        if ($writer) { $writer.Dispose() }
        if ($reader) { $reader.Dispose() }
        if ($ssl) { $ssl.Dispose() }
        if ($tcp) { $tcp.Dispose() }
    }
}

function Get-IssuerDetails {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$IssuerString,
        [string]$IssuingCAName
    )
    $issuer = $IssuerString
    if (-not $issuer -and $Certificate) { $issuer = $Certificate.Issuer }
    $ca = $IssuingCAName
    if (-not $ca -and $Certificate) {
        try { $ca = $Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $true) } catch { $ca = $null }
    }
    if (-not $ca -and $issuer) {
        if ($issuer -match '(^|,\s*)CN=([^,]+)') { $ca = $matches[2].Trim() }
        elseif ($issuer -match '(^|,\s*)O=([^,]+)') { $ca = $matches[2].Trim() }
        else { $ca = $issuer }
    }
    return @{ Issuer = $issuer; IssuingCA = $ca }
}

function Get-CertificateDisplayName {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$DistinguishedName
    )
    $name = $null
    if ($Certificate) {
        try { $name = $Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) } catch { $name = $null }
        if (-not $DistinguishedName) { $DistinguishedName = $Certificate.Subject }
    }
    if (-not $name -and $DistinguishedName) {
        if ($DistinguishedName -match '(^|,\s*)CN=([^,]+)') { $name = $matches[2].Trim() }
        elseif ($DistinguishedName -match '(^|,\s*)O=([^,]+)') { $name = $matches[2].Trim() }
        else { $name = $DistinguishedName }
    }
    return $name
}

function Get-ChainStatusSummary {
    param([System.Security.Cryptography.X509Certificates.X509Chain]$Chain)
    if (-not $Chain) { return $null }
    $statuses = @(
        $Chain.ChainStatus |
            Where-Object { $_.Status -ne [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NoError } |
            ForEach-Object { [string]$_.Status } |
            Select-Object -Unique
    )
    if (-not $statuses -or $statuses.Count -eq 0) { return 'Valid' }
    return ($statuses -join ',')
}

function Get-CertificateChainDetails {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$IssuerString,
        [string]$IssuingCAName
    )
    if (-not $Certificate) {
        return @{
            Subject = $null; Issuer = $IssuerString; IssuingCA = $IssuingCAName
            ServerCertificateCount = $null; IntermediateCA = $null; RootCA = $null
            ChainStatus = $null; DigiCertIssued = $null
        }
    }
    $issuerDetails = Get-IssuerDetails -Certificate $Certificate -IssuerString $IssuerString -IssuingCAName $IssuingCAName
    $count = 1; $inter = $null; $root = $null; $status = $null; $digi = $false
    $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
        $null = $chain.Build($Certificate)
        $elements = @($chain.ChainElements)
        if ($elements.Count -gt 0) {
            $count = $elements.Count
            $status = Get-ChainStatusSummary -Chain $chain
            $last = $elements[$elements.Count - 1].Certificate
            $selfSigned = $last -and ($last.Subject -eq $last.Issuer)
            $intCerts = @()
            if ($elements.Count -ge 3 -or $selfSigned) {
                $root = Get-CertificateDisplayName -Certificate $last
                if ($elements.Count -gt 2) {
                    $intCerts = @($elements[1..($elements.Count - 2)] | ForEach-Object { $_.Certificate })
                }
            } elseif ($elements.Count -gt 1) {
                $intCerts = @($elements[1..($elements.Count - 1)] | ForEach-Object { $_.Certificate })
            }
            $names = @(
                $intCerts | ForEach-Object { Get-CertificateDisplayName -Certificate $_ } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
            )
            if ($names.Count -gt 0) { $inter = $names -join ' | ' }
        }
    } finally { $chain.Dispose() }
    if ($issuerDetails.Issuer -match '\bDigiCert\b' -or $issuerDetails.IssuingCA -match '\bDigiCert\b' -or $inter -match '\bDigiCert\b' -or $root -match '\bDigiCert\b') {
        $digi = $true
    }
    return @{
        Subject = $Certificate.Subject; Issuer = $issuerDetails.Issuer; IssuingCA = $issuerDetails.IssuingCA
        ServerCertificateCount = $count; IntermediateCA = $inter; RootCA = $root
        ChainStatus = $status; DigiCertIssued = $digi
    }
}

function Get-CertificateStatusSummary {
    param(
        [string]$ChainStatus, [string]$ExpirationStatus,
        [string[]]$StatusItems, [bool]$HasExpirationDate
    )
    $parts = [System.Collections.Generic.List[string]]::new()
    $unique = @($StatusItems | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
    $unique | ForEach-Object { $parts.Add("CheckError: $_") }
    if (-not [string]::IsNullOrWhiteSpace($ChainStatus) -and $ChainStatus -ne 'Valid') { $parts.Add("Chain: $ChainStatus") }
    switch ($ExpirationStatus) {
        'EXPIRED' { $parts.Add('Expiration: EXPIRED') }
        'WARNING' { $parts.Add('Expiration: WARNING') }
    }
    if ($parts.Count -gt 0) { return ($parts -join ' | ') }
    if ($ChainStatus -eq 'Valid' -or ($HasExpirationDate -and $ExpirationStatus -eq 'OK')) { return 'OK' }
    return 'NoData'
}

function Get-FormattedExpirationDate {
    param([object]$ExpiryDate, [int]$WarningDays)
    if (-not $ExpiryDate) { return @{ Display = $null; Status = 'OK'; Value = $null } }
    try {
        $dt = if ($ExpiryDate -is [DateTime]) { $ExpiryDate } else { [DateTime]::Parse($ExpiryDate) }
        $now = Get-Date
        $days = ($dt - $now).Days
        $status = if ($dt -lt $now) { 'EXPIRED' } elseif ($days -le $WarningDays) { 'WARNING' } else { 'OK' }
        return @{ Display = $dt.ToString(); Status = $status; Value = $dt }
    } catch {
        return @{ Display = $ExpiryDate; Status = 'OK'; Value = $null }
    }
}
'@

# Dot-source helpers into main scope.
. ([ScriptBlock]::Create($script:HelperSource))

#endregion

#region Authentication and discovery

function ConvertTo-PlainText {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [securestring]) {
        return [System.Net.NetworkCredential]::new('', $Value).Password
    }
    throw "ConvertTo-PlainText: unexpected type [$($Value.GetType().FullName)]."
}

function Get-JwtPayload {
    param([Parameter(Mandatory)][string]$Token)
    $parts = $Token -split '\.'
    if ($parts.Count -lt 2 -or [string]::IsNullOrWhiteSpace($parts[1])) { return $null }
    $seg = $parts[1]
    switch ($seg.Length % 4) { 2 { $seg += '==' } 3 { $seg += '=' } 0 { } default { return $null } }
    try {
        $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($seg.Replace('-','+').Replace('_','/')))
        return $json | ConvertFrom-Json -ErrorAction Stop
    } catch { return $null }
}

function Get-ArmBearerToken {
    $ctx = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $ctx -or -not $ctx.Account) { throw "No Azure PowerShell context found. Run Connect-AzAccount first." }
    $resp = Get-AzAccessToken -ResourceUrl 'https://management.azure.com' -ErrorAction Stop
    $raw = if ($resp.PSObject.Properties['Token']) { $resp.Token } elseif ($resp.PSObject.Properties['AccessToken']) { $resp.AccessToken } else { $null }
    $token = ConvertTo-PlainText -Value $raw
    if ([string]::IsNullOrWhiteSpace($token)) { throw 'Failed to acquire an Azure access token from Az.Accounts.' }
    $payload = Get-JwtPayload -Token $token
    $tenantId = if ($payload -and $payload.PSObject.Properties['tid']) { [string]$payload.tid }
        elseif ($resp.PSObject.Properties['TenantId'] -and $resp.TenantId) { [string]$resp.TenantId }
        elseif ($ctx.Tenant -and $ctx.Tenant.Id) { [string]$ctx.Tenant.Id }
        else { $null }
    $userId = if ($payload -and $payload.PSObject.Properties['upn'] -and $payload.upn) { [string]$payload.upn }
        elseif ($payload -and $payload.PSObject.Properties['unique_name'] -and $payload.unique_name) { [string]$payload.unique_name }
        elseif ($resp.PSObject.Properties['UserId'] -and $resp.UserId) { [string]$resp.UserId }
        elseif ($ctx.Account -and $ctx.Account.Id) { [string]$ctx.Account.Id }
        else { $null }
    return [pscustomobject]@{ Token = $token; TenantId = $tenantId; UserId = $userId }
}

function Get-EnabledSubscriptions {
    $subs = @(Get-AzSubscription -WarningAction SilentlyContinue | Where-Object { $_.State -eq 'Enabled' })
    if (-not $subs) { throw 'No enabled Azure subscriptions are accessible for the current identity.' }
    return @($subs | Sort-Object Name, Id)
}

function Invoke-ResourceGraphQueryAllPages {
    param(
        [Parameter(Mandatory)][hashtable]$Headers,
        [Parameter(Mandatory)][string[]]$SubscriptionIds,
        [Parameter(Mandatory)][string]$Query
    )
    $results = [System.Collections.Generic.List[object]]::new()
    $skipToken = $null
    $uri = 'https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01'
    do {
        $options = @{ resultFormat = 'objectArray'; '$top' = 1000 }
        if ($skipToken) { $options['$skipToken'] = $skipToken }
        $body = @{ subscriptions = $SubscriptionIds; query = $Query; options = $options } | ConvertTo-Json -Depth 8
        $resp = Invoke-WithRetry -Action {
            Invoke-RestMethod -Method Post -Uri $uri -Headers $Headers -Body $body -ErrorAction Stop
        } -OperationName 'Resource Graph query' -Category Rest -MaxAttempts $RestRetryCount -BaseDelayMs $RetryBaseDelayMs
        foreach ($row in @($resp.data)) { $results.Add($row) }
        $skipToken = $null
        foreach ($name in '$skipToken','skipToken') {
            $p = $resp.PSObject.Properties[$name]
            if ($p -and $p.Value) { $skipToken = [string]$p.Value; break }
        }
    } while ($skipToken)
    return @($results)
}

function Get-ProgressInterval {
    param([Parameter(Mandatory)][int]$TotalCount)
    if ($TotalCount -le 0) { return 1 }
    return [Math]::Max([int][Math]::Ceiling($TotalCount / 20.0), 1)
}

# Invoke-WithRetry at script scope needs OperationName but runspace copy (from HelperSource) does not.
# Override main-scope version here with full signature.
function Invoke-WithRetry {
    param(
        [Parameter(Mandatory)][scriptblock]$Action,
        [Parameter(Mandatory)][string]$OperationName,
        [Parameter(Mandatory)][ValidateSet('Rest','Tls')][string]$Category,
        [Parameter(Mandatory)][int]$MaxAttempts,
        [Parameter(Mandatory)][int]$BaseDelayMs
    )
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try { return & $Action }
        catch {
            $ex = $_.Exception
            $transient = if ($Category -eq 'Rest') {
                Test-IsTransientRestFailure -Exception $ex
            } else {
                Test-IsTransientTlsFailure -Exception $ex -FailureMessage $ex.Message
            }
            if (-not $transient -or $attempt -ge $MaxAttempts) { throw }
            $delay = Get-RetryDelayMilliseconds -Attempt $attempt -BaseDelayMs $BaseDelayMs
            Write-Verbose ("Retrying {0} after transient {1} failure (attempt {2}/{3}, delay={4}ms): {5}" -f $OperationName, $Category, ($attempt + 1), $MaxAttempts, $delay, $ex.Message)
            Start-Sleep -Milliseconds $delay
        }
    }
}

#endregion

#region Resource Graph queries

$script:FrontDoorGraphQuery = @'
resources
| where type in~ ('microsoft.cdn/profiles', 'microsoft.network/frontdoors')
| extend skuName = tostring(sku.name)
| extend ext = todynamic(properties.extendedProperties)
| extend deploymentModel = iff(type =~ 'microsoft.network/frontdoors', 'Classic', 'Standard/Premium')
| extend migrationSourceResourceId = iff(type =~ 'microsoft.cdn/profiles', tostring(ext.MigratedFrom), '')
| extend migrationTargetResourceId = iff(type =~ 'microsoft.network/frontdoors', tostring(ext.MigratedTo), '')
| where type =~ 'microsoft.network/frontdoors' or skuName in~ ('Standard_AzureFrontDoor', 'Premium_AzureFrontDoor')
| project name, resourceGroup, subscriptionId, type, deploymentModel, migrationSourceResourceId, migrationTargetResourceId
| order by subscriptionId, name
'@

function ConvertTo-FrontDoorRecord {
    param([Parameter(Mandatory)]$Row)
    return [PSCustomObject]@{
        Name                      = $Row.name
        ResourceGroupName         = $Row.resourceGroup
        SubscriptionId            = $Row.subscriptionId
        Type                      = if ($Row.type -eq 'microsoft.network/frontdoors') { 'Classic' }
                                    elseif ($Row.PSObject.Properties['deploymentModel'] -and $Row.deploymentModel) { $Row.deploymentModel }
                                    else { 'Standard/Premium' }
        MigrationSourceResourceId = if ([string]::IsNullOrWhiteSpace([string]$Row.migrationSourceResourceId)) { $null } else { [string]$Row.migrationSourceResourceId }
        MigrationTargetResourceId = if ([string]::IsNullOrWhiteSpace([string]$Row.migrationTargetResourceId)) { $null } else { [string]$Row.migrationTargetResourceId }
    }
}

function Get-FrontDoorsViaGraph {
    param(
        [Parameter(Mandatory)][hashtable]$Headers,
        [Parameter(Mandatory)][string[]]$SubscriptionIds,
        [ValidateSet('All','StandardPremium','Classic')][string]$TypeFilter = 'All'
    )
    $rows = Invoke-ResourceGraphQueryAllPages -Headers $Headers -SubscriptionIds $SubscriptionIds -Query $script:FrontDoorGraphQuery
    $all = @($rows | ForEach-Object { ConvertTo-FrontDoorRecord -Row $_ })
    switch ($TypeFilter) {
        'StandardPremium' { return @($all | Where-Object { $_.Type -eq 'Standard/Premium' }) }
        'Classic'         { return @($all | Where-Object { $_.Type -eq 'Classic' }) }
        default           { return $all }
    }
}

#endregion

#region Export helpers

function Get-ResultExportColumns {
    return @(
        'SubscriptionId','SubscriptionName','FrontDoorName','FrontDoorType',
        'MigrationSourceResourceId','MigrationTargetResourceId','EndpointAssociation',
        'Domain','CertificateType','ProvisioningState','ValidationState',
        'Subject','Issuer','IssuingCA','ServerCertificateCount','IntermediateCA','RootCA',
        'ChainStatus','DigiCertIssued','ExpirationDate','KeyVaultName','KeyVaultSecretName'
    )
}

function Get-XlsxExportRecords {
    param([Parameter(Mandatory)][object[]]$Results, [Parameter(Mandatory)][string[]]$Columns)
    $records = foreach ($r in $Results) {
        $rec = [ordered]@{}
        foreach ($c in $Columns) { $rec[$c] = $r.$c }
        $rawProp = $r.PSObject.Properties['ExpirationDateRaw']
        if ($rawProp -and $rawProp.Value) {
            try {
                $rec['ExpirationDate'] = if ($rawProp.Value -is [DateTime]) { $rawProp.Value } else { [DateTime]::Parse($rawProp.Value.ToString()) }
            } catch { $rec['ExpirationDate'] = $r.ExpirationDate }
        }
        [PSCustomObject]$rec
    }
    return @($records)
}

function Get-FrontDoorMigrationDisplayName {
    param([string]$ResourceId)
    if ([string]::IsNullOrWhiteSpace($ResourceId)) { return $null }
    $segs = $ResourceId.TrimEnd('/') -split '/'
    if ($segs.Count -gt 0) { return $segs[-1] }
    return $ResourceId
}

function Initialize-ParentDirectoryPath {
    param([Parameter(Mandatory)][string]$FilePath)
    $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePath)
    $parent = Split-Path -Parent $resolved
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { $null = New-Item -ItemType Directory -Path $parent -Force }
    return $resolved
}

function Resolve-AvailableExportFilePath {
    param([Parameter(Mandatory)][string]$FilePath)
    $resolved = Initialize-ParentDirectoryPath -FilePath $FilePath
    $parent = Split-Path -Parent $resolved
    $name = [System.IO.Path]::GetFileName($resolved)
    $ext = [System.IO.Path]::GetExtension($resolved)
    $base = [System.IO.Path]::GetFileNameWithoutExtension($resolved)
    $lockPath = if ($ext -eq '.xlsx') { Join-Path $parent ("~$" + $name) } else { $null }
    $canWrite = $true
    if (Test-Path -LiteralPath $resolved) {
        $stream = $null
        try { $stream = [System.IO.File]::Open($resolved, 'Open', 'ReadWrite', 'None') }
        catch { $canWrite = $false }
        finally { if ($stream) { $stream.Dispose() } }
    }
    if (($lockPath -and (Test-Path -LiteralPath $lockPath)) -or -not $canWrite) {
        $ts = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
        $cand = Join-Path $parent ("{0}-{1}{2}" -f $base, $ts, $ext)
        $i = 1
        while (Test-Path -LiteralPath $cand) {
            $cand = Join-Path $parent ("{0}-{1}-{2}{3}" -f $base, $ts, $i, $ext); $i++
        }
        return @{ Path = $cand; Redirected = $true }
    }
    return @{ Path = $resolved; Redirected = $false }
}

function Set-XlsxTableStyleInfo {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$TableStyleName)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $zip = [System.IO.Compression.ZipFile]::Open($resolved, [System.IO.Compression.ZipArchiveMode]::Update)
    try {
        foreach ($entry in @($zip.Entries | Where-Object { $_.FullName -like 'xl/tables/table*.xml' })) {
            $reader = [System.IO.StreamReader]::new($entry.Open())
            try { $xml = [System.String]::Copy($reader.ReadToEnd()) } finally { $reader.Dispose() }
            $updated = $xml
            $updated = $updated -replace '(<tableStyleInfo\b[^>]*\bname=")[^"]+(")', ('$1{0}$2' -f $TableStyleName)
            $updated = $updated -replace '(showFirstColumn=")[^"]+(")', '${1}0$2'
            $updated = $updated -replace '(showLastColumn=")[^"]+(")', '${1}0$2'
            $updated = $updated -replace '(showRowStripes=")[^"]+(")', '${1}0$2'
            $updated = $updated -replace '(showColumnStripes=")[^"]+(")', '${1}0$2'
            if ($updated -eq $xml) { continue }
            $path = $entry.FullName
            $entry.Delete()
            $newEntry = $zip.CreateEntry($path)
            $enc = [System.Text.UTF8Encoding]::new($false)
            $writer = [System.IO.StreamWriter]::new($newEntry.Open(), $enc)
            try { $writer.Write($updated) } finally { $writer.Dispose() }
        }
    } finally { $zip.Dispose() }
}

#endregion


#region Custom domain and endpoint lookups (ARM REST)

function Get-StdPremCustomDomains {
    param(
        [Parameter(Mandatory)][hashtable]$Headers,
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$ProfileName
    )
    $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Cdn/profiles/$ProfileName/customDomains?api-version=$script:ApiVersion"
    $resp = Invoke-WithRetry -Action {
        Invoke-RestMethod -Method Get -Uri $uri -Headers $Headers -ErrorAction Stop
    } -OperationName "custom domains lookup for $ProfileName" -Category Rest -MaxAttempts $RestRetryCount -BaseDelayMs $RetryBaseDelayMs
    return @($resp.value)
}

function Get-StdPremSecret {
    param(
        [Parameter(Mandatory)][hashtable]$Headers,
        [Parameter(Mandatory)][string]$SecretId,
        [Parameter(Mandatory)][string]$DomainName
    )
    $uri = "https://management.azure.com$SecretId" + "?api-version=$script:ApiVersion"
    return Invoke-WithRetry -Action {
        Invoke-RestMethod -Method Get -Uri $uri -Headers $Headers -ErrorAction Stop
    } -OperationName "certificate secret lookup for $DomainName" -Category Rest -MaxAttempts $RestRetryCount -BaseDelayMs $RetryBaseDelayMs
}

function Get-StdPremEndpointAssociations {
    param(
        [Parameter(Mandatory)][hashtable]$Headers,
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$ProfileName
    )
    $sets = @{}
    $baseUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Cdn/profiles/$ProfileName"
    $epUri = "$baseUri/afdEndpoints?api-version=$script:ApiVersion"
    $epResp = Invoke-WithRetry -Action {
        Invoke-RestMethod -Method Get -Uri $epUri -Headers $Headers -ErrorAction Stop
    } -OperationName "endpoint lookup for $ProfileName" -Category Rest -MaxAttempts $RestRetryCount -BaseDelayMs $RetryBaseDelayMs
    foreach ($ep in @($epResp.value)) {
        $epName = [string]$ep.name
        if ([string]::IsNullOrWhiteSpace($epName)) { continue }
        $assoc = [string]($ep.properties.hostName ?? $epName)
        if ([string]::IsNullOrWhiteSpace($assoc)) { $assoc = $epName }
        $routesUri = "$baseUri/afdEndpoints/$epName/routes?api-version=$script:ApiVersion"
        try {
            $routesResp = Invoke-WithRetry -Action {
                Invoke-RestMethod -Method Get -Uri $routesUri -Headers $Headers -ErrorAction Stop
            } -OperationName "route lookup for $ProfileName/$epName" -Category Rest -MaxAttempts $RestRetryCount -BaseDelayMs $RetryBaseDelayMs
        } catch { continue }
        foreach ($route in @($routesResp.value)) {
            foreach ($ref in @($route.properties.customDomains)) {
                $id = [string]$ref.id
                if ([string]::IsNullOrWhiteSpace($id)) { continue }
                $key = $id.ToLowerInvariant()
                if (-not $sets.ContainsKey($key)) {
                    $sets[$key] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                }
                $null = $sets[$key].Add($assoc)
            }
        }
    }
    $map = @{}
    foreach ($k in $sets.Keys) { $map[$k] = (@($sets[$k] | Sort-Object) -join ' | ') }
    return $map
}

function Get-ClassicFrontDoor {
    param(
        [Parameter(Mandatory)][hashtable]$Headers,
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$FrontDoorName
    )
    $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Network/frontDoors/$FrontDoorName" + "?api-version=$script:ClassicApiVersion"
    return Invoke-WithRetry -Action {
        Invoke-RestMethod -Method Get -Uri $uri -Headers $Headers -ErrorAction Stop
    } -OperationName "classic FD lookup for $FrontDoorName" -Category Rest -MaxAttempts $RestRetryCount -BaseDelayMs $RetryBaseDelayMs
}

function ConvertTo-ClassicEndpointRecord {
    param([Parameter(Mandatory)]$Endpoint, [Parameter(Mandatory)][PSCustomObject]$FrontDoorInfo, [hashtable]$SubscriptionLookup)
    $hostName = if ([string]::IsNullOrWhiteSpace([string]$Endpoint.properties.hostName)) { [string]$Endpoint.name } else { [string]$Endpoint.properties.hostName }
    if ([string]::IsNullOrWhiteSpace($hostName) -or (Test-IsDefaultAzureFrontDoorHostname -HostName $hostName)) { return $null }
    $cfg = $Endpoint.properties.customHttpsConfiguration
    $certSource = $null; $kvName = $null; $kvSecret = $null
    if ($cfg) {
        if ($cfg.certificateSource) { $certSource = [string]$cfg.certificateSource }
        $vaultCandidates = @(
            $cfg.vault.id, $cfg.vault,
            $cfg.keyVaultCertificateSourceParameters.vault.id, $cfg.keyVaultCertificateSourceParameters.vault,
            $cfg.secretSource.id, $cfg.secretSource
        ) | Where-Object { $_ }
        $vaultId = @($vaultCandidates | Select-Object -First 1)[0]
        if ($vaultId -and ($vaultId -match '/vaults/([^/]+)/')) { $kvName = $Matches[1] }
        $secretCandidates = @(
            $cfg.secretName, $cfg.keyVaultCertificateSourceParameters.secretName, $cfg.secretSource.secretName
        ) | Where-Object { $_ }
        $kvSecret = @($secretCandidates | Select-Object -First 1)[0]
        if (-not $kvSecret -and $vaultId -and ($vaultId -match '/secrets/([^/]+)')) { $kvSecret = $Matches[1] }
    }
    $subName = if ($SubscriptionLookup -and $SubscriptionLookup.ContainsKey($FrontDoorInfo.SubscriptionId)) { $SubscriptionLookup[$FrontDoorInfo.SubscriptionId] } else { $FrontDoorInfo.SubscriptionId }
    return [PSCustomObject]@{
        SubscriptionId            = $FrontDoorInfo.SubscriptionId
        SubscriptionName          = $subName
        FrontDoorName             = $FrontDoorInfo.Name
        MigrationSourceResourceId = $FrontDoorInfo.MigrationSourceResourceId
        MigrationTargetResourceId = $FrontDoorInfo.MigrationTargetResourceId
        EndpointAssociation       = [string]$Endpoint.name
        HostName                  = $hostName
        CertificateSource         = $certSource
        ProvisioningState         = [string]$Endpoint.properties.customHttpsProvisioningState
        KeyVaultName              = $kvName
        KeyVaultSecretName        = $kvSecret
    }
}

#endregion

#region Per-domain processing (shared logic)

# Build a result record for a Standard/Premium domain given the custom-domain object,
# its association lookup, the Front Door context, and helpers for REST/TLS.
function New-StdPremDomainResult {
    param(
        [Parameter(Mandatory)]$Domain,
        [Parameter(Mandatory)][hashtable]$AssociationMap,
        [Parameter(Mandatory)][hashtable]$Headers,
        [Parameter(Mandatory)][PSCustomObject]$FrontDoorInfo,
        [hashtable]$SubscriptionLookup,
        [AllowNull()][Uri]$ProxyUri,
        [Parameter(Mandatory)][int]$TlsTimeoutMs,
        [Parameter(Mandatory)][int]$TlsRetryCount,
        [Parameter(Mandatory)][int]$RestRetryCount,
        [Parameter(Mandatory)][int]$RetryBaseDelayMs,
        [Parameter(Mandatory)][int]$WarningDays,
        [bool]$WriteProgress
    )
    $domainName = $Domain.properties.hostName ?? $Domain.name
    if ([string]::IsNullOrWhiteSpace($domainName) -or (Test-IsDefaultAzureFrontDoorHostname -HostName $domainName)) { return $null }

    $certSource = $null; $provState = $Domain.properties.provisioningState; $valState = $Domain.properties.domainValidationState
    $expiryDate = $null; $subject = $null; $issuer = $null; $issuingCA = $null
    $count = $null; $inter = $null; $root = $null; $chainStatus = $null; $digi = $null
    $errors = [System.Collections.Generic.List[string]]::new()
    $kvName = $null; $kvSecret = $null
    $assoc = 'Unassociated'
    $id = [string]$Domain.id
    if (-not [string]::IsNullOrWhiteSpace($id)) {
        $key = $id.ToLowerInvariant()
        if ($AssociationMap.ContainsKey($key) -and -not [string]::IsNullOrWhiteSpace([string]$AssociationMap[$key])) {
            $assoc = [string]$AssociationMap[$key]
        }
    }

    if ($Domain.properties.tlsSettings) {
        $tls = $Domain.properties.tlsSettings
        if ($tls.certificateType) {
            $certSource = switch ($tls.certificateType) {
                'ManagedCertificate' { 'Managed' }
                'CustomerCertificate' { 'KeyVault' }
                default { $tls.certificateType }
            }
        }
        if ($tls.secret -and $tls.secret.id) {
            try {
                if ($WriteProgress) { Write-Host "    Fetching certificate details for: $domainName..." -NoNewline }
                $secret = Get-StdPremSecret -Headers $Headers -SecretId $tls.secret.id -DomainName $domainName
                if ($secret.properties -and $secret.properties.parameters) {
                    $p = $secret.properties.parameters
                    if ($p.expirationDate) { $expiryDate = $p.expirationDate }
                    if ($p.subject) { $subject = $p.subject }
                    if ($p.certificateAuthority) { $issuingCA = [string]$p.certificateAuthority }
                    if ($p.issuer) { $issuer = [string]$p.issuer }
                    if ($p.type -eq 'CustomerCertificate' -and $p.secretSource -and $p.secretSource.id) {
                        $kvId = $p.secretSource.id
                        if ($kvId -match '/vaults/([^/]+)/') { $kvName = $matches[1] }
                        if ($kvId -match '/secrets/([^/]+)') { $kvSecret = $matches[1] }
                    }
                    $d = Get-IssuerDetails -IssuerString $issuer -IssuingCAName $issuingCA
                    $issuer = $d.Issuer; $issuingCA = $d.IssuingCA
                }
                if ($WriteProgress) { Write-Host " OK" -ForegroundColor Green }
            } catch {
                $err = Get-ExceptionMessageSummary -Exception $_.Exception
                $null = $errors.Add("SecretLookup: $err")
                if ($WriteProgress) { Write-Host " Failed: $err" -ForegroundColor Yellow }
            }
        }
    }

    try {
        $liveCert = Invoke-WithRetry -Action {
            Get-CertificateFromDomain -DomainName $domainName -ProxyUri $ProxyUri -TimeoutMs $TlsTimeoutMs
        } -OperationName "TLS probe for $domainName" -Category Tls -MaxAttempts $TlsRetryCount -BaseDelayMs $RetryBaseDelayMs
        if ($liveCert) {
            $cd = Get-CertificateChainDetails -Certificate $liveCert -IssuerString $issuer -IssuingCAName $issuingCA
            if (-not $subject) { $subject = $cd.Subject }
            if (-not $expiryDate) { $expiryDate = $liveCert.NotAfter }
            $issuer = $cd.Issuer; $issuingCA = $cd.IssuingCA
            $count = $cd.ServerCertificateCount; $inter = $cd.IntermediateCA; $root = $cd.RootCA
            $chainStatus = $cd.ChainStatus; $digi = $cd.DigiCertIssued
        }
    } catch {
        $err = Get-ExceptionMessageSummary -Exception $_.Exception
        $null = $errors.Add("TLS: $err")
    }

    $expInfo = Get-FormattedExpirationDate -ExpiryDate $expiryDate -WarningDays $WarningDays
    $overall = Get-CertificateStatusSummary -ChainStatus $chainStatus -ExpirationStatus $expInfo.Status -StatusItems @($errors) -HasExpirationDate ($null -ne $expInfo.Value)

    $subName = if ($SubscriptionLookup -and $SubscriptionLookup.ContainsKey($FrontDoorInfo.SubscriptionId)) { $SubscriptionLookup[$FrontDoorInfo.SubscriptionId] } else { $FrontDoorInfo.SubscriptionId }

    return [PSCustomObject]@{
        SubscriptionId            = $FrontDoorInfo.SubscriptionId
        SubscriptionName          = $subName
        FrontDoorName             = $FrontDoorInfo.Name
        FrontDoorType             = 'Standard/Premium'
        MigrationSourceResourceId = $FrontDoorInfo.MigrationSourceResourceId
        MigrationTargetResourceId = $FrontDoorInfo.MigrationTargetResourceId
        EndpointAssociation       = $assoc
        Domain                    = $domainName
        CertificateType           = $certSource
        ProvisioningState         = $provState
        ValidationState           = $valState
        Subject                   = $subject
        Issuer                    = $issuer
        IssuingCA                 = $issuingCA
        ServerCertificateCount    = $count
        IntermediateCA            = $inter
        RootCA                    = $root
        ChainStatus               = $overall
        DigiCertIssued            = $digi
        ExpirationDateRaw         = $expInfo.Value
        ExpirationDate            = $expInfo.Display
        ExpirationStatus          = $expInfo.Status
        KeyVaultName              = $kvName
        KeyVaultSecretName        = $kvSecret
    }
}

function New-ClassicEndpointResult {
    param(
        [Parameter(Mandatory)][PSCustomObject]$EndpointRecord,
        [AllowNull()][Uri]$ProxyUri,
        [Parameter(Mandatory)][int]$TlsTimeoutMs,
        [Parameter(Mandatory)][int]$TlsRetryCount,
        [Parameter(Mandatory)][int]$RetryBaseDelayMs,
        [Parameter(Mandatory)][int]$WarningDays
    )
    $expiryDate = $null; $subject = $null; $issuer = $null; $issuingCA = $null
    $count = $null; $inter = $null; $root = $null; $chainStatus = $null; $digi = $null
    $errors = [System.Collections.Generic.List[string]]::new()

    try {
        $cert = Invoke-WithRetry -Action {
            Get-CertificateFromDomain -DomainName $EndpointRecord.HostName -ProxyUri $ProxyUri -TimeoutMs $TlsTimeoutMs
        } -OperationName "TLS probe for $($EndpointRecord.HostName)" -Category Tls -MaxAttempts $TlsRetryCount -BaseDelayMs $RetryBaseDelayMs
        if ($cert) {
            $cd = Get-CertificateChainDetails -Certificate $cert
            $expiryDate = $cert.NotAfter
            $subject = $cd.Subject; $issuer = $cd.Issuer; $issuingCA = $cd.IssuingCA
            $count = $cd.ServerCertificateCount; $inter = $cd.IntermediateCA; $root = $cd.RootCA
            $chainStatus = $cd.ChainStatus; $digi = $cd.DigiCertIssued
        }
    } catch {
        $err = Get-ExceptionMessageSummary -Exception $_.Exception
        $null = $errors.Add("TLS: $err")
    }

    $expInfo = Get-FormattedExpirationDate -ExpiryDate $expiryDate -WarningDays $WarningDays
    $overall = Get-CertificateStatusSummary -ChainStatus $chainStatus -ExpirationStatus $expInfo.Status -StatusItems @($errors) -HasExpirationDate ($null -ne $expInfo.Value)

    return [PSCustomObject]@{
        SubscriptionId            = $EndpointRecord.SubscriptionId
        SubscriptionName          = $EndpointRecord.SubscriptionName
        FrontDoorName             = $EndpointRecord.FrontDoorName
        FrontDoorType             = 'Classic'
        MigrationSourceResourceId = $EndpointRecord.MigrationSourceResourceId
        MigrationTargetResourceId = $EndpointRecord.MigrationTargetResourceId
        EndpointAssociation       = $EndpointRecord.EndpointAssociation
        Domain                    = $EndpointRecord.HostName
        CertificateType           = $EndpointRecord.CertificateSource
        ProvisioningState         = $EndpointRecord.ProvisioningState
        ValidationState           = $null
        Subject                   = $subject
        Issuer                    = $issuer
        IssuingCA                 = $issuingCA
        ServerCertificateCount    = $count
        IntermediateCA            = $inter
        RootCA                    = $root
        ChainStatus               = $overall
        DigiCertIssued            = $digi
        ExpirationDateRaw         = $expInfo.Value
        ExpirationDate            = $expInfo.Display
        ExpirationStatus          = $expInfo.Status
        KeyVaultName              = $EndpointRecord.KeyVaultName
        KeyVaultSecretName        = $EndpointRecord.KeyVaultSecretName
    }
}

#endregion

#region Sequential Front Door processing (single FD / single subscription)

function Get-StandardPremiumFrontDoorCertificates {
    param(
        [Parameter(Mandatory)][hashtable]$Headers,
        [Parameter(Mandatory)][PSCustomObject]$FrontDoorInfo,
        [hashtable]$SubscriptionLookup,
        [Parameter(Mandatory)][int]$WarningDays
    )
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $fdName = $FrontDoorInfo.Name
    $rgName = $FrontDoorInfo.ResourceGroupName
    $subId = $FrontDoorInfo.SubscriptionId
    Write-Host "  Retrieving custom domains..."
    try {
        $domains = Get-StdPremCustomDomains -Headers $Headers -SubscriptionId $subId -ResourceGroupName $rgName -ProfileName $fdName
    } catch {
        Write-Host "  Failed to query custom domains for ${fdName}: $($_.Exception.Message)" -ForegroundColor Red
        return $results
    }
    if (-not $domains -or $domains.Count -eq 0) {
        Write-Host "  No custom domains found for $fdName" -ForegroundColor Yellow
        return $results
    }
    $eligible = @($domains | Where-Object {
        $h = if ([string]::IsNullOrWhiteSpace([string]$_.properties.hostName)) { [string]$_.name } else { [string]$_.properties.hostName }
        -not (Test-IsDefaultAzureFrontDoorHostname -HostName $h)
    })
    $skipped = @($domains).Count - $eligible.Count
    if ($skipped -gt 0) { Write-Host "  Skipping $skipped default Azure Front Door endpoint(s)." -ForegroundColor Gray }
    if ($eligible.Count -eq 0) {
        Write-Host "  No non-default custom domains found for $fdName" -ForegroundColor Yellow
        return $results
    }
    Write-Host "  Found $($eligible.Count) custom domain(s). Processing..."
    $assocMap = @{}
    try {
        $assocMap = Get-StdPremEndpointAssociations -Headers $Headers -SubscriptionId $subId -ResourceGroupName $rgName -ProfileName $fdName
    } catch {
        $err = Get-ExceptionMessageSummary -Exception $_.Exception
        Write-Host "  Failed to resolve endpoint associations for ${fdName}: $err" -ForegroundColor Yellow
    }

    $restInvoker = $null
    $tlsInvoker = $null
    $log = $null

    foreach ($d in $eligible) {
        $r = New-StdPremDomainResult -Domain $d -AssociationMap $assocMap -Headers $Headers `
            -FrontDoorInfo $FrontDoorInfo -SubscriptionLookup $SubscriptionLookup `
            -ProxyUri $script:ProxyUri -TlsTimeoutMs $TlsTimeoutMs `
            -TlsRetryCount $TlsRetryCount -RestRetryCount $RestRetryCount `
            -RetryBaseDelayMs $RetryBaseDelayMs -WarningDays $WarningDays `
            -WriteProgress $true
        if ($r) { $results.Add($r) }
    }
    return $results
}

function Get-ClassicFrontDoorCertificates {
    param(
        [Parameter(Mandatory)][hashtable]$Headers,
        [Parameter(Mandatory)][PSCustomObject]$FrontDoorInfo,
        [hashtable]$SubscriptionLookup,
        [Parameter(Mandatory)][int]$WarningDays
    )
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    Write-Host "  Retrieving custom domains..."
    try {
        $fd = Get-ClassicFrontDoor -Headers $Headers -SubscriptionId $FrontDoorInfo.SubscriptionId -ResourceGroupName $FrontDoorInfo.ResourceGroupName -FrontDoorName $FrontDoorInfo.Name
    } catch {
        Write-Host "  Failed to retrieve Classic FD: $($_.Exception.Message)" -ForegroundColor Yellow
        return $results
    }
    $endpoints = @($fd.properties.frontendEndpoints)
    $records = @()
    foreach ($ep in $endpoints) {
        $rec = ConvertTo-ClassicEndpointRecord -Endpoint $ep -FrontDoorInfo $FrontDoorInfo -SubscriptionLookup $SubscriptionLookup
        if ($rec) { $records += $rec }
    }
    $skipped = $endpoints.Count - $records.Count
    if ($skipped -gt 0) { Write-Host "  Skipping $skipped default Azure Front Door endpoint(s)." -ForegroundColor Gray }
    if ($records.Count -eq 0) {
        Write-Host "  No non-default custom domains found for $($FrontDoorInfo.Name)" -ForegroundColor Yellow
        return $results
    }
    Write-Host "  Found $($records.Count) custom domain(s). Processing..."
    foreach ($rec in $records) {
        Write-Host "    Fetching certificate for: $($rec.HostName)..." -NoNewline
        $r = New-ClassicEndpointResult -EndpointRecord $rec `
            -ProxyUri $script:ProxyUri -TlsTimeoutMs $TlsTimeoutMs `
            -TlsRetryCount $TlsRetryCount -RetryBaseDelayMs $RetryBaseDelayMs `
            -WarningDays $WarningDays
        if ($r) {
            $results.Add($r)
            if ($r.ChainStatus -eq 'OK') { Write-Host " OK" -ForegroundColor Green }
            else { Write-Host " $($r.ChainStatus)" -ForegroundColor Yellow }
        }
    }
    return $results
}

function Get-FrontDoorCertificatesByInfo {
    param(
        [Parameter(Mandatory)][hashtable]$Headers,
        [Parameter(Mandatory)][PSCustomObject]$FrontDoorInfo,
        [hashtable]$SubscriptionLookup,
        [Parameter(Mandatory)][int]$WarningDays
    )
    if ($FrontDoorInfo.Type -eq 'Classic') {
        return Get-ClassicFrontDoorCertificates -Headers $Headers -FrontDoorInfo $FrontDoorInfo -SubscriptionLookup $SubscriptionLookup -WarningDays $WarningDays
    }
    return Get-StandardPremiumFrontDoorCertificates -Headers $Headers -FrontDoorInfo $FrontDoorInfo -SubscriptionLookup $SubscriptionLookup -WarningDays $WarningDays
}

#endregion

#region Main execution

# Verify Azure login
$context = Get-AzContext
if (-not $context) { throw "Not logged in to Azure. Please run Connect-AzAccount first." }
if ($GridView -and ($ExportCsvPath -or $ExportXlsxPath)) {
    throw "Use either -GridView or export paths (-ExportCsvPath / -ExportXlsxPath), not both."
}

$allResults = [System.Collections.Generic.List[PSCustomObject]]::new()

Write-Host "`n=== Azure Front Door Certificate Checker ===" -ForegroundColor Cyan
Write-Host "Execution Mode: $($PSCmdlet.ParameterSetName)`n" -ForegroundColor Cyan

# Acquire bearer token up front; all modes use ARM REST now (drops Az.FrontDoor).
Write-Host "Acquiring Azure bearer token..." -ForegroundColor Cyan
$tokenInfo = Get-ArmBearerToken
$script:Headers = @{ Authorization = "Bearer $($tokenInfo.Token)"; 'Content-Type' = 'application/json' }
$tokenLabel = @(
    if ($tokenInfo.UserId) { $tokenInfo.UserId }
    if ($tokenInfo.TenantId) { "tenant $($tokenInfo.TenantId)" }
) -join ' | '
if ($tokenLabel) { Write-Host "  Token acquired for: $tokenLabel" -ForegroundColor Green }
else { Write-Host "  Token acquired successfully." -ForegroundColor Green }

if ($PSCmdlet.ParameterSetName -eq 'SingleFrontDoor') {
    $ctx = Get-AzContext
    $subId = $ctx.Subscription.Id
    $subLookup = @{ $subId = $ctx.Subscription.Name }
    Write-Host "Looking for Front Door profile: $ScanFrontDoor in resource group: $ResourceGroupName..." -ForegroundColor Cyan

    $fdInfo = $null
    $rows = Invoke-ResourceGraphQueryAllPages -Headers $script:Headers -SubscriptionIds @($subId) -Query $script:FrontDoorGraphQuery
    foreach ($row in $rows) {
        if ([string]::Equals($row.name, $ScanFrontDoor, [System.StringComparison]::OrdinalIgnoreCase) -and
            [string]::Equals($row.resourceGroup, $ResourceGroupName, [System.StringComparison]::OrdinalIgnoreCase)) {
            $fdInfo = ConvertTo-FrontDoorRecord -Row $row
            break
        }
    }
    if (-not $fdInfo) {
        Write-Host "  Front Door profile '$ScanFrontDoor' not found in subscription (checked both Standard/Premium and Classic)." -ForegroundColor Yellow
    } else {
        Write-Host "  Found $($fdInfo.Type) Front Door: $($fdInfo.Name) in resource group: $($fdInfo.ResourceGroupName)" -ForegroundColor Green
        $res = Get-FrontDoorCertificatesByInfo -Headers $script:Headers -FrontDoorInfo $fdInfo -SubscriptionLookup $subLookup -WarningDays $WarningDays
        $res | ForEach-Object { $allResults.Add($_) }
    }
}
elseif ($PSCmdlet.ParameterSetName -eq 'ScanSubscription') {
    if ($ScanSubscription) {
        Write-Host "Switching to subscription: $ScanSubscription..." -ForegroundColor Cyan
        try { $null = Set-AzContext -Subscription $ScanSubscription -ErrorAction Stop }
        catch { throw "Failed to switch to subscription '$ScanSubscription': $($_.Exception.Message)" }
        $tokenInfo = Get-ArmBearerToken
        $script:Headers = @{ Authorization = "Bearer $($tokenInfo.Token)"; 'Content-Type' = 'application/json' }
    }
    $ctx = Get-AzContext
    $subId = $ctx.Subscription.Id
    $subLookup = @{ $subId = $ctx.Subscription.Name }
    Write-Host "Scanning subscription: $($ctx.Subscription.Name) ($subId)" -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Yellow
    Write-Host "  Discovering Front Door profiles via Resource Graph..." -ForegroundColor Cyan
    if ($FrontDoorType -ne 'All') { Write-Host "    Filtering by type: $FrontDoorType" -ForegroundColor Cyan }
    $fds = Get-FrontDoorsViaGraph -Headers $script:Headers -SubscriptionIds @($subId) -TypeFilter $FrontDoorType
    $stdCount = @($fds | Where-Object { $_.Type -eq 'Standard/Premium' }).Count
    $clsCount = @($fds | Where-Object { $_.Type -eq 'Classic' }).Count
    if ($FrontDoorType -in 'All','StandardPremium') { Write-Host "    Found $stdCount Standard/Premium Front Door(s)" -ForegroundColor Green }
    if ($FrontDoorType -in 'All','Classic')         { Write-Host "    Found $clsCount Classic Front Door(s)" -ForegroundColor Green }
    if ($fds.Count -eq 0) {
        Write-Host "  No Front Door profiles found in this subscription" -ForegroundColor Yellow
    } else {
        Write-Host "  Processing $($fds.Count) Front Door profile(s)...`n" -ForegroundColor Cyan
        foreach ($fd in $fds) {
            $res = Get-FrontDoorCertificatesByInfo -Headers $script:Headers -FrontDoorInfo $fd -SubscriptionLookup $subLookup -WarningDays $WarningDays
            $res | ForEach-Object { $allResults.Add($_) }
        }
    }
}
elseif ($PSCmdlet.ParameterSetName -eq 'ScanTenant') {
    Write-Host "Scanning all Front Door profiles across tenant using Resource Graph..." -ForegroundColor Cyan
    Write-Host "  Parallelism: ThrottleLimit=$ThrottleLimit, TlsThrottleLimit=$TlsThrottleLimit" -ForegroundColor Gray
    Write-Host "`n[1/3] Resolving enabled subscriptions..." -ForegroundColor Cyan
    $subs = Get-EnabledSubscriptions
    $subIds = @($subs | Select-Object -ExpandProperty Id)
    $subLookup = @{}
    foreach ($s in $subs) { $subLookup[$s.Id] = $s.Name }
    Write-Host "  $($subs.Count) enabled subscription(s) accessible." -ForegroundColor Green

    Write-Host "`n[2/3] Discovering Front Door profiles via Resource Graph..." -ForegroundColor Cyan
    $allFDs = Get-FrontDoorsViaGraph -Headers $script:Headers -SubscriptionIds $subIds -TypeFilter $FrontDoorType
    $stdFDs = @($allFDs | Where-Object { $_.Type -eq 'Standard/Premium' })
    $clsFDs = @($allFDs | Where-Object { $_.Type -eq 'Classic' })
    if ($FrontDoorType -in 'All','StandardPremium') { Write-Host "    Found $($stdFDs.Count) Standard/Premium Front Door(s)" -ForegroundColor Green }
    if ($FrontDoorType -in 'All','Classic')         { Write-Host "    Found $($clsFDs.Count) Classic Front Door(s)" -ForegroundColor Green }
    Write-Host "  Total: $($allFDs.Count) Front Door profile(s) found across tenant`n" -ForegroundColor Cyan

    if ($allFDs.Count -eq 0) {
        Write-Host "No Front Door profiles found in the tenant." -ForegroundColor Yellow
    } else {
        Write-Host "[3/3] Processing certificates (parallel=$ThrottleLimit)..." -ForegroundColor Cyan
        $scanStartedAt = Get-Date

        if ($stdFDs.Count -gt 0) {
            Write-Host "  Processing $($stdFDs.Count) Standard/Premium Front Door(s) in parallel..." -ForegroundColor Cyan
            $progressInterval = Get-ProgressInterval -TotalCount $stdFDs.Count
            $processedCount = 0

            $stdFDs | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
                $fd = $_
                $hdrs = $using:Headers
                $apiVer = $using:ApiVersion
                $subLookup = $using:subLookup
                $warnDays = $using:WarningDays
                $scanAt = $using:scanStartedAt
                $proxyUri = $using:ProxyUri
                $tlsTimeoutMs = $using:TlsTimeoutMs
                $restRetryCount = $using:RestRetryCount
                $tlsRetryCount = $using:TlsRetryCount
                $retryBaseDelayMs = $using:RetryBaseDelayMs
                $helperSource = $using:HelperSource
                . ([ScriptBlock]::Create($helperSource))

                try {
                    $baseUri = "https://management.azure.com/subscriptions/$($fd.SubscriptionId)/resourceGroups/$($fd.ResourceGroupName)/providers/Microsoft.Cdn/profiles/$($fd.Name)"
                    $domainsUri = "$baseUri/customDomains?api-version=$apiVer"
                    $domainsResp = Invoke-WithRetry -Action {
                        Invoke-RestMethod -Method Get -Uri $domainsUri -Headers $hdrs -ErrorAction Stop
                    } -Category Rest -MaxAttempts $restRetryCount -BaseDelayMs $retryBaseDelayMs
                    $domains = @($domainsResp.value)

                    $assocSets = @{}
                    try {
                        $epUri = "$baseUri/afdEndpoints?api-version=$apiVer"
                        $epResp = Invoke-WithRetry -Action {
                            Invoke-RestMethod -Method Get -Uri $epUri -Headers $hdrs -ErrorAction Stop
                        } -Category Rest -MaxAttempts $restRetryCount -BaseDelayMs $retryBaseDelayMs
                        foreach ($ep in @($epResp.value)) {
                            $epName = [string]$ep.name
                            if ([string]::IsNullOrWhiteSpace($epName)) { continue }
                            $assoc = [string]($ep.properties.hostName ?? $epName)
                            if ([string]::IsNullOrWhiteSpace($assoc)) { $assoc = $epName }
                            $routesUri = "$baseUri/afdEndpoints/$epName/routes?api-version=$apiVer"
                            try {
                                $rr = Invoke-WithRetry -Action {
                                    Invoke-RestMethod -Method Get -Uri $routesUri -Headers $hdrs -ErrorAction Stop
                                } -Category Rest -MaxAttempts $restRetryCount -BaseDelayMs $retryBaseDelayMs
                            } catch { continue }
                            foreach ($rt in @($rr.value)) {
                                foreach ($ref in @($rt.properties.customDomains)) {
                                    $id = [string]$ref.id
                                    if ([string]::IsNullOrWhiteSpace($id)) { continue }
                                    $key = $id.ToLowerInvariant()
                                    if (-not $assocSets.ContainsKey($key)) {
                                        $assocSets[$key] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                                    }
                                    $null = $assocSets[$key].Add($assoc)
                                }
                            }
                        }
                    } catch { }
                    $assocMap = @{}
                    foreach ($k in $assocSets.Keys) { $assocMap[$k] = (@($assocSets[$k] | Sort-Object) -join ' | ') }

                    $included = 0
                    foreach ($d in $domains) {
                        $domainName = $d.properties.hostName ?? $d.name
                        if (-not [string]::IsNullOrWhiteSpace($domainName) -and (Test-IsDefaultAzureFrontDoorHostname -HostName $domainName)) { continue }
                        $included++

                        $certSource = $null
                        $provState = $d.properties.provisioningState
                        $valState = $d.properties.domainValidationState
                        $expiryDate = $null; $subject = $null; $issuer = $null; $issuingCA = $null
                        $count = $null; $inter = $null; $root = $null; $chainStatus = $null; $digi = $null
                        $errors = [System.Collections.Generic.List[string]]::new()
                        $kvName = $null; $kvSecret = $null
                        $assoc = 'Unassociated'
                        $id = [string]$d.id
                        if (-not [string]::IsNullOrWhiteSpace($id)) {
                            $k = $id.ToLowerInvariant()
                            if ($assocMap.ContainsKey($k) -and -not [string]::IsNullOrWhiteSpace([string]$assocMap[$k])) { $assoc = [string]$assocMap[$k] }
                        }

                        if ($d.properties.tlsSettings) {
                            $tls = $d.properties.tlsSettings
                            $certSource = switch ($tls.certificateType) {
                                'ManagedCertificate' { 'Managed' }
                                'CustomerCertificate' { 'KeyVault' }
                                default { $tls.certificateType }
                            }
                            if ($tls.secret -and $tls.secret.id) {
                                $secretUri = "https://management.azure.com$($tls.secret.id)?api-version=$apiVer"
                                try {
                                    $secret = Invoke-WithRetry -Action {
                                        Invoke-RestMethod -Method Get -Uri $secretUri -Headers $hdrs -ErrorAction Stop
                                    } -Category Rest -MaxAttempts $restRetryCount -BaseDelayMs $retryBaseDelayMs
                                    if ($secret.properties -and $secret.properties.parameters) {
                                        $p = $secret.properties.parameters
                                        if ($p.expirationDate) { $expiryDate = $p.expirationDate }
                                        if ($p.subject) { $subject = $p.subject }
                                        if ($p.certificateAuthority) { $issuingCA = [string]$p.certificateAuthority }
                                        if ($p.issuer) { $issuer = [string]$p.issuer }
                                        if ($p.type -eq 'CustomerCertificate' -and $p.secretSource -and $p.secretSource.id) {
                                            $kvId = $p.secretSource.id
                                            if ($kvId -match '/vaults/([^/]+)/') { $kvName = $Matches[1] }
                                            if ($kvId -match '/secrets/([^/]+)') { $kvSecret = $Matches[1] }
                                        }
                                        $dd = Get-IssuerDetails -IssuerString $issuer -IssuingCAName $issuingCA
                                        $issuer = $dd.Issuer; $issuingCA = $dd.IssuingCA
                                    }
                                } catch {
                                    $err = Get-ExceptionMessageSummary -Exception $_.Exception
                                    $null = $errors.Add("SecretLookup: $err")
                                }
                            }
                        }

                        if ($domainName) {
                            try {
                                $liveCert = Invoke-WithRetry -Action {
                                    Get-CertificateFromDomain -DomainName $domainName -ProxyUri $proxyUri -TimeoutMs $tlsTimeoutMs
                                } -Category Tls -MaxAttempts $tlsRetryCount -BaseDelayMs $retryBaseDelayMs
                                if ($liveCert) {
                                    $cd = Get-CertificateChainDetails -Certificate $liveCert -IssuerString $issuer -IssuingCAName $issuingCA
                                    if (-not $subject) { $subject = $cd.Subject }
                                    if (-not $expiryDate) { $expiryDate = $liveCert.NotAfter }
                                    $issuer = $cd.Issuer; $issuingCA = $cd.IssuingCA
                                    $count = $cd.ServerCertificateCount; $inter = $cd.IntermediateCA; $root = $cd.RootCA
                                    $chainStatus = $cd.ChainStatus; $digi = $cd.DigiCertIssued
                                }
                            } catch {
                                $err = Get-ExceptionMessageSummary -Exception $_.Exception
                                $null = $errors.Add("TLS: $err")
                            }
                        }

                        $expInfo = Get-FormattedExpirationDate -ExpiryDate $expiryDate -WarningDays $warnDays
                        $overall = Get-CertificateStatusSummary -ChainStatus $chainStatus -ExpirationStatus $expInfo.Status -StatusItems @($errors) -HasExpirationDate ($null -ne $expInfo.Value)

                        [PSCustomObject]@{
                            SubscriptionId            = $fd.SubscriptionId
                            SubscriptionName          = $subLookup[$fd.SubscriptionId] ?? $fd.SubscriptionId
                            FrontDoorName             = $fd.Name
                            MigrationSourceResourceId = $fd.MigrationSourceResourceId
                            MigrationTargetResourceId = $fd.MigrationTargetResourceId
                            EndpointAssociation       = $assoc
                            FrontDoorType             = 'Standard/Premium'
                            Domain                    = $domainName
                            CertificateType           = $certSource
                            ProvisioningState         = $provState
                            ValidationState           = $valState
                            Subject                   = $subject
                            Issuer                    = $issuer
                            IssuingCA                 = $issuingCA
                            ServerCertificateCount    = $count
                            IntermediateCA            = $inter
                            RootCA                    = $root
                            ChainStatus               = $overall
                            DigiCertIssued            = $digi
                            ExpirationDateRaw         = $expInfo.Value
                            ExpirationDate            = $expInfo.Display
                            ExpirationStatus          = $expInfo.Status
                            KeyVaultName              = $kvName
                            KeyVaultSecretName        = $kvSecret
                        }
                    }

                    [PSCustomObject]@{ __Progress = $true; FrontDoorName = $fd.Name; DomainCount = $included }
                } catch {
                    [PSCustomObject]@{ __Progress = $true; FrontDoorName = $fd.Name; DomainCount = 0; Error = (Get-ExceptionMessageSummary -Exception $_.Exception) }
                }
            } | ForEach-Object {
                if ($_.PSObject.Properties['__Progress']) {
                    $processedCount++
                    if (($processedCount % $progressInterval -eq 0) -or ($processedCount -eq $stdFDs.Count)) {
                        $errMsg = if ($_.PSObject.Properties['Error'] -and $_.Error) { " (Error: $($_.Error))" } else { "" }
                        Write-Host "    Processed $processedCount/$($stdFDs.Count): $($_.FrontDoorName) -> $($_.DomainCount) domain(s)$errMsg" -ForegroundColor DarkGray
                    }
                } else {
                    $allResults.Add($_)
                }
            }
            Write-Host "    Completed Standard/Premium processing." -ForegroundColor Green
        }

        if ($clsFDs.Count -gt 0) {
            Write-Host "  Processing $($clsFDs.Count) Classic Front Door(s)..." -ForegroundColor Cyan
            $clsEndpoints = [System.Collections.Generic.List[PSCustomObject]]::new()
            $clsProgressInterval = Get-ProgressInterval -TotalCount $clsFDs.Count
            $clsProcessed = 0
            Write-Host "    Enumerating endpoints via ARM REST in parallel (parallel=$ThrottleLimit)..." -ForegroundColor Cyan

            $clsFDs | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
                $fd = $_
                $hdrs = $using:Headers
                $apiVer = $using:ClassicApiVersion
                $subLookup = $using:subLookup
                $restRetryCount = $using:RestRetryCount
                $retryBaseDelayMs = $using:RetryBaseDelayMs
                $helperSource = $using:HelperSource
                . ([ScriptBlock]::Create($helperSource))

                try {
                    $uri = "https://management.azure.com/subscriptions/$($fd.SubscriptionId)/resourceGroups/$($fd.ResourceGroupName)/providers/Microsoft.Network/frontDoors/$($fd.Name)?api-version=$apiVer"
                    $frontDoor = Invoke-WithRetry -Action {
                        Invoke-RestMethod -Method Get -Uri $uri -Headers $hdrs -ErrorAction Stop
                    } -Category Rest -MaxAttempts $restRetryCount -BaseDelayMs $retryBaseDelayMs
                    $count = 0
                    foreach ($ep in @($frontDoor.properties.frontendEndpoints)) {
                        $h = if ([string]::IsNullOrWhiteSpace([string]$ep.properties.hostName)) { [string]$ep.name } else { [string]$ep.properties.hostName }
                        if ([string]::IsNullOrWhiteSpace($h) -or (Test-IsDefaultAzureFrontDoorHostname -HostName $h)) { continue }
                        $cfg = $ep.properties.customHttpsConfiguration
                        $certSource = $null; $kvName = $null; $kvSecret = $null
                        if ($cfg) {
                            if ($cfg.certificateSource) { $certSource = [string]$cfg.certificateSource }
                            $vc = @(
                                $cfg.vault.id, $cfg.vault,
                                $cfg.keyVaultCertificateSourceParameters.vault.id, $cfg.keyVaultCertificateSourceParameters.vault,
                                $cfg.secretSource.id, $cfg.secretSource
                            ) | Where-Object { $_ }
                            $vid = @($vc | Select-Object -First 1)[0]
                            if ($vid -and ($vid -match '/vaults/([^/]+)/')) { $kvName = $Matches[1] }
                            $sc = @($cfg.secretName, $cfg.keyVaultCertificateSourceParameters.secretName, $cfg.secretSource.secretName) | Where-Object { $_ }
                            $kvSecret = @($sc | Select-Object -First 1)[0]
                            if (-not $kvSecret -and $vid -and ($vid -match '/secrets/([^/]+)')) { $kvSecret = $Matches[1] }
                        }
                        $count++
                        [PSCustomObject]@{
                            SubscriptionId            = $fd.SubscriptionId
                            SubscriptionName          = $subLookup[$fd.SubscriptionId] ?? $fd.SubscriptionId
                            FrontDoorName             = $fd.Name
                            MigrationSourceResourceId = $fd.MigrationSourceResourceId
                            MigrationTargetResourceId = $fd.MigrationTargetResourceId
                            EndpointAssociation       = [string]$ep.name
                            HostName                  = $h
                            CertificateSource         = $certSource
                            ProvisioningState         = [string]$ep.properties.customHttpsProvisioningState
                            KeyVaultName              = $kvName
                            KeyVaultSecretName        = $kvSecret
                        }
                    }
                    [PSCustomObject]@{ __Progress = $true; FrontDoorName = $fd.Name; EndpointCount = $count }
                } catch {
                    [PSCustomObject]@{ __Progress = $true; FrontDoorName = $fd.Name; EndpointCount = 0; Error = (Get-ExceptionMessageSummary -Exception $_.Exception) }
                }
            } | ForEach-Object {
                if ($_.PSObject.Properties['__Progress']) {
                    $clsProcessed++
                    if (($clsProcessed % $clsProgressInterval -eq 0) -or ($clsProcessed -eq $clsFDs.Count)) {
                        $errMsg = if ($_.PSObject.Properties['Error'] -and $_.Error) { " (Error: $($_.Error))" } else { "" }
                        Write-Host "    Enumerated $clsProcessed/$($clsFDs.Count): $($_.FrontDoorName) -> $($_.EndpointCount) endpoint(s)$errMsg" -ForegroundColor DarkGray
                    }
                } else {
                    $clsEndpoints.Add($_)
                }
            }
            Write-Host "    Enumeration complete: $($clsEndpoints.Count) endpoint(s) from $clsProcessed Classic FD(s)" -ForegroundColor Green

            if ($clsEndpoints.Count -gt 0) {
                Write-Host "    Probing TLS certificates in parallel (TlsThrottleLimit=$TlsThrottleLimit, timeout=${TlsTimeoutMs}ms)..." -ForegroundColor Cyan
                $tlsProgressInterval = Get-ProgressInterval -TotalCount $clsEndpoints.Count
                $tlsProcessed = 0

                $clsEndpoints | ForEach-Object -ThrottleLimit $TlsThrottleLimit -Parallel {
                    $ep = $_
                    $proxy = $using:ProxyUri
                    $timeout = $using:TlsTimeoutMs
                    $warnDays = $using:WarningDays
                    $scanAt = $using:scanStartedAt
                    $tlsRetryCount = $using:TlsRetryCount
                    $retryBaseDelayMs = $using:RetryBaseDelayMs
                    $helperSource = $using:HelperSource
                    . ([ScriptBlock]::Create($helperSource))

                    $expiryDate = $null; $subject = $null; $issuer = $null; $issuingCA = $null
                    $count = $null; $inter = $null; $root = $null; $chainStatus = $null; $digi = $null
                    $errors = [System.Collections.Generic.List[string]]::new()
                    try {
                        $cert = Invoke-WithRetry -Action {
                            Get-CertificateFromDomain -DomainName $ep.HostName -ProxyUri $proxy -TimeoutMs $timeout
                        } -Category Tls -MaxAttempts $tlsRetryCount -BaseDelayMs $retryBaseDelayMs
                        if ($cert) {
                            $cd = Get-CertificateChainDetails -Certificate $cert
                            $expiryDate = $cert.NotAfter
                            $subject = $cd.Subject; $issuer = $cd.Issuer; $issuingCA = $cd.IssuingCA
                            $count = $cd.ServerCertificateCount; $inter = $cd.IntermediateCA; $root = $cd.RootCA
                            $chainStatus = $cd.ChainStatus; $digi = $cd.DigiCertIssued
                        }
                    } catch {
                        $err = Get-ExceptionMessageSummary -Exception $_.Exception
                        $null = $errors.Add("TLS: $err")
                    }

                    $expInfo = Get-FormattedExpirationDate -ExpiryDate $expiryDate -WarningDays $warnDays
                    $overall = Get-CertificateStatusSummary -ChainStatus $chainStatus -ExpirationStatus $expInfo.Status -StatusItems @($errors) -HasExpirationDate ($null -ne $expInfo.Value)

                    [PSCustomObject]@{
                        SubscriptionId            = $ep.SubscriptionId
                        SubscriptionName          = $ep.SubscriptionName
                        FrontDoorName             = $ep.FrontDoorName
                        MigrationSourceResourceId = $ep.MigrationSourceResourceId
                        MigrationTargetResourceId = $ep.MigrationTargetResourceId
                        EndpointAssociation       = $ep.EndpointAssociation
                        FrontDoorType             = 'Classic'
                        Domain                    = $ep.HostName
                        CertificateType           = $ep.CertificateSource
                        ProvisioningState         = $ep.ProvisioningState
                        ValidationState           = $null
                        Subject                   = $subject
                        Issuer                    = $issuer
                        IssuingCA                 = $issuingCA
                        ServerCertificateCount    = $count
                        IntermediateCA            = $inter
                        RootCA                    = $root
                        ChainStatus               = $overall
                        DigiCertIssued            = $digi
                        ExpirationDateRaw         = $expInfo.Value
                        ExpirationDate            = $expInfo.Display
                        ExpirationStatus          = $expInfo.Status
                        KeyVaultName              = $ep.KeyVaultName
                        KeyVaultSecretName        = $ep.KeyVaultSecretName
                    }
                } | ForEach-Object {
                    $tlsProcessed++
                    if (($tlsProcessed % $tlsProgressInterval -eq 0) -or ($tlsProcessed -eq $clsEndpoints.Count)) {
                        Write-Host "    TLS probed $tlsProcessed/$($clsEndpoints.Count): $($_.Domain)" -ForegroundColor DarkGray
                    }
                    $allResults.Add($_)
                }
                Write-Host "    Completed Classic TLS probing." -ForegroundColor Green
            }
        }
    }
}

#endregion

#region Display and export

function Get-TruncatedString {
    param([string]$Text, [int]$MaxLength)
    if (-not $Text -or $Text.Length -le $MaxLength) { return $Text }
    return $Text.Substring(0, $MaxLength - 3) + "..."
}

# Column descriptors consolidate column widths, property getters, and per-row coloring.
function Get-DisplayColumnDescriptors {
    param([bool]$HasValidationState)
    $descriptors = @(
        @{ Key='Subscription'; Header='Subscription'; Prop='SubscriptionName'; Min=15; Ideal=25 }
        @{ Key='FrontDoor';    Header='FrontDoor';    Prop='FrontDoorName';    Min=15; Ideal=26 }
        @{ Key='FDType';       Header='FDType';       Min=7;  Ideal=7; Value={ param($r) if ($r.FrontDoorType -eq 'Classic') { 'Cls' } else { 'StdPrm' } } }
        @{ Key='MigSource';    Header='MigSource';    Min=12; Ideal=18; Value={ param($r) Get-FrontDoorMigrationDisplayName -ResourceId $r.MigrationSourceResourceId } }
        @{ Key='MigTarget';    Header='MigTarget';    Min=12; Ideal=18; Value={ param($r) Get-FrontDoorMigrationDisplayName -ResourceId $r.MigrationTargetResourceId } }
        @{ Key='Domain';       Header='Domain';       Prop='Domain';           Min=25; Ideal=38 }
        @{ Key='Endpoint';     Header='Endpoint';     Prop='EndpointAssociation'; Min=14; Ideal=22 }
        @{ Key='CertType';     Header='CertType';     Min=8;  Ideal=11; Value={ param($r)
            switch -Wildcard ($r.CertificateType) {
                '*KeyVault*' { 'KeyVault' }
                '*CustomerCertificate*' { 'KeyVault' }
                '*Managed*' { 'Managed' }
                'FrontDoor' { 'Managed' }
                default { $r.CertificateType }
            }
        } }
        @{ Key='ProvState';    Header='ProvState';    Prop='ProvisioningState'; Min=10; Ideal=12;
            IconPrefix={ param($r) if ($r.ProvisioningState -and $r.ProvisioningState -notlike '*Succeeded*' -and $r.ProvisioningState -notlike '*Enabled*') { "`u{26A0}`u{FE0F} " } else { '' } }
            Color={ param($r) if ($r.ProvisioningState -and $r.ProvisioningState -notlike '*Succeeded*' -and $r.ProvisioningState -notlike '*Enabled*') { 'Yellow' } else { $null } }
        }
    )
    if ($HasValidationState) {
        $descriptors += @{ Key='ValState'; Header='ValState'; Prop='ValidationState'; Min=10; Ideal=12;
            IconPrefix={ param($r) if ($r.ValidationState -and $r.ValidationState -notlike '*Approved*') { "`u{26A0}`u{FE0F} " } else { '' } }
            Color={ param($r) if ($r.ValidationState -and $r.ValidationState -notlike '*Approved*') { 'Yellow' } else { $null } }
        }
    }
    $descriptors += @(
        @{ Key='Subject';   Header='Subject';   Prop='Subject';   Min=10; Ideal=25 }
        @{ Key='IssuingCA'; Header='IssuingCA'; Prop='IssuingCA'; Min=12; Ideal=24 }
        @{ Key='RootCA';    Header='RootCA';    Prop='RootCA';    Min=12; Ideal=24 }
        @{ Key='ExpirationDate'; Header='ExpirationDate'; Prop='ExpirationDate'; Min=22; Ideal=22;
            IconPrefix={ param($r)
                switch ($r.ExpirationStatus) {
                    'EXPIRED' { "`u{1F534} " }
                    'WARNING' { "`u{26A0}`u{FE0F} " }
                    default { '' }
                }
            }
            Color={ param($r)
                switch ($r.ExpirationStatus) {
                    'EXPIRED' { 'Red' }
                    'WARNING' { 'Yellow' }
                    default { $null }
                }
            }
        }
        @{ Key='KVName';   Header='KVName';   Prop='KeyVaultName';       Min=15; Ideal=22 }
        @{ Key='KVSecret'; Header='KVSecret'; Prop='KeyVaultSecretName'; Min=8;  Ideal=20 }
    )
    return $descriptors
}

function Resolve-DisplayColumnWidths {
    param([Parameter(Mandatory)][array]$Descriptors, [int]$MinWidth = 80)
    try {
        $consoleWidth = $Host.UI.RawUI.WindowSize.Width
        if ($consoleWidth -lt $MinWidth) { $consoleWidth = $MinWidth }
    } catch { $consoleWidth = 160 }
    $available = $consoleWidth - 10
    $minSum = ($Descriptors | ForEach-Object { $_.Min + 1 } | Measure-Object -Sum).Sum
    $widths = @{}
    if ($available -gt $minSum) {
        $extra = $available - $minSum
        $idealExtraSum = ($Descriptors | ForEach-Object { $_.Ideal - $_.Min } | Measure-Object -Sum).Sum
        foreach ($desc in $Descriptors) {
            if ($idealExtraSum -gt 0) {
                $allot = [Math]::Floor($extra * (($desc.Ideal - $desc.Min) / $idealExtraSum))
                $widths[$desc.Key] = [Math]::Min($desc.Min + $allot, $desc.Ideal)
            } else {
                $widths[$desc.Key] = $desc.Min
            }
        }
    } else {
        foreach ($desc in $Descriptors) { $widths[$desc.Key] = $desc.Min }
    }
    return $widths
}

function Get-DescriptorValue {
    param([hashtable]$Descriptor, $Record)
    if ($Descriptor.ContainsKey('Value')) { return & $Descriptor.Value $Record }
    if ($Descriptor.ContainsKey('Prop')) { return $Record.($Descriptor.Prop) }
    return $null
}

function Write-ResultsTable {
    param([Parameter(Mandatory)][object[]]$Results)
    $hasValState = @($Results | Where-Object { $_.FrontDoorType -eq 'Standard/Premium' }).Count -gt 0
    $descriptors = Get-DisplayColumnDescriptors -HasValidationState $hasValState
    $widths = Resolve-DisplayColumnWidths -Descriptors $descriptors

    # Header
    $lastKey = $descriptors[-1].Key
    foreach ($desc in $descriptors) {
        $w = $widths[$desc.Key]
        if ($desc.Key -eq $lastKey) {
            Write-Host $desc.Header -ForegroundColor Cyan
        } else {
            Write-Host (("{0,-$w} " -f $desc.Header)) -ForegroundColor Cyan -NoNewline
        }
    }
    foreach ($desc in $descriptors) {
        $w = $widths[$desc.Key]
        if ($desc.Key -eq $lastKey) {
            Write-Host ("-" * $w) -ForegroundColor Cyan
        } else {
            Write-Host (("{0,-$w} " -f ("-" * $w))) -ForegroundColor Cyan -NoNewline
        }
    }

    # Rows
    foreach ($r in $Results) {
        foreach ($desc in $descriptors) {
            $w = $widths[$desc.Key]
            $raw = Get-DescriptorValue -Descriptor $desc -Record $r
            $prefix = if ($desc.ContainsKey('IconPrefix')) { & $desc.IconPrefix $r } else { '' }
            $avail = $w - $prefix.Length
            if ($avail -lt 1) { $avail = 1 }
            $text = Get-TruncatedString $raw ($avail - 1)
            $display = $prefix + $text
            $color = if ($desc.ContainsKey('Color')) { & $desc.Color $r } else { $null }
            $isLast = $desc.Key -eq $lastKey
            $format = if ($isLast) { '{0}' } else { "{0,-$w} " }
            $formatted = $format -f $display
            $hashArgs = @{ NoNewline = (-not $isLast) }
            if ($color) { $hashArgs['ForegroundColor'] = $color }
            Write-Host $formatted @hashArgs
        }
    }
}

# Display and export results
if ($allResults.Count -eq 0) {
    Write-Host "No certificate information found." -ForegroundColor Yellow
} else {
    Write-Host "`n=== Certificate Details ===" -ForegroundColor Green
    Write-Host ""
    Write-ResultsTable -Results $allResults
    Write-Host ""

    # Summary
    $expired = ($allResults | Where-Object { $_.ExpirationStatus -eq 'EXPIRED' }).Count
    $warning = ($allResults | Where-Object { $_.ExpirationStatus -eq 'WARNING' }).Count
    Write-Host "`n=== Summary ===" -ForegroundColor Cyan
    Write-Host "Total certificates: $($allResults.Count)" -ForegroundColor Cyan
    if ($expired -gt 0) { Write-Host "🔴 $expired certificate(s) EXPIRED" -ForegroundColor Red }
    if ($warning -gt 0) { Write-Host "⚠️  $warning certificate(s) expiring within $WarningDays days" -ForegroundColor Yellow }
    if ($expired -eq 0 -and $warning -eq 0) { Write-Host "✅ All certificates are valid and not expiring soon" -ForegroundColor Green }

    if ($ExportCsvPath -or $ExportXlsxPath) {
        $cols = Get-ResultExportColumns
        $records = @($allResults | Select-Object $cols)
        $xlsxRecords = Get-XlsxExportRecords -Results $allResults -Columns $cols

        $resolvedCsv = $null
        if ($ExportCsvPath) {
            $resolvedCsv = Initialize-ParentDirectoryPath -FilePath $ExportCsvPath
            $records | Export-Csv -LiteralPath $resolvedCsv -NoTypeInformation -Encoding utf8 -Force
            Write-Host "`nResults exported to: $resolvedCsv" -ForegroundColor Green
        }

        $resolvedXlsxInfo = $null
        $resolvedXlsx = $null
        if ($ExportXlsxPath) {
            $resolvedXlsxInfo = Resolve-AvailableExportFilePath -FilePath $ExportXlsxPath
            $resolvedXlsx = $resolvedXlsxInfo.Path
        } elseif ($resolvedCsv) {
            $resolvedXlsxInfo = Resolve-AvailableExportFilePath -FilePath ([System.IO.Path]::ChangeExtension($resolvedCsv, '.xlsx'))
            $resolvedXlsx = $resolvedXlsxInfo.Path
        }

        $importExcel = Get-Module -ListAvailable -Name ImportExcel | Sort-Object Version -Descending | Select-Object -First 1
        if ($resolvedXlsx -and $importExcel) {
            try {
                Import-Module $importExcel.Path -ErrorAction Stop | Out-Null
                if ($resolvedXlsxInfo -and $resolvedXlsxInfo.Redirected) {
                    Write-Host "Requested XLSX path is in use. Exporting workbook to: $resolvedXlsx" -ForegroundColor DarkYellow
                }
                $textCols = @(
                    'SubscriptionId','SubscriptionName','FrontDoorName','FrontDoorType',
                    'MigrationSourceResourceId','MigrationTargetResourceId','EndpointAssociation',
                    'Domain','CertificateType','ProvisioningState','ValidationState',
                    'Subject','Issuer','IssuingCA','IntermediateCA','RootCA',
                    'ChainStatus','KeyVaultName','KeyVaultSecretName'
                )
                $wsName = [System.IO.Path]::GetFileNameWithoutExtension($resolvedXlsx) -replace '[\\/\?\*\[\]:]', '_'
                if ([string]::IsNullOrWhiteSpace($wsName)) { $wsName = 'afd-certs' }
                if ($wsName.Length -gt 31) { $wsName = $wsName.Substring(0, 31) }
                $expColIdx = [Array]::IndexOf($cols, 'ExpirationDate') + 1
                $countColIdx = [Array]::IndexOf($cols, 'ServerCertificateCount') + 1
                $chainColIdx = [Array]::IndexOf($cols, 'ChainStatus') + 1
                $digiColIdx = [Array]::IndexOf($cols, 'DigiCertIssued') + 1
                $dateFormat = [System.Globalization.CultureInfo]::CurrentCulture.DateTimeFormat.FullDateTimePattern
                $dateFormat = $dateFormat -replace '(?<!t)tt(?!t)', 'AM/PM'
                $dateFormat = $dateFormat -replace '(?<!t)t(?!t)', 'A/P'
                $styleCb = {
                    param($ws, $totalRows, $lastCol)
                    foreach ($ci in @($countColIdx, $chainColIdx, $digiColIdx)) {
                        if ($ci -gt 0) { $ws.Column($ci).Style.HorizontalAlignment = [OfficeOpenXml.Style.ExcelHorizontalAlignment]::Center }
                    }
                    if ($expColIdx -gt 0) {
                        $ws.Column($expColIdx).Style.Numberformat.Format = $dateFormat
                        $ws.Column($expColIdx).Style.HorizontalAlignment = [OfficeOpenXml.Style.ExcelHorizontalAlignment]::Center
                    }
                }.GetNewClosure()
                $xlsxRecords | Export-Excel -Path $resolvedXlsx -WorksheetName $wsName -TableName Table1 -TableStyle Medium2 -NoNumberConversion $textCols -AutoFilter -AutoSize -FreezeTopRow -ClearSheet -CellStyleSB $styleCb | Out-Null
                Set-XlsxTableStyleInfo -Path $resolvedXlsx -TableStyleName 'TableStyleMedium2'
                if ($resolvedCsv) { Write-Host "Companion XLSX exported to: $resolvedXlsx" -ForegroundColor Green }
                else { Write-Host "Results exported to XLSX: $resolvedXlsx" -ForegroundColor Green }
            } catch {
                Write-Host "ImportExcel is installed but XLSX export failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
            }
        } elseif ($resolvedXlsx) {
            if ($resolvedCsv) { Write-Host 'ImportExcel module not found. Skipping XLSX export and keeping CSV only.' -ForegroundColor DarkYellow }
            else { Write-Host 'ImportExcel module not found. Skipping requested XLSX export.' -ForegroundColor DarkYellow }
        }
    }

    if ($GridView) {
        Write-Host "`nOpening GridView..." -ForegroundColor Cyan
        $allResults | Select-Object (Get-ResultExportColumns) | Out-GridView -Title "Azure Front Door Certificates"
    }
}

#endregion
