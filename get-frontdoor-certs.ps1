<#
.SYNOPSIS
    Extracts and analyzes SSL/TLS certificate expirations for Azure Front Door profiles.

.DESCRIPTION
    This script extracts certificate information from Azure Front Door deployments, supporting
    both Classic and Standard/Premium Front Door profiles. It displays certificate expiration
    dates with status indicators, shows provisioning and validation states, reports classic-to-
    Standard/Premium migration links when present, and can export results to CSV and, when
    the ImportExcel module is installed, to XLSX for reporting. The XLSX output uses the same
    Medium2 table styling used by Get-AFDOriginCertChains.

    The script supports both Azure-managed certificates and custom certificates from Key Vault,
    providing detailed information including certificate subject, issuing CA, provisioning state,
    validation state, trust-chain details, and Key Vault details where applicable.

    Default Azure Front Door hostnames (*.azurefd.net) are skipped automatically so the output
    stays focused on customer-facing domains that typically need operational follow-up.

    The script supports three execution modes:
    - Single Front Door mode: Process a single Front Door by name in the current subscription
    - Subscription mode: Scan all Front Door profiles in the current or specified subscription
    - Tenant mode: Scan all Front Door profiles across all accessible subscriptions in the tenant

.PARAMETER ScanFrontDoor
    The name of a single Front Door profile to inspect. Supports both Standard/Premium and Classic
    Front Door profiles. The script will automatically detect the Front Door type.
    Requires -ResourceGroupName parameter.

.PARAMETER ResourceGroupName
    The name of the resource group containing the Front Door profile.
    Required when using -ScanFrontDoor parameter.

.PARAMETER ScanSubscription
    Scan all Front Door profiles in the specified subscription.
    Accepts either a subscription name or subscription ID.
    If an empty string is provided, uses the current subscription context.

.PARAMETER ScanTenant
    Switch to enable scanning all Front Door profiles across all accessible subscriptions
    in the current Azure AD tenant.

.PARAMETER FrontDoorType
    Filter to scan only specific Front Door types. Valid values are:
    - All: Scan both Standard/Premium and Classic Front Doors (default)
    - StandardPremium: Scan only Standard/Premium Front Doors
    - Classic: Scan only Classic Front Doors
    Only applicable when using -ScanSubscription or -ScanTenant modes.

.PARAMETER ExportCsvPath
    Optional path to export results as a CSV file. If specified, certificate details will be
    exported to this location for reporting and analysis purposes. The parent directory is
    created automatically when it does not already exist. When ImportExcel is installed and
    ExportXlsxPath is not specified, the script also writes a companion XLSX file with the same
    base name. Cannot be combined with -GridView.

.PARAMETER ExportXlsxPath
    Optional path to export results as an XLSX workbook. Requires the ImportExcel module.
    The parent directory is created automatically when it does not already exist. When omitted,
    XLSX output defaults to the same base name as ExportCsvPath when CSV export is requested.
    Cannot be combined with -GridView.

.PARAMETER GridView
    Display results in an interactive GridView window. Allows sorting, filtering, and
    selecting results. Requires a graphical environment (not supported in headless sessions).
    Cannot be combined with -ExportCsvPath or -ExportXlsxPath.

.PARAMETER WarningDays
    Number of days before certificate expiration to show warning indicators. Default is 30 days.
    Certificates expiring within this period will be highlighted with warning symbols.

.PARAMETER ThrottleLimit
    Parallelism for ARM API calls when scanning Front Doors. Default is auto-calculated based on
    CPU count (ProcessorCount * 4, capped between 8-32). Higher values increase speed but may
    hit Azure API throttling limits.

.PARAMETER TlsThrottleLimit
    Parallelism for TLS certificate checks on Classic Front Door endpoints. Default is auto-calculated
    (ProcessorCount * 8, capped between 16-64). Can be set higher than ThrottleLimit since TLS
    operations are network-bound rather than CPU-bound.

.PARAMETER TlsTimeoutMs
    Timeout in milliseconds for TLS certificate fetch operations. Default is 5000ms (5 seconds).
    Increase if operating through slow proxies or high-latency networks.

.PARAMETER RestRetryCount
    Maximum number of attempts for transient Azure REST API failures. Default is 3.

.PARAMETER TlsRetryCount
    Maximum number of attempts for transient live TLS probe failures. Default is 2.

.PARAMETER RetryBaseDelayMs
    Base delay in milliseconds for exponential retry backoff. Default is 500ms.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.Object[]
    The script outputs a formatted table showing certificate details and returns an array of
    custom objects containing certificate information, including migration source/target IDs,
    endpoint associations, issuer metadata, Key Vault details, and certificate status data.
    The exported ChainStatus field summarizes the overall certificate state for reporting by
    combining live probe errors, chain validation results, and expiration warnings. If
    ExportCsvPath is specified, results are also exported to a CSV file using a stable column
    set. If ExportXlsxPath is specified, or when ImportExcel is installed and XLSX output is
    derived from ExportCsvPath, a workbook is written with the same data.

.EXAMPLE
    .\get-frontdoor-certs.ps1 -ScanFrontDoor "my-frontdoor-profile" -ResourceGroupName "my-resource-group"
    
    Retrieves certificate information for the specified Front Door profile and displays
    results in a formatted table with color-coded status indicators.

.EXAMPLE
    .\get-frontdoor-certs.ps1 -ScanSubscription ""
    
    Scans all Front Door profiles in the current subscription and displays certificate information.

.EXAMPLE
    .\get-frontdoor-certs.ps1 -ScanSubscription "Production"
    
    Scans all Front Door profiles in the "Production" subscription.

.EXAMPLE
    .\get-frontdoor-certs.ps1 -ScanTenant -ExportCsvPath "C:\Reports\all-certs.csv"
    
    Scans all Front Door profiles across all accessible subscriptions in the tenant
    and exports results to CSV, plus a same-base XLSX workbook when ImportExcel is installed.

.EXAMPLE
    .\get-frontdoor-certs.ps1 -ScanTenant -ExportXlsxPath "C:\Reports\all-certs.xlsx"

    Scans all Front Door profiles across all accessible subscriptions in the tenant
    and exports results directly to XLSX when ImportExcel is installed.

.EXAMPLE
    .\get-frontdoor-certs.ps1 -ScanSubscription "Production" -GridView
    
    Scans all Front Door profiles in the "Production" subscription and displays results
    in an interactive GridView window for sorting and filtering.

.EXAMPLE
    .\get-frontdoor-certs.ps1 -ScanFrontDoor "my-frontdoor-profile" -ResourceGroupName "my-resource-group" -WarningDays 60
    
    Retrieves certificate information with a custom warning period of 60 days instead of
    the default 30 days.

.EXAMPLE
    .\get-frontdoor-certs.ps1 -ScanTenant -ThrottleLimit 16 -TlsThrottleLimit 64
    
    Scans all Front Door profiles across the tenant with custom parallelism settings.
    Useful for tuning performance based on your environment.

.EXAMPLE
    .\get-frontdoor-certs.ps1 -ScanTenant -FrontDoorType Classic -TlsTimeoutMs 10000
    
    Scans only Classic Front Door profiles with an extended TLS timeout of 10 seconds.
    Useful when operating through slow proxies.

.EXAMPLE
    .\get-frontdoor-certs.ps1 -ScanTenant -RestRetryCount 4 -TlsRetryCount 3 -RetryBaseDelayMs 750

    Scans the tenant with additional retry tolerance for transient ARM API and TLS failures.

.NOTES   
    Network Considerations:
    - For Classic Front Door, the script uses TcpClient + SslStream to fetch certificates
    - System proxy is automatically detected via WebRequest.GetSystemWebProxy()
    - When a proxy is configured, HTTP CONNECT tunnel is used for the TLS handshake
    - Standard/Premium Front Door certificate info is retrieved via Azure REST API,
      which also respects system proxy settings through the Az module
    
    Authentication Requirements:
    - Must be authenticated to Azure (Connect-AzAccount)
    - Requires appropriate permissions to read Azure Front Door resources
    - For tenant mode, requires access to multiple subscriptions
    
    Module Requirements:
    - Az.Accounts module is required for all modes
    - Az.FrontDoor module is required for Classic single-profile scans
    - ImportExcel module is optional for XLSX export
        - Tenant-wide discovery uses Resource Graph and ARM via REST and does not require the
            Az.ResourceGraph cmdlets
    
    Performance:
    - Tenant mode uses parallel processing for faster scanning
    - ThrottleLimit controls parallelism for ARM API calls (Standard/Premium FDs)
    - TlsThrottleLimit controls parallelism for TLS certificate probing (Classic FDs)
    - RestRetryCount and TlsRetryCount apply exponential backoff for transient failures
    - Progress updates are batched to reduce console I/O overhead
        - Default Azure Front Door hostnames (*.azurefd.net) are skipped automatically to focus
            on actionable customer-facing certificates

.LINK
    https://github.com/formicalab/AFDCerts

.LINK
    https://learn.microsoft.com/azure/frontdoor/

.LINK
    https://learn.microsoft.com/powershell/azure/
#>

#Requires -PSEdition Core
using module Az.Accounts

[CmdletBinding(DefaultParameterSetName = 'SingleFrontDoor')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'SingleFrontDoor', HelpMessage = 'Name of the Front Door profile to inspect (Standard/Premium or Classic)')]
    [string]$ScanFrontDoor,

    [Parameter(Mandatory = $true, ParameterSetName = 'SingleFrontDoor', HelpMessage = 'Resource group containing the Front Door profile')]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true, ParameterSetName = 'ScanSubscription', HelpMessage = 'Subscription name or ID to scan (use empty string for current subscription)')]
    [AllowEmptyString()]
    [string]$ScanSubscription,

    [Parameter(Mandatory = $true, ParameterSetName = 'ScanTenant', HelpMessage = 'Scan all Front Door profiles across all subscriptions in the tenant')]
    [switch]$ScanTenant,

    [Parameter(Mandatory = $false, ParameterSetName = 'ScanSubscription', HelpMessage = 'Filter by Front Door type: All, StandardPremium, or Classic')]
    [Parameter(Mandatory = $false, ParameterSetName = 'ScanTenant')]
    [ValidateSet('All', 'StandardPremium', 'Classic')]
    [string]$FrontDoorType = 'All',

    [Parameter(Mandatory = $false, HelpMessage = 'Path to export CSV results (optional)')]
    [string]$ExportCsvPath,

    [Parameter(Mandatory = $false, HelpMessage = 'Path to export XLSX results (optional, requires ImportExcel)')]
    [string]$ExportXlsxPath,

    [Parameter(Mandatory = $false, HelpMessage = 'Display results in an interactive GridView window')]
    [switch]$GridView,

    [Parameter(Mandatory = $false, HelpMessage = 'Number of days before expiration to show warning (default: 30)')]
    [int]$WarningDays = 30,

    [Parameter(Mandatory = $false, HelpMessage = 'Parallelism for ARM API calls (default: auto-calculated based on CPU)')]
    [ValidateRange(1, 64)]
    [int]$ThrottleLimit = [Math]::Min([Math]::Max([System.Environment]::ProcessorCount * 4, 8), 32),

    [Parameter(Mandatory = $false, HelpMessage = 'Parallelism for TLS certificate checks (default: auto-calculated, higher for network-bound operations)')]
    [ValidateRange(1, 256)]
    [int]$TlsThrottleLimit = [Math]::Min([Math]::Max([System.Environment]::ProcessorCount * 8, 16), 64),

    [Parameter(Mandatory = $false, HelpMessage = 'Timeout in milliseconds for TLS certificate checks (default: 5000)')]
    [ValidateRange(1000, 30000)]
    [int]$TlsTimeoutMs = 5000,

    [Parameter(Mandatory = $false, HelpMessage = 'Maximum attempts for transient Azure REST API failures (default: 3)')]
    [ValidateRange(1, 10)]
    [int]$RestRetryCount = 3,

    [Parameter(Mandatory = $false, HelpMessage = 'Maximum attempts for transient live TLS probe failures (default: 2)')]
    [ValidateRange(1, 5)]
    [int]$TlsRetryCount = 2,

    [Parameter(Mandatory = $false, HelpMessage = 'Base delay in milliseconds for exponential retry backoff (default: 500)')]
    [ValidateRange(100, 5000)]
    [int]$RetryBaseDelayMs = 500
)

Set-StrictMode -Version 1
$ErrorActionPreference = 'Stop'

# API versions used for the Standard/Premium and Classic ARM queries.
$script:ApiVersion = '2025-04-15'
$script:ClassicApiVersion = '2021-06-01'

# Resolve the process-wide proxy once so direct and parallel TLS probes use the same path.
$script:ProxyUri = $null
$proxyTestUri = [Uri]"https://azure.microsoft.com"
$systemProxy = [System.Net.WebRequest]::GetSystemWebProxy()
$detectedProxy = $systemProxy.GetProxy($proxyTestUri)
if ($detectedProxy -and $detectedProxy.Host -ne $proxyTestUri.Host) {
    $script:ProxyUri = $detectedProxy
    Write-Host "Proxy detected: $detectedProxy" -ForegroundColor Cyan
    Write-Host "  Classic Front Door certificate fetching will use HTTP CONNECT tunnel" -ForegroundColor Gray
} else {
    Write-Host "No proxy detected - using direct connections" -ForegroundColor Gray
}

#region Bearer Token and Authentication Helpers

# Converts access token values that Az.Accounts can surface either as strings or SecureStrings.
function ConvertTo-PlainText {
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Value
    )

    if ($Value -is [string]) {
        return $Value
    }

    if ($Value -is [securestring]) {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
        try {
            return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            if ($bstr -ne [IntPtr]::Zero) {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        }
    }

    throw "ConvertTo-PlainText: unexpected type [$($Value.GetType().FullName)]."
}

# Decodes the payload section of a JWT so the script can extract the actual token tenant.
function Get-JwtPayload {
    param(
        [Parameter(Mandatory)]
        [string]$Token
    )

    $parts = $Token -split '\.'
    if ($parts.Count -lt 2 -or [string]::IsNullOrWhiteSpace($parts[1])) {
        return $null
    }

    $payloadSegment = $parts[1]
    switch ($payloadSegment.Length % 4) {
        2 { $payloadSegment += '==' }
        3 { $payloadSegment += '=' }
        0 { }
        default { return $null }
    }

    try {
        $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payloadSegment.Replace('-', '+').Replace('_', '/')))
        return $json | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        return $null
    }
}

# Acquires one Azure management-plane token and returns resolved user and tenant metadata.
function Get-ArmBearerToken {
    $context = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $context -or -not $context.Account) {
        throw "No Azure PowerShell context found. Run Connect-AzAccount first."
    }

    $tokenResponse = Get-AzAccessToken -ResourceUrl 'https://management.azure.com' -ErrorAction Stop
    $rawToken = if ($tokenResponse.PSObject.Properties['Token']) {
        $tokenResponse.Token
    }
    elseif ($tokenResponse.PSObject.Properties['AccessToken']) {
        $tokenResponse.AccessToken
    }
    else {
        $null
    }

    $token = ConvertTo-PlainText -Value $rawToken
    if ([string]::IsNullOrWhiteSpace($token)) {
        throw 'Failed to acquire an Azure access token from Az.Accounts.'
    }

    $tokenPayload = Get-JwtPayload -Token $token
    $tenantId = if ($tokenPayload -and $tokenPayload.PSObject.Properties['tid']) {
        [string]$tokenPayload.tid
    }
    elseif ($tokenResponse.PSObject.Properties['TenantId'] -and $tokenResponse.TenantId) {
        [string]$tokenResponse.TenantId
    }
    elseif ($context.Tenant -and $context.Tenant.Id) {
        [string]$context.Tenant.Id
    }
    else {
        $null
    }

    $userId = if ($tokenPayload -and $tokenPayload.PSObject.Properties['upn'] -and $tokenPayload.upn) {
        [string]$tokenPayload.upn
    }
    elseif ($tokenPayload -and $tokenPayload.PSObject.Properties['unique_name'] -and $tokenPayload.unique_name) {
        [string]$tokenPayload.unique_name
    }
    elseif ($tokenResponse.PSObject.Properties['UserId'] -and $tokenResponse.UserId) {
        [string]$tokenResponse.UserId
    }
    elseif ($context.Account -and $context.Account.Id) {
        [string]$context.Account.Id
    }
    else {
        $null
    }

    return [pscustomobject]@{
        Token    = $token
        TenantId = $tenantId
        UserId   = $userId
    }
}

# Returns every enabled Azure subscription the current identity can enumerate.
function Get-EnabledSubscriptions {
    $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue | Where-Object { $_.State -eq 'Enabled' })
    if (-not $subscriptions) {
        throw 'No enabled Azure subscriptions are accessible for the current identity.'
    }

    return @($subscriptions | Sort-Object Name, Id)
}

# Executes a Resource Graph query via REST API across all target subscriptions with pagination.
function Invoke-ResourceGraphQueryAllPages {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Headers,

        [Parameter(Mandatory)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory)]
        [string]$Query
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $skipToken = $null
    $graphUri = 'https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01'

    do {
        $options = @{ resultFormat = 'objectArray'; '$top' = 1000 }
        if ($skipToken) {
            $options['$skipToken'] = $skipToken
        }

        $body = @{
            subscriptions = $SubscriptionIds
            query         = $Query
            options       = $options
        } | ConvertTo-Json -Depth 8

        $response = Invoke-WithRetry -Action {
            Invoke-RestMethod -Method Post -Uri $graphUri -Headers $Headers -Body $body -ErrorAction Stop
        } -OperationName 'Resource Graph query' -Category Rest -MaxAttempts $RestRetryCount -BaseDelayMs $RetryBaseDelayMs
        foreach ($row in @($response.data)) {
            $results.Add($row)
        }

        $skipToken = $null
        foreach ($propertyName in '$skipToken', 'skipToken') {
            $property = $response.PSObject.Properties[$propertyName]
            if ($property -and $property.Value) {
                $skipToken = [string]$property.Value
                break
            }
        }
    }
    while ($skipToken)

    return @($results)
}

# Limits progress chatter by emitting at most about twenty updates for large loops.
function Get-ProgressInterval {
    param(
        [Parameter(Mandatory)]
        [int]$TotalCount
    )

    if ($TotalCount -le 0) {
        return 1
    }

    return [Math]::Max([int][Math]::Ceiling($TotalCount / 20.0), 1)
}

# Pulls an HTTP status code out of nested exception shapes returned by REST calls.
function Get-HttpStatusCodeFromException {
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.Exception]$Exception
    )

    if (-not $Exception) {
        return $null
    }

    foreach ($propertyName in 'StatusCode', 'Response') {
        $property = $Exception.PSObject.Properties[$propertyName]
        if (-not $property) {
            continue
        }

        try {
            if ($propertyName -eq 'StatusCode' -and $null -ne $property.Value) {
                return [int]$property.Value
            }

            if ($propertyName -eq 'Response' -and $property.Value -and $property.Value.StatusCode) {
                return [int]$property.Value.StatusCode
            }
        }
        catch {
        }
    }

    if ($Exception.InnerException -and $Exception.InnerException -ne $Exception) {
        return Get-HttpStatusCodeFromException -Exception $Exception.InnerException
    }

    return $null
}

# Flattens nested exception messages into one line for logs and exported status fields.
function Get-ExceptionMessageSummary {
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.Exception]$Exception,

        [Parameter(Mandatory = $false)]
        [string]$PrefixMessage
    )

    $messageParts = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($PrefixMessage)) {
        $messageParts.Add($PrefixMessage)
    }

    $currentException = $Exception
    while ($currentException) {
        $message = [string]$currentException.Message
        if (-not [string]::IsNullOrWhiteSpace($message) -and -not $messageParts.Contains($message)) {
            $messageParts.Add($message)
        }

        if (-not $currentException.InnerException -or $currentException.InnerException -eq $currentException) {
            break
        }

        $currentException = $currentException.InnerException
    }

    if ($messageParts.Count -eq 0) {
        return $null
    }

    return ($messageParts -join ' ')
}

# Identifies Azure REST failures that are worth retrying with backoff.
function Test-IsTransientRestFailure {
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.Exception]$Exception
    )

    if (-not $Exception) {
        return $false
    }

    $statusCode = Get-HttpStatusCodeFromException -Exception $Exception
    if ($null -ne $statusCode) {
        return $statusCode -in 408, 409, 429, 500, 502, 503, 504
    }

    $message = Get-ExceptionMessageSummary -Exception $Exception
    return $message -match 'timed out|timeout|temporar|throttl|too many requests|connection.+(reset|aborted|closed)|remote party closed|EOF|unexpected end'
}

# Identifies transient network and proxy failures during live TLS probes.
function Test-IsTransientTlsFailure {
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.Exception]$Exception,

        [Parameter(Mandatory = $false)]
        [string]$FailureMessage
    )

    $message = Get-ExceptionMessageSummary -Exception $Exception -PrefixMessage $FailureMessage
    if ([string]::IsNullOrWhiteSpace($message)) {
        return $false
    }

    return $message -match 'timed out|timeout|temporar|connection.+(reset|aborted|closed)|remote party closed|EOF|unexpected end|network.+unreachable|host.+unreachable|Proxy CONNECT failed: HTTP/\d\.\d (429|502|503|504)'
}

# Applies capped exponential backoff between retry attempts.
function Get-RetryDelayMilliseconds {
    param(
        [Parameter(Mandatory)]
        [int]$Attempt,

        [Parameter(Mandatory)]
        [int]$BaseDelayMs
    )

    $multiplier = [Math]::Pow(2, [Math]::Max($Attempt - 1, 0))
    return [int][Math]::Min([Math]::Round($BaseDelayMs * $multiplier), 10000)
}

# Wraps REST and TLS operations with the shared transient-failure retry policy.
function Invoke-WithRetry {
    param(
        [Parameter(Mandatory)]
        [scriptblock]$Action,

        [Parameter(Mandatory)]
        [string]$OperationName,

        [Parameter(Mandatory)]
        [ValidateSet('Rest', 'Tls')]
        [string]$Category,

        [Parameter(Mandatory)]
        [int]$MaxAttempts,

        [Parameter(Mandatory)]
        [int]$BaseDelayMs
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            return & $Action
        }
        catch {
            $exception = $_.Exception
            $isTransient = if ($Category -eq 'Rest') {
                Test-IsTransientRestFailure -Exception $exception
            }
            else {
                Test-IsTransientTlsFailure -Exception $exception -FailureMessage $exception.Message
            }

            if (-not $isTransient -or $attempt -ge $MaxAttempts) {
                throw
            }

            $delayMs = Get-RetryDelayMilliseconds -Attempt $attempt -BaseDelayMs $BaseDelayMs
            Write-Verbose ("Retrying {0} after transient {1} failure (attempt {2}/{3}, delay={4}ms): {5}" -f $OperationName, $Category, ($attempt + 1), $MaxAttempts, $delayMs, $exception.Message)
            Start-Sleep -Milliseconds $delayMs
        }
    }
}

#endregion

# Verify Azure login
$context = Get-AzContext
if (-not $context) {
    throw "Not logged in to Azure. Please run Connect-AzAccount first."
}

if ($GridView -and ($ExportCsvPath -or $ExportXlsxPath)) {
    throw "Use either -GridView or export paths (-ExportCsvPath / -ExportXlsxPath), not both."
}

# Global results collection (using List for better append performance)
$allResults = [System.Collections.Generic.List[PSCustomObject]]::new()

#region Certificate fetching for Classic Front Door

# Opens a live TLS session to a domain and returns the presented server certificate.
function Get-CertificateFromDomain {
    param([string]$DomainName)
    
    $tcpClient = $null
    $sslStream = $null
    $networkStream = $null
    $reader = $null
    $writer = $null
    
    try {
        $tcpClient = [System.Net.Sockets.TcpClient]::new()
        $tcpClient.SendTimeout = $TlsTimeoutMs
        $tcpClient.ReceiveTimeout = $TlsTimeoutMs
        
        if ($script:ProxyUri) {
            # Establish an HTTP CONNECT tunnel before starting the TLS handshake.
            $tcpClient.Connect($script:ProxyUri.Host, $script:ProxyUri.Port)
            $networkStream = $tcpClient.GetStream()
            
            $writer = [System.IO.StreamWriter]::new($networkStream, [System.Text.Encoding]::ASCII)
            $writer.AutoFlush = $true
            $reader = [System.IO.StreamReader]::new($networkStream, [System.Text.Encoding]::ASCII)
            
            $writer.WriteLine("CONNECT ${DomainName}:443 HTTP/1.1")
            $writer.WriteLine("Host: ${DomainName}:443")
            $writer.WriteLine("")
            
            $response = $reader.ReadLine()
            if ($response -notmatch "^HTTP/\d\.\d 200") {
                throw "Proxy CONNECT failed: $response"
            }
            
            while ($true) {
                $line = $reader.ReadLine()
                if ([string]::IsNullOrEmpty($line)) { break }
            }
            
            $sslStream = [System.Net.Security.SslStream]::new(
                $networkStream,
                $false,
                { param($s, $certificate, $chain, $sslPolicyErrors) return $true }
            )
        } else {
            # Fall back to a direct TLS handshake when no proxy is configured.
            $tcpClient.Connect($DomainName, 443)
            
            $sslStream = [System.Net.Security.SslStream]::new(
                $tcpClient.GetStream(),
                $false,
                { param($s, $certificate, $chain, $sslPolicyErrors) return $true }
            )
        }
        
        $sslStream.AuthenticateAsClient($DomainName)
        $cert = $sslStream.RemoteCertificate
        
        if ($cert) {
            return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cert)
        }
        return $null
    }
    finally {
        if ($writer) { $writer.Dispose() }
        if ($reader) { $reader.Dispose() }
        if ($sslStream) { $sslStream.Dispose() }
        if ($tcpClient) { $tcpClient.Dispose() }
    }
}

#endregion

#region Certificate Metadata Helpers

# Normalizes issuer metadata into a full issuer string plus a friendly issuing-CA name.
function Get-IssuerDetails {
    param(
        [Parameter(Mandatory = $false)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory = $false)]
        [string]$IssuerString,

        [Parameter(Mandatory = $false)]
        [string]$IssuingCAName
    )

    $issuer = $IssuerString
    if (-not $issuer -and $Certificate) {
        $issuer = $Certificate.Issuer
    }

    $issuingCA = $IssuingCAName
    if (-not $issuingCA -and $Certificate) {
        try {
            $issuingCA = $Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $true)
        }
        catch {
            $issuingCA = $null
        }
    }

    if (-not $issuingCA -and $issuer) {
        if ($issuer -match '(^|,\s*)CN=([^,]+)') {
            $issuingCA = $matches[2].Trim()
        }
        elseif ($issuer -match '(^|,\s*)O=([^,]+)') {
            $issuingCA = $matches[2].Trim()
        }
        else {
            $issuingCA = $issuer
        }
    }

    return @{
        Issuer    = $issuer
        IssuingCA = $issuingCA
    }
}

# Builds a readable display name from a certificate subject or issuer distinguished name.
function Get-CertificateDisplayName {
    param(
        [Parameter(Mandatory = $false)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory = $false)]
        [string]$DistinguishedName
    )

    $displayName = $null
    if ($Certificate) {
        try {
            $displayName = $Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        }
        catch {
            $displayName = $null
        }

        if (-not $DistinguishedName) {
            $DistinguishedName = $Certificate.Subject
        }
    }

    if (-not $displayName -and $DistinguishedName) {
        if ($DistinguishedName -match '(^|,\s*)CN=([^,]+)') {
            $displayName = $matches[2].Trim()
        }
        elseif ($DistinguishedName -match '(^|,\s*)O=([^,]+)') {
            $displayName = $matches[2].Trim()
        }
        else {
            $displayName = $DistinguishedName
        }
    }

    return $displayName
}

# Summarizes the non-success statuses reported by an X509 chain build.
function Get-ChainStatusSummary {
    param(
        [Parameter(Mandatory = $false)]
        [System.Security.Cryptography.X509Certificates.X509Chain]$Chain
    )

    if (-not $Chain) {
        return $null
    }

    $statuses = @(
        $Chain.ChainStatus |
            Where-Object { $_.Status -ne [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NoError } |
            ForEach-Object { [string]$_.Status } |
            Select-Object -Unique
    )

    if (-not $statuses -or $statuses.Count -eq 0) {
        return 'Valid'
    }

    return ($statuses -join ',')
}

# Collapses probe errors, chain state, and expiration state into one export-friendly status field.
function Get-CertificateStatusSummary {
    param(
        [Parameter(Mandatory = $false)]
        [string]$ChainStatus,

        [Parameter(Mandatory = $false)]
        [string]$ExpirationStatus,

        [Parameter(Mandatory = $false)]
        [string[]]$StatusItems,

        [Parameter(Mandatory = $false)]
        [bool]$HasExpirationDate
    )

    $parts = [System.Collections.Generic.List[string]]::new()
    $uniqueStatusItems = @(
        $StatusItems |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
            Select-Object -Unique
    )

    $uniqueStatusItems | ForEach-Object {
            $parts.Add("CheckError: $_")
        }

    if (-not [string]::IsNullOrWhiteSpace($ChainStatus) -and $ChainStatus -ne 'Valid') {
        $parts.Add("Chain: $ChainStatus")
    }

    switch ($ExpirationStatus) {
        'EXPIRED' { $parts.Add('Expiration: EXPIRED') }
        'WARNING' { $parts.Add('Expiration: WARNING') }
    }

    if ($parts.Count -gt 0) {
        return ($parts -join ' | ')
    }

    if ($ChainStatus -eq 'Valid' -or ($HasExpirationDate -and $ExpirationStatus -eq 'OK')) {
        return 'OK'
    }

    return 'NoData'
}

# Builds chain metadata for reporting from a live certificate or REST-provided issuer data.
function Get-CertificateChainDetails {
    param(
        [Parameter(Mandatory = $false)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory = $false)]
        [string]$IssuerString,

        [Parameter(Mandatory = $false)]
        [string]$IssuingCAName
    )

    if (-not $Certificate) {
        return @{
            Subject                = $null
            Issuer                 = $IssuerString
            IssuingCA              = $IssuingCAName
            ServerCertificateCount = $null
            IntermediateCA         = $null
            RootCA                 = $null
            ChainStatus            = $null
            DigiCertIssued         = $null
        }
    }

    $issuerDetails = Get-IssuerDetails -Certificate $Certificate -IssuerString $IssuerString -IssuingCAName $IssuingCAName
    $serverCertificateCount = 1
    $intermediateCA = $null
    $rootCA = $null
    $chainStatus = $null
    $digiCertIssued = $false
    $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()

    try {
        # Keep chain building local and fast; revocation checks would add extra network dependency.
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
        $null = $chain.Build($Certificate)

        $chainElements = @($chain.ChainElements)
        if ($chainElements.Count -gt 0) {
            $serverCertificateCount = $chainElements.Count
            $chainStatus = Get-ChainStatusSummary -Chain $chain

            $lastElementCertificate = $chainElements[$chainElements.Count - 1].Certificate
            $lastIsSelfSigned = $lastElementCertificate -and ($lastElementCertificate.Subject -eq $lastElementCertificate.Issuer)

            $intermediateCertificates = @()
            # Treat a self-signed last element as the root and everything between leaf and root as intermediates.
            if ($chainElements.Count -ge 3 -or $lastIsSelfSigned) {
                $rootCA = Get-CertificateDisplayName -Certificate $lastElementCertificate
                if ($chainElements.Count -gt 2) {
                    $intermediateCertificates = @($chainElements[1..($chainElements.Count - 2)] | ForEach-Object { $_.Certificate })
                }
            }
            elseif ($chainElements.Count -gt 1) {
                $intermediateCertificates = @($chainElements[1..($chainElements.Count - 1)] | ForEach-Object { $_.Certificate })
            }

            $intermediateNames = @(
                $intermediateCertificates |
                    ForEach-Object { Get-CertificateDisplayName -Certificate $_ } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                    Select-Object -Unique
            )
            if ($intermediateNames.Count -gt 0) {
                $intermediateCA = $intermediateNames -join ' | '
            }
        }
    }
    finally {
        $chain.Dispose()
    }

    if ($issuerDetails.Issuer -match '\bDigiCert\b' -or $issuerDetails.IssuingCA -match '\bDigiCert\b' -or $intermediateCA -match '\bDigiCert\b' -or $rootCA -match '\bDigiCert\b') {
        $digiCertIssued = $true
    }

    return @{
        Subject                = $Certificate.Subject
        Issuer                 = $issuerDetails.Issuer
        IssuingCA              = $issuerDetails.IssuingCA
        ServerCertificateCount = $serverCertificateCount
        IntermediateCA         = $intermediateCA
        RootCA                 = $rootCA
        ChainStatus            = $chainStatus
        DigiCertIssued         = $digiCertIssued
    }
}

# Skips the default Azure Front Door hostname so output focuses on customer-facing domains.
function Test-IsDefaultAzureFrontDoorHostname {
    param(
        [Parameter(Mandatory = $false)]
        [string]$HostName
    )

    if ([string]::IsNullOrWhiteSpace($HostName)) {
        return $false
    }

    return $HostName.EndsWith('.azurefd.net', [System.StringComparison]::OrdinalIgnoreCase)
}

# Maps each Standard/Premium custom-domain resource ID to the endpoint host names whose routes reference it.
function Get-AfdCustomDomainEndpointAssociations {
    param(
        [Parameter(Mandatory)]
        [string]$SubscriptionId,

        [Parameter(Mandatory)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory)]
        [string]$ProfileName,

        [Parameter(Mandatory)]
        [string]$ApiVersion,

        [Parameter(Mandatory)]
        [int]$RestRetryCount,

        [Parameter(Mandatory)]
        [int]$RetryBaseDelayMs
    )

    $associationSets = @{}
    $pathEndpoints = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Cdn/profiles/$ProfileName/afdEndpoints?api-version=$ApiVersion"
    $endpointsResp = Invoke-WithRetry -Action {
        Invoke-AzRest -Path $pathEndpoints -Method GET -ErrorAction Stop
    } -OperationName "endpoint lookup for $ProfileName" -Category Rest -MaxAttempts $RestRetryCount -BaseDelayMs $RetryBaseDelayMs
    $afdEndpoints = @(($endpointsResp.Content | ConvertFrom-Json).value)

    foreach ($afdEndpoint in $afdEndpoints) {
        $endpointName = [string]$afdEndpoint.name
        if ([string]::IsNullOrWhiteSpace($endpointName)) {
            continue
        }

        $endpointAssociation = [string]($afdEndpoint.properties.hostName ?? $endpointName)
        if ([string]::IsNullOrWhiteSpace($endpointAssociation)) {
            $endpointAssociation = $endpointName
        }

        $pathRoutes = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Cdn/profiles/$ProfileName/afdEndpoints/$endpointName/routes?api-version=$ApiVersion"
        try {
            $routesResp = Invoke-WithRetry -Action {
                Invoke-AzRest -Path $pathRoutes -Method GET -ErrorAction Stop
            } -OperationName "route lookup for $ProfileName/$endpointName" -Category Rest -MaxAttempts $RestRetryCount -BaseDelayMs $RetryBaseDelayMs
            $routes = @(($routesResp.Content | ConvertFrom-Json).value)
        }
        catch {
            $routeLookupError = Get-ExceptionMessageSummary -Exception $_.Exception
            Write-Host "    Failed to resolve routes for endpoint ${endpointAssociation}: $routeLookupError" -ForegroundColor Yellow
            continue
        }

        foreach ($route in $routes) {
            foreach ($customDomainRef in @($route.properties.customDomains)) {
                $domainRefId = [string]$customDomainRef.id
                if ([string]::IsNullOrWhiteSpace($domainRefId)) {
                    continue
                }

                $domainKey = $domainRefId.ToLowerInvariant()
                if (-not $associationSets.ContainsKey($domainKey)) {
                    $associationSets[$domainKey] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                }

                $null = $associationSets[$domainKey].Add($endpointAssociation)
            }
        }
    }

    $associationMap = @{}
    foreach ($domainKey in $associationSets.Keys) {
        $associationMap[$domainKey] = (@($associationSets[$domainKey] | Sort-Object) -join ' | ')
    }

    return $associationMap
}

# Returns a stable column projection for CSV, XLSX, and GridView, even when mixed result
# objects do not all expose the same properties.
function Get-ResultExportColumns {
    return @(
        'SubscriptionId',
        'SubscriptionName',
        'FrontDoorName',
        'FrontDoorType',
        'MigrationSourceResourceId',
        'MigrationTargetResourceId',
        'EndpointAssociation',
        'Domain',
        'CertificateType',
        'ProvisioningState',
        'ValidationState',
        'Subject',
        'Issuer',
        'IssuingCA',
        'ServerCertificateCount',
        'IntermediateCA',
        'RootCA',
        'ChainStatus',
        'DigiCertIssued',
        'ExpirationDate',
        'KeyVaultName',
        'KeyVaultSecretName'
    )
}

# Projects records for XLSX export while preserving a typed ExpirationDate cell.
function Get-XlsxExportRecords {
    param(
        [Parameter(Mandatory)]
        [object[]]$Results,

        [Parameter(Mandatory)]
        [string[]]$Columns
    )

    $xlsxRecords = foreach ($result in $Results) {
        $record = [ordered]@{}
        foreach ($column in $Columns) {
            $record[$column] = $result.$column
        }

        $rawExpirationDate = $null
        $rawExpirationDateProperty = $result.PSObject.Properties['ExpirationDateRaw']
        if ($null -ne $rawExpirationDateProperty) {
            $rawExpirationDate = $rawExpirationDateProperty.Value
        }

        if ($rawExpirationDate) {
            try {
                $record['ExpirationDate'] = $rawExpirationDate -is [DateTime] ? $rawExpirationDate : [DateTime]::Parse($rawExpirationDate.ToString())
            }
            catch {
                $record['ExpirationDate'] = $result.ExpirationDate
            }
        }

        [PSCustomObject]$record
    }

    return @($xlsxRecords)
}

# Extracts classic-to-Standard/Premium migration links from ARM resource metadata.
function Get-FrontDoorMigrationMetadata {
    param(
        [Parameter(Mandatory = $false)]
        [object]$Resource,

        [Parameter(Mandatory)]
        [ValidateSet('Standard/Premium', 'Classic')]
        [string]$FrontDoorType
    )

    $migrationInfo = @{
        MigrationSourceResourceId = $null
        MigrationTargetResourceId = $null
    }

    if (-not $Resource) {
        return $migrationInfo
    }

    $properties = $Resource.Properties
    if (-not $properties) {
        $properties = $Resource.properties
    }

    if ($properties -is [string]) {
        try {
            $properties = $properties | ConvertFrom-Json -Depth 20
        }
        catch {
            $properties = $null
        }
    }

    if (-not $properties) {
        return $migrationInfo
    }

    $extendedProperties = $properties.extendedProperties
    if ($extendedProperties -is [string]) {
        try {
            $extendedProperties = $extendedProperties | ConvertFrom-Json -Depth 10
        }
        catch {
            $extendedProperties = $null
        }
    }

    if (-not $extendedProperties) {
        return $migrationInfo
    }

    if ($FrontDoorType -eq 'Standard/Premium') {
        $migrationInfo.MigrationSourceResourceId = [string]$extendedProperties.MigratedFrom
        if ([string]::IsNullOrWhiteSpace($migrationInfo.MigrationSourceResourceId)) {
            $migrationInfo.MigrationSourceResourceId = $null
        }
    }
    else {
        $migrationInfo.MigrationTargetResourceId = [string]$extendedProperties.MigratedTo
        if ([string]::IsNullOrWhiteSpace($migrationInfo.MigrationTargetResourceId)) {
            $migrationInfo.MigrationTargetResourceId = $null
        }
    }

    return $migrationInfo
}

# Reduces an ARM resource ID to the terminal Front Door name for compact console output.
function Get-FrontDoorMigrationDisplayName {
    param(
        [Parameter(Mandatory = $false)]
        [string]$ResourceId
    )

    if ([string]::IsNullOrWhiteSpace($ResourceId)) {
        return $null
    }

    $segments = $ResourceId.TrimEnd('/') -split '/'
    if ($segments.Count -gt 0) {
        return $segments[-1]
    }

    return $ResourceId
}

# Creates the parent directory for an export path when it does not exist yet.
function Initialize-ParentDirectoryPath {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath
    )

    $resolvedFilePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePath)
    $parentDirectory = Split-Path -Parent $resolvedFilePath
    if ($parentDirectory -and -not (Test-Path -LiteralPath $parentDirectory)) {
        $null = New-Item -ItemType Directory -Path $parentDirectory -Force
    }

    return $resolvedFilePath
}

# Redirects exports to a timestamped sibling path when the requested file is locked.
function Resolve-AvailableExportFilePath {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath
    )

    $resolvedFilePath = Initialize-ParentDirectoryPath -FilePath $FilePath
    $parentDirectory = Split-Path -Parent $resolvedFilePath
    $fileName = [System.IO.Path]::GetFileName($resolvedFilePath)
    $fileExtension = [System.IO.Path]::GetExtension($resolvedFilePath)
    $fileNameBase = [System.IO.Path]::GetFileNameWithoutExtension($resolvedFilePath)
    $lockFilePath = $null

    if ($fileExtension -eq '.xlsx') {
        $lockFilePath = Join-Path $parentDirectory ("~$" + $fileName)
    }

    $canWriteRequestedPath = $true
    if (Test-Path -LiteralPath $resolvedFilePath) {
        $stream = $null
        try {
            $stream = [System.IO.File]::Open($resolvedFilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        }
        catch {
            $canWriteRequestedPath = $false
        }
        finally {
            if ($stream) {
                $stream.Dispose()
            }
        }
    }

    if (($lockFilePath -and (Test-Path -LiteralPath $lockFilePath)) -or -not $canWriteRequestedPath) {
        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
        $candidatePath = Join-Path $parentDirectory ("{0}-{1}{2}" -f $fileNameBase, $timestamp, $fileExtension)
        $attempt = 1
        while (Test-Path -LiteralPath $candidatePath) {
            $candidatePath = Join-Path $parentDirectory ("{0}-{1}-{2}{3}" -f $fileNameBase, $timestamp, $attempt, $fileExtension)
            $attempt++
        }

        return @{
            Path = $candidatePath
            Redirected = $true
        }
    }

    return @{
        Path = $resolvedFilePath
        Redirected = $false
    }
}

# Export-Excel writes the correct table style and freeze pane metadata when it saves directly,
# but reopening and resaving through EPPlus in this environment strips that metadata.
# Patch the table XML in place so the workbook keeps the same Medium2 table style used by
# Get-AFDOriginCertChains, with row banding disabled.
function Set-XlsxTableStyleInfo {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$TableStyleName
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $zip = [System.IO.Compression.ZipFile]::Open($resolvedPath, [System.IO.Compression.ZipArchiveMode]::Update)
    try {
        $tableEntries = @($zip.Entries | Where-Object { $_.FullName -like 'xl/tables/table*.xml' })
        foreach ($tableEntry in $tableEntries) {
            $reader = [System.IO.StreamReader]::new($tableEntry.Open())
            try {
                $tableXmlText = [System.String]::Copy($reader.ReadToEnd())
            }
            finally {
                $reader.Dispose()
            }

            $updatedTableXmlText = $tableXmlText
            $updatedTableXmlText = $updatedTableXmlText -replace '(<tableStyleInfo\b[^>]*\bname=")[^"]+(")', ('$1{0}$2' -f $TableStyleName)
            $updatedTableXmlText = $updatedTableXmlText -replace '(showFirstColumn=")[^"]+(")', '${1}0$2'
            $updatedTableXmlText = $updatedTableXmlText -replace '(showLastColumn=")[^"]+(")', '${1}0$2'
            $updatedTableXmlText = $updatedTableXmlText -replace '(showRowStripes=")[^"]+(")', '${1}0$2'
            $updatedTableXmlText = $updatedTableXmlText -replace '(showColumnStripes=")[^"]+(")', '${1}0$2'

            if ($updatedTableXmlText -eq $tableXmlText) {
                continue
            }

            $tableEntryPath = $tableEntry.FullName
            $tableEntry.Delete()
            $newTableEntry = $zip.CreateEntry($tableEntryPath)
            $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
            $writer = [System.IO.StreamWriter]::new($newTableEntry.Open(), $utf8NoBom)
            try {
                $writer.Write($updatedTableXmlText)
            }
            finally {
                $writer.Dispose()
            }
        }
    }
    finally {
        $zip.Dispose()
    }
}

#endregion

#region Get-TruncatedString

# Truncates display strings so the console table stays readable.
function Get-TruncatedString {
    param(
        [string]$text,
        [int]$maxLength
    )
    
    if (-not $text -or $text.Length -le $maxLength) {
        return $text
    }
    
    return $text.Substring(0, $maxLength - 3) + "..."
}

#endregion

#region Dynamic Column Width Calculation

# Fits the console table into the current window while protecting key columns.
function Get-DynamicColumnWidths {
    param(
        [bool]$hasValidationState,
        [int]$minWidth = 80
    )
    
    # Default to a reasonable width when the host cannot report console dimensions.
    try {
        $consoleWidth = $Host.UI.RawUI.WindowSize.Width
        if ($consoleWidth -lt $minWidth) { $consoleWidth = $minWidth }
    }
    catch {
        $consoleWidth = 160
    }
    
    # Reserve a small padding budget for separators.
    $availableWidth = $consoleWidth - 10
    
    # Minimum widths keep the table usable on narrow consoles.
    $minWidths = @{
        Subscription = 15
        FrontDoor = 15
        FDType = 7
        MigSource = 12
        MigTarget = 12
        Domain = 25
        Endpoint = 14
        CertType = 8
        ProvState = 10
        ValState = 10
        Subject = 10
        IssuingCA = 12
        RootCA = 12
        ExpirationDate = 22
        KVName = 15
        KVSecret = 8
    }
    
    # Ideal widths consume extra space on wider consoles without changing column order.
    $idealWidths = @{
        Subscription = 25
        FrontDoor = 26
        FDType = 7
        MigSource = 18
        MigTarget = 18
        Domain = 38
        Endpoint = 22
        CertType = 11
        ProvState = 12
        ValState = 12
        Subject = 25
        IssuingCA = 24
        RootCA = 24
        ExpirationDate = 22
        KVName = 22
        KVSecret = 20
    }
    
    # Show validation state only when Standard/Premium rows are present.
    $columns = @('Subscription', 'FrontDoor', 'FDType', 'MigSource', 'MigTarget', 'Domain', 'Endpoint', 'CertType', 'ProvState')
    if ($hasValidationState) { $columns += 'ValState' }
    $columns += @('Subject', 'IssuingCA', 'RootCA', 'ExpirationDate', 'KVName', 'KVSecret')
    
    $minRequired = ($columns | ForEach-Object { $minWidths[$_] + 1 } | Measure-Object -Sum).Sum
    
    if ($availableWidth -gt $minRequired) {
        $extraSpace = $availableWidth - $minRequired
        $totalIdealExtra = ($columns | ForEach-Object { $idealWidths[$_] - $minWidths[$_] } | Measure-Object -Sum).Sum
        
        $widths = @{}
        foreach ($col in $columns) {
            if ($totalIdealExtra -gt 0) {
                $idealExtra = $idealWidths[$col] - $minWidths[$col]
                $allocation = [Math]::Floor($extraSpace * ($idealExtra / $totalIdealExtra))
                $widths[$col] = [Math]::Min($minWidths[$col] + $allocation, $idealWidths[$col])
            } else {
                $widths[$col] = $minWidths[$col]
            }
        }
    } else {
        $widths = @{}
        foreach ($col in $columns) {
            $widths[$col] = $minWidths[$col]
        }
    }
    
    return $widths
}

#endregion

#region Date Formatting

# Formats an expiration date consistently and classifies it against WarningDays.
function Get-FormattedExpirationDate {
    param(
        [object]$expiryDate,
        [int]$warningDays
    )
    
    if (-not $expiryDate) {
        return @{ Display = $null; Status = 'OK'; Value = $null }
    }
    
    try {
        # Handle both string and DateTime objects
        $expiryDateTime = $expiryDate -is [DateTime] ? $expiryDate : [DateTime]::Parse($expiryDate)
        
        $formattedDate = $expiryDateTime.ToString()
        $daysUntilExpiry = ($expiryDateTime - (Get-Date)).Days
        
        $status = $daysUntilExpiry -lt 0 ? 'EXPIRED' : ($daysUntilExpiry -le $warningDays ? 'WARNING' : 'OK')
        
        return @{ Display = $formattedDate; Status = $status; Value = $expiryDateTime }
    } catch {
        # If date parsing fails, use the original value
        return @{ Display = $expiryDate; Status = 'OK'; Value = $null }
    }
}

#endregion

#region Get All Front Doors in Subscription

# Enumerates Front Door profiles in the current subscription using Az cmdlets.
function Get-AllFrontDoorsInSubscription {
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet('All', 'StandardPremium', 'Classic')]
        [string]$TypeFilter = 'All'
    )
    
    $frontDoors = @()
    
    Write-Host "  Discovering Front Door profiles..." -ForegroundColor Cyan
    if ($TypeFilter -ne 'All') {
        Write-Host "    Filtering by type: $TypeFilter" -ForegroundColor Cyan
    }
    
    # Get Standard/Premium Front Doors (Microsoft.Cdn/profiles with AzureFrontDoor SKU)
    if ($TypeFilter -eq 'All' -or $TypeFilter -eq 'StandardPremium') {
        try {
            $cdnProfiles = Get-AzResource -ResourceType "Microsoft.Cdn/profiles" -ExpandProperties -ErrorAction SilentlyContinue
            $afdProfiles = $cdnProfiles | Where-Object { 
                $_.Sku.Name -eq 'Standard_AzureFrontDoor' -or $_.Sku.Name -eq 'Premium_AzureFrontDoor'
            }
            
            foreach ($afdProfile in $afdProfiles) {
                $migrationInfo = Get-FrontDoorMigrationMetadata -Resource $afdProfile -FrontDoorType 'Standard/Premium'
                $frontDoors += [PSCustomObject]@{
                    Name                      = $afdProfile.Name
                    ResourceGroupName         = $afdProfile.ResourceGroupName
                    Type                      = 'Standard/Premium'
                    MigrationSourceResourceId = $migrationInfo.MigrationSourceResourceId
                    MigrationTargetResourceId = $migrationInfo.MigrationTargetResourceId
                }
            }
            Write-Host "    Found $($afdProfiles.Count) Standard/Premium Front Door(s)" -ForegroundColor Green
        }
        catch {
            Write-Host "    Failed to query Standard/Premium Front Doors: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    
    # Get Classic Front Doors
    if ($TypeFilter -eq 'All' -or $TypeFilter -eq 'Classic') {
        try {
            $classicFDs = Get-AzResource -ResourceType "Microsoft.Network/frontdoors" -ExpandProperties -ErrorAction SilentlyContinue
            foreach ($fd in $classicFDs) {
                $migrationInfo = Get-FrontDoorMigrationMetadata -Resource $fd -FrontDoorType 'Classic'
                $frontDoors += [PSCustomObject]@{
                    Name                      = $fd.Name
                    ResourceGroupName         = $fd.ResourceGroupName
                    Type                      = 'Classic'
                    MigrationSourceResourceId = $migrationInfo.MigrationSourceResourceId
                    MigrationTargetResourceId = $migrationInfo.MigrationTargetResourceId
                }
            }
            Write-Host "    Found $($classicFDs.Count) Classic Front Door(s)" -ForegroundColor Green
        }
        catch {
            Write-Host "    Failed to query Classic Front Doors: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    
    return $frontDoors
}

#endregion

#region Get All Front Doors in Tenant (Resource Graph via REST API)

# Enumerates Front Door profiles across subscriptions through Resource Graph REST.
function Get-AllFrontDoorsInTenant {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Headers,

        [Parameter(Mandatory)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [ValidateSet('All', 'StandardPremium', 'Classic')]
        [string]$TypeFilter = 'All'
    )
    
    Write-Host "Querying Azure Resource Graph for all Front Door profiles..." -ForegroundColor Cyan
    if ($TypeFilter -ne 'All') {
        Write-Host "  Filtering by type: $TypeFilter" -ForegroundColor Cyan
    }
    
    $frontDoors = [System.Collections.Generic.List[PSCustomObject]]::new()
    
    # Combined query for all Front Door types
    $queryAll = @"
resources
| where type in~ ('microsoft.cdn/profiles', 'microsoft.network/frontdoors')
| extend skuName = tostring(sku.name)
    | extend ext = todynamic(properties.extendedProperties)
| extend deploymentModel = case(type =~ 'microsoft.network/frontdoors', 'Classic', 'Standard/Premium')
    | extend migrationSourceResourceId = iff(type =~ 'microsoft.cdn/profiles', tostring(ext.MigratedFrom), '')
    | extend migrationTargetResourceId = iff(type =~ 'microsoft.network/frontdoors', tostring(ext.MigratedTo), '')
| where type =~ 'microsoft.network/frontdoors' or skuName in~ ('Standard_AzureFrontDoor', 'Premium_AzureFrontDoor')
    | project name, resourceGroup, subscriptionId, type, deploymentModel, migrationSourceResourceId, migrationTargetResourceId
| order by subscriptionId, name
"@

    # Query for Standard/Premium only
    $queryStdPremium = @"
resources
| where type == 'microsoft.cdn/profiles'
| where sku.name in ('Standard_AzureFrontDoor', 'Premium_AzureFrontDoor')
    | extend ext = todynamic(properties.extendedProperties)
    | extend migrationSourceResourceId = tostring(ext.MigratedFrom)
    | project name, resourceGroup, subscriptionId, type, migrationSourceResourceId
| order by subscriptionId, name
"@

    # Query for Classic only
    $queryClassic = @"
resources
| where type == 'microsoft.network/frontdoors'
    | extend ext = todynamic(properties.extendedProperties)
    | extend migrationTargetResourceId = tostring(ext.MigratedTo)
    | project name, resourceGroup, subscriptionId, type, migrationTargetResourceId
| order by subscriptionId, name
"@

    # Select query based on filter
    $query = switch ($TypeFilter) {
        'StandardPremium' { $queryStdPremium }
        'Classic' { $queryClassic }
        default { $queryAll }
    }

    try {
        Write-Host "  Executing Resource Graph query via REST API..." -ForegroundColor Cyan
        $results = Invoke-ResourceGraphQueryAllPages -Headers $Headers -SubscriptionIds $SubscriptionIds -Query $query
        
        foreach ($result in $results) {
            $fdType = if ($result.type -eq 'microsoft.network/frontdoors') { 'Classic' } 
                      elseif ($result.deploymentModel) { $result.deploymentModel }
                      else { 'Standard/Premium' }
            
            $frontDoors.Add([PSCustomObject]@{
                Name                      = $result.name
                ResourceGroupName         = $result.resourceGroup
                SubscriptionId            = $result.subscriptionId
                Type                      = $fdType
                MigrationSourceResourceId = if ([string]::IsNullOrWhiteSpace([string]$result.migrationSourceResourceId)) { $null } else { [string]$result.migrationSourceResourceId }
                MigrationTargetResourceId = if ([string]::IsNullOrWhiteSpace([string]$result.migrationTargetResourceId)) { $null } else { [string]$result.migrationTargetResourceId }
            })
        }
        
        # Show breakdown by type
        $stdPremCount = ($frontDoors | Where-Object { $_.Type -eq 'Standard/Premium' }).Count
        $classicCount = ($frontDoors | Where-Object { $_.Type -eq 'Classic' }).Count
        if ($TypeFilter -eq 'All' -or $TypeFilter -eq 'StandardPremium') {
            Write-Host "    Found $stdPremCount Standard/Premium Front Door(s)" -ForegroundColor Green
        }
        if ($TypeFilter -eq 'All' -or $TypeFilter -eq 'Classic') {
            Write-Host "    Found $classicCount Classic Front Door(s)" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "    Failed to query Front Doors via Resource Graph REST API: $($_.Exception.Message)" -ForegroundColor Yellow
        throw
    }
    
    Write-Host "  Total: $($frontDoors.Count) Front Door profile(s) found across tenant`n" -ForegroundColor Cyan
    
    return @($frontDoors)
}

#endregion

#region Front Door Certificate Processing

# Collects certificate details for a single Front Door profile in the active subscription.
function Get-FrontDoorCertificates {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FrontDoorName,
        
        [Parameter(Mandatory = $false)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        [int]$WarningDays
    )
    
    $results = @()
    
    # Get current context
    $context = Get-AzContext
    
    $rgDisplay = if ($ResourceGroupName) { ", resource group: $ResourceGroupName" } else { "" }
    Write-Host "Looking for Front Door profile: $FrontDoorName in subscription: $($context.Subscription.Name)$rgDisplay..." -ForegroundColor Cyan

    # Try to find Standard/Premium Front Door first
    if ($ResourceGroupName) {
        $fd = Get-AzResource -Name $FrontDoorName -ResourceGroupName $ResourceGroupName -ResourceType "Microsoft.Cdn/profiles" -ExpandProperties -ErrorAction SilentlyContinue
    } else {
        $fd = Get-AzResource -Name $FrontDoorName -ResourceType "Microsoft.Cdn/profiles" -ExpandProperties -ErrorAction SilentlyContinue
    }

    $migrationInfo = @{
        MigrationSourceResourceId = $null
        MigrationTargetResourceId = $null
    }

    # If not found, try Classic Front Door
    if (-not $fd) {
        if ($ResourceGroupName) {
            $fdClassic = Get-AzFrontDoor -Name $FrontDoorName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
        } else {
            $fdClassic = Get-AzFrontDoor -Name $FrontDoorName -ErrorAction SilentlyContinue
        }
        if ($fdClassic) {
            Write-Host "  Found Classic Front Door: $FrontDoorName" -ForegroundColor Green
            $isClassic = $true
        } else {
            Write-Host "  Front Door profile '$FrontDoorName' not found in subscription (checked both Standard/Premium and Classic)." -ForegroundColor Yellow
            return $results
        }
    } else {
        Write-Host "  Found Standard/Premium Front Door: $($fd.Name) in resource group: $($fd.ResourceGroupName)" -ForegroundColor Green
        $isClassic = $false
        $migrationInfo = Get-FrontDoorMigrationMetadata -Resource $fd -FrontDoorType 'Standard/Premium'
    }

    if ($isClassic) {
        # ===========================
        # CLASSIC FRONT DOOR LOGIC
        # ===========================
        
        Write-Host "  Retrieving custom domains..."
        
        # Get resource group from the Classic Front Door object
        $classicRg = $fdClassic.ResourceGroupName
        if (-not $classicRg -and $ResourceGroupName) {
            $classicRg = $ResourceGroupName
        }

        $fdClassicResource = Get-AzResource -Name $FrontDoorName -ResourceGroupName $classicRg -ResourceType "Microsoft.Network/frontdoors" -ExpandProperties -ErrorAction SilentlyContinue
        $migrationInfo = Get-FrontDoorMigrationMetadata -Resource $fdClassicResource -FrontDoorType 'Classic'
        
        # Get all frontend endpoints (custom domains) from Classic Front Door using explicit parameters
        try {
            $endpoints = Get-AzFrontDoorFrontendEndpoint -FrontDoorName $FrontDoorName -ResourceGroupName $classicRg -ErrorAction Stop
        }
        catch {
            Write-Host "  Failed to retrieve endpoints: $($_.Exception.Message)" -ForegroundColor Yellow
            $endpoints = $null
        }
        
        if (-not $endpoints -or $endpoints.Count -eq 0) {
            Write-Host "  No custom domains found for Classic Front Door $FrontDoorName" -ForegroundColor Yellow
        } else {
            $eligibleEndpoints = @(
                $endpoints | Where-Object {
                    $endpointHostName = if ([string]::IsNullOrWhiteSpace([string]$_.HostName)) { [string]$_.Name } else { [string]$_.HostName }
                    -not (Test-IsDefaultAzureFrontDoorHostname -HostName $endpointHostName)
                }
            )
            $skippedDefaultEndpoints = @($endpoints).Count - $eligibleEndpoints.Count

            if ($skippedDefaultEndpoints -gt 0) {
                Write-Host "  Skipping $skippedDefaultEndpoints default Azure Front Door endpoint(s)." -ForegroundColor Gray
            }

            if (-not $eligibleEndpoints -or $eligibleEndpoints.Count -eq 0) {
                Write-Host "  No non-default custom domains found for Classic Front Door $FrontDoorName" -ForegroundColor Yellow
                return $results
            }

            Write-Host "  Found $($eligibleEndpoints.Count) custom domain(s). Processing..."
            
            foreach ($ep in $eligibleEndpoints) {
                $domainName = $ep.HostName ?? $ep.Name
                $endpointAssociation = $ep.Name
                
                Write-Host "    Fetching certificate for: $domainName..." -NoNewline
                
                # Initialize fields
                $certSource = $ep.CertificateSource
                $provisioningState = $ep.CustomHttpsProvisioningState
                $expiryDate = $null
                $subject = $null
                $issuer = $null
                $issuingCA = $null
                $serverCertificateCount = $null
                $intermediateCA = $null
                $rootCA = $null
                $chainStatus = $null
                $digiCertIssued = $null
                $statusErrors = [System.Collections.Generic.List[string]]::new()
                $keyVaultName = $null
                $keyVaultSecretName = $null
                # Classic rows keep ValidationState blank so mixed exports use one schema.
                $validationState = $null
                
                # Extract Key Vault details if present
                if ($ep.Vault) {
                    $keyVaultSecretName = $ep.SecretName
                    $keyVaultName = ($ep.Vault -split '/')[-1]
                }
                
                # Fetch certificate from domain using TcpClient + SslStream
                # Uses proxy if detected at startup ($script:ProxyUri)
                try {
                    $cert = Invoke-WithRetry -Action { Get-CertificateFromDomain -DomainName $domainName } -OperationName "TLS probe for $domainName" -Category Tls -MaxAttempts $TlsRetryCount -BaseDelayMs $RetryBaseDelayMs
                    if ($cert) {
                        $certDetails = Get-CertificateChainDetails -Certificate $cert
                        $expiryDate = $cert.NotAfter
                        $subject = $certDetails.Subject
                        $issuer = $certDetails.Issuer
                        $issuingCA = $certDetails.IssuingCA
                        $serverCertificateCount = $certDetails.ServerCertificateCount
                        $intermediateCA = $certDetails.IntermediateCA
                        $rootCA = $certDetails.RootCA
                        $chainStatus = $certDetails.ChainStatus
                        $digiCertIssued = $certDetails.DigiCertIssued
                    }
                    
                    Write-Host " OK" -ForegroundColor Green
                } catch {
                    $errorMsg = Get-ExceptionMessageSummary -Exception $_.Exception
                    $null = $statusErrors.Add($errorMsg)
                    Write-Host " Failed: $errorMsg" -ForegroundColor Yellow
                }
                
                # Format expiration date with status indicators
                $expiryInfo = Get-FormattedExpirationDate -expiryDate $expiryDate -warningDays $WarningDays
                $expiryDisplay = $expiryInfo.Display
                $expiryStatus = $expiryInfo.Status
                $expiryRaw = $expiryInfo.Value
                $overallStatus = Get-CertificateStatusSummary -ChainStatus $chainStatus -ExpirationStatus $expiryStatus -StatusItems @($statusErrors) -HasExpirationDate ($null -ne $expiryRaw)
                
                $result = [PSCustomObject]@{
                    SubscriptionId     = $context.Subscription.Id
                    SubscriptionName   = $context.Subscription.Name
                    FrontDoorName      = $FrontDoorName
                    FrontDoorType      = 'Classic'
                    MigrationSourceResourceId = $migrationInfo.MigrationSourceResourceId
                    MigrationTargetResourceId = $migrationInfo.MigrationTargetResourceId
                    EndpointAssociation = $endpointAssociation
                    Domain             = $domainName
                    CertificateType    = $certSource
                    ProvisioningState  = $provisioningState
                    ValidationState    = $validationState
                    Subject            = $subject
                    Issuer             = $issuer
                    IssuingCA          = $issuingCA
                    ServerCertificateCount = $serverCertificateCount
                    IntermediateCA         = $intermediateCA
                    RootCA                 = $rootCA
                    ChainStatus            = $overallStatus
                    DigiCertIssued         = $digiCertIssued
                    ExpirationDateRaw  = $expiryRaw
                    ExpirationDate     = $expiryDisplay
                    ExpirationStatus   = $expiryStatus
                    KeyVaultName       = $keyVaultName
                    KeyVaultSecretName = $keyVaultSecretName
                }
                
                $results += $result
            }
        }
        
    } else {
        # =================================
        # STANDARD/PREMIUM FRONT DOOR LOGIC
        # =================================
        
        $fdName = $fd.Name
        $rgName = $fd.ResourceGroupName
        $subscriptionId = $context.Subscription.Id

        Write-Host "  Retrieving custom domains..."

        # Get custom domains via REST API
        try {
            $pathDomains = "/subscriptions/$subscriptionId/resourceGroups/$rgName/providers/Microsoft.Cdn/profiles/$fdName/customDomains?api-version=$ApiVersion"
            $domainsResp = Invoke-WithRetry -Action {
                Invoke-AzRest -Path $pathDomains -Method GET -ErrorAction Stop
            } -OperationName "custom domains lookup for $fdName" -Category Rest -MaxAttempts $RestRetryCount -BaseDelayMs $RetryBaseDelayMs
            $domains = ($domainsResp.Content | ConvertFrom-Json).value
        }
        catch {
            Write-Host "  Failed to query custom domains for ${fdName}: $($_.Exception.Message)" -ForegroundColor Red
            return $results
        }

        if (-not $domains -or $domains.Count -eq 0) {
            Write-Host "  No custom domains found for $fdName" -ForegroundColor Yellow
        }
        else {
            $eligibleDomains = @(
                $domains | Where-Object {
                    $domainHostName = if ([string]::IsNullOrWhiteSpace([string]$_.properties.hostName)) { [string]$_.name } else { [string]$_.properties.hostName }
                    -not (Test-IsDefaultAzureFrontDoorHostname -HostName $domainHostName)
                }
            )
            $skippedDefaultDomains = @($domains).Count - $eligibleDomains.Count

            if ($skippedDefaultDomains -gt 0) {
                Write-Host "  Skipping $skippedDefaultDomains default Azure Front Door endpoint(s)." -ForegroundColor Gray
            }

            if (-not $eligibleDomains -or $eligibleDomains.Count -eq 0) {
                Write-Host "  No non-default custom domains found for $fdName" -ForegroundColor Yellow
                return $results
            }

            Write-Host "  Found $($eligibleDomains.Count) custom domain(s). Processing..."

            $domainEndpointAssociations = @{}
            try {
                $domainEndpointAssociations = Get-AfdCustomDomainEndpointAssociations `
                    -SubscriptionId $subscriptionId `
                    -ResourceGroupName $rgName `
                    -ProfileName $fdName `
                    -ApiVersion $ApiVersion `
                    -RestRetryCount $RestRetryCount `
                    -RetryBaseDelayMs $RetryBaseDelayMs
            }
            catch {
                $associationError = Get-ExceptionMessageSummary -Exception $_.Exception
                Write-Host "  Failed to resolve endpoint associations for ${fdName}: $associationError" -ForegroundColor Yellow
            }

            foreach ($d in $eligibleDomains) {
                # Initialize fields
                $certSource = $null
                $provisioningState = $null
                $expiryDate = $null
                $keyVaultName = $null
                $keyVaultSecretName = $null
                $validationState = $null
                $subject = $null
                $issuer = $null
                $issuingCA = $null
                $serverCertificateCount = $null
                $intermediateCA = $null
                $rootCA = $null
                $chainStatus = $null
                $digiCertIssued = $null
                $statusErrors = [System.Collections.Generic.List[string]]::new()
                
                $domainName = $d.properties.hostName ?? $d.name
                $domainAssociation = 'Unassociated'
                $domainResourceId = [string]$d.id
                if (-not [string]::IsNullOrWhiteSpace($domainResourceId)) {
                    $domainKey = $domainResourceId.ToLowerInvariant()
                    if ($domainEndpointAssociations.ContainsKey($domainKey) -and -not [string]::IsNullOrWhiteSpace([string]$domainEndpointAssociations[$domainKey])) {
                        $domainAssociation = [string]$domainEndpointAssociations[$domainKey]
                    }
                }

                # Get provisioning state
                if ($d.properties.provisioningState) { $provisioningState = $d.properties.provisioningState }
                if ($d.properties.domainValidationState) { $validationState = $d.properties.domainValidationState }

                # Get TLS settings
                if ($d.properties.tlsSettings) {
                    $tls = $d.properties.tlsSettings
                    if ($tls.certificateType) { 
                        $certSource = switch ($tls.certificateType) {
                            'ManagedCertificate' { 'Managed' }
                            'CustomerCertificate' { 'KeyVault' }
                            default { $tls.certificateType }
                        }
                    }
                    
                    # Fetch certificate details from secret
                    if ($tls.secret -and $tls.secret.id) {
                        $secretId = $tls.secret.id
                        
                        try {
                            Write-Host "    Fetching certificate details for: $domainName..." -NoNewline
                            $secretPath = "$secretId`?api-version=$ApiVersion"
                            $secretResp = Invoke-WithRetry -Action { Invoke-AzRest -Path $secretPath -Method GET -ErrorAction Stop } -OperationName "certificate secret lookup for $domainName" -Category Rest -MaxAttempts $RestRetryCount -BaseDelayMs $RetryBaseDelayMs
                            $secret = ($secretResp.Content | ConvertFrom-Json)
                            
                            if ($secret.properties -and $secret.properties.parameters) {
                                $params = $secret.properties.parameters
                                
                                if ($params.expirationDate) { 
                                    $expiryDate = $params.expirationDate 
                                }
                                if ($params.subject) {
                                    $subject = $params.subject
                                }
                                if ($params.certificateAuthority) {
                                    $issuingCA = [string]$params.certificateAuthority
                                }
                                if ($params.issuer) {
                                    $issuer = [string]$params.issuer
                                }
                                
                                # For Customer Certificates, extract Key Vault details
                                if ($params.type -eq 'CustomerCertificate' -and $params.secretSource -and $params.secretSource.id) {
                                    $kvSecretId = $params.secretSource.id
                                    if ($kvSecretId -match '/vaults/([^/]+)/') { $keyVaultName = $matches[1] }
                                    if ($kvSecretId -match '/secrets/([^/]+)') { $keyVaultSecretName = $matches[1] }
                                }

                                $issuerDetails = Get-IssuerDetails -IssuerString $issuer -IssuingCAName $issuingCA
                                $issuer = $issuerDetails.Issuer
                                $issuingCA = $issuerDetails.IssuingCA
                            }
                            Write-Host " OK" -ForegroundColor Green
                        }
                        catch {
                            $errorMsg = Get-ExceptionMessageSummary -Exception $_.Exception
                            $null = $statusErrors.Add("SecretLookup: $errorMsg")
                            Write-Host " Failed: $errorMsg" -ForegroundColor Yellow
                        }
                    }
                }

                if ($domainName) {
                    try {
                        $liveCert = Invoke-WithRetry -Action { Get-CertificateFromDomain -DomainName $domainName } -OperationName "TLS probe for $domainName" -Category Tls -MaxAttempts $TlsRetryCount -BaseDelayMs $RetryBaseDelayMs
                        if ($liveCert) {
                            $certDetails = Get-CertificateChainDetails -Certificate $liveCert -IssuerString $issuer -IssuingCAName $issuingCA
                            if (-not $subject) { $subject = $certDetails.Subject }
                            if (-not $expiryDate) { $expiryDate = $liveCert.NotAfter }
                            $issuer = $certDetails.Issuer
                            $issuingCA = $certDetails.IssuingCA
                            $serverCertificateCount = $certDetails.ServerCertificateCount
                            $intermediateCA = $certDetails.IntermediateCA
                            $rootCA = $certDetails.RootCA
                            $chainStatus = $certDetails.ChainStatus
                            $digiCertIssued = $certDetails.DigiCertIssued
                        }
                    }
                    catch {
                        $errorMsg = Get-ExceptionMessageSummary -Exception $_.Exception
                        $null = $statusErrors.Add("TLS: $errorMsg")
                    }
                }

                # Format expiration date with status indicators
                $expiryInfo = Get-FormattedExpirationDate -expiryDate $expiryDate -warningDays $WarningDays
                $expiryDisplay = $expiryInfo.Display
                $expiryStatus = $expiryInfo.Status
                $expiryRaw = $expiryInfo.Value
                $overallStatus = Get-CertificateStatusSummary -ChainStatus $chainStatus -ExpirationStatus $expiryStatus -StatusItems @($statusErrors) -HasExpirationDate ($null -ne $expiryRaw)

                $result = [PSCustomObject]@{
                    SubscriptionId     = $context.Subscription.Id
                    SubscriptionName   = $context.Subscription.Name
                    FrontDoorName      = $FrontDoorName
                    FrontDoorType      = 'Standard/Premium'
                    MigrationSourceResourceId = $migrationInfo.MigrationSourceResourceId
                    MigrationTargetResourceId = $migrationInfo.MigrationTargetResourceId
                    EndpointAssociation = $domainAssociation
                    Domain             = $domainName
                    CertificateType    = $certSource
                    ProvisioningState  = $provisioningState
                    ValidationState    = $validationState
                    Subject            = $subject
                    Issuer             = $issuer
                    IssuingCA          = $issuingCA
                    ServerCertificateCount = $serverCertificateCount
                    IntermediateCA         = $intermediateCA
                    RootCA                 = $rootCA
                    ChainStatus            = $overallStatus
                    DigiCertIssued         = $digiCertIssued
                    ExpirationDateRaw  = $expiryRaw
                    ExpirationDate     = $expiryDisplay
                    ExpirationStatus   = $expiryStatus
                    KeyVaultName       = $keyVaultName
                    KeyVaultSecretName = $keyVaultSecretName
                }

                $results += $result
            }
        }
    }
    
    return $results
}

#endregion

# Main execution logic
Write-Host "`n=== Azure Front Door Certificate Checker ===" -ForegroundColor Cyan
Write-Host "Execution Mode: $($PSCmdlet.ParameterSetName)`n" -ForegroundColor Cyan

if ($PSCmdlet.ParameterSetName -eq 'SingleFrontDoor') {
    # Single Front Door mode
    $results = Get-FrontDoorCertificates -FrontDoorName $ScanFrontDoor -ResourceGroupName $ResourceGroupName -WarningDays $WarningDays
    $results | ForEach-Object { $allResults.Add($_) }
} 
elseif ($PSCmdlet.ParameterSetName -eq 'ScanSubscription') {
    # Subscription scanning mode
    if ($ScanSubscription) {
        Write-Host "Switching to subscription: $ScanSubscription..." -ForegroundColor Cyan
        try {
            $null = Set-AzContext -Subscription $ScanSubscription -ErrorAction Stop
        }
        catch {
            throw "Failed to switch to subscription '$ScanSubscription': $($_.Exception.Message)"
        }
    }
    
    $context = Get-AzContext
    Write-Host "Scanning subscription: $($context.Subscription.Name) ($($context.Subscription.Id))" -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Yellow
    
    # Get all Front Doors in the subscription
    $frontDoors = Get-AllFrontDoorsInSubscription -TypeFilter $FrontDoorType
    
    if ($frontDoors.Count -eq 0) {
        Write-Host "  No Front Door profiles found in this subscription" -ForegroundColor Yellow
    } else {
        Write-Host "  Processing $($frontDoors.Count) Front Door profile(s)...`n" -ForegroundColor Cyan
        
        foreach ($fd in $frontDoors) {
            $fdResults = Get-FrontDoorCertificates `
                -FrontDoorName $fd.Name `
                -ResourceGroupName $fd.ResourceGroupName `
                -WarningDays $WarningDays
            
            $fdResults | ForEach-Object { $allResults.Add($_) }
        }
    }
}
elseif ($PSCmdlet.ParameterSetName -eq 'ScanTenant') {
    # Tenant-wide scanning mode using Azure Resource Graph REST API with parallel processing
    Write-Host "Scanning all Front Door profiles across tenant using Resource Graph..." -ForegroundColor Cyan
    Write-Host "  Parallelism: ThrottleLimit=$ThrottleLimit, TlsThrottleLimit=$TlsThrottleLimit" -ForegroundColor Gray
    
    # Step 1: Acquire bearer token (avoids null tenant issue with Search-AzGraph)
    Write-Host "`n[1/4] Acquiring Azure bearer token..." -ForegroundColor Cyan
    $tokenInfo = Get-ArmBearerToken
    $script:Headers = @{ Authorization = "Bearer $($tokenInfo.Token)"; 'Content-Type' = 'application/json' }
    
    $tokenLabelParts = [System.Collections.Generic.List[string]]::new()
    if ($tokenInfo.UserId) { $tokenLabelParts.Add($tokenInfo.UserId) }
    if ($tokenInfo.TenantId) { $tokenLabelParts.Add("tenant $($tokenInfo.TenantId)") }
    if ($tokenLabelParts.Count -gt 0) {
        Write-Host "  Token acquired for: $($tokenLabelParts -join ' | ')" -ForegroundColor Green
    } else {
        Write-Host "  Token acquired successfully." -ForegroundColor Green
    }
    
    # Step 2: Get enabled subscriptions
    Write-Host "`n[2/4] Resolving enabled subscriptions..." -ForegroundColor Cyan
    $subscriptions = Get-EnabledSubscriptions
    $subscriptionIds = @($subscriptions | Select-Object -ExpandProperty Id)
    $subscriptionLookup = @{}
    foreach ($sub in $subscriptions) {
        $subscriptionLookup[$sub.Id] = $sub.Name
    }
    Write-Host "  $($subscriptions.Count) enabled subscription(s) accessible." -ForegroundColor Green
    
    # Step 3: Query Front Doors via Resource Graph REST API
    Write-Host "`n[3/4] Discovering Front Door profiles via Resource Graph..." -ForegroundColor Cyan
    $allFrontDoors = Get-AllFrontDoorsInTenant -Headers $script:Headers -SubscriptionIds $subscriptionIds -TypeFilter $FrontDoorType
    
    if ($allFrontDoors.Count -eq 0) {
        Write-Host "No Front Door profiles found in the tenant." -ForegroundColor Yellow
    } else {
        # ARM metadata calls and live TLS probes saturate different resources, so keep separate throttles.
        Write-Host "[4/4] Processing certificates (parallel=$ThrottleLimit)..." -ForegroundColor Cyan
        $scanStartedAt = Get-Date
        
        $standardPremiumFDs = @($allFrontDoors | Where-Object { $_.Type -eq 'Standard/Premium' })
        $classicFDs = @($allFrontDoors | Where-Object { $_.Type -eq 'Classic' })
        
        # Process Standard/Premium Front Doors in parallel (ARM REST API calls)
        if ($standardPremiumFDs.Count -gt 0) {
            Write-Host "  Processing $($standardPremiumFDs.Count) Standard/Premium Front Door(s) in parallel..." -ForegroundColor Cyan
            $progressInterval = Get-ProgressInterval -TotalCount $standardPremiumFDs.Count
            $processedCount = 0
            
            $standardPremiumFDs | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
                $fd = $_
                $hdrs = $using:Headers
                $apiVer = $using:ApiVersion
                $subLookup = $using:subscriptionLookup
                $warnDays = $using:WarningDays
                $scanAt = $using:scanStartedAt
                $proxyUri = $using:ProxyUri
                $tlsTimeoutMs = $using:TlsTimeoutMs
                $restRetryCount = $using:RestRetryCount
                $tlsRetryCount = $using:TlsRetryCount
                $retryBaseDelayMs = $using:RetryBaseDelayMs

                # Parallel runspaces do not inherit caller-defined helpers, so keep local copies here.

                # Opens a live TLS session to the domain, optionally through the detected proxy.
                function Get-CertificateFromDomainLocal {
                    param(
                        [Parameter(Mandatory)]
                        [string]$DomainName,

                        [Parameter(Mandatory = $false)]
                        [Uri]$ProxyUri,

                        [Parameter(Mandatory)]
                        [int]$TimeoutMs
                    )

                    $tcpClient = $null
                    $sslStream = $null
                    $networkStream = $null
                    $reader = $null
                    $writer = $null

                    try {
                        $tcpClient = [System.Net.Sockets.TcpClient]::new()
                        $tcpClient.SendTimeout = $TimeoutMs
                        $tcpClient.ReceiveTimeout = $TimeoutMs

                        if ($ProxyUri) {
                            $tcpClient.Connect($ProxyUri.Host, $ProxyUri.Port)
                            $networkStream = $tcpClient.GetStream()

                            $writer = [System.IO.StreamWriter]::new($networkStream, [System.Text.Encoding]::ASCII)
                            $writer.AutoFlush = $true
                            $reader = [System.IO.StreamReader]::new($networkStream, [System.Text.Encoding]::ASCII)

                            $writer.WriteLine("CONNECT ${DomainName}:443 HTTP/1.1")
                            $writer.WriteLine("Host: ${DomainName}:443")
                            $writer.WriteLine("")

                            $response = $reader.ReadLine()
                            if ($response -notmatch '^HTTP/\d\.\d 200') {
                                throw "Proxy CONNECT failed: $response"
                            }

                            while ($true) {
                                $line = $reader.ReadLine()
                                if ([string]::IsNullOrEmpty($line)) { break }
                            }

                            $sslStream = [System.Net.Security.SslStream]::new(
                                $networkStream,
                                $false,
                                { param($s, $certificate, $chain, $sslPolicyErrors) return $true }
                            )
                        }
                        else {
                            $tcpClient.Connect($DomainName, 443)
                            $sslStream = [System.Net.Security.SslStream]::new(
                                $tcpClient.GetStream(),
                                $false,
                                { param($s, $certificate, $chain, $sslPolicyErrors) return $true }
                            )
                        }

                        $sslStream.AuthenticateAsClient($DomainName)
                        $cert = $sslStream.RemoteCertificate
                        if ($cert) {
                            return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cert)
                        }

                        return $null
                    }
                    finally {
                        if ($writer) { $writer.Dispose() }
                        if ($reader) { $reader.Dispose() }
                        if ($sslStream) { $sslStream.Dispose() }
                        if ($tcpClient) { $tcpClient.Dispose() }
                    }
                }

                # Normalizes issuer metadata into consistent Issuer and IssuingCA values.
                function Get-IssuerDetailsLocal {
                    param(
                        [Parameter(Mandatory = $false)]
                        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

                        [Parameter(Mandatory = $false)]
                        [string]$IssuerString,

                        [Parameter(Mandatory = $false)]
                        [string]$IssuingCAName
                    )

                    $issuer = $IssuerString
                    if (-not $issuer -and $Certificate) {
                        $issuer = $Certificate.Issuer
                    }

                    $issuingCA = $IssuingCAName
                    if (-not $issuingCA -and $Certificate) {
                        try {
                            $issuingCA = $Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $true)
                        }
                        catch {
                            $issuingCA = $null
                        }
                    }

                    if (-not $issuingCA -and $issuer) {
                        if ($issuer -match '(^|,\s*)CN=([^,]+)') {
                            $issuingCA = $matches[2].Trim()
                        }
                        elseif ($issuer -match '(^|,\s*)O=([^,]+)') {
                            $issuingCA = $matches[2].Trim()
                        }
                        else {
                            $issuingCA = $issuer
                        }
                    }

                    return @{
                        Issuer    = $issuer
                        IssuingCA = $issuingCA
                    }
                }

                # Pulls HTTP status codes out of nested REST exception shapes.
                function Get-HttpStatusCodeFromExceptionLocal {
                    param([AllowNull()][System.Exception]$Exception)

                    if (-not $Exception) {
                        return $null
                    }

                    foreach ($propertyName in 'StatusCode', 'Response') {
                        $property = $Exception.PSObject.Properties[$propertyName]
                        if (-not $property) {
                            continue
                        }

                        try {
                            if ($propertyName -eq 'StatusCode' -and $null -ne $property.Value) {
                                return [int]$property.Value
                            }

                            if ($propertyName -eq 'Response' -and $property.Value -and $property.Value.StatusCode) {
                                return [int]$property.Value.StatusCode
                            }
                        }
                        catch {
                        }
                    }

                    if ($Exception.InnerException -and $Exception.InnerException -ne $Exception) {
                        return Get-HttpStatusCodeFromExceptionLocal -Exception $Exception.InnerException
                    }

                    return $null
                }

                function Get-ExceptionMessageSummaryLocal {
                    param([AllowNull()][System.Exception]$Exception, [string]$PrefixMessage)

                    $messageParts = [System.Collections.Generic.List[string]]::new()
                    if (-not [string]::IsNullOrWhiteSpace($PrefixMessage)) {
                        $messageParts.Add($PrefixMessage)
                    }

                    $currentException = $Exception
                    while ($currentException) {
                        $message = [string]$currentException.Message
                        if (-not [string]::IsNullOrWhiteSpace($message) -and -not $messageParts.Contains($message)) {
                            $messageParts.Add($message)
                        }

                        if (-not $currentException.InnerException -or $currentException.InnerException -eq $currentException) {
                            break
                        }

                        $currentException = $currentException.InnerException
                    }

                    if ($messageParts.Count -eq 0) {
                        return $null
                    }

                    return ($messageParts -join ' ')
                }

                # Identifies retryable REST failures for ARM and Resource Manager calls.
                function Test-IsTransientRestFailureLocal {
                    param([AllowNull()][System.Exception]$Exception)

                    if (-not $Exception) {
                        return $false
                    }

                    $statusCode = Get-HttpStatusCodeFromExceptionLocal -Exception $Exception
                    if ($null -ne $statusCode) {
                        return $statusCode -in 408, 409, 429, 500, 502, 503, 504
                    }

                    $message = Get-ExceptionMessageSummaryLocal -Exception $Exception

                    return $message -match 'timed out|timeout|temporar|throttl|too many requests|connection.+(reset|aborted|closed)|remote party closed|EOF|unexpected end'
                }

                # Identifies retryable TLS and proxy-connect failures during live probing.
                function Test-IsTransientTlsFailureLocal {
                    param([AllowNull()][System.Exception]$Exception, [string]$FailureMessage)

                    $message = Get-ExceptionMessageSummaryLocal -Exception $Exception -PrefixMessage $FailureMessage

                    return $message -match 'timed out|timeout|temporar|connection.+(reset|aborted|closed)|remote party closed|EOF|unexpected end|network.+unreachable|host.+unreachable|Proxy CONNECT failed: HTTP/\d\.\d (429|502|503|504)'
                }

                # Applies capped exponential backoff between retry attempts.
                function Get-RetryDelayMillisecondsLocal {
                    param([int]$Attempt, [int]$BaseDelayMs)
                    return [int][Math]::Min([Math]::Round($BaseDelayMs * [Math]::Pow(2, [Math]::Max($Attempt - 1, 0))), 10000)
                }

                # Retries transient REST or TLS failures inside the runspace.
                function Invoke-WithRetryLocal {
                    param(
                        [Parameter(Mandatory)]
                        [scriptblock]$Action,

                        [Parameter(Mandatory)]
                        [ValidateSet('Rest', 'Tls')]
                        [string]$Category,

                        [Parameter(Mandatory)]
                        [int]$MaxAttempts,

                        [Parameter(Mandatory)]
                        [int]$BaseDelayMs
                    )

                    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
                        try {
                            return & $Action
                        }
                        catch {
                            $exception = $_.Exception
                            $isTransient = if ($Category -eq 'Rest') {
                                Test-IsTransientRestFailureLocal -Exception $exception
                            }
                            else {
                                Test-IsTransientTlsFailureLocal -Exception $exception -FailureMessage $exception.Message
                            }

                            if (-not $isTransient -or $attempt -ge $MaxAttempts) {
                                throw
                            }

                            Start-Sleep -Milliseconds (Get-RetryDelayMillisecondsLocal -Attempt $attempt -BaseDelayMs $BaseDelayMs)
                        }
                    }
                }

                # Builds a readable display name from a certificate subject or issuer DN.
                function Get-CertificateDisplayNameLocal {
                    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate, [string]$DistinguishedName)

                    $displayName = $null
                    if ($Certificate) {
                        try {
                            $displayName = $Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
                        }
                        catch {
                            $displayName = $null
                        }

                        if (-not $DistinguishedName) {
                            $DistinguishedName = $Certificate.Subject
                        }
                    }

                    if (-not $displayName -and $DistinguishedName) {
                        if ($DistinguishedName -match '(^|,\s*)CN=([^,]+)') {
                            $displayName = $matches[2].Trim()
                        }
                        elseif ($DistinguishedName -match '(^|,\s*)O=([^,]+)') {
                            $displayName = $matches[2].Trim()
                        }
                        else {
                            $displayName = $DistinguishedName
                        }
                    }

                    return $displayName
                }

                # Summarizes non-success statuses produced by X509 chain building.
                function Get-ChainStatusSummaryLocal {
                    param([System.Security.Cryptography.X509Certificates.X509Chain]$Chain)

                    if (-not $Chain) {
                        return $null
                    }

                    $statuses = @(
                        $Chain.ChainStatus |
                            Where-Object { $_.Status -ne [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NoError } |
                            ForEach-Object { [string]$_.Status } |
                            Select-Object -Unique
                    )

                    if (-not $statuses -or $statuses.Count -eq 0) {
                        return 'Valid'
                    }

                    return ($statuses -join ',')
                }

                # Mirrors the exported ChainStatus format used by the non-parallel scan paths.
                function Get-CertificateStatusSummaryLocal {
                    param([string]$ChainStatus, [string]$ExpirationStatus, [string[]]$StatusItems, [bool]$HasExpirationDate)

                    $parts = [System.Collections.Generic.List[string]]::new()
                    $uniqueStatusItems = @(
                        $StatusItems |
                            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                            Select-Object -Unique
                    )

                    $uniqueStatusItems | ForEach-Object {
                            $parts.Add("CheckError: $_")
                        }

                    if (-not [string]::IsNullOrWhiteSpace($ChainStatus) -and $ChainStatus -ne 'Valid') {
                        $parts.Add("Chain: $ChainStatus")
                    }

                    switch ($ExpirationStatus) {
                        'EXPIRED' { $parts.Add('Expiration: EXPIRED') }
                        'WARNING' { $parts.Add('Expiration: WARNING') }
                    }

                    if ($parts.Count -gt 0) {
                        return ($parts -join ' | ')
                    }

                    if ($ChainStatus -eq 'Valid' -or ($HasExpirationDate -and $ExpirationStatus -eq 'OK')) {
                        return 'OK'
                    }

                    return 'NoData'
                }

                # Maps each custom-domain resource ID to the endpoint host names whose routes reference it.
                function Get-DomainEndpointAssociationsLocal {
                    param(
                        [Parameter(Mandatory)]
                        [string]$ProfileBaseUri,

                        [Parameter(Mandatory)]
                        [string]$ApiVersion,

                        [Parameter(Mandatory)]
                        [hashtable]$Headers,

                        [Parameter(Mandatory)]
                        [int]$MaxAttempts,

                        [Parameter(Mandatory)]
                        [int]$BaseDelayMs
                    )

                    $associationSets = @{}
                    $endpointsUri = "$ProfileBaseUri/afdEndpoints?api-version=$ApiVersion"
                    $endpointsResp = Invoke-WithRetryLocal -Action {
                        Invoke-RestMethod -Method Get -Uri $endpointsUri -Headers $Headers -ErrorAction Stop
                    } -Category Rest -MaxAttempts $MaxAttempts -BaseDelayMs $BaseDelayMs

                    foreach ($afdEndpoint in @($endpointsResp.value)) {
                        $endpointName = [string]$afdEndpoint.name
                        if ([string]::IsNullOrWhiteSpace($endpointName)) {
                            continue
                        }

                        $endpointAssociation = [string]($afdEndpoint.properties.hostName ?? $endpointName)
                        if ([string]::IsNullOrWhiteSpace($endpointAssociation)) {
                            $endpointAssociation = $endpointName
                        }

                        $routesUri = "$ProfileBaseUri/afdEndpoints/$endpointName/routes?api-version=$ApiVersion"
                        try {
                            $routesResp = Invoke-WithRetryLocal -Action {
                                Invoke-RestMethod -Method Get -Uri $routesUri -Headers $Headers -ErrorAction Stop
                            } -Category Rest -MaxAttempts $MaxAttempts -BaseDelayMs $BaseDelayMs
                        }
                        catch {
                            continue
                        }

                        foreach ($route in @($routesResp.value)) {
                            foreach ($customDomainRef in @($route.properties.customDomains)) {
                                $domainRefId = [string]$customDomainRef.id
                                if ([string]::IsNullOrWhiteSpace($domainRefId)) {
                                    continue
                                }

                                $domainKey = $domainRefId.ToLowerInvariant()
                                if (-not $associationSets.ContainsKey($domainKey)) {
                                    $associationSets[$domainKey] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                                }

                                $null = $associationSets[$domainKey].Add($endpointAssociation)
                            }
                        }
                    }

                    $associationMap = @{}
                    foreach ($domainKey in $associationSets.Keys) {
                        $associationMap[$domainKey] = (@($associationSets[$domainKey] | Sort-Object) -join ' | ')
                    }

                    return $associationMap
                }

                # Builds certificate-chain metadata from the live certificate presented by the endpoint.
                function Get-CertificateChainDetailsLocal {
                    param(
                        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
                        [string]$IssuerString,
                        [string]$IssuingCAName
                    )

                    if (-not $Certificate) {
                        return @{
                            Subject                = $null
                            Issuer                 = $IssuerString
                            IssuingCA              = $IssuingCAName
                            ServerCertificateCount = $null
                            IntermediateCA         = $null
                            RootCA                 = $null
                            ChainStatus            = $null
                            DigiCertIssued         = $null
                        }
                    }

                    $issuerDetails = Get-IssuerDetailsLocal -Certificate $Certificate -IssuerString $IssuerString -IssuingCAName $IssuingCAName
                    $serverCertificateCount = 1
                    $intermediateCA = $null
                    $rootCA = $null
                    $chainStatus = $null
                    $digiCertIssued = $false
                    $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()

                    try {
                        # Avoid revocation lookups during inventory scans so live probing stays fast and predictable.
                        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                        $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
                        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
                        $null = $chain.Build($Certificate)

                        $chainElements = @($chain.ChainElements)
                        if ($chainElements.Count -gt 0) {
                            $serverCertificateCount = $chainElements.Count
                            $chainStatus = Get-ChainStatusSummaryLocal -Chain $chain
                            $lastElementCertificate = $chainElements[$chainElements.Count - 1].Certificate
                            $lastIsSelfSigned = $lastElementCertificate -and ($lastElementCertificate.Subject -eq $lastElementCertificate.Issuer)

                            $intermediateCertificates = @()
                            # Treat a self-signed last element as the root and everything between as intermediates.
                            if ($chainElements.Count -ge 3 -or $lastIsSelfSigned) {
                                $rootCA = Get-CertificateDisplayNameLocal -Certificate $lastElementCertificate
                                if ($chainElements.Count -gt 2) {
                                    $intermediateCertificates = @($chainElements[1..($chainElements.Count - 2)] | ForEach-Object { $_.Certificate })
                                }
                            }
                            elseif ($chainElements.Count -gt 1) {
                                $intermediateCertificates = @($chainElements[1..($chainElements.Count - 1)] | ForEach-Object { $_.Certificate })
                            }

                            $intermediateNames = @(
                                $intermediateCertificates |
                                    ForEach-Object { Get-CertificateDisplayNameLocal -Certificate $_ } |
                                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                                    Select-Object -Unique
                            )
                            if ($intermediateNames.Count -gt 0) {
                                $intermediateCA = $intermediateNames -join ' | '
                            }
                        }
                    }
                    finally {
                        $chain.Dispose()
                    }

                    if ($issuerDetails.Issuer -match '\bDigiCert\b' -or $issuerDetails.IssuingCA -match '\bDigiCert\b' -or $intermediateCA -match '\bDigiCert\b' -or $rootCA -match '\bDigiCert\b') {
                        $digiCertIssued = $true
                    }

                    return @{
                        Subject                = $Certificate.Subject
                        Issuer                 = $issuerDetails.Issuer
                        IssuingCA              = $issuerDetails.IssuingCA
                        ServerCertificateCount = $serverCertificateCount
                        IntermediateCA         = $intermediateCA
                        RootCA                 = $rootCA
                        ChainStatus            = $chainStatus
                        DigiCertIssued         = $digiCertIssued
                    }
                }

                # Query the Front Door custom-domain child resources directly so we can stay parallel.
                $baseUri = "https://management.azure.com/subscriptions/$($fd.SubscriptionId)/resourceGroups/$($fd.ResourceGroupName)/providers/Microsoft.Cdn/profiles/$($fd.Name)"

                try {
                    # Get custom domains
                    $domainsUri = "$baseUri/customDomains?api-version=$apiVer"
                    $domainsResp = Invoke-WithRetryLocal -Action {
                        Invoke-RestMethod -Method Get -Uri $domainsUri -Headers $hdrs -ErrorAction Stop
                    } -Category Rest -MaxAttempts $restRetryCount -BaseDelayMs $retryBaseDelayMs
                    $domains = @($domainsResp.value)
                    $domainEndpointAssociations = @{}
                    try {
                        $domainEndpointAssociations = Get-DomainEndpointAssociationsLocal -ProfileBaseUri $baseUri -ApiVersion $apiVer -Headers $hdrs -MaxAttempts $restRetryCount -BaseDelayMs $retryBaseDelayMs
                    }
                    catch {
                        $associationError = Get-ExceptionMessageSummaryLocal -Exception $_.Exception
                        Write-Host "    Failed to resolve endpoint associations for $($fd.Name): $associationError" -ForegroundColor Yellow
                        $domainEndpointAssociations = @{}
                    }
                    $includedDomainCount = 0

                    foreach ($d in $domains) {
                        $domainName = $d.properties.hostName ?? $d.name
                        if (-not [string]::IsNullOrWhiteSpace($domainName) -and $domainName.EndsWith('.azurefd.net', [System.StringComparison]::OrdinalIgnoreCase)) {
                            continue
                        }

                        $includedDomainCount++
                        $certSource = $null
                        $provisioningState = $d.properties.provisioningState
                        $validationState = $d.properties.domainValidationState
                        $expiryDate = $null
                        $subject = $null
                        $issuer = $null
                        $issuingCA = $null
                        $serverCertificateCount = $null
                        $intermediateCA = $null
                        $rootCA = $null
                        $chainStatus = $null
                        $digiCertIssued = $null
                        $statusErrors = [System.Collections.Generic.List[string]]::new()
                        $keyVaultName = $null
                        $keyVaultSecretName = $null
                        $domainAssociation = 'Unassociated'
                        $domainResourceId = [string]$d.id
                        if (-not [string]::IsNullOrWhiteSpace($domainResourceId)) {
                            $domainKey = $domainResourceId.ToLowerInvariant()
                            if ($domainEndpointAssociations.ContainsKey($domainKey) -and -not [string]::IsNullOrWhiteSpace([string]$domainEndpointAssociations[$domainKey])) {
                                $domainAssociation = [string]$domainEndpointAssociations[$domainKey]
                            }
                        }
                        
                        # Prefer certificate metadata from ARM, then enrich it with a live TLS probe when available.
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
                                    $secret = Invoke-WithRetryLocal -Action {
                                        Invoke-RestMethod -Method Get -Uri $secretUri -Headers $hdrs -ErrorAction Stop
                                    } -Category Rest -MaxAttempts $restRetryCount -BaseDelayMs $retryBaseDelayMs
                                    if ($secret.properties -and $secret.properties.parameters) {
                                        $params = $secret.properties.parameters
                                        if ($params.expirationDate) { $expiryDate = $params.expirationDate }
                                        if ($params.subject) { $subject = $params.subject }
                                        if ($params.certificateAuthority) { $issuingCA = [string]$params.certificateAuthority }
                                        if ($params.issuer) { $issuer = [string]$params.issuer }
                                        
                                        if ($params.type -eq 'CustomerCertificate' -and $params.secretSource -and $params.secretSource.id) {
                                            $kvSecretId = $params.secretSource.id
                                            if ($kvSecretId -match '/vaults/([^/]+)/') { $keyVaultName = $Matches[1] }
                                            if ($kvSecretId -match '/secrets/([^/]+)') { $keyVaultSecretName = $Matches[1] }
                                        }

                                        $issuerDetails = Get-IssuerDetailsLocal -IssuerString $issuer -IssuingCAName $issuingCA
                                        $issuer = $issuerDetails.Issuer
                                        $issuingCA = $issuerDetails.IssuingCA
                                    }
                                } catch {
                                    $errorMsg = Get-ExceptionMessageSummaryLocal -Exception $_.Exception
                                    $null = $statusErrors.Add("SecretLookup: $errorMsg")
                                }
                            }
                        }

                        if ($domainName) {
                            try {
                                $liveCert = Invoke-WithRetryLocal -Action {
                                    Get-CertificateFromDomainLocal -DomainName $domainName -ProxyUri $proxyUri -TimeoutMs $tlsTimeoutMs
                                } -Category Tls -MaxAttempts $tlsRetryCount -BaseDelayMs $retryBaseDelayMs
                                if ($liveCert) {
                                    $certDetails = Get-CertificateChainDetailsLocal -Certificate $liveCert -IssuerString $issuer -IssuingCAName $issuingCA
                                    if (-not $subject) { $subject = $certDetails.Subject }
                                    if (-not $expiryDate) { $expiryDate = $liveCert.NotAfter }
                                    $issuer = $certDetails.Issuer
                                    $issuingCA = $certDetails.IssuingCA
                                    $serverCertificateCount = $certDetails.ServerCertificateCount
                                    $intermediateCA = $certDetails.IntermediateCA
                                    $rootCA = $certDetails.RootCA
                                    $chainStatus = $certDetails.ChainStatus
                                    $digiCertIssued = $certDetails.DigiCertIssued
                                }
                            }
                            catch {
                                $errorMsg = Get-ExceptionMessageSummaryLocal -Exception $_.Exception
                                $null = $statusErrors.Add("TLS: $errorMsg")
                            }
                        }
                        
                        # Calculate expiration status
                        $expiryDisplay = $null
                        $expiryStatus = 'OK'
                        $expiryDateTime = $null
                        if ($expiryDate) {
                            try {
                                $expiryDateTime = if ($expiryDate -is [DateTime]) { $expiryDate } else { [DateTime]::Parse($expiryDate) }
                                $expiryDisplay = $expiryDateTime.ToString()
                                $daysUntilExpiry = ($expiryDateTime - $scanAt).Days
                                $expiryStatus = if ($daysUntilExpiry -lt 0) { 'EXPIRED' } elseif ($daysUntilExpiry -le $warnDays) { 'WARNING' } else { 'OK' }
                            } catch { $expiryDisplay = $expiryDate }
                        }
                        $overallStatus = Get-CertificateStatusSummaryLocal -ChainStatus $chainStatus -ExpirationStatus $expiryStatus -StatusItems @($statusErrors) -HasExpirationDate ($null -ne $expiryDateTime)
                        
                        [PSCustomObject]@{
                            SubscriptionId     = $fd.SubscriptionId
                            SubscriptionName   = $subLookup[$fd.SubscriptionId] ?? $fd.SubscriptionId
                            FrontDoorName      = $fd.Name
                            MigrationSourceResourceId = $fd.MigrationSourceResourceId
                            MigrationTargetResourceId = $fd.MigrationTargetResourceId
                            EndpointAssociation = $domainAssociation
                            FrontDoorType      = 'Standard/Premium'
                            Domain             = $domainName
                            CertificateType    = $certSource
                            ProvisioningState  = $provisioningState
                            ValidationState    = $validationState
                            Subject            = $subject
                            Issuer             = $issuer
                            IssuingCA          = $issuingCA
                            ServerCertificateCount = $serverCertificateCount
                            IntermediateCA         = $intermediateCA
                            RootCA                 = $rootCA
                            ChainStatus            = $overallStatus
                            DigiCertIssued         = $digiCertIssued
                            ExpirationDateRaw  = $expiryDateTime
                            ExpirationDate     = $expiryDisplay
                            ExpirationStatus   = $expiryStatus
                            KeyVaultName       = $keyVaultName
                            KeyVaultSecretName = $keyVaultSecretName
                        }
                    }
                    
                    # Progress marker
                    [PSCustomObject]@{ __Progress = $true; FrontDoorName = $fd.Name; DomainCount = $includedDomainCount }
                } catch {
                    [PSCustomObject]@{ __Progress = $true; FrontDoorName = $fd.Name; DomainCount = 0; Error = (Get-ExceptionMessageSummaryLocal -Exception $_.Exception) }
                }
            } | ForEach-Object {
                if ($_.PSObject.Properties['__Progress']) {
                    $processedCount++
                    if (($processedCount % $progressInterval -eq 0) -or ($processedCount -eq $standardPremiumFDs.Count)) {
                        $errMsg = if ($_.Error) { " (Error: $($_.Error))" } else { "" }
                        Write-Host "    Processed $processedCount/$($standardPremiumFDs.Count): $($_.FrontDoorName) -> $($_.DomainCount) domain(s)$errMsg" -ForegroundColor DarkGray
                    }
                } else {
                    $allResults.Add($_)
                }
            }
            Write-Host "    Completed Standard/Premium processing." -ForegroundColor Green
        }
        
        # Process Classic Front Doors via ARM REST and parallel TLS probing
        if ($classicFDs.Count -gt 0) {
            Write-Host "  Processing $($classicFDs.Count) Classic Front Door(s)..." -ForegroundColor Cyan
            $classicEndpoints = [System.Collections.Generic.List[PSCustomObject]]::new()
            $classicProgressInterval = Get-ProgressInterval -TotalCount $classicFDs.Count
            $classicFDsProcessed = 0

            Write-Host "    Enumerating endpoints via ARM REST in parallel (parallel=$ThrottleLimit)..." -ForegroundColor Cyan

            $classicFDs | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
                $fd = $_
                $hdrs = $using:Headers
                $apiVer = $using:ClassicApiVersion
                $subLookup = $using:subscriptionLookup
                $restRetryCount = $using:RestRetryCount
                $retryBaseDelayMs = $using:RetryBaseDelayMs

                # Pulls HTTP status codes out of nested REST exception shapes.
                function Get-HttpStatusCodeFromExceptionLocal {
                    param([AllowNull()][System.Exception]$Exception)

                    if (-not $Exception) {
                        return $null
                    }

                    foreach ($propertyName in 'StatusCode', 'Response') {
                        $property = $Exception.PSObject.Properties[$propertyName]
                        if (-not $property) {
                            continue
                        }

                        try {
                            if ($propertyName -eq 'StatusCode' -and $null -ne $property.Value) {
                                return [int]$property.Value
                            }

                            if ($propertyName -eq 'Response' -and $property.Value -and $property.Value.StatusCode) {
                                return [int]$property.Value.StatusCode
                            }
                        }
                        catch {
                        }
                    }

                    if ($Exception.InnerException -and $Exception.InnerException -ne $Exception) {
                        return Get-HttpStatusCodeFromExceptionLocal -Exception $Exception.InnerException
                    }

                    return $null
                }

                function Get-ExceptionMessageSummaryLocal {
                    param([AllowNull()][System.Exception]$Exception, [string]$PrefixMessage)

                    $messageParts = [System.Collections.Generic.List[string]]::new()
                    if (-not [string]::IsNullOrWhiteSpace($PrefixMessage)) {
                        $messageParts.Add($PrefixMessage)
                    }

                    $currentException = $Exception
                    while ($currentException) {
                        $message = [string]$currentException.Message
                        if (-not [string]::IsNullOrWhiteSpace($message) -and -not $messageParts.Contains($message)) {
                            $messageParts.Add($message)
                        }

                        if (-not $currentException.InnerException -or $currentException.InnerException -eq $currentException) {
                            break
                        }

                        $currentException = $currentException.InnerException
                    }

                    if ($messageParts.Count -eq 0) {
                        return $null
                    }

                    return ($messageParts -join ' ')
                }

                # Identifies retryable REST failures during Classic endpoint discovery.
                function Test-IsTransientRestFailureLocal {
                    param([AllowNull()][System.Exception]$Exception)

                    if (-not $Exception) {
                        return $false
                    }

                    $statusCode = Get-HttpStatusCodeFromExceptionLocal -Exception $Exception
                    if ($null -ne $statusCode) {
                        return $statusCode -in 408, 409, 429, 500, 502, 503, 504
                    }

                    $message = Get-ExceptionMessageSummaryLocal -Exception $Exception

                    return $message -match 'timed out|timeout|temporar|throttl|too many requests|connection.+(reset|aborted|closed)|remote party closed|EOF|unexpected end'
                }

                # Applies capped exponential backoff between retry attempts.
                function Get-RetryDelayMillisecondsLocal {
                    param([int]$Attempt, [int]$BaseDelayMs)
                    return [int][Math]::Min([Math]::Round($BaseDelayMs * [Math]::Pow(2, [Math]::Max($Attempt - 1, 0))), 10000)
                }

                # Retries transient REST failures while enumerating Classic endpoint metadata.
                function Invoke-WithRetryLocal {
                    param([Parameter(Mandatory)][scriptblock]$Action, [Parameter(Mandatory)][int]$MaxAttempts, [Parameter(Mandatory)][int]$BaseDelayMs)

                    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
                        try {
                            return & $Action
                        }
                        catch {
                            if (-not (Test-IsTransientRestFailureLocal -Exception $_.Exception) -or $attempt -ge $MaxAttempts) {
                                throw
                            }

                            Start-Sleep -Milliseconds (Get-RetryDelayMillisecondsLocal -Attempt $attempt -BaseDelayMs $BaseDelayMs)
                        }
                    }
                }

                try {
                    # Retrieve the full Front Door resource once and fan out over frontend endpoints locally.
                    $uri = "https://management.azure.com/subscriptions/$($fd.SubscriptionId)/resourceGroups/$($fd.ResourceGroupName)/providers/Microsoft.Network/frontDoors/$($fd.Name)?api-version=$apiVer"
                    $frontDoor = Invoke-WithRetryLocal -Action {
                        Invoke-RestMethod -Method Get -Uri $uri -Headers $hdrs -ErrorAction Stop
                    } -MaxAttempts $restRetryCount -BaseDelayMs $retryBaseDelayMs
                    $endpointCount = 0

                    foreach ($ep in @($frontDoor.properties.frontendEndpoints)) {
                        $hostName = if ([string]::IsNullOrWhiteSpace([string]$ep.properties.hostName)) { [string]$ep.name } else { [string]$ep.properties.hostName }
                        if ([string]::IsNullOrWhiteSpace($hostName)) {
                            continue
                        }
                        if ($hostName.EndsWith('.azurefd.net', [System.StringComparison]::OrdinalIgnoreCase)) {
                            continue
                        }

                        $customHttpsConfig = $ep.properties.customHttpsConfiguration
                        $certificateSource = $null
                        $keyVaultName = $null
                        $keyVaultSecretName = $null

                        if ($customHttpsConfig) {
                            if ($customHttpsConfig.certificateSource) {
                                $certificateSource = [string]$customHttpsConfig.certificateSource
                            }

                            $vaultIdCandidates = @(
                                $customHttpsConfig.vault.id,
                                $customHttpsConfig.vault,
                                $customHttpsConfig.keyVaultCertificateSourceParameters.vault.id,
                                $customHttpsConfig.keyVaultCertificateSourceParameters.vault,
                                $customHttpsConfig.secretSource.id,
                                $customHttpsConfig.secretSource
                            ) | Where-Object { $_ }

                            $vaultId = @($vaultIdCandidates | Select-Object -First 1)[0]
                            if ($vaultId -and ($vaultId -match '/vaults/([^/]+)/')) {
                                $keyVaultName = $Matches[1]
                            }

                            $secretNameCandidates = @(
                                $customHttpsConfig.secretName,
                                $customHttpsConfig.keyVaultCertificateSourceParameters.secretName,
                                $customHttpsConfig.secretSource.secretName
                            ) | Where-Object { $_ }

                            $keyVaultSecretName = @($secretNameCandidates | Select-Object -First 1)[0]
                            if (-not $keyVaultSecretName -and $vaultId -and ($vaultId -match '/secrets/([^/]+)')) {
                                $keyVaultSecretName = $Matches[1]
                            }
                        }

                        $endpointCount++
                        [PSCustomObject]@{
                            SubscriptionId     = $fd.SubscriptionId
                            SubscriptionName   = $subLookup[$fd.SubscriptionId] ?? $fd.SubscriptionId
                            FrontDoorName      = $fd.Name
                            MigrationSourceResourceId = $fd.MigrationSourceResourceId
                            MigrationTargetResourceId = $fd.MigrationTargetResourceId
                            EndpointAssociation = [string]$ep.name
                            HostName           = $hostName
                            CertificateSource  = $certificateSource
                            ProvisioningState  = [string]$ep.properties.customHttpsProvisioningState
                            KeyVaultName       = $keyVaultName
                            KeyVaultSecretName = $keyVaultSecretName
                        }
                    }

                    [PSCustomObject]@{ __Progress = $true; FrontDoorName = $fd.Name; EndpointCount = $endpointCount }
                } catch {
                    [PSCustomObject]@{ __Progress = $true; FrontDoorName = $fd.Name; EndpointCount = 0; Error = (Get-ExceptionMessageSummaryLocal -Exception $_.Exception) }
                }
            } | ForEach-Object {
                if ($_.PSObject.Properties['__Progress']) {
                    $classicFDsProcessed++
                    if (($classicFDsProcessed % $classicProgressInterval -eq 0) -or ($classicFDsProcessed -eq $classicFDs.Count)) {
                        $errMsg = if ($_.Error) { " (Error: $($_.Error))" } else { "" }
                        Write-Host "    Enumerated $classicFDsProcessed/$($classicFDs.Count): $($_.FrontDoorName) -> $($_.EndpointCount) endpoint(s)$errMsg" -ForegroundColor DarkGray
                    }
                } else {
                    $classicEndpoints.Add($_)
                }
            }
            
            Write-Host "    Enumeration complete: $($classicEndpoints.Count) endpoint(s) from $classicFDsProcessed Classic FD(s)" -ForegroundColor Green
            
            # Now probe TLS certificates in parallel
            if ($classicEndpoints.Count -gt 0) {
                Write-Host "    Probing TLS certificates in parallel (TlsThrottleLimit=$TlsThrottleLimit, timeout=${TlsTimeoutMs}ms)..." -ForegroundColor Cyan
                $tlsProgressInterval = Get-ProgressInterval -TotalCount $classicEndpoints.Count
                $tlsProcessedCount = 0
                $proxyUri = $script:ProxyUri  # Capture for $using:
                $tlsTimeout = $TlsTimeoutMs
                
                $classicEndpoints | ForEach-Object -ThrottleLimit $TlsThrottleLimit -Parallel {
                    $ep = $_
                    $proxy = $using:proxyUri
                    $timeout = $using:tlsTimeout
                    $warnDays = $using:WarningDays
                    $scanAt = $using:scanStartedAt
                    $tlsRetryCount = $using:TlsRetryCount
                    $retryBaseDelayMs = $using:RetryBaseDelayMs

                    function Get-ExceptionMessageSummaryLocal {
                        param([AllowNull()][System.Exception]$Exception, [string]$PrefixMessage)

                        $messageParts = [System.Collections.Generic.List[string]]::new()
                        if (-not [string]::IsNullOrWhiteSpace($PrefixMessage)) {
                            $messageParts.Add($PrefixMessage)
                        }

                        $currentException = $Exception
                        while ($currentException) {
                            $message = [string]$currentException.Message
                            if (-not [string]::IsNullOrWhiteSpace($message) -and -not $messageParts.Contains($message)) {
                                $messageParts.Add($message)
                            }

                            if (-not $currentException.InnerException -or $currentException.InnerException -eq $currentException) {
                                break
                            }

                            $currentException = $currentException.InnerException
                        }

                        if ($messageParts.Count -eq 0) {
                            return $null
                        }

                        return ($messageParts -join ' ')
                    }

                    # Normalizes issuer metadata into consistent Issuer and IssuingCA values.
                    function Get-IssuerDetailsLocal {
                        param(
                            [Parameter(Mandatory = $false)]
                            [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

                            [Parameter(Mandatory = $false)]
                            [string]$IssuerString,

                            [Parameter(Mandatory = $false)]
                            [string]$IssuingCAName
                        )

                        $issuer = $IssuerString
                        if (-not $issuer -and $Certificate) {
                            $issuer = $Certificate.Issuer
                        }

                        $issuingCA = $IssuingCAName
                        if (-not $issuingCA -and $Certificate) {
                            try {
                                $issuingCA = $Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $true)
                            }
                            catch {
                                $issuingCA = $null
                            }
                        }

                        if (-not $issuingCA -and $issuer) {
                            if ($issuer -match '(^|,\s*)CN=([^,]+)') {
                                $issuingCA = $matches[2].Trim()
                            }
                            elseif ($issuer -match '(^|,\s*)O=([^,]+)') {
                                $issuingCA = $matches[2].Trim()
                            }
                            else {
                                $issuingCA = $issuer
                            }
                        }

                        return @{
                            Issuer    = $issuer
                            IssuingCA = $issuingCA
                        }
                    }

                    # Identifies retryable TLS and proxy-connect failures during live probing.
                    function Test-IsTransientTlsFailureLocal {
                        param([AllowNull()][System.Exception]$Exception, [string]$FailureMessage)

                        $message = Get-ExceptionMessageSummaryLocal -Exception $Exception -PrefixMessage $FailureMessage

                        return $message -match 'timed out|timeout|temporar|connection.+(reset|aborted|closed)|remote party closed|EOF|unexpected end|network.+unreachable|host.+unreachable|Proxy CONNECT failed: HTTP/\d\.\d (429|502|503|504)'
                    }

                    # Applies capped exponential backoff between retry attempts.
                    function Get-RetryDelayMillisecondsLocal {
                        param([int]$Attempt, [int]$BaseDelayMs)
                        return [int][Math]::Min([Math]::Round($BaseDelayMs * [Math]::Pow(2, [Math]::Max($Attempt - 1, 0))), 10000)
                    }

                    # Retries transient TLS failures inside the runspace.
                    function Invoke-WithRetryLocal {
                        param([Parameter(Mandatory)][scriptblock]$Action, [Parameter(Mandatory)][int]$MaxAttempts, [Parameter(Mandatory)][int]$BaseDelayMs)

                        for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
                            try {
                                return & $Action
                            }
                            catch {
                                if (-not (Test-IsTransientTlsFailureLocal -Exception $_.Exception -FailureMessage $_.Exception.Message) -or $attempt -ge $MaxAttempts) {
                                    throw
                                }

                                Start-Sleep -Milliseconds (Get-RetryDelayMillisecondsLocal -Attempt $attempt -BaseDelayMs $BaseDelayMs)
                            }
                        }
                    }

                    # Builds a readable display name from a certificate subject or issuer DN.
                    function Get-CertificateDisplayNameLocal {
                        param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate, [string]$DistinguishedName)

                        $displayName = $null
                        if ($Certificate) {
                            try {
                                $displayName = $Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
                            }
                            catch {
                                $displayName = $null
                            }

                            if (-not $DistinguishedName) {
                                $DistinguishedName = $Certificate.Subject
                            }
                        }

                        if (-not $displayName -and $DistinguishedName) {
                            if ($DistinguishedName -match '(^|,\s*)CN=([^,]+)') {
                                $displayName = $matches[2].Trim()
                            }
                            elseif ($DistinguishedName -match '(^|,\s*)O=([^,]+)') {
                                $displayName = $matches[2].Trim()
                            }
                            else {
                                $displayName = $DistinguishedName
                            }
                        }

                        return $displayName
                    }

                    # Summarizes non-success statuses produced by X509 chain building.
                    function Get-ChainStatusSummaryLocal {
                        param([System.Security.Cryptography.X509Certificates.X509Chain]$Chain)

                        if (-not $Chain) {
                            return $null
                        }

                        $statuses = @(
                            $Chain.ChainStatus |
                                Where-Object { $_.Status -ne [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NoError } |
                                ForEach-Object { [string]$_.Status } |
                                Select-Object -Unique
                        )

                        if (-not $statuses -or $statuses.Count -eq 0) {
                            return 'Valid'
                        }

                        return ($statuses -join ',')
                    }

                    # Mirrors the exported ChainStatus format used by the non-parallel scan paths.
                    function Get-CertificateStatusSummaryLocal {
                        param([string]$ChainStatus, [string]$ExpirationStatus, [string[]]$StatusItems, [bool]$HasExpirationDate)

                        $parts = [System.Collections.Generic.List[string]]::new()
                        $uniqueStatusItems = @(
                            $StatusItems |
                                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                                Select-Object -Unique
                        )

                        $uniqueStatusItems | ForEach-Object {
                                $parts.Add("CheckError: $_")
                            }

                        if (-not [string]::IsNullOrWhiteSpace($ChainStatus) -and $ChainStatus -ne 'Valid') {
                            $parts.Add("Chain: $ChainStatus")
                        }

                        switch ($ExpirationStatus) {
                            'EXPIRED' { $parts.Add('Expiration: EXPIRED') }
                            'WARNING' { $parts.Add('Expiration: WARNING') }
                        }

                        if ($parts.Count -gt 0) {
                            return ($parts -join ' | ')
                        }

                        if ($ChainStatus -eq 'Valid' -or ($HasExpirationDate -and $ExpirationStatus -eq 'OK')) {
                            return 'OK'
                        }

                        return 'NoData'
                    }

                    # Builds certificate-chain metadata from the live certificate presented by the endpoint.
                    function Get-CertificateChainDetailsLocal {
                        param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

                        if (-not $Certificate) {
                            return @{
                                Subject                = $null
                                Issuer                 = $null
                                IssuingCA              = $null
                                ServerCertificateCount = $null
                                IntermediateCA         = $null
                                RootCA                 = $null
                                ChainStatus            = $null
                                DigiCertIssued         = $null
                            }
                        }

                        $issuerDetails = Get-IssuerDetailsLocal -Certificate $Certificate
                        $serverCertificateCount = 1
                        $intermediateCA = $null
                        $rootCA = $null
                        $chainStatus = $null
                        $digiCertIssued = $false
                        $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()

                        try {
                            # Avoid revocation lookups during inventory scans so live probing stays fast and predictable.
                            $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                            $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
                            $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
                            $null = $chain.Build($Certificate)

                            $chainElements = @($chain.ChainElements)
                            if ($chainElements.Count -gt 0) {
                                $serverCertificateCount = $chainElements.Count
                                $chainStatus = Get-ChainStatusSummaryLocal -Chain $chain
                                $lastElementCertificate = $chainElements[$chainElements.Count - 1].Certificate
                                $lastIsSelfSigned = $lastElementCertificate -and ($lastElementCertificate.Subject -eq $lastElementCertificate.Issuer)

                                $intermediateCertificates = @()
                                # Treat a self-signed last element as the root and everything between as intermediates.
                                if ($chainElements.Count -ge 3 -or $lastIsSelfSigned) {
                                    $rootCA = Get-CertificateDisplayNameLocal -Certificate $lastElementCertificate
                                    if ($chainElements.Count -gt 2) {
                                        $intermediateCertificates = @($chainElements[1..($chainElements.Count - 2)] | ForEach-Object { $_.Certificate })
                                    }
                                }
                                elseif ($chainElements.Count -gt 1) {
                                    $intermediateCertificates = @($chainElements[1..($chainElements.Count - 1)] | ForEach-Object { $_.Certificate })
                                }

                                $intermediateNames = @(
                                    $intermediateCertificates |
                                        ForEach-Object { Get-CertificateDisplayNameLocal -Certificate $_ } |
                                        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                                        Select-Object -Unique
                                )
                                if ($intermediateNames.Count -gt 0) {
                                    $intermediateCA = $intermediateNames -join ' | '
                                }
                            }
                        }
                        finally {
                            $chain.Dispose()
                        }

                        if ($issuerDetails.Issuer -match '\bDigiCert\b' -or $issuerDetails.IssuingCA -match '\bDigiCert\b' -or $intermediateCA -match '\bDigiCert\b' -or $rootCA -match '\bDigiCert\b') {
                            $digiCertIssued = $true
                        }

                        return @{
                            Subject                = $Certificate.Subject
                            Issuer                 = $issuerDetails.Issuer
                            IssuingCA              = $issuerDetails.IssuingCA
                            ServerCertificateCount = $serverCertificateCount
                            IntermediateCA         = $intermediateCA
                            RootCA                 = $rootCA
                            ChainStatus            = $chainStatus
                            DigiCertIssued         = $digiCertIssued
                        }
                    }
                    
                    $expiryDate = $null
                    $subject = $null
                    $issuer = $null
                    $issuingCA = $null
                    $serverCertificateCount = $null
                    $intermediateCA = $null
                    $rootCA = $null
                    $chainStatus = $null
                    $digiCertIssued = $null
                    $probeResult = $null
                    $statusErrors = [System.Collections.Generic.List[string]]::new()
                    
                    # Inline the TLS probe so each runspace can own and dispose its own socket state.
                    try {
                        $probeResult = Invoke-WithRetryLocal -Action {
                            $attemptTcpClient = $null
                            $attemptSslStream = $null
                            $attemptNetworkStream = $null
                            $attemptReader = $null
                            $attemptWriter = $null

                            try {
                                $attemptTcpClient = [System.Net.Sockets.TcpClient]::new()
                                $attemptTcpClient.SendTimeout = $timeout
                                $attemptTcpClient.ReceiveTimeout = $timeout

                                if ($proxy) {
                                    $attemptTcpClient.Connect($proxy.Host, $proxy.Port)
                                    $attemptNetworkStream = $attemptTcpClient.GetStream()

                                    $attemptWriter = [System.IO.StreamWriter]::new($attemptNetworkStream, [System.Text.Encoding]::ASCII)
                                    $attemptWriter.AutoFlush = $true
                                    $attemptReader = [System.IO.StreamReader]::new($attemptNetworkStream, [System.Text.Encoding]::ASCII)

                                    $attemptWriter.WriteLine("CONNECT $($ep.HostName):443 HTTP/1.1")
                                    $attemptWriter.WriteLine("Host: $($ep.HostName):443")
                                    $attemptWriter.WriteLine("")

                                    $response = $attemptReader.ReadLine()
                                    if ($response -notmatch "^HTTP/\d\.\d 200") {
                                        throw "Proxy CONNECT failed: $response"
                                    }
                                    while ($true) {
                                        $line = $attemptReader.ReadLine()
                                        if ([string]::IsNullOrEmpty($line)) { break }
                                    }

                                    $attemptSslStream = [System.Net.Security.SslStream]::new(
                                        $attemptNetworkStream, $false,
                                        { param($s, $certificate, $chain, $sslPolicyErrors) return $true }
                                    )
                                }
                                else {
                                    $attemptTcpClient.Connect($ep.HostName, 443)
                                    $attemptSslStream = [System.Net.Security.SslStream]::new(
                                        $attemptTcpClient.GetStream(), $false,
                                        { param($s, $certificate, $chain, $sslPolicyErrors) return $true }
                                    )
                                }

                                $attemptSslStream.AuthenticateAsClient($ep.HostName)
                                $cert = $attemptSslStream.RemoteCertificate

                                if ($cert) {
                                    $x509 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cert)
                                    $certDetails = Get-CertificateChainDetailsLocal -Certificate $x509
                                    return [PSCustomObject]@{
                                        ExpirationDate         = $x509.NotAfter
                                        Subject                = $certDetails.Subject
                                        Issuer                 = $certDetails.Issuer
                                        IssuingCA              = $certDetails.IssuingCA
                                        ServerCertificateCount = $certDetails.ServerCertificateCount
                                        IntermediateCA         = $certDetails.IntermediateCA
                                        RootCA                 = $certDetails.RootCA
                                        ChainStatus            = $certDetails.ChainStatus
                                        DigiCertIssued         = $certDetails.DigiCertIssued
                                    }
                                }

                                return $null
                            }
                            finally {
                                if ($attemptWriter) { $attemptWriter.Dispose() }
                                if ($attemptReader) { $attemptReader.Dispose() }
                                if ($attemptSslStream) { $attemptSslStream.Dispose() }
                                if ($attemptTcpClient) { $attemptTcpClient.Dispose() }
                            }
                        } -MaxAttempts $tlsRetryCount -BaseDelayMs $retryBaseDelayMs

                        if ($probeResult) {
                            $expiryDate = $probeResult.ExpirationDate
                            $subject = $probeResult.Subject
                            $issuer = $probeResult.Issuer
                            $issuingCA = $probeResult.IssuingCA
                            $serverCertificateCount = $probeResult.ServerCertificateCount
                            $intermediateCA = $probeResult.IntermediateCA
                            $rootCA = $probeResult.RootCA
                            $chainStatus = $probeResult.ChainStatus
                            $digiCertIssued = $probeResult.DigiCertIssued
                        }
                    } catch {
                        $errorMsg = Get-ExceptionMessageSummaryLocal -Exception $_.Exception
                        $null = $statusErrors.Add("TLS: $errorMsg")
                    }
                    
                    # Calculate expiration status
                    $expiryDisplay = $null
                    $expiryStatus = 'OK'
                    if ($expiryDate) {
                        $expiryDisplay = $expiryDate.ToString()
                        $daysUntilExpiry = ($expiryDate - $scanAt).Days
                        $expiryStatus = if ($daysUntilExpiry -lt 0) { 'EXPIRED' } elseif ($daysUntilExpiry -le $warnDays) { 'WARNING' } else { 'OK' }
                    }
                    $overallStatus = Get-CertificateStatusSummaryLocal -ChainStatus $chainStatus -ExpirationStatus $expiryStatus -StatusItems @($statusErrors) -HasExpirationDate ($null -ne $expiryDate)
                    
                    [PSCustomObject]@{
                        SubscriptionId     = $ep.SubscriptionId
                        SubscriptionName   = $ep.SubscriptionName
                        FrontDoorName      = $ep.FrontDoorName
                        MigrationSourceResourceId = $ep.MigrationSourceResourceId
                        MigrationTargetResourceId = $ep.MigrationTargetResourceId
                        EndpointAssociation = $ep.EndpointAssociation
                        FrontDoorType      = 'Classic'
                        Domain             = $ep.HostName
                        CertificateType    = $ep.CertificateSource
                        ProvisioningState  = $ep.ProvisioningState
                        ValidationState    = $null
                        Subject            = $subject
                        Issuer             = $issuer
                        IssuingCA          = $issuingCA
                        ServerCertificateCount = $serverCertificateCount
                        IntermediateCA         = $intermediateCA
                        RootCA                 = $rootCA
                        ChainStatus            = $overallStatus
                        DigiCertIssued         = $digiCertIssued
                        ExpirationDateRaw  = $expiryDate
                        ExpirationDate     = $expiryDisplay
                        ExpirationStatus   = $expiryStatus
                        KeyVaultName       = $ep.KeyVaultName
                        KeyVaultSecretName = $ep.KeyVaultSecretName
                    }
                } | ForEach-Object {
                    $tlsProcessedCount++
                    if (($tlsProcessedCount % $tlsProgressInterval -eq 0) -or ($tlsProcessedCount -eq $classicEndpoints.Count)) {
                        Write-Host "    TLS probed $tlsProcessedCount/$($classicEndpoints.Count): $($_.Domain)" -ForegroundColor DarkGray
                    }

                    $allResults.Add($_)
                }
                Write-Host "    Completed Classic TLS probing." -ForegroundColor Green
            }
        }
    }
}


# Display and export results
if ($allResults.Count -eq 0) {
    Write-Host "No certificate information found." -ForegroundColor Yellow
} else {
    Write-Host "`n=== Certificate Details ===" -ForegroundColor Green
    Write-Host ""
    
    # Show ValidationState only when Standard/Premium rows are present; Classic rows keep it blank.
    $hasValidationState = @($allResults | Where-Object { $_.FrontDoorType -eq 'Standard/Premium' }).Count -gt 0
    
    # Get dynamic column widths based on console size
    $colWidths = Get-DynamicColumnWidths -hasValidationState $hasValidationState
    
    $colSub = $colWidths['Subscription']
    $colFD = $colWidths['FrontDoor']
    $colFDType = $colWidths['FDType']
    $colMigSource = $colWidths['MigSource']
    $colMigTarget = $colWidths['MigTarget']
    $colDomain = $colWidths['Domain']
    $colEndpoint = $colWidths['Endpoint']
    $colCertType = $colWidths['CertType']
    $colProvState = $colWidths['ProvState']
    $colValState = if ($hasValidationState) { $colWidths['ValState'] } else { 0 }
    $colSubject = $colWidths['Subject']
    $colIssuingCA = $colWidths['IssuingCA']
    $colRootCA = $colWidths['RootCA']
    $colExpiry = $colWidths['ExpirationDate']
    $colKVName = $colWidths['KVName']
    $colKVSecret = $colWidths['KVSecret']
    
    # Display header
    if ($hasValidationState) {
        Write-Host ("{0,-$colSub} {1,-$colFD} {2,-$colFDType} {3,-$colMigSource} {4,-$colMigTarget} {5,-$colDomain} {6,-$colEndpoint} {7,-$colCertType} {8,-$colProvState} {9,-$colValState} {10,-$colSubject} {11,-$colIssuingCA} {12,-$colRootCA} {13,-$colExpiry} {14,-$colKVName} {15}" -f "Subscription", "FrontDoor", "FDType", "MigSource", "MigTarget", "Domain", "Endpoint", "CertType", "ProvState", "ValState", "Subject", "IssuingCA", "RootCA", "ExpirationDate", "KVName", "KVSecret") -ForegroundColor Cyan
        Write-Host ("{0,-$colSub} {1,-$colFD} {2,-$colFDType} {3,-$colMigSource} {4,-$colMigTarget} {5,-$colDomain} {6,-$colEndpoint} {7,-$colCertType} {8,-$colProvState} {9,-$colValState} {10,-$colSubject} {11,-$colIssuingCA} {12,-$colRootCA} {13,-$colExpiry} {14,-$colKVName} {15}" -f ("-" * $colSub), ("-" * $colFD), ("-" * $colFDType), ("-" * $colMigSource), ("-" * $colMigTarget), ("-" * $colDomain), ("-" * $colEndpoint), ("-" * $colCertType), ("-" * $colProvState), ("-" * $colValState), ("-" * $colSubject), ("-" * $colIssuingCA), ("-" * $colRootCA), ("-" * $colExpiry), ("-" * $colKVName), ("-" * $colKVSecret)) -ForegroundColor Cyan
    } else {
        Write-Host ("{0,-$colSub} {1,-$colFD} {2,-$colFDType} {3,-$colMigSource} {4,-$colMigTarget} {5,-$colDomain} {6,-$colEndpoint} {7,-$colCertType} {8,-$colProvState} {9,-$colSubject} {10,-$colIssuingCA} {11,-$colRootCA} {12,-$colExpiry} {13,-$colKVName} {14}" -f "Subscription", "FrontDoor", "FDType", "MigSource", "MigTarget", "Domain", "Endpoint", "CertType", "ProvState", "Subject", "IssuingCA", "RootCA", "ExpirationDate", "KVName", "KVSecret") -ForegroundColor Cyan
        Write-Host ("{0,-$colSub} {1,-$colFD} {2,-$colFDType} {3,-$colMigSource} {4,-$colMigTarget} {5,-$colDomain} {6,-$colEndpoint} {7,-$colCertType} {8,-$colProvState} {9,-$colSubject} {10,-$colIssuingCA} {11,-$colRootCA} {12,-$colExpiry} {13,-$colKVName} {14}" -f ("-" * $colSub), ("-" * $colFD), ("-" * $colFDType), ("-" * $colMigSource), ("-" * $colMigTarget), ("-" * $colDomain), ("-" * $colEndpoint), ("-" * $colCertType), ("-" * $colProvState), ("-" * $colSubject), ("-" * $colIssuingCA), ("-" * $colRootCA), ("-" * $colExpiry), ("-" * $colKVName), ("-" * $colKVSecret)) -ForegroundColor Cyan
    }
    
    # Display results with color coding and truncation
    foreach ($result in $allResults) {
        # Truncate all fields for display
        $dispSub = Get-TruncatedString $result.SubscriptionName ($colSub - 1)
        $dispFD = Get-TruncatedString $result.FrontDoorName ($colFD - 1)
        $dispFDType = if ($result.FrontDoorType -eq 'Classic') { 'Cls' } else { 'StdPrm' }
        $dispFDType = Get-TruncatedString $dispFDType ($colFDType - 1)
        $dispMigSource = Get-TruncatedString (Get-FrontDoorMigrationDisplayName -ResourceId $result.MigrationSourceResourceId) ($colMigSource - 1)
        $dispMigTarget = Get-TruncatedString (Get-FrontDoorMigrationDisplayName -ResourceId $result.MigrationTargetResourceId) ($colMigTarget - 1)
        $dispDomain = Get-TruncatedString $result.Domain ($colDomain - 1)
        $dispEndpoint = Get-TruncatedString $result.EndpointAssociation ($colEndpoint - 1)
        
        # Simplify certificate type display
        $certType = $result.CertificateType
        $certTypeDisplay = switch -Wildcard ($certType) {
            '*KeyVault*' { 'KeyVault' }
            '*CustomerCertificate*' { 'KeyVault' }
            '*Managed*' { 'Managed' }
            'FrontDoor' { 'Managed' }
            default { $certType }
        }
        $dispCertType = Get-TruncatedString $certTypeDisplay ($colCertType - 1)
        
        $dispSubject = Get-TruncatedString $result.Subject ($colSubject - 1)
        $dispIssuingCA = Get-TruncatedString $result.IssuingCA ($colIssuingCA - 1)
        $dispRootCA = Get-TruncatedString $result.RootCA ($colRootCA - 1)
        $dispKVName = Get-TruncatedString $result.KeyVaultName ($colKVName - 1)
        $dispKVSecret = Get-TruncatedString $result.KeyVaultSecretName ($colKVSecret - 1)
        
        # Add icons to ProvisioningState display (adjust truncation to maintain column width)
        if ($result.ProvisioningState -and $result.ProvisioningState -notlike '*Succeeded*' -and $result.ProvisioningState -notlike '*Enabled*') {
            $dispProvState = "⚠️ " + (Get-TruncatedString $result.ProvisioningState ($colProvState - 3))
        } else {
            $dispProvState = Get-TruncatedString $result.ProvisioningState ($colProvState - 1)
        }
        
        # Add icons to ExpirationDate display based on status (adjust truncation to maintain column width)
        if ($result.ExpirationStatus -eq 'EXPIRED') {
            $dispExpiry = "🔴 " + (Get-TruncatedString $result.ExpirationDate ($colExpiry - 3))
        } elseif ($result.ExpirationStatus -eq 'WARNING') {
            $dispExpiry = "⚠️ " + (Get-TruncatedString $result.ExpirationDate ($colExpiry - 3))
        } else {
            $dispExpiry = Get-TruncatedString $result.ExpirationDate ($colExpiry - 1)
        }
        
        # Display subscription, frontdoor, migration hints, domain, and cert type
        Write-Host ("{0,-$colSub} {1,-$colFD} {2,-$colFDType} {3,-$colMigSource} {4,-$colMigTarget} {5,-$colDomain} {6,-$colEndpoint} {7,-$colCertType}" -f $dispSub, $dispFD, $dispFDType, $dispMigSource, $dispMigTarget, $dispDomain, $dispEndpoint, $dispCertType) -NoNewline
        
        # Provisioning State with color
        if ($result.ProvisioningState -and $result.ProvisioningState -notlike '*Succeeded*' -and $result.ProvisioningState -notlike '*Enabled*') {
            Write-Host (" {0,-$colProvState}" -f $dispProvState) -NoNewline -ForegroundColor Yellow
        } else {
            Write-Host (" {0,-$colProvState}" -f $dispProvState) -NoNewline
        }
        
        # Validation State with color (Standard/Premium only)
        if ($hasValidationState) {
            $dispValState = Get-TruncatedString $result.ValidationState ($colValState - 1)
            # Add icon for non-approved validation states
            if ($result.ValidationState -and $result.ValidationState -notlike '*Approved*') {
                $dispValState = "⚠️ " + $dispValState
                Write-Host (" {0,-$colValState}" -f $dispValState) -NoNewline -ForegroundColor Yellow
            } else {
                Write-Host (" {0,-$colValState}" -f $dispValState) -NoNewline
            }
        }
        
        # Subject
        Write-Host (" {0,-$colSubject}" -f $dispSubject) -NoNewline
        Write-Host (" {0,-$colIssuingCA}" -f $dispIssuingCA) -NoNewline
        Write-Host (" {0,-$colRootCA}" -f $dispRootCA) -NoNewline
        
        # Expiration Date with color
        if ($result.ExpirationStatus -eq 'EXPIRED') {
            Write-Host (" {0,-$colExpiry}" -f $dispExpiry) -NoNewline -ForegroundColor Red
        } elseif ($result.ExpirationStatus -eq 'WARNING') {
            Write-Host (" {0,-$colExpiry}" -f $dispExpiry) -NoNewline -ForegroundColor Yellow
        } else {
            Write-Host (" {0,-$colExpiry}" -f $dispExpiry) -NoNewline
        }
        
        # Key Vault details
        Write-Host (" {0,-$colKVName} {1}" -f $dispKVName, $dispKVSecret)
    }
    
    Write-Host ""
    
    # Summary of issues
    $expired = ($allResults | Where-Object { $_.ExpirationStatus -eq 'EXPIRED' }).Count
    $expiringSoon = ($allResults | Where-Object { $_.ExpirationStatus -eq 'WARNING' }).Count
    $totalCerts = $allResults.Count
    
    Write-Host "`n=== Summary ===" -ForegroundColor Cyan
    Write-Host "Total certificates: $totalCerts" -ForegroundColor Cyan
    
    if ($expired -gt 0) {
        Write-Host "🔴 $expired certificate(s) EXPIRED" -ForegroundColor Red
    }
    if ($expiringSoon -gt 0) {
        Write-Host "⚠️  $expiringSoon certificate(s) expiring within $WarningDays days" -ForegroundColor Yellow
    }
    if ($expired -eq 0 -and $expiringSoon -eq 0) {
        Write-Host "✅ All certificates are valid and not expiring soon" -ForegroundColor Green
    }
    
    # Export to CSV and/or XLSX if requested
    if ($ExportCsvPath -or $ExportXlsxPath) {
        $exportColumns = Get-ResultExportColumns
        $exportRecords = @($allResults | Select-Object $exportColumns)
        $xlsxExportRecords = Get-XlsxExportRecords -Results $allResults -Columns $exportColumns

        $resolvedExportCsvPath = $null
        if ($ExportCsvPath) {
            $resolvedExportCsvPath = Initialize-ParentDirectoryPath -FilePath $ExportCsvPath
            $exportRecords | Export-Csv -LiteralPath $resolvedExportCsvPath -NoTypeInformation -Encoding utf8 -Force
            Write-Host "`nResults exported to: $resolvedExportCsvPath" -ForegroundColor Green
        }

        # An explicit XLSX path wins; otherwise keep the existing companion-workbook behavior
        # by deriving the workbook path from the CSV export path.
        $resolvedExportXlsxInfo = $null
        $resolvedExportXlsxPath = $null
        if ($ExportXlsxPath) {
            $resolvedExportXlsxInfo = Resolve-AvailableExportFilePath -FilePath $ExportXlsxPath
            $resolvedExportXlsxPath = $resolvedExportXlsxInfo.Path
        }
        elseif ($resolvedExportCsvPath) {
            $resolvedExportXlsxInfo = Resolve-AvailableExportFilePath -FilePath ([System.IO.Path]::ChangeExtension($resolvedExportCsvPath, '.xlsx'))
            $resolvedExportXlsxPath = $resolvedExportXlsxInfo.Path
        }

        $importExcelModule = Get-Module -ListAvailable -Name ImportExcel | Sort-Object Version -Descending | Select-Object -First 1
        if ($resolvedExportXlsxPath -and $importExcelModule) {
            try {
                Import-Module $importExcelModule.Path -ErrorAction Stop | Out-Null

                if ($resolvedExportXlsxInfo -and $resolvedExportXlsxInfo.Redirected) {
                    Write-Host "Requested XLSX path is in use. Exporting workbook to: $resolvedExportXlsxPath" -ForegroundColor DarkYellow
                }

                $xlsxTextColumns = @(
                    'SubscriptionId',
                    'SubscriptionName',
                    'FrontDoorName',
                    'FrontDoorType',
                    'MigrationSourceResourceId',
                    'MigrationTargetResourceId',
                    'EndpointAssociation',
                    'Domain',
                    'CertificateType',
                    'ProvisioningState',
                    'ValidationState',
                    'Subject',
                    'Issuer',
                    'IssuingCA',
                    'IntermediateCA',
                    'RootCA',
                    'ChainStatus',
                    'KeyVaultName',
                    'KeyVaultSecretName'
                )

                $worksheetName = [System.IO.Path]::GetFileNameWithoutExtension($resolvedExportXlsxPath)
                $worksheetName = $worksheetName -replace '[\\/\?\*\[\]:]', '_'
                if ([string]::IsNullOrWhiteSpace($worksheetName)) {
                    $worksheetName = 'afd-certs'
                }
                if ($worksheetName.Length -gt 31) {
                    $worksheetName = $worksheetName.Substring(0, 31)
                }

                $expirationDateColumnIndex = [Array]::IndexOf($exportColumns, 'ExpirationDate') + 1
                $serverCertificateCountColumnIndex = [Array]::IndexOf($exportColumns, 'ServerCertificateCount') + 1
                $chainStatusColumnIndex = [Array]::IndexOf($exportColumns, 'ChainStatus') + 1
                $digiCertIssuedColumnIndex = [Array]::IndexOf($exportColumns, 'DigiCertIssued') + 1
                $expirationDateNumberFormat = [System.Globalization.CultureInfo]::CurrentCulture.DateTimeFormat.FullDateTimePattern
                $expirationDateNumberFormat = $expirationDateNumberFormat -replace '(?<!t)tt(?!t)', 'AM/PM'
                $expirationDateNumberFormat = $expirationDateNumberFormat -replace '(?<!t)t(?!t)', 'A/P'
                $xlsxCellStyle = {
                    param($worksheet, $totalRows, $lastColumn)

                    $centeredColumns = @($serverCertificateCountColumnIndex, $chainStatusColumnIndex, $digiCertIssuedColumnIndex)
                    foreach ($columnIndex in $centeredColumns) {
                        if ($columnIndex -gt 0) {
                            $worksheet.Column($columnIndex).Style.HorizontalAlignment = [OfficeOpenXml.Style.ExcelHorizontalAlignment]::Center
                        }
                    }

                    if ($expirationDateColumnIndex -gt 0) {
                        $worksheet.Column($expirationDateColumnIndex).Style.Numberformat.Format = $expirationDateNumberFormat
                        $worksheet.Column($expirationDateColumnIndex).Style.HorizontalAlignment = [OfficeOpenXml.Style.ExcelHorizontalAlignment]::Center
                    }
                }.GetNewClosure()

                # ImportExcel attempts CurrentCulture numeric parsing on string values by default.
                # Keep text-heavy columns as literal text so hostnames and IDs are never coerced.
                $xlsxExportRecords | Export-Excel -Path $resolvedExportXlsxPath -WorksheetName $worksheetName -TableName Table1 -TableStyle Medium2 -NoNumberConversion $xlsxTextColumns -AutoFilter -AutoSize -FreezeTopRow -ClearSheet -CellStyleSB $xlsxCellStyle | Out-Null
                Set-XlsxTableStyleInfo -Path $resolvedExportXlsxPath -TableStyleName 'TableStyleMedium2'
                if ($resolvedExportCsvPath) {
                    Write-Host "Companion XLSX exported to: $resolvedExportXlsxPath" -ForegroundColor Green
                }
                else {
                    Write-Host "Results exported to XLSX: $resolvedExportXlsxPath" -ForegroundColor Green
                }
            }
            catch {
                Write-Host "ImportExcel is installed but XLSX export failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
            }
        }
        elseif ($resolvedExportXlsxPath) {
            if ($resolvedExportCsvPath) {
                Write-Host 'ImportExcel module not found. Skipping XLSX export and keeping CSV only.' -ForegroundColor DarkYellow
            }
            else {
                Write-Host 'ImportExcel module not found. Skipping requested XLSX export.' -ForegroundColor DarkYellow
            }
        }
    }
    
    # Display in GridView if requested
    if ($GridView) {
        Write-Host "`nOpening GridView..." -ForegroundColor Cyan
        $gridViewColumns = Get-ResultExportColumns
        $allResults | Select-Object $gridViewColumns | Out-GridView -Title "Azure Front Door Certificates"
    }
}
