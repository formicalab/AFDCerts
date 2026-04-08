<#
.SYNOPSIS
    Extracts and analyzes SSL/TLS certificate expirations for Azure Front Door profiles.

.DESCRIPTION
    This script extracts certificate information from Azure Front Door deployments, supporting
    both Classic and Standard/Premium Front Door profiles. It displays certificate expiration
    dates with status indicators, shows provisioning and validation states, and can export
    results to CSV for reporting.

    The script supports both Azure-managed certificates and custom certificates from Key Vault,
    providing detailed information including certificate subject, provisioning state,
    validation state, and Key Vault details where applicable.

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
    exported to this location for reporting and analysis purposes.

.PARAMETER GridView
    Display results in an interactive GridView window. Allows sorting, filtering, and
    selecting results. Requires a graphical environment (not supported in headless sessions).

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

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.Object[]
    The script outputs a formatted table showing certificate details and returns an array of
    custom objects containing certificate information. If ExportCsvPath is specified,
    results are also exported to a CSV file.

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
    and exports results to CSV.

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
    - Az.FrontDoor module is required for Classic Front Door enumeration in subscription mode
    
    Performance:
    - Tenant mode uses parallel processing for faster scanning
    - ThrottleLimit controls parallelism for ARM API calls (Standard/Premium FDs)
    - TlsThrottleLimit controls parallelism for TLS certificate probing (Classic FDs)
    - Progress updates are batched to reduce console I/O overhead

.LINK
    https://github.com/formicalab/AFDCerts

.LINK
    https://docs.microsoft.com/en-us/azure/frontdoor/

.LINK
    https://docs.microsoft.com/en-us/powershell/azure/
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
    [int]$TlsTimeoutMs = 5000
)

Set-StrictMode -Version 1
$ErrorActionPreference = 'Stop'

# API version constant
$script:ApiVersion = '2025-04-15'

# Check for system proxy configuration once at startup
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

        $response = Invoke-RestMethod -Method Post -Uri $graphUri -Headers $Headers -Body $body -ErrorAction Stop
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

#endregion

# Verify Azure login
$context = Get-AzContext
if (-not $context) {
    throw "Not logged in to Azure. Please run Connect-AzAccount first."
}

# Global results collection (using List for better append performance)
$allResults = [System.Collections.Generic.List[PSCustomObject]]::new()

#region Certificate fetching for Classic Front Door

# Helper function to get certificate from a domain using TcpClient + SslStream
# Uses $script:ProxyUri detected at startup for HTTP CONNECT tunnel
function Get-CertificateFromDomain {
    param([string]$DomainName)
    
    $tcpClient = $null
    $sslStream = $null
    $networkStream = $null
    
    try {
        $tcpClient = [System.Net.Sockets.TcpClient]::new()
        
        if ($script:ProxyUri) {
            # Connect to proxy server
            $tcpClient.Connect($script:ProxyUri.Host, $script:ProxyUri.Port)
            $networkStream = $tcpClient.GetStream()
            
            # Send HTTP CONNECT request to establish tunnel
            $writer = [System.IO.StreamWriter]::new($networkStream, [System.Text.Encoding]::ASCII)
            $writer.AutoFlush = $true
            $reader = [System.IO.StreamReader]::new($networkStream, [System.Text.Encoding]::ASCII)
            
            $writer.WriteLine("CONNECT ${DomainName}:443 HTTP/1.1")
            $writer.WriteLine("Host: ${DomainName}:443")
            $writer.WriteLine("")
            
            # Read proxy response
            $response = $reader.ReadLine()
            if ($response -notmatch "^HTTP/\d\.\d 200") {
                throw "Proxy CONNECT failed: $response"
            }
            
            # Read and discard remaining headers until empty line
            while ($true) {
                $line = $reader.ReadLine()
                if ([string]::IsNullOrEmpty($line)) { break }
            }
            
            # Now the tunnel is established, perform TLS handshake through it
            $sslStream = [System.Net.Security.SslStream]::new(
                $networkStream,
                $false,
                { param($s, $certificate, $chain, $sslPolicyErrors) return $true }
            )
        } else {
            # Direct connection (no proxy)
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
        if ($sslStream) { $sslStream.Dispose() }
        if ($tcpClient) { $tcpClient.Dispose() }
    }
}

#endregion

#region Get-TruncatedString

# Function to truncate any string to fit column width
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

# Function to calculate dynamic column widths based on console width
function Get-DynamicColumnWidths {
    param(
        [bool]$hasValidationState,
        [int]$minWidth = 80
    )
    
    # Get console width, default to 160 if unable to determine
    try {
        $consoleWidth = $Host.UI.RawUI.WindowSize.Width
        if ($consoleWidth -lt $minWidth) { $consoleWidth = $minWidth }
    }
    catch {
        $consoleWidth = 160
    }
    
    # Calculate available width (subtract some for spacing and borders)
    $availableWidth = $consoleWidth - 10
    
    # Define minimum widths for each column (required space)
    # High priority columns: FrontDoor, FDType, Domain, CertType, ExpirationDate (never truncated), KVName
    # Lower priority columns: Subscription, Subject, KVSecret (can be truncated if space is limited)
    $minWidths = @{
        Subscription = 15
        FrontDoor = 15
        FDType = 7
        Domain = 25
        CertType = 8
        ProvState = 10
        ValState = 10
        Subject = 10
        ExpirationDate = 22
        KVName = 15
        KVSecret = 8
    }
    
    # Define ideal widths (what we'd like if we have space)
    $idealWidths = @{
        Subscription = 25
        FrontDoor = 26
        FDType = 7
        Domain = 38
        CertType = 11
        ProvState = 12
        ValState = 12
        Subject = 25
        ExpirationDate = 22
        KVName = 22
        KVSecret = 20
    }
    
    # Determine which columns to show based on mode
    $columns = @('Subscription', 'FrontDoor', 'FDType', 'Domain', 'CertType', 'ProvState')
    if ($hasValidationState) { $columns += 'ValState' }
    $columns += @('Subject', 'ExpirationDate', 'KVName', 'KVSecret')
    
    # Calculate minimum required width
    $minRequired = ($columns | ForEach-Object { $minWidths[$_] + 1 } | Measure-Object -Sum).Sum
    
    # If we have more space than minimum, distribute proportionally
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
        # Use minimum widths if console is narrow
        $widths = @{}
        foreach ($col in $columns) {
            $widths[$col] = $minWidths[$col]
        }
    }
    
    return $widths
}

#endregion

#region Date Formatting

# Function to format expiration date with status indicators
function Get-FormattedExpirationDate {
    param(
        [object]$expiryDate,
        [int]$warningDays
    )
    
    if (-not $expiryDate) {
        return @{ Display = $null; Status = 'OK' }
    }
    
    try {
        # Handle both string and DateTime objects
        $expiryDateTime = $expiryDate -is [DateTime] ? $expiryDate : [DateTime]::Parse($expiryDate)
        
        $formattedDate = $expiryDateTime.ToString()
        $daysUntilExpiry = ($expiryDateTime - (Get-Date)).Days
        
        $status = $daysUntilExpiry -lt 0 ? 'EXPIRED' : ($daysUntilExpiry -le $warningDays ? 'WARNING' : 'OK')
        
        return @{ Display = $formattedDate; Status = $status }
    } catch {
        # If date parsing fails, use the original value
        return @{ Display = $expiryDate; Status = 'OK' }
    }
}

#endregion

#region Get All Front Doors in Subscription

# Function to get all Front Door profiles in the current subscription
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
            $cdnProfiles = Get-AzResource -ResourceType "Microsoft.Cdn/profiles" -ErrorAction SilentlyContinue
            $afdProfiles = $cdnProfiles | Where-Object { 
                $_.Sku.Name -eq 'Standard_AzureFrontDoor' -or $_.Sku.Name -eq 'Premium_AzureFrontDoor'
            }
            
            foreach ($afdProfile in $afdProfiles) {
                $frontDoors += [PSCustomObject]@{
                    Name = $afdProfile.Name
                    ResourceGroupName = $afdProfile.ResourceGroupName
                    Type = 'Standard/Premium'
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
            $classicFDs = Get-AzFrontDoor -ErrorAction SilentlyContinue
            foreach ($fd in $classicFDs) {
                $frontDoors += [PSCustomObject]@{
                    Name = $fd.Name
                    ResourceGroupName = $fd.ResourceGroupName
                    Type = 'Classic'
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

# Function to get all Front Door profiles across all subscriptions using Azure Resource Graph REST API
# This approach avoids the null tenant issue with Search-AzGraph cmdlet and supports proper pagination
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
| extend deploymentModel = case(type =~ 'microsoft.network/frontdoors', 'Classic', 'Standard/Premium')
| where type =~ 'microsoft.network/frontdoors' or skuName in~ ('Standard_AzureFrontDoor', 'Premium_AzureFrontDoor')
| project name, resourceGroup, subscriptionId, type, deploymentModel
| order by subscriptionId, name
"@

    # Query for Standard/Premium only
    $queryStdPremium = @"
resources
| where type == 'microsoft.cdn/profiles'
| where sku.name in ('Standard_AzureFrontDoor', 'Premium_AzureFrontDoor')
| project name, resourceGroup, subscriptionId, type
| order by subscriptionId, name
"@

    # Query for Classic only
    $queryClassic = @"
resources
| where type == 'microsoft.network/frontdoors'
| project name, resourceGroup, subscriptionId, type
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
                Name              = $result.name
                ResourceGroupName = $result.resourceGroup
                SubscriptionId    = $result.subscriptionId
                Type              = $fdType
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

# Main function to process a single Front Door
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
        $fd = Get-AzResource -Name $FrontDoorName -ResourceGroupName $ResourceGroupName -ResourceType "Microsoft.Cdn/profiles" -ErrorAction SilentlyContinue
    } else {
        $fd = Get-AzResource -Name $FrontDoorName -ResourceType "Microsoft.Cdn/profiles" -ErrorAction SilentlyContinue
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
            Write-Host "  Found $($endpoints.Count) custom domain(s). Processing..."
            
            foreach ($ep in $endpoints) {
                $domainName = $ep.HostName ?? $ep.Name
                
                Write-Host "    Fetching certificate for: $domainName..." -NoNewline
                
                # Initialize fields
                $certSource = $ep.CertificateSource
                $provisioningState = $ep.CustomHttpsProvisioningState
                $expiryDate = $null
                $subject = $null
                $keyVaultName = $null
                $keyVaultSecretName = $null
                $validationState = $null  # Classic Front Door does not expose domain validation state
                
                # Extract Key Vault details if present
                if ($ep.Vault) {
                    $keyVaultSecretName = $ep.SecretName
                    $keyVaultName = ($ep.Vault -split '/')[-1]
                }
                
                # Fetch certificate from domain using TcpClient + SslStream
                # Uses proxy if detected at startup ($script:ProxyUri)
                try {
                    $cert = Get-CertificateFromDomain -DomainName $domainName
                    if ($cert) {
                        $expiryDate = $cert.NotAfter
                        $subject = $cert.Subject
                    }
                    
                    Write-Host " OK" -ForegroundColor Green
                } catch {
                    # Extract a cleaner error message from exception chain
                    $innerEx = $_.Exception.InnerException
                    while ($innerEx -and $innerEx.InnerException) { $innerEx = $innerEx.InnerException }
                    $errorMsg = if ($innerEx) { $innerEx.Message } else { $_.Exception.Message }
                    Write-Host " Failed: $errorMsg" -ForegroundColor Yellow
                }
                
                # Format expiration date with status indicators
                $expiryInfo = Get-FormattedExpirationDate -expiryDate $expiryDate -warningDays $WarningDays
                $expiryDisplay = $expiryInfo.Display
                $expiryStatus = $expiryInfo.Status
                
                $result = [PSCustomObject]@{
                    SubscriptionId     = $context.Subscription.Id
                    SubscriptionName   = $context.Subscription.Name
                    FrontDoorName      = $FrontDoorName
                    FrontDoorType      = 'Classic'
                    Domain             = $domainName
                    CertificateType    = $certSource
                    ProvisioningState  = $provisioningState
                    Subject            = $subject
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
            $domainsResp = Invoke-AzRest -Path $pathDomains -Method GET -ErrorAction Stop
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
            Write-Host "  Found $($domains.Count) custom domain(s). Processing..."

            foreach ($d in $domains) {
                # Initialize fields
                $certSource = $null
                $provisioningState = $null
                $expiryDate = $null
                $keyVaultName = $null
                $keyVaultSecretName = $null
                $validationState = $null
                $subject = $null
                
                $domainName = $d.properties.hostName ?? $d.name

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
                            $secretResp = Invoke-AzRest -Path $secretPath -Method GET -ErrorAction Stop
                            $secret = ($secretResp.Content | ConvertFrom-Json)
                            
                            if ($secret.properties -and $secret.properties.parameters) {
                                $params = $secret.properties.parameters
                                
                                if ($params.expirationDate) { 
                                    $expiryDate = $params.expirationDate 
                                }
                                if ($params.subject) {
                                    $subject = $params.subject
                                }
                                
                                # For Customer Certificates, extract Key Vault details
                                if ($params.type -eq 'CustomerCertificate' -and $params.secretSource -and $params.secretSource.id) {
                                    $kvSecretId = $params.secretSource.id
                                    if ($kvSecretId -match '/vaults/([^/]+)/') { $keyVaultName = $matches[1] }
                                    if ($kvSecretId -match '/secrets/([^/]+)') { $keyVaultSecretName = $matches[1] }
                                }
                            }
                            Write-Host " OK" -ForegroundColor Green
                        }
                        catch {
                            Write-Host " Failed" -ForegroundColor Yellow
                        }
                    }
                }

                # Format expiration date with status indicators
                $expiryInfo = Get-FormattedExpirationDate -expiryDate $expiryDate -warningDays $WarningDays
                $expiryDisplay = $expiryInfo.Display
                $expiryStatus = $expiryInfo.Status

                $result = [PSCustomObject]@{
                    SubscriptionId     = $context.Subscription.Id
                    SubscriptionName   = $context.Subscription.Name
                    FrontDoorName      = $FrontDoorName
                    FrontDoorType      = 'Standard/Premium'
                    Domain             = $domainName
                    CertificateType    = $certSource
                    ProvisioningState  = $provisioningState
                    ValidationState    = $validationState
                    Subject            = $subject
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
        # Step 4: Process Front Doors in parallel grouped by type
        Write-Host "[4/4] Processing certificates (parallel=$ThrottleLimit)..." -ForegroundColor Cyan
        
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
                
                # Build ARM REST URI for this Front Door's custom domains
                $baseUri = "https://management.azure.com/subscriptions/$($fd.SubscriptionId)/resourceGroups/$($fd.ResourceGroupName)/providers/Microsoft.Cdn/profiles/$($fd.Name)"
                
                try {
                    # Get custom domains
                    $domainsUri = "$baseUri/customDomains?api-version=$apiVer"
                    $domainsResp = Invoke-RestMethod -Method Get -Uri $domainsUri -Headers $hdrs -ErrorAction Stop
                    $domains = @($domainsResp.value)
                    
                    foreach ($d in $domains) {
                        $domainName = $d.properties.hostName ?? $d.name
                        $certSource = $null
                        $provisioningState = $d.properties.provisioningState
                        $validationState = $d.properties.domainValidationState
                        $expiryDate = $null
                        $subject = $null
                        $keyVaultName = $null
                        $keyVaultSecretName = $null
                        
                        # Get TLS settings
                        if ($d.properties.tlsSettings) {
                            $tls = $d.properties.tlsSettings
                            $certSource = switch ($tls.certificateType) {
                                'ManagedCertificate' { 'Managed' }
                                'CustomerCertificate' { 'KeyVault' }
                                default { $tls.certificateType }
                            }
                            
                            # Fetch certificate details from secret
                            if ($tls.secret -and $tls.secret.id) {
                                $secretUri = "https://management.azure.com$($tls.secret.id)?api-version=$apiVer"
                                try {
                                    $secret = Invoke-RestMethod -Method Get -Uri $secretUri -Headers $hdrs -ErrorAction Stop
                                    if ($secret.properties -and $secret.properties.parameters) {
                                        $params = $secret.properties.parameters
                                        if ($params.expirationDate) { $expiryDate = $params.expirationDate }
                                        if ($params.subject) { $subject = $params.subject }
                                        
                                        if ($params.type -eq 'CustomerCertificate' -and $params.secretSource -and $params.secretSource.id) {
                                            $kvSecretId = $params.secretSource.id
                                            if ($kvSecretId -match '/vaults/([^/]+)/') { $keyVaultName = $Matches[1] }
                                            if ($kvSecretId -match '/secrets/([^/]+)') { $keyVaultSecretName = $Matches[1] }
                                        }
                                    }
                                } catch { }
                            }
                        }
                        
                        # Calculate expiration status
                        $expiryDisplay = $null
                        $expiryStatus = 'OK'
                        if ($expiryDate) {
                            try {
                                $expiryDateTime = if ($expiryDate -is [DateTime]) { $expiryDate } else { [DateTime]::Parse($expiryDate) }
                                $expiryDisplay = $expiryDateTime.ToString()
                                $daysUntilExpiry = ($expiryDateTime - (Get-Date)).Days
                                $expiryStatus = if ($daysUntilExpiry -lt 0) { 'EXPIRED' } elseif ($daysUntilExpiry -le $warnDays) { 'WARNING' } else { 'OK' }
                            } catch { $expiryDisplay = $expiryDate }
                        }
                        
                        [PSCustomObject]@{
                            SubscriptionId     = $fd.SubscriptionId
                            SubscriptionName   = $subLookup[$fd.SubscriptionId] ?? $fd.SubscriptionId
                            FrontDoorName      = $fd.Name
                            FrontDoorType      = 'Standard/Premium'
                            Domain             = $domainName
                            CertificateType    = $certSource
                            ProvisioningState  = $provisioningState
                            ValidationState    = $validationState
                            Subject            = $subject
                            ExpirationDate     = $expiryDisplay
                            ExpirationStatus   = $expiryStatus
                            KeyVaultName       = $keyVaultName
                            KeyVaultSecretName = $keyVaultSecretName
                        }
                    }
                    
                    # Progress marker
                    [PSCustomObject]@{ __Progress = $true; FrontDoorName = $fd.Name; DomainCount = $domains.Count }
                } catch {
                    [PSCustomObject]@{ __Progress = $true; FrontDoorName = $fd.Name; DomainCount = 0; Error = $_.Exception.Message }
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
        
        # Process Classic Front Doors with parallel TLS probing
        if ($classicFDs.Count -gt 0) {
            Write-Host "  Processing $($classicFDs.Count) Classic Front Door(s)..." -ForegroundColor Cyan
            
            # First, enumerate all Classic FD endpoints (requires Az context switching, done sequentially)
            $classicEndpoints = [System.Collections.Generic.List[PSCustomObject]]::new()
            
            # Group by subscription to minimize context switches
            $classicBySubscription = $classicFDs | Group-Object SubscriptionId
            $subIndex = 0
            $totalSubs = $classicBySubscription.Count
            $classicFDsProcessed = 0
            
            Write-Host "    Enumerating endpoints across $totalSubs subscription(s)..." -ForegroundColor Cyan
            
            foreach ($subGroup in $classicBySubscription) {
                $subIndex++
                try {
                    $null = Set-AzContext -Subscription $subGroup.Name -ErrorAction Stop
                    $ctx = Get-AzContext
                    $subName = $ctx.Subscription.Name
                    $fdsInSub = $subGroup.Group.Count
                    
                    foreach ($fd in $subGroup.Group) {
                        $classicFDsProcessed++
                        try {
                            $endpoints = Get-AzFrontDoorFrontendEndpoint -FrontDoorName $fd.Name -ResourceGroupName $fd.ResourceGroupName -ErrorAction Stop
                            foreach ($ep in $endpoints) {
                                $classicEndpoints.Add([PSCustomObject]@{
                                    SubscriptionId     = $ctx.Subscription.Id
                                    SubscriptionName   = $ctx.Subscription.Name
                                    FrontDoorName      = $fd.Name
                                    ResourceGroupName  = $fd.ResourceGroupName
                                    HostName           = $ep.HostName ?? $ep.Name
                                    CertificateSource  = $ep.CertificateSource
                                    ProvisioningState  = $ep.CustomHttpsProvisioningState
                                    KeyVaultName       = if ($ep.Vault) { ($ep.Vault -split '/')[-1] } else { $null }
                                    KeyVaultSecretName = $ep.SecretName
                                })
                            }
                        } catch {
                            Write-Host "      Warning: Failed to get endpoints for $($fd.Name): $($_.Exception.Message)" -ForegroundColor Yellow
                        }
                    }
                    Write-Host "      [$subIndex/$totalSubs] $subName : $fdsInSub FD(s), $($classicEndpoints.Count) endpoint(s) total" -ForegroundColor DarkGray
                } catch {
                    Write-Host "      [$subIndex/$totalSubs] Warning: Failed to switch to subscription $($subGroup.Name): $($_.Exception.Message)" -ForegroundColor Yellow
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
                    
                    $expiryDate = $null
                    $subject = $null
                    $errorMsg = $null
                    
                    # Inline TLS certificate fetching (functions don't inherit in parallel runspaces)
                    try {
                        $tcpClient = [System.Net.Sockets.TcpClient]::new()
                        $tcpClient.SendTimeout = $timeout
                        $tcpClient.ReceiveTimeout = $timeout
                        
                        if ($proxy) {
                            # Connect via proxy with HTTP CONNECT tunnel
                            $tcpClient.Connect($proxy.Host, $proxy.Port)
                            $networkStream = $tcpClient.GetStream()
                            
                            $writer = [System.IO.StreamWriter]::new($networkStream, [System.Text.Encoding]::ASCII)
                            $writer.AutoFlush = $true
                            $reader = [System.IO.StreamReader]::new($networkStream, [System.Text.Encoding]::ASCII)
                            
                            $writer.WriteLine("CONNECT $($ep.HostName):443 HTTP/1.1")
                            $writer.WriteLine("Host: $($ep.HostName):443")
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
                                $networkStream, $false,
                                { param($s, $certificate, $chain, $sslPolicyErrors) return $true }
                            )
                        } else {
                            # Direct connection
                            $tcpClient.Connect($ep.HostName, 443)
                            $sslStream = [System.Net.Security.SslStream]::new(
                                $tcpClient.GetStream(), $false,
                                { param($s, $certificate, $chain, $sslPolicyErrors) return $true }
                            )
                        }
                        
                        $sslStream.AuthenticateAsClient($ep.HostName)
                        $cert = $sslStream.RemoteCertificate
                        
                        if ($cert) {
                            $x509 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cert)
                            $expiryDate = $x509.NotAfter
                            $subject = $x509.Subject
                        }
                        
                        $sslStream.Dispose()
                        $tcpClient.Dispose()
                    } catch {
                        $innerEx = $_.Exception.InnerException
                        while ($innerEx -and $innerEx.InnerException) { $innerEx = $innerEx.InnerException }
                        $errorMsg = if ($innerEx) { $innerEx.Message } else { $_.Exception.Message }
                    }
                    
                    # Calculate expiration status
                    $expiryDisplay = $null
                    $expiryStatus = 'OK'
                    if ($expiryDate) {
                        $expiryDisplay = $expiryDate.ToString()
                        $daysUntilExpiry = ($expiryDate - (Get-Date)).Days
                        $expiryStatus = if ($daysUntilExpiry -lt 0) { 'EXPIRED' } elseif ($daysUntilExpiry -le $warnDays) { 'WARNING' } else { 'OK' }
                    }
                    
                    [PSCustomObject]@{
                        SubscriptionId     = $ep.SubscriptionId
                        SubscriptionName   = $ep.SubscriptionName
                        FrontDoorName      = $ep.FrontDoorName
                        FrontDoorType      = 'Classic'
                        Domain             = $ep.HostName
                        CertificateType    = $ep.CertificateSource
                        ProvisioningState  = $ep.ProvisioningState
                        Subject            = $subject
                        ExpirationDate     = $expiryDisplay
                        ExpirationStatus   = $expiryStatus
                        KeyVaultName       = $ep.KeyVaultName
                        KeyVaultSecretName = $ep.KeyVaultSecretName
                        TlsError           = $errorMsg
                        __Progress         = $true
                    }
                } | ForEach-Object {
                    $tlsProcessedCount++
                    if (($tlsProcessedCount % $tlsProgressInterval -eq 0) -or ($tlsProcessedCount -eq $classicEndpoints.Count)) {
                        $status = if ($_.TlsError) { "Error" } else { "OK" }
                        Write-Host "    TLS probed $tlsProcessedCount/$($classicEndpoints.Count): $($_.Domain) -> $status" -ForegroundColor DarkGray
                    }
                    
                    # Remove internal properties and add to results
                    $result = [PSCustomObject]@{
                        SubscriptionId     = $_.SubscriptionId
                        SubscriptionName   = $_.SubscriptionName
                        FrontDoorName      = $_.FrontDoorName
                        FrontDoorType      = $_.FrontDoorType
                        Domain             = $_.Domain
                        CertificateType    = $_.CertificateType
                        ProvisioningState  = $_.ProvisioningState
                        Subject            = $_.Subject
                        ExpirationDate     = $_.ExpirationDate
                        ExpirationStatus   = $_.ExpirationStatus
                        KeyVaultName       = $_.KeyVaultName
                        KeyVaultSecretName = $_.KeyVaultSecretName
                    }
                    $allResults.Add($result)
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
    
    # Check if any result has ValidationState (Standard/Premium) or not (Classic)
    $hasValidationState = $allResults[0].PSObject.Properties.Name -contains 'ValidationState'
    
    # Get dynamic column widths based on console size
    $colWidths = Get-DynamicColumnWidths -hasValidationState $hasValidationState
    
    $colSub = $colWidths['Subscription']
    $colFD = $colWidths['FrontDoor']
    $colFDType = $colWidths['FDType']
    $colDomain = $colWidths['Domain']
    $colCertType = $colWidths['CertType']
    $colProvState = $colWidths['ProvState']
    $colValState = if ($hasValidationState) { $colWidths['ValState'] } else { 0 }
    $colSubject = $colWidths['Subject']
    $colExpiry = $colWidths['ExpirationDate']
    $colKVName = $colWidths['KVName']
    $colKVSecret = $colWidths['KVSecret']
    
    # Display header
    if ($hasValidationState) {
        Write-Host ("{0,-$colSub} {1,-$colFD} {2,-$colFDType} {3,-$colDomain} {4,-$colCertType} {5,-$colProvState} {6,-$colValState} {7,-$colSubject} {8,-$colExpiry} {9,-$colKVName} {10}" -f "Subscription", "FrontDoor", "FDType", "Domain", "CertType", "ProvState", "ValState", "Subject", "ExpirationDate", "KVName", "KVSecret") -ForegroundColor Cyan
        Write-Host ("{0,-$colSub} {1,-$colFD} {2,-$colFDType} {3,-$colDomain} {4,-$colCertType} {5,-$colProvState} {6,-$colValState} {7,-$colSubject} {8,-$colExpiry} {9,-$colKVName} {10}" -f ("-" * $colSub), ("-" * $colFD), ("-" * $colFDType), ("-" * $colDomain), ("-" * $colCertType), ("-" * $colProvState), ("-" * $colValState), ("-" * $colSubject), ("-" * $colExpiry), ("-" * $colKVName), ("-" * $colKVSecret)) -ForegroundColor Cyan
    } else {
        Write-Host ("{0,-$colSub} {1,-$colFD} {2,-$colFDType} {3,-$colDomain} {4,-$colCertType} {5,-$colProvState} {6,-$colSubject} {7,-$colExpiry} {8,-$colKVName} {9}" -f "Subscription", "FrontDoor", "FDType", "Domain", "CertType", "ProvState", "Subject", "ExpirationDate", "KVName", "KVSecret") -ForegroundColor Cyan
        Write-Host ("{0,-$colSub} {1,-$colFD} {2,-$colFDType} {3,-$colDomain} {4,-$colCertType} {5,-$colProvState} {6,-$colSubject} {7,-$colExpiry} {8,-$colKVName} {9}" -f ("-" * $colSub), ("-" * $colFD), ("-" * $colFDType), ("-" * $colDomain), ("-" * $colCertType), ("-" * $colProvState), ("-" * $colSubject), ("-" * $colExpiry), ("-" * $colKVName), ("-" * $colKVSecret)) -ForegroundColor Cyan
    }
    
    # Display results with color coding and truncation
    foreach ($result in $allResults) {
        # Truncate all fields for display
        $dispSub = Get-TruncatedString $result.SubscriptionName ($colSub - 1)
        $dispFD = Get-TruncatedString $result.FrontDoorName ($colFD - 1)
        $dispFDType = if ($result.FrontDoorType -eq 'Classic') { 'Cls' } else { 'StdPrm' }
        $dispFDType = Get-TruncatedString $dispFDType ($colFDType - 1)
        $dispDomain = Get-TruncatedString $result.Domain ($colDomain - 1)
        
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
        
        # Display subscription, frontdoor, fdtype, domain, and cert type
        Write-Host ("{0,-$colSub} {1,-$colFD} {2,-$colFDType} {3,-$colDomain} {4,-$colCertType}" -f $dispSub, $dispFD, $dispFDType, $dispDomain, $dispCertType) -NoNewline
        
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
    
    # Export to CSV if requested
    if ($ExportCsvPath) {
        $allResults | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Force
        Write-Host "`nResults exported to: $ExportCsvPath" -ForegroundColor Green
    }
    
    # Display in GridView if requested
    if ($GridView) {
        Write-Host "`nOpening GridView..." -ForegroundColor Cyan
        $allResults | Select-Object SubscriptionName, FrontDoorName, FrontDoorType, Domain, CertificateType, `
            ProvisioningState, ValidationState, Subject, ExpirationDate, ExpirationStatus, `
            KeyVaultName, KeyVaultSecretName | Out-GridView -Title "Azure Front Door Certificates"
    }
}
