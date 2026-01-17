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
    - Az.ResourceGraph module is required for -ScanTenant mode (Install-Module Az.ResourceGraph)

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
    [int]$WarningDays = 30
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

#region Get All Front Doors in Tenant (Resource Graph)

# Function to get all Front Door profiles across all subscriptions using Azure Resource Graph
function Get-AllFrontDoorsInTenant {
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet('All', 'StandardPremium', 'Classic')]
        [string]$TypeFilter = 'All'
    )
    
    Write-Host "Querying Azure Resource Graph for all Front Door profiles..." -ForegroundColor Cyan
    if ($TypeFilter -ne 'All') {
        Write-Host "  Filtering by type: $TypeFilter" -ForegroundColor Cyan
    }
    
    $frontDoors = @()
    
    # Query for Standard/Premium Front Doors (Microsoft.Cdn/profiles with AzureFrontDoor SKU)
    $queryStdPremium = @"
resources
| where type == 'microsoft.cdn/profiles'
| where sku.name in ('Standard_AzureFrontDoor', 'Premium_AzureFrontDoor')
| project name, resourceGroup, subscriptionId, type, sku
| order by subscriptionId, name
"@

    # Query for Classic Front Doors (Microsoft.Network/frontDoors)
    $queryClassic = @"
resources
| where type == 'microsoft.network/frontdoors'
| project name, resourceGroup, subscriptionId, type
| order by subscriptionId, name
"@

    # Execute Standard/Premium query
    if ($TypeFilter -eq 'All' -or $TypeFilter -eq 'StandardPremium') {
        try {
            Write-Host "  Querying Standard/Premium Front Doors..." -ForegroundColor Cyan
            $stdPremiumResults = Search-AzGraph -Query $queryStdPremium -First 1000 -ErrorAction Stop
            
            foreach ($result in $stdPremiumResults) {
                $frontDoors += [PSCustomObject]@{
                    Name              = $result.name
                    ResourceGroupName = $result.resourceGroup
                    SubscriptionId    = $result.subscriptionId
                    Type              = 'Standard/Premium'
                }
            }
            Write-Host "    Found $($stdPremiumResults.Count) Standard/Premium Front Door(s)" -ForegroundColor Green
        }
        catch {
            Write-Host "    Failed to query Standard/Premium Front Doors via Resource Graph: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "    Make sure you have the Az.ResourceGraph module installed (Install-Module Az.ResourceGraph)" -ForegroundColor Yellow
        }
    }
    
    # Execute Classic query
    if ($TypeFilter -eq 'All' -or $TypeFilter -eq 'Classic') {
        try {
            Write-Host "  Querying Classic Front Doors..." -ForegroundColor Cyan
            $classicResults = Search-AzGraph -Query $queryClassic -First 1000 -ErrorAction Stop
            
            foreach ($result in $classicResults) {
                $frontDoors += [PSCustomObject]@{
                    Name              = $result.name
                    ResourceGroupName = $result.resourceGroup
                    SubscriptionId    = $result.subscriptionId
                    Type              = 'Classic'
                }
            }
            Write-Host "    Found $($classicResults.Count) Classic Front Door(s)" -ForegroundColor Green
        }
        catch {
            Write-Host "    Failed to query Classic Front Doors via Resource Graph: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    
    Write-Host "  Total: $($frontDoors.Count) Front Door profile(s) found across tenant`n" -ForegroundColor Cyan
    
    return $frontDoors
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
    # Tenant-wide scanning mode using Azure Resource Graph
    Write-Host "Scanning all Front Door profiles across tenant using Resource Graph..." -ForegroundColor Cyan
    
    # Get all Front Doors across tenant using Resource Graph
    $allFrontDoors = Get-AllFrontDoorsInTenant -TypeFilter $FrontDoorType
    
    if ($allFrontDoors.Count -eq 0) {
        Write-Host "No Front Door profiles found in the tenant." -ForegroundColor Yellow
    } else {
        # Group by subscription to minimize context switches
        $groupedBySubscription = $allFrontDoors | Group-Object SubscriptionId | Sort-Object Name
        
        Write-Host "Found Front Door profiles in $($groupedBySubscription.Count) subscription(s)" -ForegroundColor Cyan
        Write-Host "Processing sorted by subscription to minimize context switches...`n" -ForegroundColor Cyan
        
        $subscriptionCount = 0
        foreach ($subGroup in $groupedBySubscription) {
            $subscriptionCount++
            $subscriptionId = $subGroup.Name
            $frontDoorsInSub = $subGroup.Group
            
            # Switch to the subscription
            try {
                $context = Set-AzContext -Subscription $subscriptionId -ErrorAction Stop
                Write-Host "[$subscriptionCount/$($groupedBySubscription.Count)] Processing $($frontDoorsInSub.Count) Front Door(s) in subscription: $($context.Subscription.Name)" -ForegroundColor Yellow
                Write-Host ("=" * 80) -ForegroundColor Yellow
            }
            catch {
                Write-Host "[$subscriptionCount/$($groupedBySubscription.Count)] Failed to switch to subscription '$subscriptionId': $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "  Skipping $($frontDoorsInSub.Count) Front Door(s) in this subscription`n" -ForegroundColor Yellow
                continue
            }
            
            # Process each Front Door in this subscription
            foreach ($fd in $frontDoorsInSub) {
                $fdResults = Get-FrontDoorCertificates `
                    -FrontDoorName $fd.Name `
                    -ResourceGroupName $fd.ResourceGroupName `
                    -WarningDays $WarningDays
                
                $fdResults | ForEach-Object { $allResults.Add($_) }
            }
            Write-Host ""
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
