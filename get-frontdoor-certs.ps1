<#
.SYNOPSIS
    Retrieves and analyzes SSL/TLS certificates for Azure Front Door profiles.

.DESCRIPTION
    This script monitors certificate health across Azure Front Door deployments by retrieving
    certificate information from both Classic and Standard/Premium Front Door profiles.
    It displays certificate expiration dates with visual warnings, shows provisioning and
    validation states, and can export results to CSV for reporting.

    The script supports both Azure-managed certificates and custom certificates from Key Vault,
    providing detailed information including certificate subject, provisioning state,
    validation state, and Key Vault details where applicable.

    The script supports two execution modes:
    - Single Front Door mode: Process a single Front Door in the current subscription
    - Bulk processing mode: Process multiple Front Doors across multiple subscriptions

.PARAMETER FrontDoorName
    The name of the Front Door profile to inspect. Supports both Standard/Premium and Classic
    Front Door profiles. The script will automatically detect the Front Door type.
    This parameter is used in SingleFrontDoor parameter set.

.PARAMETER CsvFilePath
    Path to a CSV file containing Front Door configurations for bulk processing.
    The CSV file must contain two columns:
    - SubscriptionName: The name of the Azure subscription (not the ID)
    - FrontDoorName: The name of the Front Door profile
    
    Example CSV content:
    SubscriptionName,FrontDoorName
    Production,prod-frontdoor-01
    Production,prod-frontdoor-02
    Development,dev-frontdoor-01
    
    The script will automatically sort by SubscriptionName to minimize context switches.
    This parameter is used in BulkProcessing parameter set.

.PARAMETER ExportCsvPath
    Optional path to export results as a CSV file. If specified, certificate details will be
    exported to this location for reporting and analysis purposes.

.PARAMETER ApiVersion
    The API version to use for Front Door REST API calls. Default is '2024-02-01'.
    Override this parameter if you need to use a different API version for compatibility.

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
    .\get-frontdoor-certs.ps1 -FrontDoorName "my-frontdoor-profile"
    
    Retrieves certificate information for the specified Front Door profile and displays
    results in a formatted table with color-coded status indicators.

.EXAMPLE
    .\get-frontdoor-certs.ps1 -FrontDoorName "my-frontdoor-profile" -ExportCsvPath "C:\Reports\certificates.csv"
    
    Retrieves certificate information and exports the results to a CSV file for reporting.

.EXAMPLE
    .\get-frontdoor-certs.ps1 -FrontDoorName "my-frontdoor-profile" -WarningDays 60
    
    Retrieves certificate information with a custom warning period of 60 days instead of
    the default 30 days.

.EXAMPLE
    .\get-frontdoor-certs.ps1 -FrontDoorName "my-frontdoor-profile" -ApiVersion "2023-05-01"
    
    Retrieves certificate information using a specific API version for compatibility.

.EXAMPLE
    $csvContent = @"
SubscriptionName,FrontDoorName
Production,prod-frontdoor-01
Production,prod-frontdoor-02
Development,dev-frontdoor-01
"@
    $csvContent | Out-File "frontdoors.csv"
    .\get-frontdoor-certs.ps1 -CsvFilePath "frontdoors.csv" -ExportCsvPath "all-certs.csv"
    
    Creates a CSV file with Front Door configurations and processes them in bulk mode,
    exporting consolidated results to CSV.

.NOTES   
    Network Considerations:
    - Usage with corporate proxies has not been thoroughly tested
    - Direct TCP connections for Classic Front Door may not work through proxy servers
    - If connection issues occur in corporate environments, try running from outside
      the corporate network or use Standard/Premium Front Door profiles
    
    Authentication Requirements:
    - Must be authenticated to Azure (Connect-AzAccount)
    - Requires appropriate permissions to read Azure Front Door resources
    - For bulk processing mode, requires access to all specified subscriptions

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
    [string]$FrontDoorName,

    [Parameter(Mandatory = $true, ParameterSetName = 'BulkProcessing', HelpMessage = 'Path to CSV file with SubscriptionName and FrontDoorName columns for bulk processing')]
    [string]$CsvFilePath,

    [Parameter(Mandatory = $false, HelpMessage = 'Path to export CSV results (optional)')]
    [string]$ExportCsvPath,

    [Parameter(Mandatory = $false, HelpMessage = 'API version to use for Front Door REST calls (override if needed)')]
    [string]$ApiVersion = '2024-02-01',

    [Parameter(Mandatory = $false, HelpMessage = 'Number of days before expiration to show warning (default: 30)')]
    [int]$WarningDays = 30
)

Set-StrictMode -Version 1
$ErrorActionPreference = 'Stop'

# Global variables
$allResults = @()

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

# Function to calculate dynamic column widths based on console width
function Get-DynamicColumnWidths {
    param(
        [bool]$hasValidationState,
        [bool]$isBulkMode,
        [bool]$hasMultipleSubscriptions,
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
    
    # Define minimum widths for each column (must-have space)
    # Priority: Subscription, FrontDoor, Domain, CertType, ExpirationDate, KVName
    # Subject and KVSecret can be sacrificed for space
    $minWidths = @{
        Subscription = 20
        FrontDoor = 15
        Domain = 25
        CertType = 8
        ProvState = 10
        ValState = 10
        Subject = 10
        ExpirationDate = 18
        KVName = 15
        KVSecret = 8
    }
    
    # Define ideal widths (what we'd like if we have space)
    $idealWidths = @{
        Subscription = 28
        FrontDoor = 26
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
    $columns = @('Subscription', 'FrontDoor', 'Domain', 'CertType', 'ProvState')
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
        $display = $daysUntilExpiry -lt 0 ? "🔴 $formattedDate" : 
                   ($daysUntilExpiry -le $warningDays ? "⚠️ $formattedDate" : $formattedDate)
        
        return @{ Display = $display; Status = $status }
    } catch {
        # If date parsing fails, use the original value
        return @{ Display = $expiryDate; Status = 'OK' }
    }
}


# Main function to process a single Front Door
function Get-FrontDoorCertificates {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FrontDoorName,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiVersion,
        
        [Parameter(Mandatory = $true)]
        [int]$WarningDays
    )
    
    $results = @()
    
    # Get current context
    $context = Get-AzContext
    if (-not $context) {
        throw "Not logged in to Azure. Please run Connect-AzAccount first."
    }
    
    Write-Host "Looking for Front Door profile: $FrontDoorName in subscription: $($context.Subscription.Name)..." -ForegroundColor Cyan

    # Try to find Standard/Premium Front Door first
    $fd = Get-AzResource -Name $FrontDoorName -ResourceType "Microsoft.Cdn/profiles" -ErrorAction SilentlyContinue

    # If not found, try Classic Front Door
    if (-not $fd) {
        $fdClassic = Get-AzFrontDoor -Name $FrontDoorName -ErrorAction SilentlyContinue
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
        
        # Get all frontend endpoints (custom domains) from Classic Front Door
        $endpoints = $fdClassic | Get-AzFrontDoorFrontendEndpoint
        
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
                
                # Perform TLS connection to get certificate details
                $tcpClient = $null
                $sslStream = $null
                try {
                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                    $tcpClient.Connect($domainName, 443)
                    
                    $sslStream = New-Object System.Net.Security.SslStream(
                        $tcpClient.GetStream(),
                        $false,
                        { param($s, $certificate, $chain, $sslPolicyErrors) return $true }
                    )
                    
                    $sslStream.AuthenticateAsClient($domainName)
                    $cert = $sslStream.RemoteCertificate
                    
                    if ($cert) {
                        $x509cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert)
                        $expiryDate = $x509cert.NotAfter
                        $subject = $x509cert.Subject
                    }
                    
                    Write-Host " OK" -ForegroundColor Green
                } catch {
                    Write-Host " Failed: $($_.Exception.Message)" -ForegroundColor Yellow
                } finally {
                    if ($sslStream) { $sslStream.Dispose() }
                    if ($tcpClient) { $tcpClient.Dispose() }
                }
                
                # Add warning indicators for non-success states (Classic AFD may have 'Enabled' or 'Succeeded')
                $provisioningDisplay = ($provisioningState -and $provisioningState -notin @('Succeeded', 'Enabled')) ? 
                    "⚠️ $provisioningState" : $provisioningState
                
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
                    ProvisioningState  = $provisioningDisplay
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

                # Add warning indicators for non-success states
                $provisioningDisplay = ($provisioningState -and $provisioningState -ne 'Succeeded') ? 
                    "⚠️ $provisioningState" : $provisioningState
                
                $validationDisplay = ($validationState -and $validationState -ne 'Approved') ? 
                    "⚠️ $validationState" : $validationState

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
                    ProvisioningState  = $provisioningDisplay
                    ValidationState    = $validationDisplay
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


# Main execution logic
Write-Host "`n=== Azure Front Door Certificate Checker ===" -ForegroundColor Cyan
Write-Host "Execution Mode: $($PSCmdlet.ParameterSetName)`n" -ForegroundColor Cyan

if ($PSCmdlet.ParameterSetName -eq 'SingleFrontDoor') {
    # Single Front Door mode
    $allResults = Get-FrontDoorCertificates -FrontDoorName $FrontDoorName -ApiVersion $ApiVersion -WarningDays $WarningDays
} else {
    # Bulk processing mode - read CSV file
    Write-Host "Reading Front Door list from CSV: $CsvFilePath..." -ForegroundColor Cyan
    
    if (-not (Test-Path $CsvFilePath)) {
        throw "CSV file not found: $CsvFilePath"
    }
    
    try {
        $frontDoorList = Import-Csv -Path $CsvFilePath -ErrorAction Stop
    }
    catch {
        throw "Failed to read CSV file: $($_.Exception.Message)"
    }
    
    # Validate CSV columns
    $requiredColumns = @('SubscriptionName', 'FrontDoorName')
    $csvColumns = $frontDoorList[0].PSObject.Properties.Name
    foreach ($col in $requiredColumns) {
        if ($col -notin $csvColumns) {
            throw "CSV file must contain '$col' column. Found columns: $($csvColumns -join ', ')"
        }
    }
    
    Write-Host "Found $($frontDoorList.Count) Front Door profile(s) in CSV" -ForegroundColor Cyan
    Write-Host "Sorting by subscription to minimize context switches...`n" -ForegroundColor Cyan
    
    # Sort by SubscriptionName to minimize context switches
    $sortedList = $frontDoorList | Sort-Object SubscriptionName
    
    # Group by subscription for efficient processing
    $groupedBySubscription = $sortedList | Group-Object SubscriptionName
    
    Write-Host "Found $($groupedBySubscription.Count) unique subscription(s)`n" -ForegroundColor Cyan
    
    foreach ($subGroup in $groupedBySubscription) {
        $subscriptionName = $subGroup.Name
        $frontDoorsInSub = $subGroup.Group
        
        Write-Host "Processing $($frontDoorsInSub.Count) Front Door(s) in subscription: $subscriptionName" -ForegroundColor Yellow
        Write-Host ("=" * 80) -ForegroundColor Yellow
        
        # Switch to the subscription by name
        try {
            Write-Host "Switching to subscription: $subscriptionName..." -ForegroundColor Cyan
            $context = Set-AzContext -Subscription $subscriptionName -ErrorAction Stop
            Write-Host "  Switched to subscription: $($context.Subscription.Name) (ID: $($context.Subscription.Id))" -ForegroundColor Green
        }
        catch {
            Write-Host "  Failed to switch to subscription '$subscriptionName': $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "  Skipping $($frontDoorsInSub.Count) Front Door(s) in this subscription`n" -ForegroundColor Yellow
            continue
        }
        
        # Process each Front Door in this subscription
        foreach ($fdItem in $frontDoorsInSub) {
            $fdResults = Get-FrontDoorCertificates `
                -FrontDoorName $fdItem.FrontDoorName `
                -ApiVersion $ApiVersion `
                -WarningDays $WarningDays
            
            $allResults += $fdResults
        }
        
        Write-Host ""
    }
}


# Display and export results
if ($allResults.Count -eq 0) {
    Write-Host "No certificate information found." -ForegroundColor Yellow
} else {
    Write-Host "`n=== Certificate Details ===" -ForegroundColor Green
    Write-Host ""
    
    # Determine if we're in bulk mode (multiple subscriptions/FrontDoors)
    $isBulkMode = $PSCmdlet.ParameterSetName -eq 'BulkProcessing'
    $hasMultipleSubscriptions = ($allResults | Select-Object -ExpandProperty SubscriptionId -Unique).Count -gt 1
    
    # Check if any result has ValidationState (Standard/Premium) or not (Classic)
    $hasValidationState = $allResults[0].PSObject.Properties.Name -contains 'ValidationState'
    
    # Get dynamic column widths based on console size
    $colWidths = Get-DynamicColumnWidths -hasValidationState $hasValidationState -isBulkMode $isBulkMode -hasMultipleSubscriptions $hasMultipleSubscriptions
    
    $colSub = $colWidths['Subscription']
    $colFD = $colWidths['FrontDoor']
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
        Write-Host ("{0,-$colSub} {1,-$colFD} {2,-$colDomain} {3,-$colCertType} {4,-$colProvState} {5,-$colValState} {6,-$colSubject} {7,-$colExpiry} {8,-$colKVName} {9}" -f "Subscription", "FrontDoor", "Domain", "CertType", "ProvState", "ValState", "Subject", "ExpirationDate", "KVName", "KVSecret") -ForegroundColor Cyan
        Write-Host ("{0,-$colSub} {1,-$colFD} {2,-$colDomain} {3,-$colCertType} {4,-$colProvState} {5,-$colValState} {6,-$colSubject} {7,-$colExpiry} {8,-$colKVName} {9}" -f "------------", "---------", "------", "--------", "---------", "--------", "-------", "--------------", "------", "--------") -ForegroundColor Cyan
    } else {
        Write-Host ("{0,-$colSub} {1,-$colFD} {2,-$colDomain} {3,-$colCertType} {4,-$colProvState} {5,-$colSubject} {6,-$colExpiry} {7,-$colKVName} {8}" -f "Subscription", "FrontDoor", "Domain", "CertType", "ProvState", "Subject", "ExpirationDate", "KVName", "KVSecret") -ForegroundColor Cyan
        Write-Host ("{0,-$colSub} {1,-$colFD} {2,-$colDomain} {3,-$colCertType} {4,-$colProvState} {5,-$colSubject} {6,-$colExpiry} {7,-$colKVName} {8}" -f "------------", "---------", "------", "--------", "---------", "-------", "--------------", "------", "--------") -ForegroundColor Cyan
    }
    
    # Display results with color coding and truncation
    foreach ($result in $allResults) {
        # Truncate all fields for display
        $dispSub = Get-TruncatedString $result.SubscriptionName ($colSub - 1)
        $dispFD = Get-TruncatedString $result.FrontDoorName ($colFD - 1)
        $dispDomain = Get-TruncatedString $result.Domain ($colDomain - 1)
        $dispCertType = Get-TruncatedString $result.CertificateType ($colCertType - 1)
        $dispProvState = Get-TruncatedString $result.ProvisioningState ($colProvState - 1)
        $dispSubject = Get-TruncatedString $result.Subject ($colSubject - 1)
        $dispExpiry = Get-TruncatedString $result.ExpirationDate ($colExpiry - 1)
        $dispKVName = Get-TruncatedString $result.KeyVaultName ($colKVName - 1)
        $dispKVSecret = Get-TruncatedString $result.KeyVaultSecretName ($colKVSecret - 1)
        
        # Display subscription, frontdoor, domain, and cert type
        Write-Host ("{0,-$colSub} {1,-$colFD} {2,-$colDomain} {3,-$colCertType}" -f $dispSub, $dispFD, $dispDomain, $dispCertType) -NoNewline
        
        # Provisioning State with color
        if ($result.ProvisioningState -and $result.ProvisioningState -notlike '*Succeeded*' -and $result.ProvisioningState -notlike '*Enabled*') {
            Write-Host ("{0,-$colProvState}" -f $dispProvState) -NoNewline -ForegroundColor Yellow
        } else {
            Write-Host ("{0,-$colProvState}" -f $dispProvState) -NoNewline
        }
        
        # Validation State with color (only for Standard/Premium)
        if ($hasValidationState) {
            $dispValState = Get-TruncatedString $result.ValidationState ($colValState - 1)
            if ($result.ValidationState -and $result.ValidationState -notlike '*Approved*') {
                Write-Host ("{0,-$colValState}" -f $dispValState) -NoNewline -ForegroundColor Yellow
            } else {
                Write-Host ("{0,-$colValState}" -f $dispValState) -NoNewline
            }
        }
        
        # Subject
        Write-Host ("{0,-$colSubject}" -f $dispSubject) -NoNewline
        
        # Expiration Date with color
        if ($result.ExpirationStatus -eq 'EXPIRED') {
            Write-Host ("{0,-$colExpiry}" -f $dispExpiry) -NoNewline -ForegroundColor Red
        } elseif ($result.ExpirationStatus -eq 'WARNING') {
            Write-Host ("{0,-$colExpiry}" -f $dispExpiry) -NoNewline -ForegroundColor Yellow
        } else {
            Write-Host ("{0,-$colExpiry}" -f $dispExpiry) -NoNewline
        }
        
        # Key Vault details
        Write-Host ("{0,-$colKVName} {1}" -f $dispKVName, $dispKVSecret)
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
}
