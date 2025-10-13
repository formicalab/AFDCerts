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

.PARAMETER FrontDoorName
    The name of the Front Door profile to inspect. Supports both Standard/Premium and Classic
    Front Door profiles. The script will automatically detect the Front Door type.

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

.NOTES   
    Network Considerations:
    - Usage with corporate proxies has not been thoroughly tested
    - Direct TCP connections for Classic Front Door may not work through proxy servers
    - If connection issues occur in corporate environments, try running from outside
      the corporate network or use Standard/Premium Front Door profiles
    
    Authentication Requirements:
    - Must be authenticated to Azure (Connect-AzAccount)
    - Requires appropriate permissions to read Azure Front Door resources

.LINK
    https://github.com/formicalab/AFDCerts

.LINK
    https://docs.microsoft.com/en-us/azure/frontdoor/

.LINK
    https://docs.microsoft.com/en-us/powershell/azure/
#>

#Requires -PSEdition Core
using module Az.Accounts

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = 'Name of the Front Door profile to inspect (Standard/Premium or Classic)')]
    [string]$FrontDoorName,

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
$results = @()

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


# Get current context
$context = Get-AzContext
if (-not $context) {
    throw "Not logged in to Azure. Please run Connect-AzAccount first."
}

Write-Host "Looking for Front Door profile: $FrontDoorName..."

# Try to find Standard/Premium Front Door first
$fd = Get-AzResource -Name $FrontDoorName -ResourceType "Microsoft.Cdn/profiles" -ErrorAction SilentlyContinue

# If not found, try Classic Front Door
if (-not $fd) {
    $fdClassic = Get-AzFrontDoor -Name $FrontDoorName -ErrorAction SilentlyContinue
    if ($fdClassic) {
        Write-Host "Found Classic Front Door: $FrontDoorName" -ForegroundColor Cyan
        $isClassic = $true
    } else {
        throw "Front Door profile '$FrontDoorName' not found in current subscription (checked both Standard/Premium and Classic)."
    }
} else {
    Write-Host "Found Standard/Premium Front Door: $($fd.Name) in resource group: $($fd.ResourceGroupName)" -ForegroundColor Cyan
    $isClassic = $false
}

if ($isClassic) {
    # ===========================
    # CLASSIC FRONT DOOR LOGIC
    # ===========================
    
    Write-Host "Retrieving custom domains..."
    
    # Get all frontend endpoints (custom domains) from Classic Front Door
    $endpoints = $fdClassic | Get-AzFrontDoorFrontendEndpoint
    
    if (-not $endpoints -or $endpoints.Count -eq 0) {
        Write-Host "No custom domains found for Classic Front Door $FrontDoorName" -ForegroundColor Yellow
    } else {
        Write-Host "Found $($endpoints.Count) custom domain(s). Processing..."
        
        foreach ($ep in $endpoints) {
            $domainName = $ep.HostName ?? $ep.Name
            
            Write-Host "  Fetching certificate for: $domainName..." -NoNewline
            
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

    Write-Host "Retrieving custom domains..."

    # Get custom domains via REST API
    try {
        $pathDomains = "/subscriptions/$subscriptionId/resourceGroups/$rgName/providers/Microsoft.Cdn/profiles/$fdName/customDomains?api-version=$ApiVersion"
        $domainsResp = Invoke-AzRest -Path $pathDomains -Method GET -ErrorAction Stop
        $domains = ($domainsResp.Content | ConvertFrom-Json).value
    }
    catch {
        throw "Failed to query custom domains for ${fdName}: $($_.Exception.Message)"
    }

    if (-not $domains -or $domains.Count -eq 0) {
        Write-Host "No custom domains found for $fdName" -ForegroundColor Yellow
    }
    else {
        Write-Host "Found $($domains.Count) custom domain(s). Processing..."

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
                        Write-Host "  Fetching certificate details for: $domainName..." -NoNewline
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

# Output
if ($results.Count -eq 0) {
    Write-Host "No certificate information found." -ForegroundColor Yellow
}
else {
    Write-Host "`nCertificate Details:" -ForegroundColor Green
    Write-Host ""
    
    # Check if any result has ValidationState (Standard/Premium) or not (Classic)
    $hasValidationState = $results[0].PSObject.Properties.Name -contains 'ValidationState'
    
    # Define column widths optimized for ~160 char total width with padding
    # Standard/Premium: Domain(42) + CertType(14) + ProvState(14) + ValState(17) + Subject(30) + Expiry(24) + KVName(20) = ~161
    # Classic: Domain(42) + CertType(14) + ProvState(14) + Subject(40) + Expiry(24) + KVName(20) = ~154
    
    if ($hasValidationState) {
        # Standard/Premium columns (optimized for ≤160 chars)
        $colDomain = 42
        $colCertType = 14
        $colProvState = 14
        $colValState = 17
        $colSubject = 30
        $colExpiry = 24
        $colKVName = 20
        
        Write-Host ("{0,-$colDomain} {1,-$colCertType} {2,-$colProvState} {3,-$colValState} {4,-$colSubject} {5,-$colExpiry} {6,-$colKVName} {7}" -f "Domain", "CertType", "ProvState", "ValState", "Subject", "ExpirationDate", "KVName", "KVSecret") -ForegroundColor Cyan
        Write-Host ("{0,-$colDomain} {1,-$colCertType} {2,-$colProvState} {3,-$colValState} {4,-$colSubject} {5,-$colExpiry} {6,-$colKVName} {7}" -f "------", "--------", "---------", "--------", "-------", "--------------", "------", "--------") -ForegroundColor Cyan
    } else {
        # Classic columns (optimized for ≤160 chars)
        $colDomain = 42
        $colCertType = 14
        $colProvState = 14
        $colSubject = 40
        $colExpiry = 24
        $colKVName = 20
        
        Write-Host ("{0,-$colDomain} {1,-$colCertType} {2,-$colProvState} {3,-$colSubject} {4,-$colExpiry} {5,-$colKVName} {6}" -f "Domain", "CertType", "ProvState", "Subject", "ExpirationDate", "KVName", "KVSecret") -ForegroundColor Cyan
        Write-Host ("{0,-$colDomain} {1,-$colCertType} {2,-$colProvState} {3,-$colSubject} {4,-$colExpiry} {5,-$colKVName} {6}" -f "------", "--------", "---------", "-------", "--------------", "------", "--------") -ForegroundColor Cyan
    }
    
    # Display results with color coding and truncation
    foreach ($result in $results) {
        # Truncate all fields for display (subtract 1 for spacing)
        $dispDomain = Get-TruncatedString $result.Domain ($colDomain - 1)
        $dispCertType = Get-TruncatedString $result.CertificateType ($colCertType - 1)
        $dispProvState = Get-TruncatedString $result.ProvisioningState ($colProvState - 1)
        $dispSubject = Get-TruncatedString $result.Subject ($colSubject - 1)
        $dispExpiry = Get-TruncatedString $result.ExpirationDate ($colExpiry - 1)
        $dispKVName = Get-TruncatedString $result.KeyVaultName ($colKVName - 1)
        $dispKVSecret = Get-TruncatedString $result.KeyVaultSecretName 32
        
        # Domain and certificate type
        Write-Host ("{0,-$colDomain} {1,-$colCertType}" -f $dispDomain, $dispCertType) -NoNewline
        
        # Provisioning State with color
        if ($result.ProvisioningState -and $result.ProvisioningState -notlike '*Succeeded*') {
            Write-Host ("{0,-$colProvState}" -f $dispProvState) -NoNewline -ForegroundColor Yellow
        } else {
            Write-Host ("{0,-$colProvState}" -f $dispProvState) -NoNewline
        }
        
        # Validation State with color (only for Standard/Premium)
        if ($hasValidationState) {
            $dispValState = Get-TruncatedString $result.ValidationState $colValState
            if ($result.ValidationState -and $result.ValidationState -notlike '*Approved*') {
                Write-Host ("{0,-$colValState}" -f $dispValState) -NoNewline -ForegroundColor Yellow
            } else {
                Write-Host ("{0,-$colValState}" -f $dispValState) -NoNewline
            }
        }
        
        # Subject
        Write-Host ("{0,-$colSubject}" -f $dispSubject) -NoNewline
        
        # Expiration Date with color based on status
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
    $expired = ($results | Where-Object { $_.ExpirationStatus -eq 'EXPIRED' }).Count
    $expiringSoon = ($results | Where-Object { $_.ExpirationStatus -eq 'WARNING' }).Count
    
    if ($expired -gt 0) {
        Write-Host "🔴 $expired certificate(s) EXPIRED" -ForegroundColor Red
    }
    if ($expiringSoon -gt 0) {
        Write-Host "⚠️  $expiringSoon certificate(s) expiring within $WarningDays days" -ForegroundColor Yellow
    }
    if ($expired -eq 0 -and $expiringSoon -eq 0) {
        Write-Host "✅ All certificates are valid and not expiring soon" -ForegroundColor Green
    }
}

if ($ExportCsvPath) {
    $results | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Force
    Write-Host "Results exported to $ExportCsvPath"
}
