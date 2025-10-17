# AFDCerts - Azure Front Door Certificate Monitor

A PowerShell script to monitor and analyze SSL/TLS certificates for Azure Front Door profiles, supporting both Classic and Standard/Premium Front Door services.

## Overview

This tool helps Azure administrators monitor certificate health across their Front Door deployments by:
- Retrieving certificate information from both Classic and Standard/Premium Azure Front Door profiles
- Displaying certificate expiration dates with visual warnings
- Showing provisioning and validation states
- Exporting results to CSV for reporting
- Supporting both managed certificates and custom certificates from Key Vault

## Features

- ✅ **Dual Front Door Support**: Works with both Classic and Standard/Premium Front Door profiles
- ✅ **Bulk Processing Mode**: Process multiple Front Doors across multiple subscriptions with optimized context switching
- ✅ **Certificate Expiration Monitoring**: Visual indicators for expired and soon-to-expire certificates
- ✅ **Multiple Certificate Types**: Supports both Azure-managed and custom Key Vault certificates
- ✅ **Detailed Information**: Shows certificate subject, provisioning state, validation state, and Key Vault details
- ✅ **CSV Export**: Export results for reporting and analysis
- ✅ **Configurable Warning Period**: Set custom warning threshold for certificate expiration
- ✅ **Color-coded Output**: Easy-to-read console output with status indicators
- ✅ **PowerShell 7 Features**: Leverages modern PowerShell features for improved performance

## Prerequisites

- PowerShell 7.x (PowerShell Core)
- Azure PowerShell module (`Az.Accounts` and related modules)
- Authenticated Azure session (`Connect-AzAccount`)
- Appropriate permissions to read Azure Front Door resources

### Network Considerations

**Proxy Support**: Usage with corporate proxies has not been thoroughly tested. The script makes direct TCP connections to retrieve certificate details for Classic Front Door profiles, which may not work through proxy servers. If you encounter connection issues in a corporate environment, try running the script from outside the corporate network or use a Standard/Premium Front Door profile which relies solely on Azure REST APIs.

## Installation

1. Clone or download this repository:
   ```powershell
   git clone https://github.com/formicalab/AFDCerts.git
   cd AFDCerts
   ```

2. Ensure you have the required Azure PowerShell modules:
   ```powershell
   Install-Module -Name Az -Repository PSGallery -Force
   ```

3. Connect to your Azure account:
   ```powershell
   Connect-AzAccount
   ```

## Usage

The script supports two execution modes:
1. **Single Front Door Mode**: Process a single Front Door in the current subscription
2. **Bulk Processing Mode**: Process multiple Front Doors across multiple subscriptions from a CSV file

### Single Front Door Mode

```powershell
# Basic usage
.\get-frontdoor-certs.ps1 -FrontDoorName "my-frontdoor-profile"
```

### Bulk Processing Mode

Create a CSV file with `SubscriptionName` and `FrontDoorName` columns:

**frontdoors.csv:**
```csv
SubscriptionName,FrontDoorName
Production,prod-frontdoor-01
Production,prod-frontdoor-02
Development,dev-frontdoor-01
```

```powershell
# Process all Front Doors from CSV (automatically sorted by subscription)
.\get-frontdoor-certs.ps1 -CsvFilePath "frontdoors.csv" -ExportCsvPath "all-certs.csv"
```

### Advanced Usage

```powershell
# Single Front Door with CSV export
.\get-frontdoor-certs.ps1 -FrontDoorName "my-frontdoor-profile" -ExportCsvPath "C:\Reports\certificates.csv"

# Custom warning period (60 days instead of default 30)
.\get-frontdoor-certs.ps1 -FrontDoorName "my-frontdoor-profile" -WarningDays 60

# Use specific API version
.\get-frontdoor-certs.ps1 -FrontDoorName "my-frontdoor-profile" -ApiVersion "2024-02-01"

# Bulk processing with custom warning period
.\get-frontdoor-certs.ps1 -CsvFilePath "frontdoors.csv" -WarningDays 60 -ExportCsvPath "report.csv"
```

## Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `FrontDoorName` | String | Yes* | - | Name of the Front Door profile to inspect (SingleFrontDoor mode) |
| `CsvFilePath` | String | Yes* | - | Path to CSV file with SubscriptionName and FrontDoorName columns (BulkProcessing mode) |
| `ExportCsvPath` | String | No | - | Path to export CSV results |
| `ApiVersion` | String | No | `2024-02-01` | API version for Front Door REST calls |
| `WarningDays` | Int | No | `30` | Days before expiration to show warning |

*Either `FrontDoorName` or `CsvFilePath` must be specified, depending on the execution mode.

### Parameter Sets

The script uses PowerShell parameter sets to distinguish between execution modes:
- **SingleFrontDoor**: Use `-FrontDoorName` to process a single Front Door
- **BulkProcessing**: Use `-CsvFilePath` to process multiple Front Doors from a CSV file

### CSV File Format

For bulk processing mode, create a CSV file with two columns:

```csv
SubscriptionName,FrontDoorName
Production,prod-frontdoor-01
Production,prod-frontdoor-02
Development,dev-frontdoor-01
```

The script will automatically sort entries by `SubscriptionName` to minimize Azure context switches.

## Output

The script provides formatted output that adapts based on the execution mode:

### For Single Front Door Mode - Standard/Premium:
- **Domain**: Custom domain name
- **CertType**: Certificate type (Managed/KeyVault)
- **ProvState**: Provisioning state
- **ValState**: Domain validation state
- **Subject**: Certificate subject
- **ExpirationDate**: Certificate expiration with status indicators
- **KVName**: Key Vault name (for custom certificates)
- **KVSecret**: Key Vault secret name (for custom certificates)

### For Single Front Door Mode - Classic:
- **Domain**: Custom domain name
- **CertType**: Certificate source
- **ProvState**: Provisioning state
- **Subject**: Certificate subject
- **ExpirationDate**: Certificate expiration with status indicators
- **KVName**: Key Vault name (for custom certificates)
- **KVSecret**: Key Vault secret name (for custom certificates)

### For Bulk Processing Mode (Multiple Subscriptions):
- **Subscription**: Subscription name
- **FrontDoor**: Front Door name
- **Domain**: Custom domain name
- **CertType**: Certificate type
- **ProvState**: Provisioning state
- **ValState**: Domain validation state (if applicable)
- **Subject**: Certificate subject
- **ExpirationDate**: Certificate expiration with status indicators
- **KVName**: Key Vault name (for custom certificates)
- **Subject**: Certificate subject
- **ExpirationDate**: Certificate expiration with status indicators
- **KVName**: Key Vault name (for custom certificates)
- **KVSecret**: Key Vault secret name (for custom certificates)

### Status Indicators

- 🔴 **Red**: Expired certificates
- ⚠️ **Yellow**: Certificates expiring within the warning period or provisioning issues
- ✅ **Green**: Healthy certificates

## Examples

### Example Output - Single Front Door (Standard/Premium)
```
=== Azure Front Door Certificate Checker ===
Execution Mode: SingleFrontDoor

Looking for Front Door profile: my-frontdoor-profile in subscription: Production...
  Found Standard/Premium Front Door: my-frontdoor-profile in resource group: rg-frontdoor
  Retrieving custom domains...
  Found 3 custom domain(s). Processing...

=== Certificate Details ===

Domain                                     CertType       ProvState      ValState         Subject                        ExpirationDate           KVName               KVSecret
------                                     --------       ---------      --------         -------                        --------------           ------               --------
www.example.com                           Managed        Succeeded      Approved         CN=www.example.com             2024-12-15 10:30:45      
api.example.com                           KeyVault       Succeeded      Approved         CN=*.example.com               ⚠️ 2024-11-01 08:15:22   my-keyvault          api-cert
old.example.com                           Managed        Succeeded      Approved         CN=old.example.com             🔴 2024-09-30 12:00:00   

=== Summary ===
Total certificates: 3
🔴 1 certificate(s) EXPIRED
⚠️ 1 certificate(s) expiring within 30 days
```

### Example Output - Bulk Processing Mode
```
=== Azure Front Door Certificate Checker ===
Execution Mode: BulkProcessing

Reading Front Door list from CSV: frontdoors.csv...
Found 4 Front Door profile(s) in CSV
Sorting by subscription to minimize context switches...

Found 2 unique subscription(s)

Processing 3 Front Door(s) in subscription: Production
================================================================================
Switching to subscription: Production...
  Switched to subscription: Production (ID: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee)
Looking for Front Door profile: prod-fd-01 in subscription: Production...
  Found Standard/Premium Front Door: prod-fd-01 in resource group: rg-frontdoor
  Retrieving custom domains...
  Found 2 custom domain(s). Processing...

Looking for Front Door profile: prod-fd-02 in subscription: Production...
  Found Standard/Premium Front Door: prod-fd-02 in resource group: rg-frontdoor
  Retrieving custom domains...
  Found 1 custom domain(s). Processing...

Processing 1 Front Door(s) in subscription: Development
================================================================================
Switching to subscription: Development...
  Switched to subscription: Development (ID: ffffffff-gggg-hhhh-iiii-jjjjjjjjjjjj)
Looking for Front Door profile: dev-fd-01 in subscription: Development...
  Found Standard/Premium Front Door: dev-fd-01 in resource group: rg-dev
  Retrieving custom domains...
  Found 2 custom domain(s). Processing...

=== Certificate Details ===

Subscription                           FrontDoor            Domain                         CertType   ProvState    ValState    Subject                   ExpirationDate         KVName
------------                           ---------            ------                         --------   ---------    --------    -------                   --------------         ------
Production                             prod-fd-01           www.example.com                Managed    Succeeded    Approved    CN=www.example.com        2025-06-15 10:30:45    
Production                             prod-fd-01           api.example.com                KeyVault   Succeeded    Approved    CN=*.example.com          2025-03-01 08:15:22    my-kv-prod
Production                             prod-fd-02           shop.example.com               Managed    Succeeded    Approved    CN=shop.example.com       ⚠️ 2024-11-05 14:22:10 
Development                            dev-fd-01            dev.example.com                Managed    Succeeded    Approved    CN=dev.example.com        2025-02-20 09:45:33    
Development                            dev-fd-01            test.example.com               KeyVault   Succeeded    Approved    CN=test.example.com       2025-05-10 16:30:00    my-kv-dev

=== Summary ===
Total certificates: 5
⚠️ 1 certificate(s) expiring within 30 days

Results exported to: all-certs.csv
```

### Example Output - Classic Front Door
```
Certificate Details:

Domain                                     CertType       ProvState      Subject                                  ExpirationDate           KVName               KVSecret
------                                     --------       ---------      -------                                  --------------           ------               --------
www.example.com                           FrontDoorCertificateSourceManagedCertificate  Enabled   CN=www.example.com        2024-12-15 10:30:45
api.example.com                           FrontDoorCertificateSourceCustomerCertificate Enabled   CN=*.example.com          ⚠️ 2024-11-01 08:15:22   my-keyvault          api-cert

⚠️ 1 certificate(s) expiring within 30 days
✅ All other certificates are valid and not expiring soon
```

## Error Handling

The script includes comprehensive error handling for:
- Invalid Front Door profile names
- Network connectivity issues
- Authentication problems
- API version compatibility
- Certificate retrieval failures

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues, questions, or contributions, please visit the [GitHub repository](https://github.com/formicalab/AFDCerts).

## Changelog

### Version 2.0
- ✨ **New**: Bulk processing mode for multiple Front Doors across subscriptions
- ✨ **New**: PowerShell parameter sets to distinguish between single and bulk modes
- ✨ **New**: Automatic subscription sorting to minimize Azure context switches
- ✨ **New**: Enhanced output with subscription and Front Door name columns in bulk mode
- ✨ **New**: Improved summary statistics for bulk processing
- ⚡ **Enhancement**: Leverages PowerShell 7 features for better performance
- ⚡ **Enhancement**: Refactored code into reusable functions
- 📝 **Documentation**: Added comprehensive examples including CSV import scenarios

### Version 1.0
- Initial release
- Support for both Classic and Standard/Premium Front Door
- Certificate expiration monitoring
- CSV export functionality
- Color-coded console output