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
- ✅ **Certificate Expiration Monitoring**: Visual indicators for expired and soon-to-expire certificates
- ✅ **Multiple Certificate Types**: Supports both Azure-managed and custom Key Vault certificates
- ✅ **Detailed Information**: Shows certificate subject, provisioning state, validation state, and Key Vault details
- ✅ **CSV Export**: Export results for reporting and analysis
- ✅ **Configurable Warning Period**: Set custom warning threshold for certificate expiration
- ✅ **Color-coded Output**: Easy-to-read console output with status indicators

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

### Basic Usage

```powershell
.\get-frontdoor-certs.ps1 -FrontDoorName "my-frontdoor-profile"
```

### Advanced Usage

```powershell
# Export results to CSV
.\get-frontdoor-certs.ps1 -FrontDoorName "my-frontdoor-profile" -ExportCsvPath "C:\Reports\certificates.csv"

# Custom warning period (60 days instead of default 30)
.\get-frontdoor-certs.ps1 -FrontDoorName "my-frontdoor-profile" -WarningDays 60

# Use specific API version
.\get-frontdoor-certs.ps1 -FrontDoorName "my-frontdoor-profile" -ApiVersion "2024-02-01"
```

## Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `FrontDoorName` | String | Yes | - | Name of the Front Door profile to inspect |
| `ExportCsvPath` | String | No | - | Path to export CSV results |
| `ApiVersion` | String | No | `2024-02-01` | API version for Front Door REST calls |
| `WarningDays` | Int | No | `30` | Days before expiration to show warning |

## Output

The script provides a formatted table showing:

### For Standard/Premium Front Door:
- **Domain**: Custom domain name
- **CertType**: Certificate type (Managed/KeyVault)
- **ProvState**: Provisioning state
- **ValState**: Domain validation state
- **Subject**: Certificate subject
- **ExpirationDate**: Certificate expiration with status indicators
- **KVName**: Key Vault name (for custom certificates)
- **KVSecret**: Key Vault secret name (for custom certificates)

### For Classic Front Door:
- **Domain**: Custom domain name
- **CertType**: Certificate source
- **ProvState**: Provisioning state
- **Subject**: Certificate subject
- **ExpirationDate**: Certificate expiration with status indicators
- **KVName**: Key Vault name (for custom certificates)
- **KVSecret**: Key Vault secret name (for custom certificates)

### Status Indicators

- 🔴 **Red**: Expired certificates
- ⚠️ **Yellow**: Certificates expiring within the warning period or provisioning issues
- ✅ **Green**: Healthy certificates

## Examples

### Example Output - Standard/Premium Front Door
```
Certificate Details:

Domain                                     CertType       ProvState      ValState         Subject                        ExpirationDate           KVName               KVSecret
------                                     --------       ---------      --------         -------                        --------------           ------               --------
www.example.com                           Managed        Succeeded      Approved         CN=www.example.com             2024-12-15 10:30:45      
api.example.com                           KeyVault       Succeeded      Approved         CN=*.example.com               ⚠️ 2024-11-01 08:15:22   my-keyvault          api-cert
old.example.com                           Managed        Succeeded      Approved         CN=old.example.com             🔴 2024-09-30 12:00:00   

🔴 1 certificate(s) EXPIRED
⚠️ 1 certificate(s) expiring within 30 days
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

### Version 1.0
- Initial release
- Support for both Classic and Standard/Premium Front Door
- Certificate expiration monitoring
- CSV export functionality
- Color-coded console output