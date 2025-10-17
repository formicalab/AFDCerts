# AFDCerts

Extract SSL/TLS certificate expirations from Azure Front Door profiles.

## Requirements

- PowerShell 7
- Az PowerShell module
- Azure login: `Connect-AzAccount`

## Examples

### Single Front Door

```powershell
.\get-frontdoor-certs.ps1 -FrontDoorName "my-frontdoor"
```

### With CSV export

```powershell
.\get-frontdoor-certs.ps1 -FrontDoorName "my-frontdoor" -ExportCsvPath "certs.csv"
```

### Bulk processing from CSV

Create `frontdoors.csv`:
```
SubscriptionName,FrontDoorName
Production,prod-frontdoor
Development,dev-frontdoor
```

Run:
```powershell
.\get-frontdoor-certs.ps1 -CsvFilePath "frontdoors.csv" -ExportCsvPath "report.csv"
```

### Custom warning threshold

```powershell
.\get-frontdoor-certs.ps1 -FrontDoorName "my-frontdoor" -WarningDays 90
```

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| FrontDoorName | Yes* | - | Front Door name |
| CsvFilePath | Yes* | - | CSV with SubscriptionName, FrontDoorName |
| ExportCsvPath | No | - | Export CSV path |
| WarningDays | No | 30 | Warning days before expiration |
| ApiVersion | No | 2024-02-01 | API version |

*Either FrontDoorName or CsvFilePath required

## Output

- **Console**: Dynamic table with Subscription, FrontDoor, FDType, Domain, CertType, ProvState, ValState, Subject, ExpirationDate, KVName, KVSecret. Status indicators: 🔴 expired | ⚠️ warning | ✅ healthy
- **CSV**: Clean data without emojis, suitable for Excel
