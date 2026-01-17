# AFDCerts

Extract SSL/TLS certificate expirations from Azure Front Door profiles (both Classic and Standard/Premium).

## Requirements

- PowerShell 7 (Core)
- Az PowerShell module (Az.Accounts, Az.FrontDoor)
- Az.ResourceGraph module (required for `-ScanTenant` mode)
- Azure login: `Connect-AzAccount`

## Features

- Supports both **Classic** and **Standard/Premium** Azure Front Door profiles
- Three scan modes: single Front Door, subscription-wide, or tenant-wide
- Color-coded expiration status with configurable warning threshold
- Export to CSV or interactive GridView
- Filter by Front Door type (StandardPremium or Classic)

## Examples

### Single Front Door

```powershell
.\get-frontdoor-certs.ps1 -ScanFrontDoor "my-frontdoor" -ResourceGroupName "my-rg"
```

### Scan all Front Doors in current subscription

```powershell
.\get-frontdoor-certs.ps1 -ScanSubscription ""
```

### Scan all Front Doors in a specific subscription

```powershell
.\get-frontdoor-certs.ps1 -ScanSubscription "Production"
```

### Scan all Front Doors across the entire tenant

```powershell
.\get-frontdoor-certs.ps1 -ScanTenant
```

### With CSV export

```powershell
.\get-frontdoor-certs.ps1 -ScanTenant -ExportCsvPath "all-certs.csv"
```

### With GridView output

```powershell
.\get-frontdoor-certs.ps1 -ScanSubscription "Production" -GridView
```

### Scan only Standard/Premium Front Doors

```powershell
.\get-frontdoor-certs.ps1 -ScanTenant -FrontDoorType StandardPremium
```

### Scan only Classic Front Doors in a subscription

```powershell
.\get-frontdoor-certs.ps1 -ScanSubscription "Production" -FrontDoorType Classic
```

### Custom warning threshold

```powershell
.\get-frontdoor-certs.ps1 -ScanFrontDoor "my-frontdoor" -ResourceGroupName "my-rg" -WarningDays 90
```

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| ScanFrontDoor | Yes* | - | Single Front Door name to inspect |
| ResourceGroupName | Yes** | - | Resource group containing the Front Door |
| ScanSubscription | Yes* | - | Subscription name or ID to scan (use "" for current) |
| ScanTenant | Yes* | - | Scan all Front Doors across all subscriptions |
| FrontDoorType | No | All | Filter by type: All, StandardPremium, or Classic |
| ExportCsvPath | No | - | Export CSV path |
| GridView | No | - | Display results in interactive GridView window |
| WarningDays | No | 30 | Warning days before expiration |

\*One of ScanFrontDoor, ScanSubscription, or ScanTenant is required  
\*\*Required when using -ScanFrontDoor  
FrontDoorType only applies to -ScanSubscription and -ScanTenant modes

## Output

- **Console**: Dynamic table with Subscription, FrontDoor, FDType, Domain, CertType, ProvState, ValState, Subject, ExpirationDate, KVName, KVSecret. Status indicators: 🔴 expired | ⚠️ warning | ✅ healthy
- **CSV**: Clean data without emojis, suitable for Excel
