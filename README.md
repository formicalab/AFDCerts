# AFDCerts

Extract SSL/TLS certificate details from Azure Front Door deployments, including both Classic and Standard/Premium profiles.

## Requirements

- PowerShell 7
- `Az.Accounts`
- An authenticated Azure session via `Connect-AzAccount`
- Optional: `ImportExcel` for XLSX output

All discovery and ARM calls use Azure Resource Graph and REST with the bearer token returned by `Az.Accounts`. `Az.FrontDoor` is not required.

## What the script does

- Scans one Front Door, a subscription, or every accessible subscription in the tenant
- Supports both Standard/Premium and Classic Front Door deployments
- Skips default `*.azurefd.net` hostnames automatically so results focus on customer-facing domains
- Reads ARM metadata for certificate configuration and enriches it with a live TLS probe for each domain
- Extracts subject, issuer, issuing CA, chain status, intermediate CA, root CA, and a `DigiCertIssued` flag
- Surfaces Classic-to-Standard/Premium migration linkage (`MigrationSourceResourceId` / `MigrationTargetResourceId`) when the `extendedProperties` on either side of a migration expose it
- Applies exponential-backoff retry for transient REST and TLS failures
- Prints a coloured table to the console and, optionally, writes CSV and/or XLSX, or shows a `GridView`

`-GridView` and the export paths (`-ExportCsvPath`, `-ExportXlsxPath`) are mutually exclusive.

## Scan modes

### Single Front Door

```powershell
.\get-frontdoor-certs.ps1 -ScanFrontDoor "my-frontdoor" -ResourceGroupName "my-rg"
```

### Current subscription

```powershell
.\get-frontdoor-certs.ps1 -ScanSubscription ""
```

### Specific subscription

```powershell
.\get-frontdoor-certs.ps1 -ScanSubscription "Production"
```

### Entire tenant

```powershell
.\get-frontdoor-certs.ps1 -ScanTenant
```

## Common examples

### Export tenant results to CSV (and XLSX if `ImportExcel` is installed)

```powershell
.\get-frontdoor-certs.ps1 -ScanTenant -ExportCsvPath ".\reports\afd-certs.csv"
```

When only `-ExportCsvPath` is provided, a companion `.xlsx` is written next to the CSV when `ImportExcel` is available.

### Export only XLSX

```powershell
.\get-frontdoor-certs.ps1 -ScanTenant -ExportXlsxPath ".\reports\afd-certs.xlsx"
```

### Show a subscription scan in GridView

```powershell
.\get-frontdoor-certs.ps1 -ScanSubscription "Production" -GridView
```

### Scan only Standard/Premium profiles

```powershell
.\get-frontdoor-certs.ps1 -ScanTenant -FrontDoorType StandardPremium
```

### Scan only Classic profiles

```powershell
.\get-frontdoor-certs.ps1 -ScanTenant -FrontDoorType Classic
```

### Increase the warning window

```powershell
.\get-frontdoor-certs.ps1 -ScanFrontDoor "my-frontdoor" -ResourceGroupName "my-rg" -WarningDays 90
```

### Tune concurrency and retries

```powershell
.\get-frontdoor-certs.ps1 -ScanTenant -ThrottleLimit 16 -TlsThrottleLimit 64 -RestRetryCount 4 -TlsRetryCount 3 -RetryBaseDelayMs 750
```

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `ScanFrontDoor` | Yes* | - | Name of a single Front Door profile to inspect |
| `ResourceGroupName` | Yes** | - | Resource group for `ScanFrontDoor` |
| `ScanSubscription` | Yes* | - | Subscription name or ID to scan. Use `""` for the current subscription |
| `ScanTenant` | Yes* | - | Scan all accessible subscriptions in the current tenant |
| `FrontDoorType` | No | `All` | Filter subscription or tenant scans to `All`, `StandardPremium`, or `Classic` |
| `ExportCsvPath` | No | - | Export results to CSV. Parent folders are created automatically. When `ImportExcel` is present, a companion XLSX is also written next to it |
| `ExportXlsxPath` | No | - | Export results to XLSX. Requires the `ImportExcel` module |
| `GridView` | No | `False` | Show results in GridView (mutually exclusive with the export paths) |
| `WarningDays` | No | `30` | Mark certificates expiring within this many days as warnings |
| `ThrottleLimit` | No | auto | Parallelism for ARM and Resource Graph work |
| `TlsThrottleLimit` | No | auto | Parallelism for live TLS probing |
| `TlsTimeoutMs` | No | `5000` | Timeout for live TLS probes in milliseconds |
| `RestRetryCount` | No | `3` | Maximum attempts for transient REST failures |
| `TlsRetryCount` | No | `2` | Maximum attempts for transient TLS failures |
| `RetryBaseDelayMs` | No | `500` | Base delay for exponential retry backoff |

`*` One of `ScanFrontDoor`, `ScanSubscription`, or `ScanTenant` is required.

`**` `ResourceGroupName` is required with `ScanFrontDoor`.

## Output

### Console table

The compact console table shows:

`Subscription`, `FrontDoor`, `FDType`, `MigSource`, `MigTarget`, `Domain`, `Endpoint`, `CertType`, `ProvState`, `ValState` (Standard/Premium only), `Subject`, `IssuingCA`, `RootCA`, `ExpirationDate`, `KVName`, `KVSecret`.

Column widths adapt to the console width. Rows with non-`Succeeded` provisioning state, non-`Approved` validation state, or upcoming/past expirations are highlighted with icons and colour.

### CSV and XLSX export schema

Both exports share the same column list:

- `SubscriptionId`
- `SubscriptionName`
- `FrontDoorName`
- `FrontDoorType`
- `MigrationSourceResourceId`
- `MigrationTargetResourceId`
- `EndpointAssociation`
- `Domain`
- `CertificateType`
- `ProvisioningState`
- `ValidationState`
- `Subject`
- `Issuer`
- `IssuingCA`
- `ServerCertificateCount`
- `IntermediateCA`
- `RootCA`
- `ChainStatus`
- `DigiCertIssued`
- `ExpirationDate`
- `KeyVaultName`
- `KeyVaultSecretName`

XLSX files additionally get a typed `ExpirationDate` column (real Excel date), an auto-filtered table, and a frozen header row.

Classic rows leave `ValidationState` blank because Classic Front Door does not expose a matching field.

## Proxy behaviour

The script checks the default .NET system proxy once at startup with `GetSystemWebProxy()` and `IsBypassed`.

- Live TLS probes use a direct connection when no proxy is configured
- Live TLS probes open an HTTP CONNECT tunnel when a proxy is configured
- ARM and Resource Graph calls use whatever networking configuration is available to the current PowerShell session

The script does not expose a separate parameter for a custom proxy URI or credentials. Configure the PowerShell process or system proxy settings before running it.

## Notes

- Classic certificate expiry is determined from the live certificate presented by the endpoint
- Standard/Premium scans prefer ARM metadata and supplement it with a live TLS probe when the domain resolves
- Tenant-mode progress output is intentionally batched (one line per ~5 % of profiles) so large scans do not spend excessive time writing to the console
# AFDCerts

Extract SSL/TLS certificate details from Azure Front Door deployments, including both Classic and Standard/Premium profiles.

## Requirements

- PowerShell 7
- Az.Accounts
- Az.FrontDoor for Classic single-profile scans
- Optional: ImportExcel for XLSX export
- An authenticated Azure session via `Connect-AzAccount`

Tenant-wide discovery uses Azure Resource Graph and ARM through REST with the bearer token returned by Az.Accounts. It does not require the `Az.ResourceGraph` cmdlets.

## What the script does

- Scans one Front Door, a subscription, or every accessible subscription in the tenant
- Supports both Standard/Premium and Classic Front Door deployments
- Skips default `*.azurefd.net` hostnames automatically so results focus on customer-facing domains
- Reads ARM metadata for certificate configuration and enriches it with live TLS certificate data when available
- Detects classic-to-Standard/Premium migration links and reports the related source or target resource IDs
- Extracts issuer, issuing CA, chain status, intermediate CA, root CA, and a `DigiCertIssued` flag
- Applies retry and backoff for transient REST and TLS failures
- Exports to CSV and, when ImportExcel is available, to XLSX with the same table styling used by Get-AFDOriginCertChains, or shows results in GridView

`-GridView` cannot be combined with `-ExportCsvPath` or `-ExportXlsxPath`. The two export paths can be used together. GridView also requires a graphical session and is not supported in headless environments.

## Scan modes

### Single Front Door

```powershell
.\get-frontdoor-certs.ps1 -ScanFrontDoor "my-frontdoor" -ResourceGroupName "my-rg"
```

### Current subscription

```powershell
.\get-frontdoor-certs.ps1 -ScanSubscription ""
```

### Specific subscription

```powershell
.\get-frontdoor-certs.ps1 -ScanSubscription "Production"
```

### Entire tenant

```powershell
.\get-frontdoor-certs.ps1 -ScanTenant
```

## Common examples

### Export tenant results to CSV and companion XLSX when available

```powershell
.\get-frontdoor-certs.ps1 -ScanTenant -ExportCsvPath ".\reports\afd-certs.csv"
```

### Export tenant results directly to XLSX

```powershell
.\get-frontdoor-certs.ps1 -ScanTenant -ExportXlsxPath ".\reports\afd-certs.xlsx"
```

### Show a subscription scan in GridView

```powershell
.\get-frontdoor-certs.ps1 -ScanSubscription "Production" -GridView
```

### Scan only Standard/Premium profiles

```powershell
.\get-frontdoor-certs.ps1 -ScanTenant -FrontDoorType StandardPremium
```

### Scan only Classic profiles

```powershell
.\get-frontdoor-certs.ps1 -ScanTenant -FrontDoorType Classic
```

### Increase the warning window

```powershell
.\get-frontdoor-certs.ps1 -ScanFrontDoor "my-frontdoor" -ResourceGroupName "my-rg" -WarningDays 90
```

### Tune concurrency and retries

```powershell
.\get-frontdoor-certs.ps1 -ScanTenant -ThrottleLimit 16 -TlsThrottleLimit 64 -RestRetryCount 4 -TlsRetryCount 3 -RetryBaseDelayMs 750
```

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `ScanFrontDoor` | Yes* | - | Name of a single Front Door profile to inspect |
| `ResourceGroupName` | Yes** | - | Resource group for `ScanFrontDoor` |
| `ScanSubscription` | Yes* | - | Subscription name or ID to scan. Use `""` for the current subscription |
| `ScanTenant` | Yes* | - | Scan all accessible subscriptions in the current tenant |
| `FrontDoorType` | No | `All` | Filter subscription or tenant scans to `All`, `StandardPremium`, or `Classic` |
| `ExportCsvPath` | No | - | Export results to CSV. When ImportExcel is installed and `ExportXlsxPath` is not specified, a companion XLSX with the same base name is also written. Parent folders are created automatically |
| `ExportXlsxPath` | No | - | Export results to XLSX. Requires ImportExcel. When omitted, XLSX output falls back to the same base name as `ExportCsvPath` when CSV export is requested |
| `GridView` | No | `False` | Show results in GridView instead of exporting results |
| `WarningDays` | No | `30` | Mark certificates expiring within this many days as warnings |
| `ThrottleLimit` | No | auto | Parallelism for ARM and Resource Graph work |
| `TlsThrottleLimit` | No | auto | Parallelism for live TLS probing |
| `TlsTimeoutMs` | No | `5000` | Timeout for live TLS probes in milliseconds |
| `RestRetryCount` | No | `3` | Maximum attempts for transient REST failures |
| `TlsRetryCount` | No | `2` | Maximum attempts for transient TLS failures |
| `RetryBaseDelayMs` | No | `500` | Base delay for exponential retry backoff |

`*` One of `ScanFrontDoor`, `ScanSubscription`, or `ScanTenant` is required.

`**` `ResourceGroupName` is required with `ScanFrontDoor`.

## Output

The console view shows a compact table with these operational columns:

- `Subscription`
- `FrontDoor`
- `FDType`
- `MigSource`
- `MigTarget`
- `Domain`
- `Endpoint`
- `CertType`
- `ProvState`
- `ValState` when Standard/Premium rows are present
- `Subject`
- `IssuingCA`
- `RootCA`
- `ExpirationDate`
- `KVName`
- `KVSecret`

CSV, XLSX, and GridView use the full stable export schema:

- `SubscriptionId`
- `SubscriptionName`
- `FrontDoorName`
- `FrontDoorType`
- `MigrationSourceResourceId`
- `MigrationTargetResourceId`
- `EndpointAssociation`
- `Domain`
- `CertificateType`
- `ProvisioningState`
- `ValidationState`
- `Subject`
- `Issuer`
- `IssuingCA`
- `ServerCertificateCount`
- `IntermediateCA`
- `RootCA`
- `ChainStatus`
- `DigiCertIssued`
- `ExpirationDate`
- `KeyVaultName`
- `KeyVaultSecretName`

`ChainStatus` now represents the overall certificate situation for export and GridView purposes. It combines live probe errors, chain validation results, and expiration warnings into one field such as `OK`, `Chain: PartialChain`, `Expiration: WARNING`, or `CheckError: No such host is known`.

When XLSX export is available, `ExpirationDate` is written as a real Excel date/time value and formatted with the current culture's long date/time pattern so Excel can render the local date, hour, minute, and second presentation correctly.

Classic rows leave `ValidationState` blank because Azure Front Door Classic does not expose a matching validation-state field.

Standard/Premium rows populate `MigrationSourceResourceId` when they are the target of a Classic migration. Classic rows populate `MigrationTargetResourceId` when they have been migrated to Standard/Premium.

For Standard/Premium rows, `EndpointAssociation` is derived from the endpoint host names whose routes reference each custom domain. The script keeps partial association results even if one endpoint's route lookup fails. Domains that are not referenced by any endpoint route are reported as `Unassociated`.

If the requested XLSX output path is already open in Excel, the script writes the workbook to a timestamped sibling file instead of failing the export.

## Proxy behavior

The script checks the default .NET system proxy once at startup with `GetSystemWebProxy()`.

- Live TLS probes use a direct connection when no proxy is configured
- Live TLS probes use an HTTP CONNECT tunnel when a proxy is configured
- ARM and Az-based calls use the networking configuration available to the current PowerShell session

The script does not expose a separate command-line parameter for a custom proxy URI or custom proxy credentials. Configure the PowerShell process or system proxy settings before running it.

## Notes

- Classic certificate expiry is determined from the live certificate presented by the endpoint
- Standard/Premium scans prefer ARM metadata and then supplement it with a live TLS probe when possible
- Progress output is intentionally batched so large tenant scans do not spend excessive time writing to the console
