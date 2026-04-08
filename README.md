# AFDCerts

Extract SSL/TLS certificate details from Azure Front Door deployments, including both Classic and Standard/Premium profiles.

## Requirements

- PowerShell 7
- Az.Accounts
- Az.FrontDoor for Classic single-profile and subscription scans
- An authenticated Azure session via `Connect-AzAccount`

Tenant-wide discovery uses Azure Resource Graph and ARM through REST with the bearer token returned by Az.Accounts. It does not require the `Az.ResourceGraph` cmdlets.

## What the script does

- Scans one Front Door, a subscription, or every accessible subscription in the tenant
- Supports both Standard/Premium and Classic Front Door deployments
- Skips default `*.azurefd.net` hostnames automatically so results focus on customer-facing domains
- Reads ARM metadata for certificate configuration and enriches it with live TLS certificate data when available
- Extracts issuer, issuing CA, chain status, intermediate CA, root CA, and a `DigiCertIssued` flag
- Applies retry and backoff for transient REST and TLS failures
- Exports to CSV or shows results in GridView

`-GridView` and `-ExportCsvPath` are mutually exclusive.

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

### Export tenant results to CSV

```powershell
.\get-frontdoor-certs.ps1 -ScanTenant -ExportCsvPath ".\reports\afd-certs.csv"
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
| `ExportCsvPath` | No | - | Export results to CSV. Parent folders are created automatically |
| `GridView` | No | `False` | Show results in GridView instead of exporting to CSV |
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
- `Domain`
- `CertType`
- `ProvState`
- `ValState` when Standard/Premium rows are present
- `Subject`
- `IssuingCA`
- `ExpirationDate`
- `KVName`
- `KVSecret`

CSV and GridView use the full stable export schema:

- `SubscriptionId`
- `SubscriptionName`
- `FrontDoorName`
- `FrontDoorType`
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
- `ExpirationStatus`
- `KeyVaultName`
- `KeyVaultSecretName`

Classic rows leave `ValidationState` blank because Azure Front Door Classic does not expose a matching validation-state field.

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
