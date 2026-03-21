# Entra ID Conditional Access – Tor Exit Nodes Automation

Automates and securely maintains **Entra ID Conditional Access Named Locations** based on current
**Tor Exit Node** IP addresses. Both scripts are designed for **Azure Automation** with **Managed Identity**.

---

## Files

### 1. Initialize-NamedLocationAutomationIdentity.ps1

One-time setup script. Assigns the required Microsoft Graph application permissions to the Managed
Identity so that the runbook can modify Conditional Access objects.

**What it does**

- Connects to Microsoft Graph using delegated admin permissions
- Locates the Managed Identity Service Principal
- Assigns the following Microsoft Graph application permissions:
  - `Policy.ReadWrite.ConditionalAccess`
  - `Policy.Read.All`
- Idempotent – existing assignments are detected and not duplicated

**When to run**

- Initial setup
- After moving the automation to a new tenant or Automation Account
- When permissions need to be revalidated or restored

---

### 2. Invoke-TorExitNodesNamedLocation.ps1

Runbook script. Keeps the Tor Exit Node Named Locations up to date on every execution.

**What it does**

- Authenticates via **Managed Identity**
- Validates the active tenant against `ExpectedTenantId` (safety guardrail)
- Downloads current Tor exit node lists:
  - IPv4 → `/32` CIDR notation
  - IPv6 → `/128` CIDR notation
- Creates or updates the Named Locations:
  - `Tor Exit Nodes IPv4`
  - `Tor Exit Nodes IPv6`
- Idempotent – no duplicate IP ranges, no unnecessary updates

---

## Execution Order

1. **Run once** – grant permissions to the Managed Identity:
   ```
   Initialize-NamedLocationAutomationIdentity.ps1
   ```

2. **Run on schedule** – keep Named Locations current:
   ```
   Invoke-TorExitNodesNamedLocation.ps1
   ```

---

## Azure Automation Prerequisites

### PowerShell Runtime

- PowerShell 7+

### Required Modules

- `Microsoft.Graph.Authentication`
- `Microsoft.Graph.Identity.SignIns`

### Managed Identity

- System-assigned or user-assigned Managed Identity enabled on the Automation Account
- Admin consent granted for `Policy.ReadWrite.ConditionalAccess`

### Automation Variable

| Name             | Type   | Encrypted |
|------------------|--------|-----------|
| ExpectedTenantId | String | Yes       |

Used as a guardrail to prevent accidental execution in the wrong tenant.

---

## Example Output

### First run (Named Locations do not exist yet)

```
Successfully connected as Managed Identity to tenant '9018152c-...' (Environment: Global).

  [IPv4] Tor Exit Nodes IPv4
  Id       : <guid>
  Total    : 1234 entries  |  Created new location – all entries added.

  [IPv6] Tor Exit Nodes IPv6
  Id       : <guid>
  Total    : 567 entries  |  Created new location – all entries added.
```

### Subsequent run (Named Locations already exist)

```
Successfully connected as Managed Identity to tenant '9018152c-...' (Environment: Global).

  [IPv4] Tor Exit Nodes IPv4
  Id       : <guid>
  Total    : 1237 entries  |  Unchanged: 1231  |  Added: 6  |  Removed: 3
  Added (+):
    + 1.2.3.4/32
    + 5.6.7.8/32
    ...
  Removed (-):
    - 9.10.11.12/32

  [IPv6] Tor Exit Nodes IPv6
  Id       : <guid>
  Total    : 567 entries  |  Unchanged: 567  |  Added: 0  |  Removed: 0
  No changes.
```

---

## Recommended Scheduling

Run `Invoke-TorExitNodesNamedLocation.ps1` every **3 hours** (or more frequently if your security
policy requires rapid updates).

---

## Data Source

Tor exit node lists are retrieved from:
[https://github.com/Enkidu-6/tor-relay-lists](https://github.com/Enkidu-6/tor-relay-lists)

---

## Security Considerations

- No credentials or secrets are stored in the scripts
- Authentication exclusively via Managed Identity
- Tenant validation prevents accidental cross-tenant changes
- Permissions are scoped to Conditional Access only

---

## Monitoring & Alerts

This automation depends on external services (Tor exit node source, Microsoft Graph). Configure a
Log Analytics-based alert to detect failures between scheduled executions.

### Diagnostic Settings

Enable **JobLogs** on the Azure Automation Account and send them to a Log Analytics workspace.

### Alert Rule: Tor Named Location Automation Failed

| Setting                  | Value                                           |
|--------------------------|-------------------------------------------------|
| Alert name               | `[ALERT] Tor Named Location Automation Failed`  |
| Severity                 | 1 – Error                                       |
| Scope                    | Automation Account `aa-namedlocations`          |
| Measure                  | Table rows                                      |
| Aggregation type         | Count                                           |
| Aggregation granularity  | 5 minutes                                       |
| Operator                 | Greater than                                    |
| Threshold                | 0                                               |
| Evaluation frequency     | 5 minutes                                       |
| Auto-mitigate            | Disabled                                        |
| Action group             | `AutomationError`                               |

### KQL Query

```kusto
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.AUTOMATION"
| where Category == "JobLogs"
| where ResultType == "Failed"
| where TimeGenerated >= ago(10m)
```

The query scans the last 10 minutes and is evaluated every 5 minutes. At least one failed job
triggers the alert immediately.

---

## Author

Stefan Redlin
