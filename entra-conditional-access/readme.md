# Entra ID Conditional Access – Tor Exit Nodes Automation

This folder contains two PowerShell scripts used together to automate and securely maintain
**Entra ID Conditional Access Named Locations** based on current **Tor Exit Node** IP addresses.

Both scripts are designed for **Azure Automation** and **Managed Identity** usage.

---

## Files in this folder

### 1) Initialize-NamedLocationAutomationIdentity.ps1

**Purpose**

Initializes the Managed Identity (Service Principal) that is used by Azure Automation
to manage Conditional Access Named Locations.

The script assigns the required **Microsoft Graph Application Permissions**
to the Managed Identity so that automation can modify Conditional Access objects.

**What it does**

- Connects to Microsoft Graph using delegated admin permissions
- Locates the Managed Identity Service Principal
- Assigns the following Microsoft Graph application permissions:
  - `Policy.ReadWrite.ConditionalAccess`
  - `Policy.Read.All`
- Is idempotent (existing assignments are detected and not duplicated)

**When to run**

- One-time setup
- When permissions need to be revalidated or restored
- When moving the automation to a new tenant or Automation Account

---

### 2) Invoke-TorExitNodesNamedLocation.ps1

**Purpose**

Maintains Entra ID Conditional Access Named Locations containing current
Tor Exit Node IP ranges (IPv4 and IPv6).

**What it does**

- Authenticates to Microsoft Graph using **Managed Identity**
- Validates the active tenant context (safety guardrail)
- Downloads current Tor exit node lists:
  - IPv4 → converted to `/32`
  - IPv6 → converted to `/128`
- Creates or updates the following Named Locations:
  - `Tor Exit Nodes IPv4`
  - `Tor Exit Nodes IPv6`
- Ensures idempotent execution (no duplicate IP ranges)

**Designed for**

- Azure Automation Runbooks
- Scheduled execution (e.g. daily)
- CI/CD pipelines with Managed Identity

---

## Execution order (important)

1. **Run once**
   ```text
   Initialize-NamedLocationAutomationIdentity.ps1
   ```
   Grants the required Microsoft Graph permissions to the Managed Identity.

2. **Run repeatedly**
   ```text
   Invoke-TorExitNodesNamedLocation.ps1
   ```
   Keeps the Tor Exit Node Named Locations up to date.

---

## Azure Automation prerequisites

### PowerShell Runtime
- PowerShell 7+

### Required Modules
- `Microsoft.Graph.Authentication`
- `Microsoft.Graph.Identity.SignIns`

### Managed Identity
- System-assigned or user-assigned Managed Identity enabled
- Admin consent granted for:
  - `Policy.ReadWrite.ConditionalAccess`

### Automation Variable

Create the following Automation Variable:

| Name              | Type   | Encrypted |
|-------------------|--------|-----------|
| ExpectedTenantId  | String | Yes       |

This variable is used as a guardrail to prevent execution in the wrong tenant.

---

## Security considerations

- No credentials or secrets are stored in the scripts
- Authentication is performed exclusively via Managed Identity
- Tenant validation prevents accidental cross-tenant changes
- Permissions are scoped to Conditional Access only

---

## Recommended scheduling

Run `Invoke-TorExitNodesNamedLocation.ps1`:
- Every three hours (recommended)
- Or more frequently if your security policy requires rapid updates

---

## Data source

Tor Exit Node lists are retrieved from:

- https://github.com/Enkidu-6/tor-relay-lists

---

## Monitoring & Alerts (Recommended)

This automation relies on external dependencies (for example, the Tor
Exit Node data source and Microsoft Graph APIs). To ensure operational
reliability, a **Log Analytics--based alert** is configured so that
failures are detected even when the runbook executes only every few
hours.

### Log Analytics Integration (Azure Automation → Diagnostic Settings)

The Azure Automation Account must send diagnostic logs to a Log
Analytics workspace.

Enable at minimum: - **JobLogs**

These logs are required for detecting failed runbook executions.

------------------------------------------------------------------------

## Alert Rule: Tor Named Location Automation Failed

The following alert rule monitors the Automation Account for **failed
runbook jobs**.

### Alert Characteristics

  -----------------------------------------------------------------------
  Setting                             Value
  ----------------------------------- -----------------------------------
  Alert name                          **\[ALERT\] Tor Named Location
                                      Automation Failed**

  Severity                            **1 (Error / Critical)**

  Scope                               Automation Account
                                      `aa-namedlocations`
 
  Measure                             **Table rows**

  Aggregation Type                    **Count**

  Aggregation granularity             **5 minutes**

  Operator                            **Greater than**
  
  Threshold value                     **0**

  Frequency of evaluation             **5 minutes**

  Auto-mitigate                       Disabled

  Action group                        `AutomationError`

  Notification subject                **\[ALERT\] Tor Named Location
                                      Automation Failed**
  -----------------------------------------------------------------------

### KQL Query Used

``` kusto
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.AUTOMATION"
| where Category == "JobLogs"
| where ResultType == "Failed"
| where TimeGenerated >= ago(10m)
```

### Alert Trigger Logic

- The alert is evaluated every **5 minutes**
- The query always scans the **last 10 minutes**
- If **at least one failed job** is found, the alert triggers immediately

---

## Author

Stefan Redlin
