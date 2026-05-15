<#
.SYNOPSIS
    MRM-Runbook: Lizenzierte F3/F1-Nutzer ermitteln und Retention Policy zuweisen.

.DESCRIPTION
    Authentifiziert sich per System-Assigned Managed Identity gegen Microsoft Graph
    und Exchange Online. Ermittelt alle Nutzer mit SPE_F1- oder DESKLESSPACK-Lizenz
    und weist diesen die Exchange Retention Policy "F3 Mailbox Cleanup 12M" zu.
    Nutzer ohne Mailbox werden übersprungen. Bereits korrekt konfigurierte Mailboxen
    werden nicht verändert (idempotent).

.NOTES
    Benötigte Graph-Berechtigungen (Application):
      - User.Read.All
      - Organization.Read.All

    Benötigte Exchange-Berechtigungen (Managed Identity):
      - Exchange.ManageAsApp (Entra App Role)
      - Mail Recipients (Exchange Management Role)

    Benötigte Module im Automation Account:
      - Microsoft.Graph.Authentication
      - Microsoft.Graph.Users
      - Microsoft.Graph.Identity.DirectoryManagement
      - ExchangeOnlineManagement (v3.x)
#>

# ══════════════════════════════════════════
#  Konfiguration
# ══════════════════════════════════════════
$targetSkuPartNumbers = @("SPE_F1", "DESKLESSPACK")
$retentionPolicyName  = "F3 Mailbox Cleanup 12M"

# ── Verbindung Microsoft Graph ────────────────────────────────────────────────
try {
    Connect-MgGraph -Identity -NoWelcome
    Write-Output "✔ Verbunden mit Microsoft Graph (Managed Identity)"
}
catch {
    Write-Error "Fehler beim Verbinden mit Graph: $_"
    throw
}

# ── Tenant Domain automatisch ermitteln ──────────────────────────────────────
$tenantDomain = (Get-MgOrganization).VerifiedDomains |
    Where-Object { $_.IsInitial -eq $true } |
    Select-Object -ExpandProperty Name

Write-Output "Tenant Domain: $tenantDomain"

# ── SKU-IDs ermitteln ─────────────────────────────────────────────────────────
$f3SkuIds = (Get-MgSubscribedSku -All |
    Where-Object { $_.SkuPartNumber -in $targetSkuPartNumbers }
).SkuId

if (-not $f3SkuIds) {
    Write-Warning "Keine SKUs mit SkuPartNumber in ($($targetSkuPartNumbers -join ', ')) gefunden."
    Disconnect-MgGraph | Out-Null
    return
}

Write-Output "Gefundene SKU-IDs: $($f3SkuIds -join ', ')"

# ── Nutzer abrufen ────────────────────────────────────────────────────────────
$filterParts = $f3SkuIds | ForEach-Object {
    "assignedLicenses/any(x:x/skuId eq $_ )"
}
$graphFilter = $filterParts -join " or "

Write-Output "Verwende Filter: $graphFilter"

try {
    $licensedUsers = Get-MgUser -All -Filter $graphFilter `
        -Property "Id,DisplayName,UserPrincipalName,AssignedLicenses" `
        -ConsistencyLevel eventual `
        -CountVariable userCount
}
catch {
    Write-Error "Fehler beim Abrufen der Nutzer: $_"
    Disconnect-MgGraph | Out-Null
    throw
}

# ── Auswertung pro SKU ────────────────────────────────────────────────────────
Write-Output ""
Write-Output "══════════════════════════════════════════"
Write-Output " Lizenz-Auswertung: F3 / Frontline Worker"
Write-Output "══════════════════════════════════════════"

foreach ($skuId in $f3SkuIds) {
    $skuName = (Get-MgSubscribedSku -All |
        Where-Object SkuId -eq $skuId).SkuPartNumber

    $countForSku = ($licensedUsers | Where-Object {
        $_.AssignedLicenses.SkuId -contains $skuId
    }).Count

    Write-Output "  $skuName ($skuId): $countForSku Nutzer"
}

Write-Output "──────────────────────────────────────────"
Write-Output "  GESAMT lizenzierte Nutzer : $($licensedUsers.Count)"
Write-Output "══════════════════════════════════════════"

Disconnect-MgGraph | Out-Null
Write-Output "✔ Graph-Verbindung getrennt"

# ── Verbindung Exchange Online ────────────────────────────────────────────────
try {
    Connect-ExchangeOnline -ManagedIdentity -Organization $tenantDomain -ShowBanner:$false
    Write-Output "✔ Verbunden mit Exchange Online (Managed Identity)"
}
catch {
    Write-Error "Fehler beim Verbinden mit Exchange Online: $_"
    throw
}

# ── Retention Policy zuweisen ─────────────────────────────────────────────────
$assignedCount = 0
$skippedCount  = 0
$alreadyCount  = 0

Write-Output ""
Write-Output "══════════════════════════════════════════"
Write-Output " Retention Policy Zuweisung"
Write-Output "══════════════════════════════════════════"

foreach ($user in $licensedUsers) {
    $upn = $user.UserPrincipalName

    try {
        $mailbox = Get-Mailbox -Identity $upn -ErrorAction Stop
    }
    catch {
        Write-Warning "Keine Mailbox gefunden für $upn – übersprungen."
        $skippedCount++
        continue
    }

    if ($mailbox.RetentionPolicy -eq $retentionPolicyName) {
        Write-Output "  [SKIP]    $upn – Richtlinie bereits zugewiesen"
        $alreadyCount++
        continue
    }

    try {
        Set-Mailbox -Identity $upn -RetentionPolicy $retentionPolicyName -ErrorAction Stop
        Write-Output "  [OK]      $upn – Richtlinie zugewiesen"
        $assignedCount++
    }
    catch {
        Write-Warning "  [FEHLER]  $upn – $($_.Exception.Message)"
        $skippedCount++
    }
}

Write-Output "──────────────────────────────────────────"
Write-Output "  Neu zugewiesen  : $assignedCount"
Write-Output "  Bereits gesetzt : $alreadyCount"
Write-Output "  Übersprungen    : $skippedCount"
Write-Output "══════════════════════════════════════════"

Disconnect-ExchangeOnline -Confirm:$false
Write-Output "✔ Exchange Online-Verbindung getrennt"
