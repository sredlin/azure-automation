# Sync-DelegateAccessByAttribute – Azure Automation Runbook

**Skript:** `Sync-DelegateAccessByAttribute.ps1`
**Version:** 3.0
**Autor:** Stefan / Vater Business IT GmbH
**Datum:** 2026-03-20
**Ausführungsumgebung:** Azure Automation (PowerShell 7.x)

---

## Übersicht

Das Runbook synchronisiert FullAccess-Berechtigungen der Delegate-Mailbox in Exchange Online.
Es liest alle Postfächer des Tenants, prüft ein konfigurierbares `CustomAttribute` und führt zwei Phasen aus:

| Phase | Logik |
|-------|-------|
| **GRANT** | Postfächer **MIT** dem Attributwert → Delegate-Mailbox erhält FullAccess auf dieses Postfach (falls noch nicht vorhanden) |
| **REVOKE** | Postfächer **OHNE** den Attributwert → FullAccess der Delegate-Mailbox wird entzogen (falls vorhanden) |

Die Delegate-Mailbox selbst wird in beiden Phasen übersprungen. Das Skript ist idempotent.

### Attribut-Mapping

Das Steuerattribut wird im **Active Directory** gepflegt und per **Entra Connect** nach Exchange Online synchronisiert:

| AD-Attribut | Exchange Online | Standard-Sollwert |
|-------------|-----------------|-------------------|
| `extensionAttribute3` | `CustomAttribute3` | `PDS` |

Ein Postfach gewährt der Delegate-Mailbox also genau dann FullAccess, wenn `extensionAttribute3 = PDS` am AD-Objekt gesetzt ist. Bei leerem Wert oder abweichendem Inhalt wird der Zugriff entzogen.

---

## Voraussetzungen

### Einmalige Einrichtung (als Global Admin)

#### 1. App-Rolle der Managed Identity zuweisen (Entra ID / Azure AD)

```powershell
# Object-ID der Managed Identity (System-Assigned des Automation Accounts)
# Zu finden in: Entra ID → Enterprise Applications → <ManagedIdentityName> → Objekt-ID
$MIObjectId     = "<ObjectId-der-ManagedIdentity>"
$ExoAppId       = "00000002-0000-0ff1-ce00-000000000000"   # Exchange Online (fix)
$PermissionName = "Exchange.ManageAsApp"

$ExoSP   = Get-AzureADServicePrincipal -Filter "AppId eq '$ExoAppId'"
$AppRole = $ExoSP.AppRoles | Where-Object { $_.Value -eq $PermissionName }

New-AzureADServiceAppRoleAssignment `
    -ObjectId    $MIObjectId `
    -PrincipalId $MIObjectId `
    -ResourceId  $ExoSP.ObjectId `
    -Id          $AppRole.Id
```

#### 2. Service Principal in Exchange Online registrieren

```powershell
# AppId  → Entra ID → Enterprise Applications → <ManagedIdentityName> → Anwendungs-ID
# ObjectId → Entra ID → Enterprise Applications → <ManagedIdentityName> → Objekt-ID
New-ServicePrincipal `
    -AppId       "<AppId-der-ManagedIdentity>" `
    -ObjectId    "<ObjectId-der-ManagedIdentity>" `
    -DisplayName "<ManagedIdentityName>"
```

> **Hinweis:** AppId und ObjectId müssen der tatsächlichen Managed Identity des Automation Accounts entsprechen.

#### 3. Custom RBAC-Rolle erstellen (Least Privilege)

```powershell
# Neue Management Role auf Basis von "Mailbox Permission Management"
New-ManagementRole -Name "<Service>-FullAccess-Sync" -Parent "Mailbox Permission Management"

# Alle nicht benötigten Cmdlets entfernen
$Keep     = @("Get-Mailbox", "Get-MailboxPermission", "Add-MailboxPermission", "Remove-MailboxPermission")
$ToRemove = Get-ManagementRoleEntry "PDS-FullAccess-Sync\*" |
                Where-Object { $_.Name -notin $Keep }

foreach ($Entry in $ToRemove) {
    try {
        Remove-ManagementRoleEntry "$($Entry.Role)\$($Entry.Name)" -Confirm:$false -ErrorAction Stop
        Write-Output "Entfernt: $($Entry.Name)"
    }
    catch {
        Write-Warning "Fehler bei $($Entry.Name): $_"
    }
    Start-Sleep -Milliseconds 500
}
```

#### 4. Rolle dem Service Principal zuweisen

```powershell
New-ManagementRoleAssignment `
    -Role "PDS-FullAccess-Sync" `
    -App  "<AppId-der-ManagedIdentity>"
```

---

## Parameter

| Parameter | Pflicht | Standard | Beschreibung |
|-----------|:-------:|----------|--------------|
| `DelegateMailbox` | ✅ | – | UPN der Mailbox, die FullAccess erhalten/verlieren soll |
| `Organization` | ✅ | – | `*.onmicrosoft.com`-Domain des Tenants |
| `CustomAttribute` | – | – | Exchange-Attributname (entspricht `extensionAttribute3` in AD) |
| `AttributeValue` | – | – | Sollwert des Attributs – bei Übereinstimmung wird FullAccess gewährt |
| `TestMailbox` | – | – | UPN eines einzelnen Postfachs für Testlauf |

---

## Ausführung

### Volllauf (Produktiv)

```powershell
.\Sync-DelegateAccessByAttribute.ps1 `
    -DelegateMailbox "delegate@contoso.com" `
    -Organization    "contoso.onmicrosoft.com"
```

### Testlauf (einzelnes Postfach)

```powershell
.\Sync-DelegateAccessByAttribute.ps1 `
    -DelegateMailbox "delegate@contoso.com" `
    -Organization    "contoso.onmicrosoft.com" `
    -CustomAttribute "CustomAttribute3" `
    -AttributeValue  "PDS" `
    -TestMailbox     "testuser@contoso.com"
```

---

## Ausgabe / Logging

Das Skript gibt am Ende eine strukturierte Zusammenfassung aus:

```
=== Zusammenfassung ===
--- GRANT ---
Neu gesetzt      : 5
Bereits vorhanden: 12
Fehler           : 0
--- REVOKE ---
Entfernt         : 2
Fehler           : 0
--- GESAMT ---
Übersprungen     : 1
```

Jeder Einzelschritt wird in der Form `[STATUS] UPN – Hinweis` ausgegeben und ist im Azure Automation **Job-Protokoll** vollständig einsehbar.

### Mögliche Statuswerte

| Status | Bedeutung |
|--------|-----------|
| `GESETZT` | FullAccess wurde neu hinzugefügt |
| `BEREITS VORHANDEN` | Berechtigung war schon gesetzt, keine Aktion |
| `ENTFERNT` | FullAccess wurde widerrufen |
| `ÜBERSPRUNGEN` | Postfach ist die Delegate-Mailbox selbst |
| `FEHLER` | Fehler bei Get-/Add-/Remove-MailboxPermission |

---

## Zeitplan (Empfehlung)

Das Runbook sollte über einen **Azure Automation-Zeitplan** regelmäßig ausgeführt werden, damit Berechtigungen zeitnah mit dem Attributstatus synchronisiert bleiben.

Empfohlene Intervalle:
- **Stündlich** – bei häufigen AD-Änderungen
- **Täglich (z. B. 02:00 Uhr)** – Standardfall für die meisten Mandanten

> **Hinweis Sync-Delay:** Änderungen am `extensionAttribute3` im AD werden erst nach dem nächsten Entra Connect-Synchronisierungszyklus (Standard: 30 Min.) in Exchange Online sichtbar. Das Runbook sollte frühestens danach laufen.


---

## Sicherheitshinweise

- Die Managed Identity hat **nur** die vier notwendigen Exchange-Cmdlets (Least Privilege).
- Es werden **keine Credentials** gespeichert; die Authentifizierung erfolgt ausschließlich über die System-Managed Identity.
- Das Skript führt **keine irreversiblen Aktionen** durch – alle Berechtigungen können neu gesetzt oder erneut entzogen werden.
- Die Delegate-Mailbox wird in beiden Phasen **explizit übersprungen**, um unbeabsichtigte Selbst-Zuweisung zu verhindern.

---
