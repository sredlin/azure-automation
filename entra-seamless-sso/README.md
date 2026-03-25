# Kerberos Key Rollover via Azure Automation

Automatisiert die monatliche Rotation des Kerberos Decryption Keys für **Entra ID Seamless SSO** (`AZUREADSSOACC`-Konto im lokalen Active Directory).

---

## Hintergrund

Im Rahmen der Seamless SSO-Konfiguration erstellt Microsoft Entra Connect im lokalen Active Directory ein Computerkonto namens `AZUREADSSOACC`. Microsoft empfiehlt, den zugehörigen **Kerberos Decryption Key alle 30 Tage zu rotieren**.

---

## Dateien

| Datei | Zweck | Ausführung |
|-------|-------|------------|
| `Initialize-KerberosDelegation.ps1` | Erstellt AD-Serviceaccount und delegiert Mindestrechte auf `AZUREADSSOACC` | Einmalig (DC / RSAT) |
| `Initialize-HybridWorker.ps1` | Erstellt Automation Account und Hybrid Worker Group | Einmalig |
| `Reset-KerberosSSO.ps1` | Führt den Kerberos Key Rollover durch | Monatlich (Azure Automation Schedule) |

---

## Voraussetzungen

### Konten & Berechtigungen

| Konto | Typ | Benötigte Berechtigungen |
|-------|-----|--------------------------|
| `sa-kerberos-rollover` | AD-Serviceaccount | Delegiert auf `AZUREADSSOACC`: Reset Password + Write `msDS-SupportedEncryptionTypes` |
| `AADSSOCloudCredential` | Entra ID Benutzerkonto | **Global Administrator** |

> **Bekanntes Issue:** Aufgrund eines bekannten Bugs reicht die Rolle *Hybrid Identity Administrator* für `Update-AzureADSSOForest` derzeit nicht aus. Der Cloud-Serviceaccount benötigt temporär **Global Administrator**. Microsoft ist informiert. Den Account als dedizierten, durch Conditional Access abgesicherten Service Account einrichten.

### Infrastruktur

- Azure Automation Account (in `rg-automation`)
- Windows Server mit **Microsoft Entra Connect** – als **Arc Machine** registriert (in `rg-arc`)
- Arc Machine mit **Extension-based Hybrid Runbook Worker** (`HybridWorkerForWindows`)

> **Wichtig:** Agent-based Hybrid Worker ist seit 31.08.2024 EOL und wird ab 01.04.2025 nicht mehr unterstützt. Ausschließlich Extension-based Worker verwenden.

---

## Einrichtung

### Schritt 1 – AD-Serviceaccount erstellen und Rechte delegieren

Auf einem Domain Controller oder Server mit RSAT/AD-Modul:

```powershell
.\Initialize-KerberosDelegation.ps1 `
    -ServiceAccountOU "OU=ServiceAccounts,DC=contoso,DC=com"
```

Der Domain-FQDN wird automatisch über `Get-ADDomain` ermittelt.

Das Skript gibt das generierte Passwort **einmalig** aus – direkt im nächsten Schritt als Credential Asset hinterlegen.

### Schritt 2 – Automation Account und Hybrid Worker Group erstellen

```powershell
.\Initialize-HybridWorker.ps1 `
    -AutomationResourceGroupName "rg-automation" `
    -AutomationAccountName "aa-kerberos-rollover" `
    -Location "westeurope" `
    -HybridWorkerGroupName "HybridWorkerGroup-EntraConnect"
```

### Schritt 3 – HybridWorkerForWindows Extension an der Arc Machine aktivieren

Im Azure Portal: **Arc Machine → Extensions → + Add → HybridWorkerForWindows**

| Feld | Wert |
|------|------|
| Automation Account | `aa-kerberos-rollover` |
| Hybrid Worker Group | `HybridWorkerGroup-EntraConnect` |

### Schritt 4 – Credential Assets anlegen

Im Azure Portal → Automation Account → **Shared Resources → Credentials** zwei Assets anlegen:

| Name | Username | Passwort |
|------|----------|----------|
| `AADSSOOnPremCredential` | `DOMAIN\sa-kerberos-rollover` | Ausgabe aus Schritt 1 |
| `AADSSOCloudCredential` | UPN des Entra Global Admin | — |

### Schritt 5 – Runbook importieren

Im Automation Account → **Runbooks → Import a runbook** → `Reset-KerberosSSO.ps1` hochladen (Typ: PowerShell 5.1).

### Schritt 6 – Schedule anlegen und verknüpfen

Im Runbook → **Link to Schedule** → neuen Schedule erstellen:

| Einstellung | Wert |
|-------------|------|
| Frequenz | Monatlich |
| Zeitpunkt | z. B. jeden 1. des Monats, 02:00 Uhr |
| Run on | Hybrid Worker → `HybridWorkerGroup-EntraConnect` |

---

## Parameter des Runbooks

| Parameter | Typ | Standard | Beschreibung |
|-----------|-----|----------|--------------|
| `PreserveCustomPermissions` | Switch | `$false` | Aktivieren, wenn delegierte Berechtigungen auf `AZUREADSSOACC` erhalten bleiben sollen |

---

## Verifizierung nach dem ersten Lauf

**Entra Admin Center:**
*Identity → Hybrid management → Microsoft Entra Connect → Seamless single sign-on*

**PowerShell auf einem Domain Controller:**

```powershell
Get-ADComputer AZUREADSSOACC -Properties * | Select-Object Name, PasswordLastSet
```

`PasswordLastSet` muss mit dem Ausführungszeitpunkt des Runbooks übereinstimmen.

**Delegation prüfen:**

```powershell
Get-Acl "AD:\CN=AZUREADSSOACC,DC=contoso,DC=com" |
    Select-Object -ExpandProperty Access |
    Where-Object { $_.IdentityReference -like "*sa-kerberos-rollover*" }
```

---

## Multi-Forest-Umgebungen

Sind mehrere AD-Forests mit Seamless SSO aktiv, muss `Update-AzureADSSOForest` **pro Forest exakt einmal** ausgeführt werden.

> **Achtung:** Mehrfachausführung für denselben Forest deaktiviert das Feature, bis alle Kerberos-Tickets der betroffenen Benutzer abgelaufen und neu ausgestellt wurden.

Für Multi-Forest den Runbook-Parameter `-OnPremCredentials` pro Forest mit dem jeweils zuständigen AD-Account aufrufen. Empfehlung: Pro Forest einen separaten Runbook-Job einplanen.

---

## Architektur

```
DC / RSAT
└── Initialize-KerberosDelegation.ps1
      └── sa-kerberos-rollover  (delegiert: Reset PW + Write msDS-SupportedEncryptionTypes)
            └── AZUREADSSOACC  (Seamless SSO Computerkonto)

rg-automation
└── Automation Account: aa-kerberos-rollover
    ├── Credential Assets
    │   ├── AADSSOOnPremCredential  (DOMAIN\sa-kerberos-rollover)
    │   └── AADSSOCloudCredential   (Entra Global Admin)
    ├── Runbook: Reset-KerberosSSO.ps1
    ├── Schedule (monatlich)
    └── Hybrid Worker Group: HybridWorkerGroup-EntraConnect
            └── Arc Machine (Entra Connect Server)  ← rg-arc
                    └── Extension: HybridWorkerForWindows
                            └── AzureADSSO.psd1 → Update-AzureADSSOForest
```

---

## Lizenz

MIT – siehe [LICENSE](../LICENSE)
