# Kerberos Key Rollover via Azure Automation

Automatisiert die monatliche Rotation des Kerberos Decryption Keys für **Entra ID Seamless SSO** (`AZUREADSSOACC`-Konto im lokalen Active Directory).

---

## Hintergrund

Im Rahmen der Seamless SSO-Konfiguration erstellt Microsoft Entra Connect im lokalen Active Directory ein Computerkonto namens `AZUREADSSOACC`. Microsoft empfiehlt, den zugehörigen **Kerberos Decryption Key alle 30 Tage zu rotieren**.

---

## Dateien

| Datei | Zweck | Ausführung |
|-------|-------|------------|
| `Initialize-HybridWorker.ps1` | Richtet Hybrid Worker Group ein und gibt Anleitung zur Worker-Registrierung | Einmalig (lokal, als Admin) |
| `Reset-KerberosSSO.ps1` | Führt den Kerberos Key Rollover durch | Monatlich (Azure Automation Schedule) |

---

## Voraussetzungen

### Konten & Berechtigungen

| Konto | Typ | Benötigte Rolle |
|-------|-----|-----------------|
| `AADSSOCloudCredential` | Entra ID Benutzerkonto | **Global Administrator** |
| `AADSSOOnPremCredential` | AD-Benutzerkonto | **Enterprise Administrator** oder **Domain Administrator** |

> **Bekanntes Issue:** Aufgrund eines bekannten Bugs reicht die Rolle *Hybrid Identity Administrator* für `Update-AzureADSSOForest` derzeit nicht aus. Der Cloud-Serviceaccount benötigt temporär **Global Administrator**. Microsoft ist informiert. Den Account als dedizierten, durch Conditional Access abgesicherten Service Account einrichten.

### Infrastruktur

- Azure Automation Account
- Windows Server mit **Microsoft Entra Connect** (enthält `AzureADSSO.psd1`)
- Server als **Extension-based Hybrid Runbook Worker** registriert

> **Wichtig:** Agent-based Hybrid Worker ist seit 31.08.2024 EOL und wird ab 01.04.2025 nicht mehr unterstützt. Ausschließlich Extension-based Worker verwenden.

---

## Einrichtung

### Schritt 1 – Hybrid Worker einrichten

Auf dem Entra Connect Server (PowerShell als Administrator):

```powershell
.\Initialize-HybridWorker.ps1 `
    -ResourceGroupName "rg-automation" `
    -AutomationAccountName "aa-kerberos-rollover" `
    -HybridWorkerGroupName "HybridWorkerGroup-EntraConnect"
```

Anschließend den Server im Azure Portal als Worker zur Gruppe hinzufügen:
**Automation Account → Hybrid Worker Groups → `HybridWorkerGroup-EntraConnect` → Add machines**

### Schritt 2 – Credential Assets anlegen

Im Azure Portal → Automation Account → **Shared Resources → Credentials** zwei Assets anlegen:

| Name | Inhalt |
|------|--------|
| `AADSSOOnPremCredential` | AD-Serviceaccount (`DOMAIN\Username`) |
| `AADSSOCloudCredential` | Entra ID Global Admin Serviceaccount (UPN) |

### Schritt 3 – Runbook importieren

Im Automation Account → **Runbooks → Import a runbook** → `Reset-KerberosSSO.ps1` hochladen (Typ: PowerShell 5.1).

### Schritt 4 – Schedule anlegen und verknüpfen

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

---

## Multi-Forest-Umgebungen

Sind mehrere AD-Forests mit Seamless SSO aktiv, muss `Update-AzureADSSOForest` **pro Forest exakt einmal** ausgeführt werden.

> **Achtung:** Mehrfachausführung für denselben Forest deaktiviert das Feature, bis alle Kerberos-Tickets der betroffenen Benutzer abgelaufen und neu ausgestellt wurden.

Für Multi-Forest den Runbook-Parameter `-OnPremCredentials` pro Forest mit dem jeweils zuständigen AD-Account aufrufen. Empfehlung: Pro Forest einen separaten Runbook-Job einplanen.

---

## Architektur

```
Azure Automation Account
├── Credential Assets
│   ├── AADSSOOnPremCredential  (AD Enterprise/Domain Admin)
│   └── AADSSOCloudCredential   (Entra Global Admin)
├── Runbook: Reset-KerberosSSO.ps1
├── Schedule (monatlich)
└── Hybrid Worker Group: HybridWorkerGroup-EntraConnect
        └── Entra Connect Server (Extension-based Worker)
                └── AzureADSSO.psd1 → Update-AzureADSSOForest
```

---

## Lizenz

MIT – siehe [LICENSE](../LICENSE)
