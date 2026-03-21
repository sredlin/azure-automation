# azure-automation

PowerShell Runbooks für **Azure Automation** – entwickelt von Stefan Redlin / Vater Business IT GmbH.

Alle Skripte nutzen ausschließlich **System-Managed Identity** (keine gespeicherten Credentials) und folgen dem Prinzip der minimalen Rechte (Least Privilege).

---

## Inhalt

```
azure-automation/
├── app-registration-expiry-alerts/
│   ├── Initialize-AppExpiryAlertAutomationIdentity.ps1  # Einmalige Berechtigungseinrichtung
│   └── Invoke-AppRegistrationExpiryAlerts.ps1           # Runbook: Ablaufende Secrets/Zertifikate warnen
│
├── entra-conditional-access/
│   ├── Initialize-NamedLocationAutomationIdentity.ps1   # Einmalige Berechtigungseinrichtung
│   └── Invoke-TorExitNodesNamedLocation.ps1             # Runbook: Tor Exit Nodes aktuell halten
│
└── exchange/
    └── delegate-access-sync/
        └── Sync-DelegateAccessByAttribute.ps1           # Runbook: FullAccess per AD-Attribut steuern
```

---

## Runbooks

### App Registration – Expiry Alerts

**Verzeichnis:** `app-registration-expiry-alerts/`

Prüft alle **App Registrations** und **Service Principals** auf ablaufende **Client Secrets** und **Zertifikate** und sendet Warnmeldungen per **Teams-Webhook** (Adaptive Card) und **E-Mail** (HTML).

| Skript | Zweck | Ausführung |
|--------|-------|------------|
| `Initialize-AppExpiryAlertAutomationIdentity.ps1` | Weist der Managed Identity die nötigen Graph-Berechtigungen zu | Einmalig |
| `Invoke-AppRegistrationExpiryAlerts.ps1` | Prüft Credentials und sendet Benachrichtigungen | Geplant (täglich) |

**Benötigte Graph-Berechtigungen:** `Application.Read.All`, `Mail.Send`

Weitere Details: [`app-registration-expiry-alerts/README.md`](app-registration-expiry-alerts/README.md)

---

### Entra ID Conditional Access – Tor Exit Nodes

**Verzeichnis:** `entra-conditional-access/`

Hält Entra ID **Conditional Access Named Locations** mit aktuellen Tor-Exit-Node-IP-Adressen (IPv4 + IPv6) synchron.

| Skript | Zweck | Ausführung |
|--------|-------|------------|
| `Initialize-NamedLocationAutomationIdentity.ps1` | Weist der Managed Identity die nötigen Microsoft Graph-Berechtigungen zu | Einmalig |
| `Invoke-TorExitNodesNamedLocation.ps1` | Aktualisiert die Named Locations mit aktuellen Tor-Exit-Nodes | Geplant (alle 3 h) |

**Benötigte Graph-Berechtigungen:** `Policy.ReadWrite.ConditionalAccess`, `Policy.Read.All`
**Datenquelle:** [enkidu-6/tor-relay-lists](https://github.com/Enkidu-6/tor-relay-lists)

Weitere Details: [`entra-conditional-access/readme.md`](entra-conditional-access/readme.md)

---

### Exchange Online – Delegate Access Sync

**Verzeichnis:** `exchange/delegate-access-sync/`

Synchronisiert **FullAccess-Berechtigungen** einer Delegate-Mailbox in Exchange Online anhand eines AD-Attributs (`extensionAttribute3`), das per Entra Connect synchronisiert wird.

| Phase | Logik |
|-------|-------|
| **GRANT** | Postfächer mit passendem Attributwert → FullAccess gewähren |
| **REVOKE** | Postfächer ohne Attributwert → FullAccess entziehen |

**Benötigte Exchange-Berechtigungen (Least Privilege):** `Get-Mailbox`, `Get-MailboxPermission`, `Add-MailboxPermission`, `Remove-MailboxPermission`

Weitere Details: [`exchange/delegate-access-sync/README.md`](exchange/delegate-access-sync/README.md)

---

## Voraussetzungen

- Azure Automation Account mit aktivierter **System-Managed Identity**
- PowerShell **7.x** Runtime
- Einmalige Berechtigungseinrichtung je Runbook (siehe jeweilige README)

---

## Lizenz

MIT – siehe [LICENSE](LICENSE)
