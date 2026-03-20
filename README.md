# azure-automation

PowerShell Runbooks für **Azure Automation** – entwickelt von Stefan Redlin / Vater Business IT GmbH.

Alle Skripte nutzen ausschließlich **System-Managed Identity** (keine gespeicherten Credentials) und folgen dem Prinzip der minimalen Rechte (Least Privilege).

---

## Inhalt

```
azure-automation/
├── entra-conditional-access/
│   ├── Initialize-NamedLocationAutomationIdentity.ps1   # Einmalige Berechtigungseinrichtung
│   └── Invoke-TorExitNodesNamedLocation.ps1             # Runbook: Tor Exit Nodes aktuell halten
│
├── exchange/
│   └── delegate-access-sync/
│       └── Sync-DelegateAccessByAttribute.ps1           # Runbook: FullAccess per AD-Attribut steuern
│
└── entra-seamless-sso/
    ├── Initialize-HybridWorker.ps1                      # Einmalige Hybrid Worker Group Einrichtung
    └── Reset-KerberosSSO.ps1                            # Runbook: Kerberos Key monatlich rotieren
```

---

## Runbooks

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

### Kerberos Key Rollover – Seamless SSO

**Verzeichnis:** `entra-seamless-sso/`

Rotiert den **Kerberos Decryption Key** des `AZUREADSSOACC`-Kontos für Entra ID Seamless SSO monatlich via Hybrid Runbook Worker.

| Skript | Zweck | Ausführung |
|--------|-------|------------|
| `Initialize-HybridWorker.ps1` | Richtet Hybrid Worker Group ein | Einmalig (lokal, als Admin) |
| `Reset-KerberosSSO.ps1` | Rotiert den Kerberos Decryption Key | Monatlich (Hybrid Worker) |

**Benötigte Credential Assets:** `AADSSOOnPremCredential` (AD Enterprise/Domain Admin), `AADSSOCloudCredential` (Entra Global Admin)
**Ausführungsort:** Extension-based Hybrid Runbook Worker auf dem Entra Connect Server

> Hinweis: Agent-based Hybrid Worker ist seit 31.08.2024 EOL (Abschaltung 01.04.2025).

Weitere Details: [`entra-seamless-sso/README.md`](entra-seamless-sso/README.md)

---

## Voraussetzungen

- Azure Automation Account mit aktivierter **System-Managed Identity**
- PowerShell **7.x** Runtime
- Einmalige Berechtigungseinrichtung je Runbook (siehe jeweilige README)

---

## Lizenz

MIT – siehe [LICENSE](LICENSE)
