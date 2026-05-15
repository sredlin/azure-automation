# aa-mrm – Azure Automation Runbook

## Übersicht

Dieses Runbook ermittelt alle Nutzer mit einer **Microsoft 365 Frontline Worker**-Lizenz (F1/F3) und weist ihnen automatisch die Exchange **Retention Policy "F3 Mailbox Cleanup 12M"** zu. Bereits korrekt konfigurierte Mailboxen werden nicht verändert (idempotent).

---

## Komponenten

| Datei | Beschreibung |
|---|---|
| `Invoke-MRMPolicy.ps1` | Hauptrunbook: Lizenzermittlung + Retention Policy Zuweisung |
| `Initialize-MRMAutomationIdentity.ps1` | Einmaliges Setup: Berechtigungen für die Managed Identity |
| `README.md` | Diese Datei |

---

## Voraussetzungen

### Azure Automation Account
- Name: `aa-mrm`
- System-Assigned **Managed Identity** aktiviert

### Module (im Automation Account installiert)
| Modul | Mindestversion |
|---|---|
| `Microsoft.Graph.Authentication` | 2.x |
| `Microsoft.Graph.Users` | 2.x |
| `Microsoft.Graph.Identity.DirectoryManagement` | 2.x |
| `ExchangeOnlineManagement` | 3.x |

### Berechtigungen
Die Managed Identity benötigt folgende Berechtigungen:

**Microsoft Graph (Application)**
| Berechtigung | Zweck |
|---|---|
| `User.Read.All` | Lizenzierte Nutzer abrufen |
| `Organization.Read.All` | Tenant Domain + SKU-Informationen |

**Exchange Online**
| Berechtigung | Typ | Zweck |
|---|---|---|
| `Exchange.ManageAsApp` | Entra App Role | Exchange-Zugriff per Managed Identity |
| `Mail Recipients` | Exchange Management Role | `Get-Mailbox` / `Set-Mailbox` |

---

## Onboarding

Das Skript `Initialize-MRMAutomationIdentity.ps1` richtet alle Berechtigungen **idempotent** ein. Es kann beliebig oft ausgeführt werden – bereits vorhandene Zuweisungen werden übersprungen.

**Ausführen als:** Global Admin oder Privileged Role Admin  
**Empfohlene Umgebung:** Azure Cloud Shell (PowerShell)

```powershell
.\Initialize-MRMAutomationIdentity.ps1
```

Das Skript ermittelt Object ID der Managed Identity und Tenant Domain automatisch anhand des Automation Account-Namens (`aa-mrm`).

> **Hinweis:** Nach dem Onboarding 5–10 Minuten warten, bevor das Runbook getestet wird. Berechtigungen propagieren nicht sofort.

---

## Ablauf Runbook

```
1. Connect-MgGraph (Managed Identity)
       │
2. Tenant Domain automatisch ermitteln
       │
3. SKU-IDs für SPE_F1 / DESKLESSPACK abrufen
       │
4. Alle lizenzierten Nutzer per Graph-Filter abrufen
       │
5. Lizenz-Auswertung ausgeben (pro SKU + Gesamt)
       │
6. Disconnect-MgGraph
       │
7. Connect-ExchangeOnline (Managed Identity)
       │
8. Pro Nutzer:
   ├── Keine Mailbox → Warning + überspringen
   ├── Policy bereits gesetzt → [SKIP]
   └── Policy zuweisen → [OK] / [FEHLER]
       │
9. Zusammenfassung ausgeben
       │
10. Disconnect-ExchangeOnline
```

---

## Konfiguration

Alle anpassbaren Parameter befinden sich im Konfigurationsblock am Anfang von `Invoke-MRMPolicy.ps1`:

```powershell
$targetSkuPartNumbers = @("SPE_F1", "DESKLESSPACK")
$retentionPolicyName  = "F3 Mailbox Cleanup 12M"
```

---

## Ausgabe-Beispiel

```
✔ Verbunden mit Microsoft Graph (Managed Identity)
Tenant Domain: contoso.onmicrosoft.com
Gefundene SKU-IDs: xxxxxxxx-..., yyyyyyyy-...

══════════════════════════════════════════
 Lizenz-Auswertung: F3 / Frontline Worker
══════════════════════════════════════════
  SPE_F1      (...): 42 Nutzer
  DESKLESSPACK(...): 18 Nutzer
──────────────────────────────────────────
  GESAMT lizenzierte Nutzer : 60
══════════════════════════════════════════
✔ Graph-Verbindung getrennt

✔ Verbunden mit Exchange Online (Managed Identity)

══════════════════════════════════════════
 Retention Policy Zuweisung
══════════════════════════════════════════
  [OK]      max.mustermann@contoso.com – Richtlinie zugewiesen
  [SKIP]    erika.muster@contoso.com – Richtlinie bereits zugewiesen
  [WARN]    kein.postfach@contoso.com – Keine Mailbox gefunden
──────────────────────────────────────────
  Neu zugewiesen  : 41
  Bereits gesetzt : 18
  Übersprungen    : 1
══════════════════════════════════════════
✔ Exchange Online-Verbindung getrennt
```

---

## Fehlerbehebung

| Fehler | Ursache | Lösung |
|---|---|---|
| `UnAuthorized` bei `Connect-ExchangeOnline` | `Exchange.ManageAsApp` fehlt oder noch nicht propagiert | Onboarding prüfen, 10 Min. warten |
| `Keine Mailbox gefunden` | Nutzer hat keine Exchange-Mailbox (z. B. nur Teams) | Erwartetes Verhalten, kein Handlungsbedarf |
| `Keine SKUs gefunden` | Tenant hat keine F1/F3-Lizenzen | `$targetSkuPartNumbers` prüfen |
| `RetentionPolicy not found` | Policy existiert nicht in Exchange | Policy-Namen prüfen: `Get-RetentionPolicy` |

---

## Zeitplanung (empfohlen)

Das Runbook kann als **wiederkehrender Schedule** im Automation Account eingerichtet werden, z. B. wöchentlich, um neu lizenzierte Nutzer automatisch zu erfassen.

```
Automation Account → Runbooks → Invoke-MRMPolicy → Schedules → Link to schedule
```
