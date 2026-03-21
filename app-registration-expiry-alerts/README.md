# App Registration – Expiry Alerts

Prüft alle **App Registrations** und **Service Principals** im Entra ID-Mandanten auf ablaufende **Client Secrets** und **Zertifikate** und sendet Warnmeldungen über **Microsoft Teams** (Adaptive Card) und/oder **E-Mail** (HTML).

---

## Skripte

| Skript | Zweck | Ausführung |
|--------|-------|------------|
| `Initialize-AppExpiryAlertAutomationIdentity.ps1` | Weist der Managed Identity die nötigen Graph-Berechtigungen zu | Einmalig |
| `Invoke-AppRegistrationExpiryAlerts.ps1` | Prüft Credentials und sendet Benachrichtigungen | Geplant (täglich) |

---

## Funktionsweise

1. Verbindung zu Microsoft Graph per **System-Managed Identity**
2. Alle **App Registrations** (`/applications`) werden auf `passwordCredentials` (Secrets) und `keyCredentials` (Zertifikate) geprüft
3. Alle **Service Principals** mit Credentials, die **keine** lokale App Registration besitzen (externe/mandantenübergreifende Apps), werden ebenfalls geprüft
4. Credentials werden in vier Dringlichkeitsstufen eingeteilt:

| Stufe | Kriterium | Farbe |
|-------|-----------|-------|
| **ABGELAUFEN** | Ablaufdatum überschritten | 🔴 Rot |
| **KRITISCH** | ≤ 14 Tage | 🔴 Rot |
| **WARNUNG** | 15 – 30 Tage | 🟠 Orange |
| **HINWEIS** | 31 Tage – Schwellenwert | 🔵 Blau |

5. Wenn mindestens ein ablaufendes Credential gefunden wird:
   - **Teams**: Adaptive Card mit Zusammenfassung und Detailliste
   - **E-Mail**: HTML-E-Mail mit farbcodierter Tabelle (via Graph Mail API)
6. Werden keine ablaufenden Credentials gefunden, wird **keine** Benachrichtigung gesendet

---

## Benötigte Graph-Berechtigungen (Application)

| Berechtigung | Zweck |
|---|---|
| `Application.Read.All` | App Registrations und Service Principals lesen |
| `Mail.Send` | E-Mail über Graph API senden |

Die Berechtigungen werden mit `Initialize-AppExpiryAlertAutomationIdentity.ps1` einmalig zugewiesen.

---

## Automation-Variablen

Die Variablen werden im Azure Automation Account unter **Freigegebene Ressourcen → Variablen** angelegt.

### Erforderlich

| Variable | Typ | Beispielwert | Beschreibung |
|---|---|---|---|
| `ExpectedTenantId` | String | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` | Mandanten-ID als Sicherheitsprüfung |
| `AppExpiryAlertThresholdDays` | Integer | `60` | Vorwarnzeit in Tagen |

### Optional – Benachrichtigungskanäle

Mindestens ein Kanal muss konfiguriert sein. **Nicht angelegte Variablen** deaktivieren den jeweiligen Kanal automatisch – es ist kein leerer Platzhalter nötig.

| Variable | Typ | Beispielwert | Beschreibung |
|---|---|---|---|
| `AppExpiryTeamsWebhookUrl` | String | `https://…` | Teams Incoming-Webhook-URL |
| `AppExpiryAlertMailFrom` | String | `automation@contoso.com` | Absender-UPN für Graph-Mail |
| `AppExpiryAlertMailTo` | String | `it@contoso.com,admin@contoso.com` | Empfänger, kommagetrennt |

> Sind **beide** Kanäle konfiguriert, werden beide Benachrichtigungen gesendet.
> Ist **kein** Kanal konfiguriert, gibt das Runbook eine Warnung aus und läuft trotzdem durch.

---

## Teams-Webhook einrichten

Das Skript verwendet das moderne **Adaptive Card**-Format, das mit dem **Workflows**-Webhook in Teams kompatibel ist.

1. Teams-Kanal öffnen → **···** → **Workflows** → **Post to a channel when a webhook request is received**
2. Webhook-URL kopieren und in die Automation-Variable `AppExpiryTeamsWebhookUrl` eintragen

> **Hinweis:** Der veraltete Office 365 Connector (Legacy Incoming Webhook) wird von Microsoft seit 2024 schrittweise abgekündigt.

---

## E-Mail-Versand einrichten

Der Versand erfolgt über die **Microsoft Graph Mail API** (`POST /users/{from}/sendMail`).
Die Managed Identity benötigt dafür `Mail.Send` als Application Permission.

> Die `Mail.Send`-Berechtigung erlaubt der Managed Identity, im Namen **aller** Postfächer im Mandanten zu senden. Es empfiehlt sich, die Berechtigung per [App Access Policy](https://learn.microsoft.com/de-de/graph/auth-limit-mailbox-access) auf ein dediziertes Automationspostfach zu beschränken.

---

## Einmalige Einrichtung

```powershell
# 1. Automation Account anlegen, System-Managed Identity aktivieren

# 2. DisplayName des Automation Accounts in Initialize-*.ps1 anpassen:
#    $managedIdentity = Get-MgServicePrincipal -Filter "DisplayName eq 'aa-appexpiry'"

# 3. Berechtigungen zuweisen (als privilegierter Admin ausführen):
.\Initialize-AppExpiryAlertAutomationIdentity.ps1

# 4. Automation-Variablen im Portal anlegen (siehe Tabelle oben)

# 5. Runbook importieren: Invoke-AppRegistrationExpiryAlerts.ps1
#    Runtime: PowerShell 7.x
#    Module:  Microsoft.Graph.Authentication, Microsoft.Graph.Applications

# 6. Zeitplan einrichten (empfohlen: täglich 06:00 UTC)
```

---

## Beispiel-Ausgaben

### Teams (Adaptive Card)

```
⚠️  App Registration – Ablaufende Credentials
    Geprüft: 21.03.2026 06:00   |   3 Einträge (Schwellenwert: 60 Tage)

Zusammenfassung
  🔴 Kritisch (≤ 14 Tage):   1
  🟠 Warnung  (≤ 30 Tage):   1
  🔵 Hinweis  (≤ 60 Tage):   1

🔴  KRITISCH  (1 – 14 Tage)  (1)
  ───────────────────────────────────────
  MyWebApp                          7 Tage
  App Registration
  Typ:          Client Secret
  Name:         prod-secret
  Ablaufdatum:  28.03.2026
  App ID:       xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

### E-Mail

Die E-Mail enthält eine strukturierte HTML-Tabelle mit:
- Farbcodierter Zusammenfassung (Kacheln oben)
- Tabellenzeilen farbcodiert nach Dringlichkeit
- Status-Badge (ABGELAUFEN / KRITISCH / WARNUNG / HINWEIS)
- Hinweis auf den Erneuerungsweg im Azure-Portal

---

## Lizenz

MIT – siehe [LICENSE](../LICENSE)
