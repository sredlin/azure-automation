#Requires -Version 7
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications

<#
.SYNOPSIS
    Prüft alle App Registrations und Service Principals auf ablaufende
    Client Secrets und Zertifikate und sendet Warnmeldungen per Teams-Webhook
    und/oder E-Mail.

.DESCRIPTION
    Das Skript verbindet sich per Managed Identity mit Microsoft Graph,
    liest alle App Registrations und überprüft deren passwordCredentials
    (Secrets) und keyCredentials (Zertifikate) auf bevorstehende Ablaufdaten.

    Credentials werden in vier Dringlichkeitsstufen eingeteilt:
      - ABGELAUFEN  : Ablaufdatum bereits überschritten
      - KRITISCH    : läuft innerhalb von 14 Tagen ab
      - WARNUNG     : läuft innerhalb von 30 Tagen ab
      - HINWEIS     : läuft innerhalb des konfigurierten Schwellenwerts ab

    Benachrichtigungskanäle:
      - Microsoft Teams  (Adaptive Card via Incoming Webhook)
      - E-Mail           (HTML-formatiert via Microsoft Graph Mail API)

    Werden keine ablaufenden Credentials gefunden, wird keine
    Benachrichtigung gesendet.

.NOTES
    Author:          Stefan Redlin
    Graph-Berechtigungen (Application):
      Application.Read.All    – App Registrations lesen
      Organization.Read.All   – Mandantenname auslesen (optional, für Anzeige)
      Mail.Send               – E-Mail versenden

    Automation-Variablen:
      Erforderlich:
        ExpectedTenantId              – Mandanten-ID zur Sicherheitsprüfung
        AppExpiryAlertThresholdDays   – Vorwarnung in Tagen (z. B. 60)
      Optional (mindestens eine Gruppe muss gesetzt sein):
        AppExpiryTeamsWebhookUrl      – Teams Incoming-Webhook-URL
        AppExpiryAlertMailFrom        – Absender-UPN für Graph-Mail
        AppExpiryAlertMailTo          – Empfänger, kommagetrennt

    Nicht angelegte optionale Variablen deaktivieren den jeweiligen Kanal.
    Leere Strings haben denselben Effekt.
#>

### Microsoft Graph verbinden ###
try {
    Connect-MgGraph -Identity -NoWelcome -ErrorAction Stop
}
catch {
    throw "Verbindung zu Microsoft Graph (Managed Identity) fehlgeschlagen. $_"
}

### Automation-Variablen einlesen ###

# Erforderliche Variablen – fehlen sie, bricht das Runbook sofort ab.
try {
    $ExpectedTenantId = Get-AutomationVariable -Name 'ExpectedTenantId'                -ErrorAction Stop
    $ThresholdDays    = [int](Get-AutomationVariable -Name 'AppExpiryAlertThresholdDays' -ErrorAction Stop)
}
catch {
    throw "Fehler beim Lesen der erforderlichen Automation-Variablen. $_"
}

# Optionale Variablen – nicht vorhandene oder leere Variablen deaktivieren
# den jeweiligen Benachrichtigungskanal, ohne das Runbook abzubrechen.
function Get-OptionalAutomationVariable {
    param([string]$Name)
    try   { Get-AutomationVariable -Name $Name -ErrorAction Stop }
    catch { '' }
}

$TeamsWebhookUrl = Get-OptionalAutomationVariable 'AppExpiryTeamsWebhookUrl'
$AlertMailFrom   = Get-OptionalAutomationVariable 'AlertMailFrom'
$AlertMailTo     = Get-OptionalAutomationVariable 'AlertMailTo'

###############################################################################
# Hilfsfunktionen
###############################################################################

function Confirm-MgTenantContext {
    <#
    .SYNOPSIS
        Prüft den aktiven Microsoft Graph-Mandantenkontext.

    .PARAMETER SkipTenantConfirmation
        Unterdrückt die interaktive Bestätigungsabfrage (für Automation).

    .PARAMETER ExpectedTenantId
        Erwartet TenantId – bricht ab, wenn der verbundene Mandant abweicht.

    .NOTES
        Author: Stefan Redlin
    #>
    [CmdletBinding()]
    param(
        [switch]$SkipTenantConfirmation,
        [string]$ExpectedTenantId
    )

    $ctx = Get-MgContext
    if (-not $ctx) {
        throw "Kein Microsoft Graph-Kontext gefunden. Bitte zuerst Connect-MgGraph ausführen."
    }

    if ($ExpectedTenantId -and ($ctx.TenantId -ne $ExpectedTenantId)) {
        throw "Mandantenkontext stimmt nicht überein. Erwartet '$ExpectedTenantId', verbunden mit '$($ctx.TenantId)'."
    }

    $identity = if ($ctx.Account) { "Account '$($ctx.Account)'" } else { "Managed Identity" }
    Write-Output "Verbunden als $identity mit Mandant '$($ctx.TenantId)' (Umgebung: $($ctx.Environment))."

    if (-not $SkipTenantConfirmation) {
        $answer = Read-Host "Ist dies der richtige Mandant? Mit 'Y' bestätigen"
        if ($answer -ne 'Y') {
            throw "Abgebrochen. Mandantenkontext nicht bestätigt."
        }
    }
}

function Get-ExpiringCredentials {
    <#
    .SYNOPSIS
        Gibt alle Credentials zurück, die innerhalb des Schwellenwerts ablaufen,

    .DESCRIPTION
        Prüft alle App Registrations des eigenen Mandanten.
        Credentials ohne Ablaufdatum werden übersprungen.

    .PARAMETER ThresholdDays
        Anzahl Tage bis zum Ablaufdatum, ab der gewarnt wird.

    .OUTPUTS
        PSCustomObject[] – sortiert nach DaysLeft (aufsteigend)

    .NOTES
        Author: Stefan Redlin
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$ThresholdDays
    )

    $now     = Get-Date
    $cutoff  = $now.AddDays($ThresholdDays)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    ### App Registrations ###
    Write-Output "Lese App Registrations..."
    try {
        $apps = Get-MgApplication -All `
            -Property 'id,displayName,appId,passwordCredentials,keyCredentials' `
            -ErrorAction Stop
    }
    catch {
        throw "App Registrations konnten nicht gelesen werden. $_"
    }

    Write-Output "  $($apps.Count) App Registration(s) gefunden."

    foreach ($app in $apps) {
        if ([string]::IsNullOrEmpty($app.Id)) { continue }

        foreach ($secret in $app.PasswordCredentials) {
            if ($null -eq $secret)                { continue }
            if (-not $secret.KeyId)               { continue }   # leeres SDK-Objekt
            if (-not $secret.EndDateTime)         { continue }
            if ($secret.EndDateTime -gt $cutoff)  { continue }

            $daysLeft = [math]::Floor(($secret.EndDateTime - $now).TotalDays)
            $results.Add([PSCustomObject]@{
                Source         = 'App Registration'
                AppName        = $app.DisplayName
                AppId          = $app.AppId
                ObjectId       = $app.Id
                CredentialType = 'Client Secret'
                CredentialName = if ($secret.DisplayName) { $secret.DisplayName } else { '(kein Name)' }
                KeyId          = $secret.KeyId
                ExpiryDate     = $secret.EndDateTime
                DaysLeft       = $daysLeft
            })
        }

        foreach ($cert in $app.KeyCredentials) {
            if ($null -eq $cert)              { continue }
            if (-not $cert.KeyId)             { continue }   # leeres SDK-Objekt
            if (-not $cert.EndDateTime)       { continue }
            if ($cert.EndDateTime -gt $cutoff){ continue }

            $daysLeft = [math]::Floor(($cert.EndDateTime - $now).TotalDays)
            $results.Add([PSCustomObject]@{
                Source         = 'App Registration'
                AppName        = $app.DisplayName
                AppId          = $app.AppId
                ObjectId       = $app.Id
                CredentialType = 'Zertifikat'
                CredentialName = if ($cert.DisplayName) { $cert.DisplayName } else { '(kein Name)' }
                KeyId          = $cert.KeyId
                ExpiryDate     = $cert.EndDateTime
                DaysLeft       = $daysLeft
            })
        }
    }

    return ($results | Where-Object { $_.CredentialType -and $null -ne $_.DaysLeft } | Sort-Object DaysLeft)
}

function New-TeamsAlertCard {
    <#
    .SYNOPSIS
        Erstellt eine Teams-Adaptive-Card-Payload für den Incoming Webhook.

    .PARAMETER Items
        Liste der ablaufenden Credentials.

    .PARAMETER ThresholdDays
        Konfigurierter Schwellenwert (nur für die Anzeige).

    .OUTPUTS
        Hashtable – JSON-serialisierbare Struktur für den Webhook-Aufruf.

    .NOTES
        Kompatibel mit dem modernen Teams-Workflows-Webhook (Adaptive Card 1.5).
        Author: Stefan Redlin
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [PSCustomObject[]]$Items,
        [Parameter(Mandatory)] [int]$ThresholdDays
    )

    $dateStr  = (Get-Date).ToString('dd.MM.yyyy  HH:mm')
    $expired  = @($Items | Where-Object { $_.DaysLeft -le 0 })
    $critical = @($Items | Where-Object { $_.DaysLeft -gt 0  -and $_.DaysLeft -le 14 })
    $warning  = @($Items | Where-Object { $_.DaysLeft -gt 14 -and $_.DaysLeft -le 30 })
    $info     = @($Items | Where-Object { $_.DaysLeft -gt 30 })

    $headerStyle = if ($expired.Count -gt 0 -or $critical.Count -gt 0) { 'attention' }
                   elseif ($warning.Count -gt 0)                        { 'warning'   }
                   else                                                  { 'accent'    }

    $cardBody = [System.Collections.Generic.List[object]]::new()

    # ── Header ────────────────────────────────────────────────────────────────
    $cardBody.Add(@{
        type  = 'Container'
        style = $headerStyle
        bleed = $true
        items = @(
            @{
                type    = 'ColumnSet'
                columns = @(
                    @{
                        type  = 'Column'
                        width = 'auto'
                        items = @(
                            @{ type = 'TextBlock'; text = '⚠️'; size = 'ExtraLarge' }
                        )
                    },
                    @{
                        type  = 'Column'
                        width = 'stretch'
                        items = @(
                            @{
                                type   = 'TextBlock'
                                text   = 'App Registration – Ablaufende Credentials'
                                weight = 'Bolder'
                                size   = 'Large'
                                wrap   = $true
                                color  = 'Light'
                            },
                            @{
                                type     = 'TextBlock'
                                text     = "Geprüft: $dateStr   |   $($Items.Count) Einträge (Schwellenwert: $ThresholdDays Tage)"
                                isSubtle = $true
                                size     = 'Small'
                                wrap     = $true
                                color    = 'Light'
                            }
                        )
                    }
                )
            }
        )
    })

    # ── Zusammenfassung ────────────────────────────────────────────────────────
    $summaryFacts = [System.Collections.Generic.List[object]]::new()
    if ($expired.Count  -gt 0) { $summaryFacts.Add(@{ title = '🔴 Abgelaufen:'; value = "$($expired.Count)" }) }
    if ($critical.Count -gt 0) { $summaryFacts.Add(@{ title = '🔴 Kritisch (≤ 14 Tage):'; value = "$($critical.Count)" }) }
    if ($warning.Count  -gt 0) { $summaryFacts.Add(@{ title = '🟠 Warnung (≤ 30 Tage):';  value = "$($warning.Count)" }) }
    if ($info.Count     -gt 0) { $summaryFacts.Add(@{ title = "🔵 Hinweis (≤ $ThresholdDays Tage):"; value = "$($info.Count)" }) }

    $cardBody.Add(@{
        type      = 'Container'
        separator = $true
        spacing   = 'Medium'
        items     = @(
            @{ type = 'TextBlock'; text = 'Zusammenfassung'; weight = 'Bolder'; size = 'Medium' },
            @{ type = 'FactSet'; facts = @($summaryFacts) }
        )
    })

    # ── Einträge pro Gruppe ────────────────────────────────────────────────────
    function Add-CredentialGroup {
        param(
            [PSCustomObject[]]$GroupItems,
            [string]$Label,
            [string]$Color
        )
        if (-not $GroupItems -or $GroupItems.Count -eq 0) { return }

        $section = @{
            type      = 'Container'
            separator = $true
            spacing   = 'Medium'
            items     = [System.Collections.Generic.List[object]]::new()
        }

        $section.items.Add(@{
            type    = 'TextBlock'
            text    = "$Label  ($($GroupItems.Count))"
            weight  = 'Bolder'
            color   = $Color
            size    = 'Medium'
            spacing = 'None'
        })

        foreach ($item in $GroupItems) {
            $expiryStr   = $item.ExpiryDate.ToString('dd.MM.yyyy')
            $daysLeftStr = if ($item.DaysLeft -le 0) {
                               "ABGELAUFEN  (seit $([Math]::Abs($item.DaysLeft)) Tag$(if([Math]::Abs($item.DaysLeft)-ne1){'en'}))"
                           } else {
                               "$($item.DaysLeft) Tag$(if($item.DaysLeft -ne 1){'e'})"
                           }

            $section.items.Add(@{
                type      = 'Container'
                separator = $true
                spacing   = 'Small'
                items     = @(
                    @{
                        type    = 'ColumnSet'
                        spacing = 'Small'
                        columns = @(
                            @{
                                type  = 'Column'
                                width = 'stretch'
                                items = @(
                                    @{ type = 'TextBlock'; text = $item.AppName; weight = 'Bolder'; wrap = $true },
                                    @{ type = 'TextBlock'; text = $item.Source; isSubtle = $true; size = 'Small'; spacing = 'None' }
                                )
                            },
                            @{
                                type                     = 'Column'
                                width                    = 'auto'
                                verticalContentAlignment = 'Center'
                                items                    = @(
                                    @{ type = 'TextBlock'; text = $daysLeftStr; color = $Color; weight = 'Bolder'; horizontalAlignment = 'Right' }
                                )
                            }
                        )
                    },
                    @{
                        type    = 'FactSet'
                        spacing = 'Small'
                        facts   = @(
                            @{ title = 'Typ:';         value = $item.CredentialType }
                            @{ title = 'Name:';        value = $item.CredentialName }
                            @{ title = 'Ablaufdatum:'; value = $expiryStr }
                            @{ title = 'App ID:';      value = $item.AppId }
                        )
                    }
                )
            })
        }

        $cardBody.Add($section)
    }

    Add-CredentialGroup -GroupItems $expired  -Label '🔴  ABGELAUFEN'                     -Color 'Attention'
    Add-CredentialGroup -GroupItems $critical -Label '🔴  KRITISCH  (1 – 14 Tage)'         -Color 'Attention'
    Add-CredentialGroup -GroupItems $warning  -Label '🟠  WARNUNG  (15 – 30 Tage)'         -Color 'Warning'
    Add-CredentialGroup -GroupItems $info     -Label "🔵  HINWEIS  (31 – $ThresholdDays Tage)" -Color 'Accent'

    # ── Legende ───────────────────────────────────────────────────────────────
    $cardBody.Add(@{
        type      = 'Container'
        separator = $true
        spacing   = 'Small'
        items     = @(
            @{
                type     = 'TextBlock'
                text     = "🔴 ABGELAUFEN: überschritten  |  🔴 KRITISCH: ≤ 14 Tage  |  🟠 WARNUNG: ≤ 30 Tage  |  🔵 HINWEIS: ≤ $ThresholdDays Tage"
                isSubtle = $true
                size     = 'Small'
                wrap     = $true
            }
        )
    })

    $card = @{
        type      = 'AdaptiveCard'
        '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'
        version   = '1.5'
        msteams   = @{ width = 'Full' }
        body      = @($cardBody)
    }

    return @{
        type        = 'message'
        attachments = @(
            @{
                contentType = 'application/vnd.microsoft.card.adaptive'
                contentUrl  = $null
                content     = $card
            }
        )
    }
}

function Send-TeamsAlert {
    <#
    .SYNOPSIS
        Sendet die Adaptive Card an den konfigurierten Teams-Webhook.

    .NOTES
        Author: Stefan Redlin
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [PSCustomObject[]]$Items,
        [Parameter(Mandatory)] [int]$ThresholdDays,
        [Parameter(Mandatory)] [string]$WebhookUrl
    )

    $payload = New-TeamsAlertCard -Items $Items -ThresholdDays $ThresholdDays |
               ConvertTo-Json -Depth 20 -Compress

    try {
        $null = Invoke-RestMethod `
            -Method      Post `
            -Uri         $WebhookUrl `
            -Body        $payload `
            -ContentType 'application/json; charset=utf-8' `
            -ErrorAction Stop
        Write-Output "Teams-Benachrichtigung erfolgreich gesendet."
    }
    catch {
        Write-Error "Teams-Benachrichtigung fehlgeschlagen. $_"
    }
}

function New-HtmlMailBody {
    <#
    .SYNOPSIS
        Erstellt den HTML-Körper für die E-Mail-Benachrichtigung.

    .NOTES
        Author: Stefan Redlin
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [PSCustomObject[]]$Items,
        [Parameter(Mandatory)] [int]$ThresholdDays,
        [string]$TenantName = '',
        [string]$TenantId   = ''
    )

    $dateStr  = (Get-Date).ToString('dd.MM.yyyy  HH:mm')
    $expired  = @($Items | Where-Object { $_.DaysLeft -le 0 })
    $critical = @($Items | Where-Object { $_.DaysLeft -gt 0  -and $_.DaysLeft -le 14 })
    $warning  = @($Items | Where-Object { $_.DaysLeft -gt 14 -and $_.DaysLeft -le 30 })
    $info     = @($Items | Where-Object { $_.DaysLeft -gt 30 })

    $tenantLine = if ($TenantName -or $TenantId) {
        $parts = @()
        if ($TenantName) { $parts += [System.Net.WebUtility]::HtmlEncode($TenantName) }
        if ($TenantId)   { $parts += "<span style='font-family:Consolas,monospace;font-size:11px;opacity:.75;'>$TenantId</span>" }
        $parts -join '&nbsp;&nbsp;<span style=''opacity:.4;''>&middot;</span>&nbsp;&nbsp;'
    } else { '' }

    # Vater IT CI: Dark Navy #06263F | Blue #0F436A | Mint #1AF0C5
    function Get-AccentColor ([int]$d) {
        if ($d -le 0)  { return '#b91c1c' }
        if ($d -le 14) { return '#c2410c' }
        if ($d -le 30) { return '#b45309' }
        return '#1AF0C5'
    }

    function Get-BadgeHtml ([int]$d) {
        if ($d -le 0)  { return "<span style='display:inline-block;background:#fef2f2;color:#b91c1c;border:1px solid #fecaca;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:.4px;white-space:nowrap;'>ABGELAUFEN</span>" }
        if ($d -le 14) { return "<span style='display:inline-block;background:#fff7ed;color:#c2410c;border:1px solid #fed7aa;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:.4px;white-space:nowrap;'>KRITISCH</span>" }
        if ($d -le 30) { return "<span style='display:inline-block;background:#fffbeb;color:#b45309;border:1px solid #fde68a;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:.4px;white-space:nowrap;'>WARNUNG</span>" }
        return "<span style='display:inline-block;background:#06263F;color:#1AF0C5;border:1px solid #0F436A;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:.4px;white-space:nowrap;'>HINWEIS</span>"
    }

    function Get-DaysText ([int]$d) {
        if ($d -le 0) { return "vor $([Math]::Abs($d)) Tag$(if([Math]::Abs($d)-ne1){'en'})" }
        return "in $d Tag$(if($d -ne 1){'en'})"
    }

    $tableRows = foreach ($item in $Items | Sort-Object DaysLeft) {
        $accent    = Get-AccentColor $item.DaysLeft
        $badge     = Get-BadgeHtml   $item.DaysLeft
        $daysText  = Get-DaysText    $item.DaysLeft
        $expiry    = if ($item.ExpiryDate) { $item.ExpiryDate.ToString('dd.MM.yyyy') } else { 'Unbekannt' }
        $appName   = [System.Net.WebUtility]::HtmlEncode($item.AppName)
        $credName  = [System.Net.WebUtility]::HtmlEncode($item.CredentialName)
        $credType  = [System.Net.WebUtility]::HtmlEncode($item.CredentialType)
        $source    = [System.Net.WebUtility]::HtmlEncode($item.Source)
        $appId     = [System.Net.WebUtility]::HtmlEncode($item.AppId)

        @"
        <tr>
          <td style="padding:11px 14px 11px 16px;border-bottom:1px solid #edf0f3;font-weight:600;color:#06263F;border-left:3px solid $accent;">$appName</td>
          <td style="padding:11px 14px;border-bottom:1px solid #edf0f3;color:#6b7280;font-size:12px;">$source</td>
          <td style="padding:11px 14px;border-bottom:1px solid #edf0f3;color:#374151;">$credType</td>
          <td style="padding:11px 14px;border-bottom:1px solid #edf0f3;color:#374151;max-width:220px;word-break:break-all;">$credName</td>
          <td style="padding:11px 14px;border-bottom:1px solid #edf0f3;font-family:Consolas,monospace;font-size:11px;color:#6b7280;">$appId</td>
          <td style="padding:11px 14px;border-bottom:1px solid #edf0f3;white-space:nowrap;color:#374151;">$expiry</td>
          <td style="padding:11px 14px;border-bottom:1px solid #edf0f3;white-space:nowrap;color:$accent;font-weight:600;">$daysText</td>
          <td style="padding:11px 14px;border-bottom:1px solid #edf0f3;text-align:center;">$badge</td>
        </tr>
"@
    }

    function summaryBlock ([int]$count, [string]$label, [string]$accent) {
        if ($count -eq 0) { return '' }
        return @"
    <div style="display:flex;align-items:center;gap:12px;padding:12px 20px;border-radius:8px;background:#fff;border:1px solid #e5e7eb;border-left:4px solid $accent;min-width:120px;">
      <span style="font-size:28px;font-weight:800;color:$accent;line-height:1;">$count</span>
      <span style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.6px;color:#6b7280;">$label</span>
    </div>
"@
    }

    $summaryHtml  = summaryBlock $expired.Count  'Abgelaufen' '#b91c1c'
    $summaryHtml += summaryBlock $critical.Count 'Kritisch'   '#c2410c'
    $summaryHtml += summaryBlock $warning.Count  'Warnung'    '#b45309'
    $summaryHtml += summaryBlock $info.Count     'Hinweis'    '#1AF0C5'

    return @"
<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body style="margin:0;padding:0;background:#eef1f5;font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#1f2937;">
<div style="max-width:1000px;margin:32px auto;background:#fff;border-radius:10px;box-shadow:0 4px 24px rgba(6,38,63,.12);overflow:hidden;">

  <!-- Header – immer Dark Navy, kein dynamisches Rot -->
  <div style="background:#06263F;padding:24px 32px;display:flex;align-items:center;gap:24px;">
    <div style="flex:1;">
      <div style="font-size:9px;font-weight:700;letter-spacing:3px;text-transform:uppercase;color:#1AF0C5;margin-bottom:6px;">Azure Automation</div>
      <div style="font-size:22px;font-weight:700;color:#fff;margin-bottom:5px;line-height:1.2;">App Registration<br><span style="color:#1AF0C5;">Ablaufende Credentials</span></div>
      <div style="font-size:12px;color:#7fa8c4;margin-top:8px;">
        $dateStr &nbsp;&nbsp;|&nbsp;&nbsp; Schwellenwert: $ThresholdDays Tage &nbsp;&nbsp;|&nbsp;&nbsp; $($Items.Count) Einträge
      </div>
      $(if ($tenantLine) { "<div style='margin-top:10px;padding-top:10px;border-top:1px solid rgba(255,255,255,.12);font-size:12px;color:#aac4d8;'>Mandant:&nbsp;&nbsp;$tenantLine</div>" })
    </div>
    <!-- Wortmarke inline SVG -->
    <div style="flex-shrink:0;">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 80" width="140" height="56" aria-label="vater IT">
        <g transform="translate(0,4) scale(0.78)">
          <rect x="0"  y="16" width="20" height="20" fill="none" stroke="#fff" stroke-width="2" transform="rotate(45 10 26)"/>
          <rect x="22" y="16" width="20" height="20" fill="#fff" opacity=".9" transform="rotate(45 32 26)"/>
          <rect x="11" y="32" width="20" height="20" fill="#fff" opacity=".7" transform="rotate(45 21 42)"/>
          <rect x="33" y="0"  width="20" height="20" fill="#1AF0C5" transform="rotate(45 43 10)"/>
        </g>
        <text x="62" y="38" font-family="Segoe UI,Arial,sans-serif" font-size="30" font-weight="700" fill="#fff">vater</text>
        <text x="62" y="62" font-family="Segoe UI,Arial,sans-serif" font-size="20" font-weight="800" fill="#1AF0C5" letter-spacing="4">IT</text>
      </svg>
    </div>
  </div>

  <!-- Mint-Akzentlinie -->
  <div style="height:3px;background:linear-gradient(90deg,#1AF0C5 0%,#0F436A 100%);"></div>

  <!-- Zusammenfassung -->
  <div style="display:flex;gap:12px;flex-wrap:wrap;padding:20px 32px;background:#f8f9fb;border-bottom:1px solid #e5e7eb;">
$summaryHtml
  </div>

  <!-- Tabelle -->
  <div style="padding:24px 32px 32px;">
    <table style="width:100%;border-collapse:collapse;font-size:13px;">
      <thead>
        <tr style="background:#0F436A;color:#fff;">
          <th style="padding:11px 16px;text-align:left;font-weight:600;font-size:12px;letter-spacing:.3px;border-bottom:2px solid #06263F;white-space:nowrap;">Anwendung</th>
          <th style="padding:11px 14px;text-align:left;font-weight:600;font-size:12px;letter-spacing:.3px;border-bottom:2px solid #06263F;white-space:nowrap;">Quelle</th>
          <th style="padding:11px 14px;text-align:left;font-weight:600;font-size:12px;letter-spacing:.3px;border-bottom:2px solid #06263F;white-space:nowrap;">Typ</th>
          <th style="padding:11px 14px;text-align:left;font-weight:600;font-size:12px;letter-spacing:.3px;border-bottom:2px solid #06263F;white-space:nowrap;">Name / Beschreibung</th>
          <th style="padding:11px 14px;text-align:left;font-weight:600;font-size:12px;letter-spacing:.3px;border-bottom:2px solid #06263F;white-space:nowrap;">App ID</th>
          <th style="padding:11px 14px;text-align:left;font-weight:600;font-size:12px;letter-spacing:.3px;border-bottom:2px solid #06263F;white-space:nowrap;">Ablaufdatum</th>
          <th style="padding:11px 14px;text-align:left;font-weight:600;font-size:12px;letter-spacing:.3px;border-bottom:2px solid #06263F;white-space:nowrap;">Verbleibend</th>
          <th style="padding:11px 14px;text-align:center;font-weight:600;font-size:12px;letter-spacing:.3px;border-bottom:2px solid #1AF0C5;white-space:nowrap;color:#1AF0C5;">Status</th>
        </tr>
      </thead>
      <tbody>
$($tableRows -join '')
      </tbody>
    </table>
  </div>

  <!-- Legende -->
  <div style="padding:12px 32px 16px;background:#f8f9fb;border-top:1px solid #e5e7eb;font-size:11px;color:#6b7280;">
    <span style="font-weight:600;color:#374151;">Dringlichkeitsstufen:&nbsp;&nbsp;</span>
    <span style="margin-right:14px;"><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#b91c1c;margin-right:4px;vertical-align:middle;"></span>ABGELAUFEN – Ablaufdatum überschritten</span>
    <span style="margin-right:14px;"><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#c2410c;margin-right:4px;vertical-align:middle;"></span>KRITISCH – innerhalb von 14 Tagen</span>
    <span style="margin-right:14px;"><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#b45309;margin-right:4px;vertical-align:middle;"></span>WARNUNG – innerhalb von 30 Tagen</span>
    <span><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#1AF0C5;margin-right:4px;vertical-align:middle;"></span>HINWEIS – innerhalb von $ThresholdDays Tagen</span>
  </div>

  <!-- Footer -->
  <div style="padding:16px 32px;background:#06263F;font-size:12px;color:#7fa8c4;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">
    <span>Generiert von <strong style="color:#1AF0C5;">Azure Automation</strong> &nbsp;&middot;&nbsp; Vater Business IT GmbH</span>
    <span style="color:#4a7a9b;">Entra ID &rarr; App-Registrierungen &rarr; Zertifikate &amp; Geheimnisse</span>
  </div>

</div>
</body>
</html>
"@
}

function Send-MailAlert {
    <#
    .SYNOPSIS
        Sendet die HTML-E-Mail über die Microsoft Graph Mail API.

    .NOTES
        Erfordert Mail.Send-Berechtigung für die Managed Identity.
        Author: Stefan Redlin
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [PSCustomObject[]]$Items,
        [Parameter(Mandatory)] [int]$ThresholdDays,
        [Parameter(Mandatory)] [string]$From,
        [Parameter(Mandatory)] [string[]]$To,
        [string]$TenantName = '',
        [string]$TenantId   = ''
    )

    $htmlBody = New-HtmlMailBody -Items $Items -ThresholdDays $ThresholdDays -TenantName $TenantName -TenantId $TenantId

    $expired  = ($Items | Where-Object { $_.DaysLeft -le 0 }).Count
    $critical = ($Items | Where-Object { $_.DaysLeft -gt 0 -and $_.DaysLeft -le 14 }).Count

    $urgencyTag = if ($expired -gt 0 -or $critical -gt 0) { '[KRITISCH]' }
                  elseif (($Items | Where-Object { $_.DaysLeft -le 30 }).Count -gt 0) { '[WARNUNG]' }
                  else { '[HINWEIS]' }

    $credWord = if ($Items.Count -ne 1) { 'Credentials' } else { 'Credential' }
    $subject  = "$urgencyTag App Registration – $($Items.Count) ablaufende $credWord (Schwellenwert: $ThresholdDays Tage)"

    $toRecipients = $To | ForEach-Object {
        @{ emailAddress = @{ address = $_.Trim() } }
    }

    $mailPayload = @{
        message        = @{
            subject      = $subject
            body         = @{
                contentType = 'HTML'
                content     = $htmlBody
            }
            toRecipients = @($toRecipients)
        }
        saveToSentItems = $false
    }

    try {
        Invoke-MgGraphRequest `
            -Method      POST `
            -Uri         "https://graph.microsoft.com/v1.0/users/$From/sendMail" `
            -Body        ($mailPayload | ConvertTo-Json -Depth 10) `
            -ContentType 'application/json' `
            -ErrorAction Stop
        Write-Output "E-Mail-Benachrichtigung gesendet an: $($To -join ', ')"
    }
    catch {
        $hint = if ($_ -match 'ErrorInvalidUser|404') {
            " KONFIGURATIONSFEHLER: Das Postfach '$From' existiert nicht im Tenant oder hat keine Lizenz. Bitte AlertMailFrom auf eine gültige Mailbox-UPN setzen (z. B. ein freigegebenes Postfach oder eine lizenzierte User-Mailbox)."
        } else { '' }
        Write-Error "E-Mail-Benachrichtigung fehlgeschlagen.$hint $_"
    }
}

###############################################################################
# Hauptfunktion
###############################################################################

function Invoke-AppRegistrationExpiryAlerts {
    <#
    .SYNOPSIS
        Orchestriert die Prüfung und den Versand der Ablaufwarnungen.

    .NOTES
        Author: Stefan Redlin
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [int]$ThresholdDays,
        [string]$TeamsWebhookUrl = '',
        [string]$MailFrom        = '',
        [string[]]$MailTo        = @(),
        [switch]$SkipTenantConfirmation,
        [string]$ExpectedTenantId
    )

    Confirm-MgTenantContext `
        -SkipTenantConfirmation:$SkipTenantConfirmation `
        -ExpectedTenantId $ExpectedTenantId

    $tenantId   = (Get-MgContext).TenantId
    $tenantName = try { (Get-MgOrganization -Select displayName -ErrorAction Stop).DisplayName } catch { Write-Warning "Mandantenname konnte nicht gelesen werden – Organization.Read.All fehlt?"; '' }

    Write-Output ""
    Write-Output "=== App Registration Expiry Check ==="
    Write-Output "Schwellenwert : $ThresholdDays Tage"
    Write-Output "Zeitpunkt     : $(Get-Date -Format 'dd.MM.yyyy HH:mm') UTC"
    Write-Output ""
    Write-Output "Credentials werden in vier Dringlichkeitsstufen eingeteilt:"
    Write-Output "  - ABGELAUFEN  : Ablaufdatum bereits überschritten"
    Write-Output "  - KRITISCH    : läuft innerhalb von 14 Tagen ab"
    Write-Output "  - WARNUNG     : läuft innerhalb von 30 Tagen ab"
    Write-Output "  - HINWEIS     : läuft innerhalb von $ThresholdDays Tagen ab"
    Write-Output ""

    $expiringItems = @(Get-ExpiringCredentials -ThresholdDays $ThresholdDays |
        Where-Object { -not [string]::IsNullOrEmpty($_.AppId) -and $_.CredentialType -and $null -ne $_.DaysLeft })

    if ($expiringItems.Count -eq 0) {
        Write-Output "Keine ablaufenden Credentials innerhalb von $ThresholdDays Tagen gefunden."
        Write-Output "Keine Benachrichtigungen gesendet."
        Write-Output ""
        Write-Output "=== Fertig ==="
        return
    }

    Write-Output ""
    Write-Output "Gefundene Einträge: $($expiringItems.Count)"
    foreach ($item in $expiringItems) {
        $status = if ($item.DaysLeft -le 0) { "ABGELAUFEN" }
                  elseif ($item.DaysLeft -le 14) { "KRITISCH" }
                  elseif ($item.DaysLeft -le 30) { "WARNUNG" }
                  else { "HINWEIS" }
        $nameOrId = if ($item.AppName) { $item.AppName } else { "(ObjectId: $($item.ObjectId))" }
        Write-Output "  [$status] $nameOrId  |  $($item.CredentialType)  |  $($item.CredentialName)  |  $($item.DaysLeft) Tage"
    }
    Write-Output ""

    $teamsEnabled = -not [string]::IsNullOrWhiteSpace($TeamsWebhookUrl)
    $mailEnabled  = (-not [string]::IsNullOrWhiteSpace($MailFrom)) -and
                    ($MailTo | Where-Object { $_ }).Count -gt 0

    if (-not $teamsEnabled -and -not $mailEnabled) {
        Write-Warning "Kein Benachrichtigungskanal konfiguriert. Bitte mindestens eine der Variablen setzen: AppExpiryTeamsWebhookUrl  –oder–  AppExpiryAlertMailFrom + AppExpiryAlertMailTo."
    }

    if ($teamsEnabled) {
        Send-TeamsAlert -Items $expiringItems -ThresholdDays $ThresholdDays -WebhookUrl $TeamsWebhookUrl
    }
    else {
        Write-Output "Teams-Webhook nicht konfiguriert – übersprungen."
    }

    if ($mailEnabled) {
        Send-MailAlert -Items $expiringItems -ThresholdDays $ThresholdDays -From $MailFrom -To $MailTo -TenantName $tenantName -TenantId $tenantId
    }
    else {
        Write-Output "E-Mail-Versand nicht konfiguriert – übersprungen."
    }

    Write-Output ""
    Write-Output "=== Fertig ==="
}

### Ausführen ###
Invoke-AppRegistrationExpiryAlerts `
    -ThresholdDays          $ThresholdDays `
    -TeamsWebhookUrl        $TeamsWebhookUrl `
    -MailFrom               $AlertMailFrom `
    -MailTo                 ($AlertMailTo -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) `
    -SkipTenantConfirmation `
    -ExpectedTenantId       $ExpectedTenantId
