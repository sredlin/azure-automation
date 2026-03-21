#Requires -Version 7
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications

<#
.SYNOPSIS
    Prüft alle App Registrations und Service Principals auf ablaufende
    Client Secrets und Zertifikate und sendet Warnmeldungen per Teams-Webhook
    und/oder E-Mail.

.DESCRIPTION
    Das Skript verbindet sich per Managed Identity mit Microsoft Graph,
    liest alle App Registrations sowie Service Principals ohne lokale
    App Registration und überprüft deren passwordCredentials (Secrets)
    und keyCredentials (Zertifikate) auf bevorstehende Ablaufdaten.

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
      Application.Read.All   – App Registrations & SPNs lesen
      Mail.Send              – E-Mail versenden

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
        Prüft alle App Registrations sowie Service Principals, deren App-ID
        keiner lokalen App Registration entspricht (externe/mandantenübergreifende
        Apps). Credentials, die kein Ablaufdatum haben, werden übersprungen.

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

    $localAppIds = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($app in $apps) { $null = $localAppIds.Add($app.AppId) }

    Write-Output "  $($apps.Count) App Registration(s) gefunden."

    foreach ($app in $apps) {

        foreach ($secret in $app.PasswordCredentials) {
            if ($null -eq $secret.EndDateTime)    { continue }
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
            if ($null -eq $cert.EndDateTime)    { continue }
            if ($cert.EndDateTime -gt $cutoff)  { continue }

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

    ### Service Principals ohne lokale App Registration ###
    Write-Output "Lese Service Principals mit Credentials..."
    try {
        $spns = Get-MgServicePrincipal -All `
            -Property 'id,displayName,appId,appOwnerOrganizationId,passwordCredentials,keyCredentials' `
            -ErrorAction Stop |
            Where-Object {
                ($_.PasswordCredentials.Count -gt 0 -or $_.KeyCredentials.Count -gt 0) -and
                -not $localAppIds.Contains($_.AppId)
            }
    }
    catch {
        throw "Service Principals konnten nicht gelesen werden. $_"
    }

    Write-Output "  $($spns.Count) Service Principal(s) mit Credentials (ohne lokale App Registration) gefunden."

    foreach ($spn in $spns) {

        foreach ($secret in $spn.PasswordCredentials) {
            if ($null -eq $secret.EndDateTime)    { continue }
            if ($secret.EndDateTime -gt $cutoff)  { continue }

            $daysLeft = [math]::Floor(($secret.EndDateTime - $now).TotalDays)
            $results.Add([PSCustomObject]@{
                Source         = 'Service Principal'
                AppName        = $spn.DisplayName
                AppId          = $spn.AppId
                ObjectId       = $spn.Id
                CredentialType = 'Client Secret'
                CredentialName = if ($secret.DisplayName) { $secret.DisplayName } else { '(kein Name)' }
                KeyId          = $secret.KeyId
                ExpiryDate     = $secret.EndDateTime
                DaysLeft       = $daysLeft
            })
        }

        foreach ($cert in $spn.KeyCredentials) {
            if ($null -eq $cert.EndDateTime)    { continue }
            if ($cert.EndDateTime -gt $cutoff)  { continue }

            $daysLeft = [math]::Floor(($cert.EndDateTime - $now).TotalDays)
            $results.Add([PSCustomObject]@{
                Source         = 'Service Principal'
                AppName        = $spn.DisplayName
                AppId          = $spn.AppId
                ObjectId       = $spn.Id
                CredentialType = 'Zertifikat'
                CredentialName = if ($cert.DisplayName) { $cert.DisplayName } else { '(kein Name)' }
                KeyId          = $cert.KeyId
                ExpiryDate     = $cert.EndDateTime
                DaysLeft       = $daysLeft
            })
        }
    }

    return ($results | Sort-Object DaysLeft)
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
        [Parameter(Mandatory)] [int]$ThresholdDays
    )

    $dateStr  = (Get-Date).ToString('dd.MM.yyyy  HH:mm')
    $expired  = @($Items | Where-Object { $_.DaysLeft -le 0 })
    $critical = @($Items | Where-Object { $_.DaysLeft -gt 0  -and $_.DaysLeft -le 14 })
    $warning  = @($Items | Where-Object { $_.DaysLeft -gt 14 -and $_.DaysLeft -le 30 })
    $info     = @($Items | Where-Object { $_.DaysLeft -gt 30 })

    $summaryColor = if ($expired.Count -gt 0 -or $critical.Count -gt 0) { '#c0392b' }
                    elseif ($warning.Count -gt 0)                        { '#d35400' }
                    else                                                  { '#2471a3' }

    function Get-RowBg ([int]$d) {
        if ($d -le 0)  { return '#fdf2f2' }
        if ($d -le 14) { return '#fdf2f2' }
        if ($d -le 30) { return '#fef9e7' }
        return '#eaf4fb'
    }

    function Get-BadgeHtml ([int]$d) {
        if ($d -le 0)  { return "<span style='background:#c0392b;color:#fff;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:700;letter-spacing:.3px;'>ABGELAUFEN</span>" }
        if ($d -le 14) { return "<span style='background:#c0392b;color:#fff;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:700;letter-spacing:.3px;'>KRITISCH</span>" }
        if ($d -le 30) { return "<span style='background:#d35400;color:#fff;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:700;letter-spacing:.3px;'>WARNUNG</span>" }
        return "<span style='background:#2471a3;color:#fff;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:700;letter-spacing:.3px;'>HINWEIS</span>"
    }

    function Get-DaysText ([int]$d) {
        if ($d -le 0) { return "Abgelaufen (vor $([Math]::Abs($d)) Tag$(if([Math]::Abs($d)-ne1){'en'}))" }
        return "$d Tag$(if($d -ne 1){'e'})"
    }

    $tableRows = foreach ($item in $Items | Sort-Object DaysLeft) {
        $bg        = Get-RowBg    $item.DaysLeft
        $badge     = Get-BadgeHtml $item.DaysLeft
        $daysText  = Get-DaysText  $item.DaysLeft
        $expiry    = $item.ExpiryDate.ToString('dd.MM.yyyy')
        $appName   = [System.Net.WebUtility]::HtmlEncode($item.AppName)
        $credName  = [System.Net.WebUtility]::HtmlEncode($item.CredentialName)
        $credType  = [System.Net.WebUtility]::HtmlEncode($item.CredentialType)
        $source    = [System.Net.WebUtility]::HtmlEncode($item.Source)
        $appId     = [System.Net.WebUtility]::HtmlEncode($item.AppId)

        @"
        <tr style="background:$bg;">
          <td style="padding:9px 14px;border-bottom:1px solid #e8e8e8;font-weight:600;">$appName</td>
          <td style="padding:9px 14px;border-bottom:1px solid #e8e8e8;color:#555;">$source</td>
          <td style="padding:9px 14px;border-bottom:1px solid #e8e8e8;">$credType</td>
          <td style="padding:9px 14px;border-bottom:1px solid #e8e8e8;">$credName</td>
          <td style="padding:9px 14px;border-bottom:1px solid #e8e8e8;font-family:Consolas,monospace;font-size:12px;color:#555;">$appId</td>
          <td style="padding:9px 14px;border-bottom:1px solid #e8e8e8;white-space:nowrap;">$expiry</td>
          <td style="padding:9px 14px;border-bottom:1px solid #e8e8e8;white-space:nowrap;">$daysText</td>
          <td style="padding:9px 14px;border-bottom:1px solid #e8e8e8;text-align:center;">$badge</td>
        </tr>
"@
    }

    function summaryBlock ([int]$count, [string]$label, [string]$bg, [string]$fg) {
        if ($count -eq 0) { return '' }
        return @"
    <div style="text-align:center;padding:10px 18px;border-radius:6px;background:$bg;min-width:80px;">
      <span style="display:block;font-size:26px;font-weight:700;color:$fg;">$count</span>
      <span style="font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:$fg;">$label</span>
    </div>
"@
    }

    $summaryHtml  = summaryBlock $expired.Count  'Abgelaufen' '#fde8e8' '#c0392b'
    $summaryHtml += summaryBlock $critical.Count 'Kritisch'   '#fde8e8' '#c0392b'
    $summaryHtml += summaryBlock $warning.Count  'Warnung'    '#fef3cd' '#935200'
    $summaryHtml += summaryBlock $info.Count     'Hinweis'    '#dbeafe' '#1d4ed8'

    return @"
<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body style="margin:0;padding:0;background:#f0f2f5;font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#222;">
<div style="max-width:980px;margin:28px auto;background:#fff;border-radius:8px;box-shadow:0 2px 12px rgba(0,0,0,.1);overflow:hidden;">

  <!-- Header -->
  <div style="background:$summaryColor;color:#fff;padding:22px 28px;">
    <div style="font-size:22px;font-weight:700;margin-bottom:4px;">⚠️&nbsp; App Registration – Ablaufende Credentials</div>
    <div style="font-size:13px;opacity:.88;">
      Geprüft am: $dateStr &nbsp;·&nbsp; Schwellenwert: $ThresholdDays Tage &nbsp;·&nbsp; Gesamt: $($Items.Count) Einträge
    </div>
  </div>

  <!-- Zusammenfassung -->
  <div style="display:flex;gap:14px;flex-wrap:wrap;padding:18px 28px;background:#fafafa;border-bottom:1px solid #e8e8e8;">
$summaryHtml
  </div>

  <!-- Tabelle -->
  <div style="padding:20px 28px 28px;">
    <table style="width:100%;border-collapse:collapse;font-size:13px;">
      <thead>
        <tr style="background:#f5f5f5;">
          <th style="padding:10px 14px;text-align:left;font-weight:600;border-bottom:2px solid #ddd;white-space:nowrap;">Anwendung</th>
          <th style="padding:10px 14px;text-align:left;font-weight:600;border-bottom:2px solid #ddd;white-space:nowrap;">Quelle</th>
          <th style="padding:10px 14px;text-align:left;font-weight:600;border-bottom:2px solid #ddd;white-space:nowrap;">Typ</th>
          <th style="padding:10px 14px;text-align:left;font-weight:600;border-bottom:2px solid #ddd;white-space:nowrap;">Name / Beschreibung</th>
          <th style="padding:10px 14px;text-align:left;font-weight:600;border-bottom:2px solid #ddd;white-space:nowrap;">App ID</th>
          <th style="padding:10px 14px;text-align:left;font-weight:600;border-bottom:2px solid #ddd;white-space:nowrap;">Ablaufdatum</th>
          <th style="padding:10px 14px;text-align:left;font-weight:600;border-bottom:2px solid #ddd;white-space:nowrap;">Verbleibend</th>
          <th style="padding:10px 14px;text-align:left;font-weight:600;border-bottom:2px solid #ddd;white-space:nowrap;">Status</th>
        </tr>
      </thead>
      <tbody>
$($tableRows -join '')
      </tbody>
    </table>
  </div>

  <!-- Footer -->
  <div style="padding:14px 28px;background:#fafafa;border-top:1px solid #e8e8e8;font-size:12px;color:#888;">
    Generiert von Azure Automation &nbsp;·&nbsp; Vater Business IT GmbH<br>
    Bitte erneuern Sie die betroffenen Credentials im Azure-Portal unter
    <em>Entra ID &rarr; App-Registrierungen &rarr; [App] &rarr; Zertifikate &amp; Geheimnisse</em>.
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
        [Parameter(Mandatory)] [string[]]$To
    )

    $htmlBody = New-HtmlMailBody -Items $Items -ThresholdDays $ThresholdDays

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
        Write-Error "E-Mail-Benachrichtigung fehlgeschlagen. $_"
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

    Write-Output ""
    Write-Output "=== App Registration Expiry Check ==="
    Write-Output "Schwellenwert : $ThresholdDays Tage"
    Write-Output "Zeitpunkt     : $(Get-Date -Format 'dd.MM.yyyy HH:mm') UTC"
    Write-Output ""

    $expiringItems = Get-ExpiringCredentials -ThresholdDays $ThresholdDays

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
        Write-Output "  [$status] $($item.AppName)  |  $($item.CredentialType)  |  $($item.CredentialName)  |  $($item.DaysLeft) Tage"
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
        Send-MailAlert -Items $expiringItems -ThresholdDays $ThresholdDays -From $MailFrom -To $MailTo
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
