<#
.SYNOPSIS
    Synchronisiert FullAccess-Berechtigungen einer Delegate-Mailbox
    auf Basis eines CustomAttribute-Wertes.

.DESCRIPTION
    Das Skript liest alle Postfächer aus Exchange Online und vergleicht
    den Wert eines konfigurierbaren CustomAttribute mit einem definierten
    Sollwert.

    PHASE 1 – GRANT:  Postfächer MIT dem Attributwert erhalten FullAccess
                      für die Delegate-Mailbox (falls noch nicht vorhanden).

    PHASE 2 – REVOKE: Postfächer OHNE den Attributwert verlieren FullAccess
                      der Delegate-Mailbox (falls vorhanden).

    Die Delegate-Mailbox selbst wird in beiden Phasen übersprungen.
    Das Skript ist idempotent und kann wiederholt ausgeführt werden.

.PARAMETER DelegateMailbox
    UPN der Mailbox, die FullAccess erhalten bzw. verlieren soll.
    Pflichtparameter.

.PARAMETER Organization
    onmicrosoft.com-Domain des Tenants. Wird für Connect-ExchangeOnline
    bei Managed Identity benötigt. Pflichtparameter.

.PARAMETER AttributeValue
    Wert, den das CustomAttribute haben muss, damit FullAccess gewährt wird.


.PARAMETER CustomAttribute
    Name des zu prüfenden CustomAttribute (CustomAttribute1–15).


    Hinweis: CustomAttribute1-15 in Exchange Online entspricht extensionAttribute1-15
    im Active Directory – beide Felder sind identisch, der Name unterscheidet
    sich lediglich je nach Kontext (AD vs. Exchange/EXO).

.PARAMETER TestMailbox
    Optional: UPN eines einzelnen Postfachs. Nur dieses wird geprüft
    und bearbeitet – nützlich zum Testen vor dem Volllauf.

.NOTES
    Version:    3.0
    Autor:      Stefan / Vater Business IT GmbH
    Datum:      2026-03-20


.EXAMPLE
    .\Sync-DelegateAccessByAttribute.ps1 `
        -DelegateMailbox "delegate@contoso.com" `
        -Organization    "contoso.onmicrosoft.com" `
        -CustomAttribute "CustomAttribute1" `
        -AttributeValue  "<Value>" `
        -TestMailbox     "user@contoso.com"

.EXAMPLE
    .\Sync-DelegateAccessByAttribute.ps1 `
        -DelegateMailbox "delegate@contoso.com" `
        -Organization    "contoso.onmicrosoft.com" `
        -CustomAttribute "CustomAttribute1" `
        -AttributeValue  "<Value>" `

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DelegateMailbox,
    [Parameter(Mandatory)][string]$Organization,
    [string]$AttributeValue  = "",
    [string]$CustomAttribute = "",
    [string]$TestMailbox
)

#region ── Verbindung ───────────────────────────────────────────────────────────

Write-Output "=== Verbinde mit Exchange Online ==="

try {
    Connect-ExchangeOnline `
        -ManagedIdentity `
        -Organization $Organization `
        -ShowBanner:$false `
        -ErrorAction Stop

    Write-Output "Verbindung erfolgreich."
}
catch {
    Write-Error "Verbindungsfehler: $_"
    throw
}

#endregion ──────────────────────────────────────────────────────────────────────

$Results = [System.Collections.Generic.List[PSCustomObject]]::new()

try {

    #region ── Postfächer laden ─────────────────────────────────────────────────

    Write-Output ""
    Write-Output "=== Lade Postfächer ==="
    Write-Output "Delegate       : $DelegateMailbox"
    Write-Output "Attribut       : $CustomAttribute = '$AttributeValue'"

    if ($TestMailbox) {
        Write-Output "Testmodus      : Nur '$TestMailbox'"
        $MB = Get-Mailbox -Identity $TestMailbox -ErrorAction Stop
        if ($MB.$CustomAttribute -eq $AttributeValue) {
            $GrantMailboxes  = @($MB)
            $RevokeMailboxes = @()
        }
        else {
            $GrantMailboxes  = @()
            $RevokeMailboxes = @($MB)
        }
    }
    else {
        $GrantMailboxes  = Get-Mailbox -ResultSize Unlimited -Filter "$CustomAttribute -eq '$AttributeValue'" -ErrorAction Stop
        $RevokeMailboxes = Get-Mailbox -ResultSize Unlimited -Filter "$CustomAttribute -ne '$AttributeValue'" -ErrorAction Stop
    }

    Write-Output "Grant-Kandidaten : $($GrantMailboxes.Count)"
    Write-Output "Revoke-Kandidaten: $($RevokeMailboxes.Count)"

    #endregion ──────────────────────────────────────────────────────────────────

    #region ── PHASE 1: GRANT ───────────────────────────────────────────────────

    Write-Output ""
    Write-Output "=== PHASE 1: GRANT – FullAccess setzen ==="

    foreach ($Mailbox in $GrantMailboxes) {

        $Result = [PSCustomObject]@{
            Phase       = "GRANT"
            Mailbox     = $Mailbox.UserPrincipalName
            DisplayName = $Mailbox.DisplayName
            Status      = ""
            Hinweis     = ""
        }

        if ($Mailbox.UserPrincipalName -eq $DelegateMailbox) {
            $Result.Status  = "ÜBERSPRUNGEN"
            $Result.Hinweis = "Eigenes Postfach"
            $Results.Add($Result)
            continue
        }

        try {
            $Existing = Get-MailboxPermission `
                            -Identity $Mailbox.UserPrincipalName `
                            -User     $DelegateMailbox `
                            -ErrorAction Stop |
                        Where-Object { $_.AccessRights -contains "FullAccess" }

            if ($Existing) {
                $Result.Status  = "BEREITS VORHANDEN"
                $Result.Hinweis = "Keine Aktion nötig"
            }
            else {
                Add-MailboxPermission `
                    -Identity        $Mailbox.UserPrincipalName `
                    -User            $DelegateMailbox `
                    -AccessRights    FullAccess `
                    -InheritanceType All `
                    -AutoMapping     $false `
                    -ErrorAction     Stop | Out-Null

                $Result.Status  = "GESETZT"
                $Result.Hinweis = "FullAccess hinzugefügt"
            }
        }
        catch {
            $Result.Status  = "FEHLER"
            $Result.Hinweis = $_.Exception.Message
        }

        $Results.Add($Result)
        Write-Output "[$($Result.Status)] $($Result.Mailbox) – $($Result.Hinweis)"
    }

    #endregion ──────────────────────────────────────────────────────────────────

    #region ── PHASE 2: REVOKE ──────────────────────────────────────────────────

    Write-Output ""
    Write-Output "=== PHASE 2: REVOKE – FullAccess entfernen ==="

    foreach ($Mailbox in $RevokeMailboxes) {

        $Result = [PSCustomObject]@{
            Phase       = "REVOKE"
            Mailbox     = $Mailbox.UserPrincipalName
            DisplayName = $Mailbox.DisplayName
            Status      = ""
            Hinweis     = ""
        }

        if ($Mailbox.UserPrincipalName -eq $DelegateMailbox) {
            $Result.Status  = "ÜBERSPRUNGEN"
            $Result.Hinweis = "Eigenes Postfach"
            $Results.Add($Result)
            continue
        }

        try {
            $Existing = Get-MailboxPermission `
                            -Identity $Mailbox.UserPrincipalName `
                            -User     $DelegateMailbox `
                            -ErrorAction Stop |
                        Where-Object { $_.AccessRights -contains "FullAccess" }

            if (-not $Existing) { continue }

            Remove-MailboxPermission `
                -Identity     $Mailbox.UserPrincipalName `
                -User         $DelegateMailbox `
                -AccessRights FullAccess `
                -Confirm:$false `
                -ErrorAction  Stop

            $Result.Status  = "ENTFERNT"
            $Result.Hinweis = "FullAccess widerrufen"
        }
        catch {
            $Result.Status  = "FEHLER"
            $Result.Hinweis = $_.Exception.Message
        }

        $Results.Add($Result)
        Write-Output "[$($Result.Status)] $($Result.Mailbox) – $($Result.Hinweis)"
    }

    #endregion ──────────────────────────────────────────────────────────────────

    #region ── Zusammenfassung ──────────────────────────────────────────────────

    Write-Output ""
    Write-Output "=== Zusammenfassung ==="
    $Results | Format-Table Phase, Mailbox, DisplayName, Status, Hinweis -AutoSize

    Write-Output "--- GRANT ---"
    Write-Output "Neu gesetzt      : $(($Results | Where-Object { $_.Phase -eq 'GRANT' -and $_.Status -eq 'GESETZT' }).Count)"
    Write-Output "Bereits vorhanden: $(($Results | Where-Object { $_.Phase -eq 'GRANT' -and $_.Status -eq 'BEREITS VORHANDEN' }).Count)"
    Write-Output "Fehler           : $(($Results | Where-Object { $_.Phase -eq 'GRANT' -and $_.Status -eq 'FEHLER' }).Count)"

    Write-Output "--- REVOKE ---"
    Write-Output "Entfernt         : $(($Results | Where-Object { $_.Phase -eq 'REVOKE' -and $_.Status -eq 'ENTFERNT' }).Count)"
    Write-Output "Fehler           : $(($Results | Where-Object { $_.Phase -eq 'REVOKE' -and $_.Status -eq 'FEHLER' }).Count)"

    Write-Output "--- GESAMT ---"
    Write-Output "Übersprungen     : $(($Results | Where-Object { $_.Status -eq 'ÜBERSPRUNGEN' }).Count)"

    #endregion ──────────────────────────────────────────────────────────────────

}
finally {
    Disconnect-ExchangeOnline -Confirm:$false
    Write-Output ""
    Write-Output "=== Fertig ==="
}
