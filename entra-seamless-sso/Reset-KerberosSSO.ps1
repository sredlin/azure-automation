#Requires -Version 5.1
<#
.SYNOPSIS
    Rotiert den Kerberos Decryption Key fuer Seamless SSO (AZUREADSSOACC).

.DESCRIPTION
    Dieses Runbook rotiert den Kerberos Decryption Key des AZUREADSSOACC-Kontos,
    das im Rahmen der Entra ID Seamless SSO-Konfiguration im lokalen Active Directory
    erstellt wird. Microsoft empfiehlt eine Rotation alle 30 Tage.

    Das Runbook muss auf einem Extension-based Hybrid Runbook Worker ausgefuehrt werden,
    auf dem Microsoft Entra Connect installiert ist (AzureADSSO.psd1 vorhanden).

    Benoetigt zwei Credential Assets im Automation Account:
      - AADSSOOnPremCredential : AD-Serviceaccount (DOMAIN\sa-kerberos-rollover).
                                 Benoetigt Mitgliedschaft in "Domain Admins".
                                 Hinweis: Least-Privilege per ACE-Delegation auf
                                 AZUREADSSOACC wurde getestet und ist nicht moeglich –
                                 Update-AzureADSSOForest prueft intern die Gruppen-
                                 mitgliedschaft und schlaegt andernfalls fehl.
      - AADSSOCloudCredential  : Entra ID Global Administrator Serviceaccount
                                 (Hinweis: Hybrid Identity Administrator reicht derzeit
                                  aufgrund eines bekannten Bugs nicht aus)

    Fuer Multi-Forest-Umgebungen: Update-AzureADSSOForest darf pro Forest nur einmal
    ausgefuehrt werden. Mehrfachausfuehrung deaktiviert das Feature bis zum Ablauf der
    Kerberos-Tickets aller betroffenen Benutzer.

.NOTES
    Ausfuehrung    : Extension-based Hybrid Runbook Worker (Entra Connect Server)
    Schedule       : Monatlich (empfohlen: jeden 1. des Monats, 02:00 Uhr)
    Getestet mit   : Azure Automation, PowerShell 5.1
    Erstellt von   : Stefan Redlin / Vater Business IT GmbH
#>

[CmdletBinding()]
param (
    # Delegierte Berechtigungen auf AZUREADSSOACC nach dem Rollover erhalten.
    # Standard: $true – verhindert, dass via Initialize-KerberosDelegation.ps1
    # gesetzte ACEs bei jedem Rollover überschrieben werden.
    [switch]$PreserveCustomPermissions = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Hilfsfunktionen

function Write-Log {
    param (
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Output "[$timestamp] [$Level] $Message"
}

#endregion

#region Voraussetzungen pruefen

Write-Log "Kerberos Key Rollover gestartet."

# Pfad zum AzureADSSO-Modul auf dem Entra Connect Server
$ssoModulePath = "C:\Program Files\Microsoft Azure Active Directory Connect\AzureADSSO.psd1"

if (-not (Test-Path -Path $ssoModulePath)) {
    throw "AzureADSSO.psd1 nicht gefunden unter: $ssoModulePath. " +
          "Dieses Runbook muss auf dem Entra Connect Server ausgefuehrt werden."
}

#endregion

#region Credentials laden

Write-Log "Lade Credential Assets aus dem Automation Account."

try {
    $onPremCred = Get-AutomationPSCredential -Name 'AADSSOOnPremCredential'
    if ($null -eq $onPremCred) {
        throw "Credential Asset 'AADSSOOnPremCredential' nicht gefunden."
    }
}
catch {
    throw "Fehler beim Laden von 'AADSSOOnPremCredential': $_"
}

try {
    $cloudCred = Get-AutomationPSCredential -Name 'AADSSOCloudCredential'
    if ($null -eq $cloudCred) {
        throw "Credential Asset 'AADSSOCloudCredential' nicht gefunden."
    }
}
catch {
    throw "Fehler beim Laden von 'AADSSOCloudCredential': $_"
}

Write-Log "Credential Assets erfolgreich geladen."

#endregion

#region Modul importieren und Rollover durchfuehren

Write-Log "Importiere AzureADSSO-Modul von: $ssoModulePath"

try {
    Import-Module -Name $ssoModulePath -Force
}
catch {
    throw "Fehler beim Importieren des AzureADSSO-Moduls: $_"
}

Write-Log "Stelle Authentifizierungskontext zu Entra ID her."

try {
    New-AzureADSSOAuthenticationContext -CloudCredentials $cloudCred
}
catch {
    throw "Fehler bei New-AzureADSSOAuthenticationContext: $_. " +
          "Pruefen: Global Administrator-Rolle fuer AADSSOCloudCredential vorhanden?"
}

Write-Log "Starte Kerberos Key Rollover fuer den AD-Forest."

try {
    if ($PreserveCustomPermissions) {
        Write-Log "PreserveCustomPermissions aktiv: Delegierte Rechte auf AZUREADSSOACC werden beibehalten."
        Update-AzureADSSOForest -OnPremCredentials $onPremCred -PreserveCustomPermissionsOnDesktopSsoAccount
    }
    else {
        Update-AzureADSSOForest -OnPremCredentials $onPremCred
    }
}
catch {
    throw "Fehler bei Update-AzureADSSOForest: $_"
}

#endregion

#region Ergebnis ausgeben

Write-Log "Kerberos Decryption Key Rollover erfolgreich abgeschlossen: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Log "Zur Verifikation auf einem DC ausfuehren: Get-ADComputer AZUREADSSOACC -Properties * | Select-Object Name, PasswordLastSet"

#endregion
