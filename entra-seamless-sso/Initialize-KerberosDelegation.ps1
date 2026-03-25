#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Erstellt den AD-Serviceaccount fuer den Kerberos Key Rollover und fuegt ihn zu Domain Admins hinzu.

.DESCRIPTION
    Dieses Einrichtungsskript wird einmalig auf einem Domain Controller (oder einem
    Server mit installiertem RSAT/ActiveDirectory-Modul) ausgefuehrt.

    Es fuehrt folgende Schritte aus:
      1. Generiert ein sicheres 32-Zeichen-Zufallspasswort (nur bei neuem Account)
      2. Legt den Serviceaccount im angegebenen OU-Pfad an (falls nicht vorhanden)
      3. Fuegt den Account zur Gruppe "Domain Admins" hinzu
      4. Gibt das generierte Passwort einmalig aus (nur bei neuem Account)

    Hinweis: Ein Least-Privilege-Ansatz per ACE-Delegation auf AZUREADSSOACC
    wurde getestet und ist nicht moeglich. Update-AzureADSSOForest prueft intern
    die Gruppenmitgliedschaft und schlaegt mit "Zugriff verweigert" fehl, auch
    wenn alle relevanten Berechtigungen auf AZUREADSSOACC korrekt gesetzt sind.

    Das Passwort wird nicht in Logs oder Dateien gespeichert.
    Direkt nach der Ausgabe im Automation Account als Credential Asset hinterlegen:
      Name: AADSSOOnPremCredential
      User: DOMAIN\sa-kerberos-rollover

.PARAMETER ServiceAccountName
    SAMAccountName des Serviceaccounts.
    Standard: "sa-kerberos-rollover"

.PARAMETER ServiceAccountOU
    Distinguished Name der OU, in der der Account angelegt wird.
    Beispiel: "OU=ServiceAccounts,DC=contoso,DC=com"

.EXAMPLE
    .\Initialize-KerberosDelegation.ps1 `
        -ServiceAccountOU "OU=ServiceAccounts,DC=contoso,DC=com"

.NOTES
    Ausfuehrung    : Einmalig, auf DC oder Server mit AD-Modul (als Domain Admin)
    Erstellt von   : Stefan Redlin / Vater Business IT GmbH
#>

[CmdletBinding()]
param (
    [string]$ServiceAccountName = 'sa-kerberos-rollover',

    [Parameter(Mandatory)]
    [string]$ServiceAccountOU
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Anführungszeichen entfernen, die beim Aufruf versehentlich im Wert landen können
$ServiceAccountOU = $ServiceAccountOU.Trim().Trim('"').Trim("'").Trim()

#region Hilfsfunktionen

function Write-Log {
    param (
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$timestamp] [$Level] $Message"
}

function New-SecureRandomPassword {
    param ([int]$Length = 32)

    $charSets = @(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        'abcdefghijklmnopqrstuvwxyz',
        '0123456789',
        '!@#$%^&*()-_=+[]{}|;:,.<>?'
    )

    $allChars = ($charSets -join '')
    $rng      = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes    = [byte[]]::new($Length)
    $rng.GetBytes($bytes)

    # Mindestens ein Zeichen aus jedem Zeichensatz sicherstellen
    $result = [char[]]::new($Length)
    for ($i = 0; $i -lt $charSets.Count; $i++) {
        $set        = $charSets[$i]
        $result[$i] = $set[$bytes[$i] % $set.Length]
    }
    for ($i = $charSets.Count; $i -lt $Length; $i++) {
        $result[$i] = $allChars[$bytes[$i] % $allChars.Length]
    }

    # Fisher-Yates-Shuffle fuer gleichmaessige Verteilung
    $rng.GetBytes($bytes)
    for ($i = $Length - 1; $i -gt 0; $i--) {
        $j          = $bytes[$i] % ($i + 1)
        $temp       = $result[$i]
        $result[$i] = $result[$j]
        $result[$j] = $temp
    }

    $rng.Dispose()
    return -join $result
}

#endregion

#region Domain ermitteln

$domain        = Get-ADDomain
$DomainFQDN    = $domain.DNSRoot
$domainNetBIOS = $domain.NetBIOSName
Write-Log "Domain erkannt: $DomainFQDN ($domainNetBIOS)"

#endregion

#region Serviceaccount anlegen

Write-Log "Prueffe Serviceaccount '$ServiceAccountName'."

$existingAccount = Get-ADUser -Filter { SamAccountName -eq $ServiceAccountName } -ErrorAction SilentlyContinue

$newAccount = $null -eq $existingAccount

if ($newAccount) {
    Write-Log "Generiere sicheres 32-Zeichen-Passwort."
    $plainPassword  = New-SecureRandomPassword -Length 32
    $securePassword = ConvertTo-SecureString -String $plainPassword -AsPlainText -Force

    Write-Log "Account nicht vorhanden. Lege an in: $ServiceAccountOU"
    New-ADUser `
        -Name                 $ServiceAccountName `
        -SamAccountName       $ServiceAccountName `
        -UserPrincipalName    "$ServiceAccountName@$DomainFQDN" `
        -Path                 $ServiceAccountOU `
        -AccountPassword      $securePassword `
        -Enabled              $true `
        -PasswordNeverExpires $true `
        -CannotChangePassword $true `
        -Description          "Automation account - Kerberos Key Rollover (Seamless SSO) - kein interaktiver Login"
    Write-Log "Serviceaccount '$ServiceAccountName' erstellt."
}
else {
    Write-Log "Serviceaccount '$ServiceAccountName' bereits vorhanden."
}

#endregion

#region Domain Admins Mitgliedschaft sicherstellen

Write-Log "Prueffe Domain Admins Mitgliedschaft."

# Gruppe per SID ermitteln (sprachunabhaengig, RID 512 = Domain Admins / Domaenen-Admins)
$domainAdminsSID   = "$($domain.DomainSID)-512"
$domainAdminsGroup = Get-ADGroup -Filter { SID -eq $domainAdminsSID }

$isDomainAdmin = Get-ADGroupMember -Identity $domainAdminsGroup |
    Where-Object { $_.SamAccountName -eq $ServiceAccountName }

if ($null -eq $isDomainAdmin) {
    Write-Log "Fuege '$ServiceAccountName' zu '$($domainAdminsGroup.Name)' hinzu."
    Add-ADGroupMember -Identity $domainAdminsGroup -Members $ServiceAccountName
    Write-Log "Mitgliedschaft gesetzt."
}
else {
    Write-Log "'$ServiceAccountName' ist bereits Mitglied von '$($domainAdminsGroup.Name)'."
}

#endregion

#region Ergebnis ausgeben

if ($newAccount) {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Yellow
    Write-Host " PASSWORT – NUR EINMALIG ANGEZEIGT" -ForegroundColor Yellow
    Write-Host "============================================================" -ForegroundColor Yellow
    Write-Host " Account : $domainNetBIOS\$ServiceAccountName"
    Write-Host " Passwort: $plainPassword"
    Write-Host "============================================================" -ForegroundColor Yellow
    Write-Host " Jetzt im Azure Automation Account hinterlegen:"
    Write-Host " Automation Account > Credentials > AADSSOOnPremCredential"
    Write-Host " Username : $domainNetBIOS\$ServiceAccountName"
    Write-Host " Password : (s. o.)"
    Write-Host "============================================================" -ForegroundColor Yellow
    Write-Host ""

    # Passwort aus dem Speicher loeschen
    $plainPassword = $null
    [System.GC]::Collect()
}

Write-Log "Einrichtung abgeschlossen."

#endregion
