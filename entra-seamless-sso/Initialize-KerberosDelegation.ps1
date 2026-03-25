#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Erstellt den AD-Serviceaccount fuer den Kerberos Key Rollover und setzt ACEs auf AZUREADSSOACC.

.DESCRIPTION
    Dieses Einrichtungsskript wird einmalig auf einem Domain Controller (oder einem
    Server mit installiertem RSAT/ActiveDirectory-Modul) ausgefuehrt.

    Es fuehrt folgende Schritte aus:
      1. Generiert ein sicheres 32-Zeichen-Zufallspasswort (nur bei neuem Account)
      2. Legt den Serviceaccount im angegebenen OU-Pfad an (falls nicht vorhanden)
      3. Setzt ACEs auf dem AZUREADSSOACC-Computerkonto:
           - Read All Properties
           - Reset Password
           - Write msDS-SupportedEncryptionTypes
      4. Gibt das generierte Passwort einmalig aus (nur bei neuem Account)

    WICHTIG – Least Privilege nicht moeglich:
    Der Least-Privilege-Ansatz (nur ACE-Delegation auf AZUREADSSOACC) wurde getestet
    und ist nicht ausreichend. Update-AzureADSSOForest prueft intern die Gruppen-
    mitgliedschaft und schlaegt mit "Zugriff verweigert" fehl, auch wenn alle
    relevanten Berechtigungen auf AZUREADSSOACC korrekt gesetzt sind.
    Der Account muss Mitglied der Gruppe "Domain Admins" sein.
    Das Skript gibt am Ende den entsprechenden Befehl aus.

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
        $set       = $charSets[$i]
        $result[$i] = $set[$bytes[$i] % $set.Length]
    }
    for ($i = $charSets.Count; $i -lt $Length; $i++) {
        $result[$i] = $allChars[$bytes[$i] % $allChars.Length]
    }

    # Fisher-Yates-Shuffle fuer gleichmaessige Verteilung
    $rng.GetBytes($bytes)
    for ($i = $Length - 1; $i -gt 0; $i--) {
        $j             = $bytes[$i] % ($i + 1)
        $temp          = $result[$i]
        $result[$i]    = $result[$j]
        $result[$j]    = $temp
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

$accountDN = "CN=$ServiceAccountName,$ServiceAccountOU"

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
    Write-Log "Serviceaccount '$ServiceAccountName' bereits vorhanden. Nur Berechtigungen werden gesetzt (kein Passwort-Reset)."
}

#endregion

#region Berechtigungen auf AZUREADSSOACC delegieren

Write-Log "Suche AZUREADSSOACC-Computerkonto."

$ssoAccount = Get-ADComputer -Filter { Name -eq 'AZUREADSSOACC' } -ErrorAction SilentlyContinue

if ($null -eq $ssoAccount) {
    throw "Computerkonto 'AZUREADSSOACC' nicht gefunden. Ist Seamless SSO konfiguriert?"
}

$ssoAccountDN   = $ssoAccount.DistinguishedName
$ssoAccountPath = "AD:\$ssoAccountDN"

Write-Log "AZUREADSSOACC gefunden: $ssoAccountDN"
Write-Log "Delegiere Berechtigungen fuer '$ServiceAccountName'."

$acl            = Get-Acl -Path $ssoAccountPath
$accountSID     = (Get-ADUser -Identity $ServiceAccountName).SID
$identity       = [System.Security.Principal.SecurityIdentifier]$accountSID

# GUIDs der relevanten AD-Attribute und Extended Rights
$guidResetPassword              = [Guid]'00299570-246d-11d0-a768-00aa006e0529'
$guidMsDsSupportedEncTypes      = [Guid]'20119867-1d04-4ab7-9371-cfc3d5df0afd'
$adRightsReadProperty           = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty
$adRightsWriteProperty          = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
$adRightsExtendedRight          = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
$accessControlTypeAllow         = [System.Security.AccessControl.AccessControlType]::Allow
$inheritanceFlagNone            = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None

# Read All Properties
$aceReadAll = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $identity,
    $adRightsReadProperty,
    $accessControlTypeAllow,
    [Guid]::Empty,
    $inheritanceFlagNone,
    [Guid]::Empty
)

# Reset Password
$aceResetPassword = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $identity,
    $adRightsExtendedRight,
    $accessControlTypeAllow,
    $guidResetPassword,
    $inheritanceFlagNone,
    [Guid]::Empty
)

# Write msDS-SupportedEncryptionTypes
$aceWriteEncTypes = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $identity,
    $adRightsWriteProperty,
    $accessControlTypeAllow,
    $guidMsDsSupportedEncTypes,
    $inheritanceFlagNone,
    [Guid]::Empty
)

$acl.AddAccessRule($aceReadAll)
$acl.AddAccessRule($aceResetPassword)
$acl.AddAccessRule($aceWriteEncTypes)
Set-Acl -Path $ssoAccountPath -AclObject $acl

Write-Log "Berechtigungen erfolgreich delegiert."

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
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " NAECHSTER SCHRITT: Domain Admins Mitgliedschaft setzen" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Update-AzureADSSOForest erfordert Domain Administrator-"
Write-Host " Mitgliedschaft. ACE-Delegation allein ist nicht ausreichend."
Write-Host ""
Write-Host " Add-ADGroupMember -Identity 'Domain Admins' -Members '$ServiceAccountName'"
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

#endregion
