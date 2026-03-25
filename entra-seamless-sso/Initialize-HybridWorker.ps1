#Requires -Version 5.1
<#
.SYNOPSIS
    Erstellt den Azure Automation Account und die Hybrid Worker Group fuer den Kerberos Key Rollover.

.DESCRIPTION
    Dieses Einrichtungsskript wird einmalig ausgefuehrt und erstellt:
      1. Den Azure Automation Account (in der Automation-RG)
      2. Die Hybrid Worker Group im Automation Account

    Anschliessend muss die HybridWorkerForWindows-Extension manuell an der
    Arc Machine aktiviert und mit dem Automation Account verknuepft werden.

    Reihenfolge:
      1. Dieses Skript ausfuehren
      2. Im Azure Portal: Arc Machine > Extensions > HybridWorkerForWindows
         hinzufuegen und mit Automation Account + Worker Group verknuepfen
      3. Credential Assets anlegen (AADSSOOnPremCredential, AADSSOCloudCredential)
      4. Runbook Reset-KerberosSSO.ps1 hochladen und Schedule anlegen

.PARAMETER AutomationResourceGroupName
    Name der Resource Group fuer den Automation Account.

.PARAMETER AutomationAccountName
    Name des Automation Accounts (wird angelegt, falls nicht vorhanden).

.PARAMETER Location
    Azure Region fuer den Automation Account.
    Standard: "westeurope"

.PARAMETER HybridWorkerGroupName
    Name der Hybrid Worker Group (wird angelegt, falls nicht vorhanden).
    Standard: "HybridWorkerGroup-EntraConnect"

.PARAMETER SubscriptionId
    Azure Subscription ID. Wenn nicht angegeben, wird die aktuelle Subscription
    des angemeldeten Kontos verwendet.

.EXAMPLE
    .\Initialize-HybridWorker.ps1 `
        -AutomationResourceGroupName "rg-automation" `
        -AutomationAccountName "aa-kerberos-rollover" `
        -Location "westeurope" `
        -HybridWorkerGroupName "HybridWorkerGroup-EntraConnect"

.NOTES
    Ausfuehrung    : Einmalig (von beliebigem Rechner mit Az-Modul)
    Erstellt von   : Stefan Redlin / Vater Business IT GmbH
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]$AutomationResourceGroupName,

    [Parameter(Mandatory)]
    [string]$AutomationAccountName,

    [string]$Location = 'westeurope',

    [string]$HybridWorkerGroupName = 'HybridWorkerGroup-EntraConnect',

    [string]$SubscriptionId
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
    Write-Host "[$timestamp] [$Level] $Message"
}

#endregion

#region Az-Module sicherstellen

foreach ($module in @('Az.Accounts', 'Az.Automation')) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Log "Installiere Modul: $module"
        Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber
    }
}

Import-Module -Name Az.Accounts, Az.Automation -Force

#endregion

#region Azure-Verbindung herstellen

Write-Log "Verbinde mit Azure."
Connect-AzAccount

if ($SubscriptionId) {
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
}

$currentSub = (Get-AzContext).Subscription
Write-Log "Aktive Subscription: $($currentSub.Name) ($($currentSub.Id))"

#endregion

#region Automation Account erstellen

Write-Log "Prueffe Automation Account '$AutomationAccountName'."

$automationAccount = Get-AzAutomationAccount `
    -ResourceGroupName $AutomationResourceGroupName `
    -Name $AutomationAccountName `
    -ErrorAction SilentlyContinue

if ($null -eq $automationAccount) {
    Write-Log "Automation Account nicht vorhanden. Lege an..."
    New-AzAutomationAccount `
        -ResourceGroupName $AutomationResourceGroupName `
        -Name $AutomationAccountName `
        -Location $Location | Out-Null
    Write-Log "Automation Account '$AutomationAccountName' erstellt."
}
else {
    Write-Log "Automation Account '$AutomationAccountName' bereits vorhanden."
}

#endregion

#region Hybrid Worker Group erstellen

Write-Log "Prueffe Hybrid Worker Group '$HybridWorkerGroupName'."

$existingGroup = Get-AzAutomationHybridRunbookWorkerGroup `
    -ResourceGroupName $AutomationResourceGroupName `
    -AutomationAccountName $AutomationAccountName `
    -Name $HybridWorkerGroupName `
    -ErrorAction SilentlyContinue

if ($null -eq $existingGroup) {
    Write-Log "Hybrid Worker Group nicht vorhanden. Lege an..."
    New-AzAutomationHybridRunbookWorkerGroup `
        -ResourceGroupName $AutomationResourceGroupName `
        -AutomationAccountName $AutomationAccountName `
        -Name $HybridWorkerGroupName | Out-Null
    Write-Log "Hybrid Worker Group '$HybridWorkerGroupName' erstellt."
}
else {
    Write-Log "Hybrid Worker Group '$HybridWorkerGroupName' bereits vorhanden."
}

#endregion

#region Naechste Schritte

Write-Log "Einrichtung abgeschlossen."
Write-Log ""
Write-Log "Naechste Schritte:"
Write-Log "  1. Arc Machine > Extensions > + Add > HybridWorkerForWindows"
Write-Log "     Automation Account : $AutomationAccountName"
Write-Log "     Worker Group       : $HybridWorkerGroupName"
Write-Log "  2. Automation Account > Credentials > zwei Assets anlegen:"
Write-Log "     - AADSSOOnPremCredential  (AD Enterprise/Domain Admin)"
Write-Log "     - AADSSOCloudCredential   (Entra Global Admin)"
Write-Log "  3. Runbook Reset-KerberosSSO.ps1 hochladen und Schedule anlegen."

#endregion
