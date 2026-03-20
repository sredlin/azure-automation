#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Richtet den Entra Connect Server als Extension-based Hybrid Runbook Worker ein.

.DESCRIPTION
    Dieses Einrichtungsskript wird einmalig auf dem Entra Connect Server ausgefuehrt
    (PowerShell als Administrator). Es installiert das Az-Modul (falls noetig) und
    registriert den Server als Extension-based Hybrid Runbook Worker in einer
    dedizierten Hybrid Worker Group des angegebenen Automation Accounts.

    HINWEIS: Agent-based Hybrid Worker ist seit 31. August 2024 EOL und wird ab
    1. April 2025 nicht mehr unterstuetzt. Dieses Skript verwendet ausschliesslich
    Extension-based Worker (VM-Extension oder Arc-Extension).

    Nach der Ausfuehrung dieses Skripts muss der Worker noch ueber das Azure Portal
    oder per ARM/Bicep mit der VM-Extension verbunden werden. Siehe README.md.

.PARAMETER ResourceGroupName
    Name der Resource Group des Azure Automation Accounts.

.PARAMETER AutomationAccountName
    Name des Azure Automation Accounts.

.PARAMETER HybridWorkerGroupName
    Name der Hybrid Worker Group (wird angelegt, falls nicht vorhanden).
    Standard: "HybridWorkerGroup-EntraConnect"

.PARAMETER SubscriptionId
    Azure Subscription ID. Wenn nicht angegeben, wird die aktuelle Subscription
    des angemeldeten Kontos verwendet.

.EXAMPLE
    .\Initialize-HybridWorker.ps1 `
        -ResourceGroupName "rg-automation" `
        -AutomationAccountName "aa-kerberos-rollover" `
        -HybridWorkerGroupName "HybridWorkerGroup-EntraConnect"

.NOTES
    Ausfuehrung    : Einmalig, lokal auf dem Entra Connect Server (als Admin)
    Erstellt von   : Stefan Redlin / Vater Business IT GmbH
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory)]
    [string]$AutomationAccountName,

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

#region Az-Modul sicherstellen

Write-Log "Prueffe Az.Automation Modul."

if (-not (Get-Module -ListAvailable -Name Az.Automation)) {
    Write-Log "Az.Automation nicht gefunden. Installiere Az-Modul (AllUsers)..."
    Install-Module -Name Az -Scope AllUsers -Force -AllowClobber
    Write-Log "Az-Modul installiert."
}
else {
    Write-Log "Az.Automation Modul vorhanden."
}

Import-Module -Name Az.Automation, Az.Accounts -Force

#endregion

#region Azure-Verbindung herstellen

Write-Log "Verbinde mit Azure (interaktiver Login)."
Connect-AzAccount

if ($SubscriptionId) {
    Write-Log "Setze Subscription: $SubscriptionId"
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
}

$currentSub = (Get-AzContext).Subscription
Write-Log "Aktive Subscription: $($currentSub.Name) ($($currentSub.Id))"

#endregion

#region Hybrid Worker Group anlegen

Write-Log "Prueffe Hybrid Worker Group '$HybridWorkerGroupName'."

$existingGroup = Get-AzAutomationHybridRunbookWorkerGroup `
    -ResourceGroupName $ResourceGroupName `
    -AutomationAccountName $AutomationAccountName `
    -Name $HybridWorkerGroupName `
    -ErrorAction SilentlyContinue

if ($null -eq $existingGroup) {
    Write-Log "Hybrid Worker Group nicht vorhanden. Lege an..."
    New-AzAutomationHybridRunbookWorkerGroup `
        -ResourceGroupName $ResourceGroupName `
        -AutomationAccountName $AutomationAccountName `
        -Name $HybridWorkerGroupName | Out-Null
    Write-Log "Hybrid Worker Group '$HybridWorkerGroupName' erstellt."
}
else {
    Write-Log "Hybrid Worker Group '$HybridWorkerGroupName' bereits vorhanden."
}

#endregion

#region Naechste Schritte

Write-Log "Hybrid Worker Group ist bereit."
Write-Log ""
Write-Log "Naechste Schritte (im Azure Portal oder per ARM/Bicep):"
Write-Log "  1. Navigiere zum Automation Account: $AutomationAccountName"
Write-Log "  2. Hybrid Worker Groups > $HybridWorkerGroupName > Add machines"
Write-Log "  3. Diesen Server ($env:COMPUTERNAME) als Extension-based Worker hinzufuegen."
Write-Log "     - Azure VM: VM-Extension 'HybridWorkerForWindows' installieren"
Write-Log "     - On-premises/Arc: Azure Arc einrichten, dann Arc-Extension"
Write-Log "  4. Nach Registrierung: Runbook Reset-KerberosSSO.ps1 hochladen und"
Write-Log "     Schedule auf diese Worker Group zeigen lassen."
Write-Log ""
Write-Log "Dokumentation Extension-based Worker:"
Write-Log "  https://learn.microsoft.com/azure/automation/extension-based-hybrid-runbook-worker-install"

#endregion
