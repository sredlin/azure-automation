<#
.SYNOPSIS
    Idempotentes Onboarding-Skript für den Automation Account "aa-mrm".
    Richtet alle notwendigen Berechtigungen für das MRM-Runbook ein.

.NOTES
    Ausführen als: Global Admin oder Privileged Role Admin
    Benötigt: Microsoft.Graph.* Module (lokal oder in Cloud Shell)
#>

# ── Konfiguration ─────────────────────────────────────────────────────────────
$automationAccountName = "aa-mrm"

$graphAppId    = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph
$exchangeAppId = "00000002-0000-0ff1-ce00-000000000000"  # Exchange Online

$graphRoles    = @("User.Read.All", "Organization.Read.All")
$exchangeRoles = @("Exchange.ManageAsApp")

$exManagementRole = "Mail Recipients"

# ── Verbinden ─────────────────────────────────────────────────────────────────
Write-Output "Verbinde mit Microsoft Graph..."
Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All","Application.Read.All","Organization.Read.All" -NoWelcome

# ── Automatisch auslesen ──────────────────────────────────────────────────────
$miSP = Get-MgServicePrincipal -Filter "DisplayName eq '$automationAccountName'" -Property "Id,AppId,DisplayName"
if (-not $miSP) {
    throw "Service Principal '$automationAccountName' nicht gefunden. Ist die Managed Identity aktiviert?"
}
$miObjectId = $miSP.Id
Write-Output "Managed Identity Object ID : $miObjectId"

$tenantDomain = (Get-MgOrganization).VerifiedDomains |
    Where-Object { $_.IsInitial -eq $true } |
    Select-Object -ExpandProperty Name
Write-Output "Tenant Domain              : $tenantDomain"

# ── Hilfsfunktion: App Role idempotent zuweisen ───────────────────────────────
function Set-AppRoleIfMissing {
    param(
        [string]$ResourceAppId,
        [string[]]$RoleValues,
        [string]$MiObjectId
    )

    $resourceSP = Get-MgServicePrincipal -Filter "AppId eq '$ResourceAppId'"
    if (-not $resourceSP) {
        Write-Warning "Service Principal für AppId $ResourceAppId nicht gefunden."
        return
    }

    $existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $MiObjectId |
        Where-Object ResourceId -eq $resourceSP.Id

    foreach ($roleValue in $RoleValues) {
        $appRole = $resourceSP.AppRoles | Where-Object Value -eq $roleValue

        if (-not $appRole) {
            Write-Warning "  App-Rolle '$roleValue' nicht gefunden in $($resourceSP.DisplayName)."
            continue
        }

        $alreadyAssigned = $existing | Where-Object AppRoleId -eq $appRole.Id

        if ($alreadyAssigned) {
            Write-Output "  [SKIP]  $roleValue – bereits zugewiesen"
        }
        else {
            New-MgServicePrincipalAppRoleAssignment `
                -ServicePrincipalId $MiObjectId `
                -PrincipalId        $MiObjectId `
                -ResourceId         $resourceSP.Id `
                -AppRoleId          $appRole.Id | Out-Null
            Write-Output "  [OK]    $roleValue – zugewiesen"
        }
    }
}

# ── Hilfsfunktion: Exchange Management Role idempotent zuweisen ───────────────
function Set-ExchangeManagementRoleIfMissing {
    param(
        [string]$MiObjectId,
        [string]$MiAppId,
        [string]$MiDisplayName,
        [string]$Role
    )

    # Service Principal in Exchange registrieren (idempotent)
    $sp = Get-ServicePrincipal -Identity $MiObjectId -ErrorAction SilentlyContinue
    if (-not $sp) {
        Write-Output "  Registriere Service Principal in Exchange..."
        New-ServicePrincipal `
            -AppId       $MiAppId `
            -ObjectId    $MiObjectId `
            -DisplayName $MiDisplayName | Out-Null
        Write-Output "  [OK]    Service Principal registriert"
    }
    else {
        Write-Output "  [SKIP]  Service Principal bereits registriert ($($sp.DisplayName))"
    }

    # Management Role Assignment prüfen – korrekter Parameter: -RoleAssignee
    $existing = Get-ManagementRoleAssignment -RoleAssignee $MiObjectId -ErrorAction SilentlyContinue |
        Where-Object { $_.Role -eq $Role }

    if ($existing) {
        Write-Output "  [SKIP]  Exchange-Rolle '$Role' – bereits zugewiesen"
    }
    else {
        New-ManagementRoleAssignment -Role $Role -App $MiObjectId | Out-Null
        Write-Output "  [OK]    Exchange-Rolle '$Role' – zugewiesen"
    }
}

# ── Graph-Berechtigungen ──────────────────────────────────────────────────────
Write-Output ""
Write-Output "══════════════════════════════════════════"
Write-Output " Microsoft Graph App-Rollen"
Write-Output "══════════════════════════════════════════"
Set-AppRoleIfMissing -ResourceAppId $graphAppId -RoleValues $graphRoles -MiObjectId $miObjectId

# ── Exchange App-Rolle ────────────────────────────────────────────────────────
Write-Output ""
Write-Output "══════════════════════════════════════════"
Write-Output " Exchange Online App-Rolle"
Write-Output "══════════════════════════════════════════"
Set-AppRoleIfMissing -ResourceAppId $exchangeAppId -RoleValues $exchangeRoles -MiObjectId $miObjectId

# ── Exchange Management Role ──────────────────────────────────────────────────
Write-Output ""
Write-Output "══════════════════════════════════════════"
Write-Output " Exchange Management Role"
Write-Output "══════════════════════════════════════════"
Write-Output "Verbinde mit Exchange Online..."
Connect-ExchangeOnline -ShowBanner:$false

Set-ExchangeManagementRoleIfMissing `
    -MiObjectId    $miObjectId `
    -MiAppId       $miSP.AppId `
    -MiDisplayName $automationAccountName `
    -Role          $exManagementRole

Disconnect-ExchangeOnline -Confirm:$false

# ── Zusammenfassung ───────────────────────────────────────────────────────────
Write-Output ""
Write-Output "══════════════════════════════════════════"
Write-Output " Onboarding abgeschlossen"
Write-Output " Automation Account : $automationAccountName"
Write-Output " Managed Identity   : $miObjectId"
Write-Output " Tenant Domain      : $tenantDomain"
Write-Output "══════════════════════════════════════════"
Write-Output "Hinweis: Berechtigungen können 5-10 Min. zur Propagation benötigen."

