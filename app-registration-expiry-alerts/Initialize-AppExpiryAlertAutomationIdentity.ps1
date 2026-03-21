# Benötigte Delegated Scopes für den ausführenden Admin-User:
# - AppRoleAssignment.ReadWrite.All (Zuweisen von App Roles)
# - Application.Read.All           (Lesen von Service Principals / App Roles)
Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All", "Application.Read.All"

# 1) Managed Identity Service Principal holen
#    Passe den DisplayName an den Namen deines Automation Accounts an.
$managedIdentity = Get-MgServicePrincipal -Filter "DisplayName eq 'aa-appexpiry'" | Select-Object -First 1
if (-not $managedIdentity) { throw "Service Principal 'aa-appexpiry' nicht gefunden." }

# 2) Microsoft Graph Service Principal holen (well-known AppId)
$graphSPN = Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'" | Select-Object -First 1
if (-not $graphSPN) { throw "Microsoft Graph Service Principal nicht gefunden." }

# 3) Benötigte Application Permissions (App Roles)
$permissions = @(
    'Application.Read.All',   # App Registrations & Service Principals lesen
    'Mail.Send'               # E-Mail über Graph API senden
)

foreach ($perm in $permissions) {

    $appRole = $graphSPN.AppRoles |
        Where-Object { $_.Value -eq $perm -and $_.AllowedMemberTypes -contains 'Application' } |
        Select-Object -First 1

    if (-not $appRole) {
        Write-Warning "AppRole '$perm' nicht im Graph SPN gefunden (oder nicht als Application Permission verfügbar)."
        continue
    }

    $existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $managedIdentity.Id -All |
        Where-Object { $_.ResourceId -eq $graphSPN.Id -and $_.AppRoleId -eq $appRole.Id }

    if ($existing) {
        Write-Host "Bereits vorhanden: $perm"
        continue
    }

    $bodyParam = @{
        PrincipalId = $managedIdentity.Id
        ResourceId  = $graphSPN.Id
        AppRoleId   = $appRole.Id
    }

    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $managedIdentity.Id -BodyParameter $bodyParam | Out-Null
    Write-Host "Zugewiesen: $perm"
}
