# Benötigte Delegated Scopes für den ausführenden Admin-User:
# - AppRoleAssignment.ReadWrite.All (Zuweisen von App Roles)
# - Application.Read.All (Lesen von SPNs/AppRoles)
Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All","Application.Read.All"

# 1) Managed Identity Service Principal holen
$managedIdentity = Get-MgServicePrincipal -Filter "DisplayName eq 'aa-namedlocations'" | Select-Object -First 1
if (-not $managedIdentity) { throw "Service Principal 'aa-namedlocations' nicht gefunden." }

# 2) Microsoft Graph Service Principal holen (well-known AppId)
$graphSPN = Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'" | Select-Object -First 1
if (-not $graphSPN) { throw "Microsoft Graph Service Principal nicht gefunden." }

# 3) Gewünschte Application Permissions (App Roles)
$permissions = @(
  "Policy.ReadWrite.ConditionalAccess",
  "Policy.Read.All"
)

foreach ($perm in $permissions) {

  # Passende AppRole finden (Application = AllowedMemberTypes enthält "Application")
  $appRole = $graphSPN.AppRoles |
    Where-Object { $_.Value -eq $perm -and $_.AllowedMemberTypes -contains "Application" } |
    Select-Object -First 1

  if (-not $appRole) {
    Write-Warning "AppRole '$perm' nicht im Graph SPN gefunden (oder nicht als Application Permission verfügbar)."
    continue
  }

  # Optional: prüfen, ob die Zuweisung bereits existiert (Idempotenz)
  $existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $managedIdentity.Id -All |
    Where-Object { $_.ResourceId -eq $graphSPN.Id -and $_.AppRoleId -eq $appRole.Id }

  if ($existing) {
    Write-Host "Bereits vorhanden: $perm"
    continue
  }

  # 4) AppRoleAssignment erstellen
  $bodyParam = @{
    PrincipalId = $managedIdentity.Id
    ResourceId  = $graphSPN.Id
    AppRoleId   = $appRole.Id
  }

  New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $managedIdentity.Id -BodyParameter $bodyParam | Out-Null
  Write-Host "Zugewiesen: $perm"
}
