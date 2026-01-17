<#
.SYNOPSIS
    Automates the maintenance of Entra ID Conditional Access Named Locations
    based on current Tor Exit Node IP addresses (IPv4 and IPv6).

.DESCRIPTION
    This script connects via Microsoft Graph (Managed Identity),
    downloads the current Tor Exit Node lists (IPv4 /32 and IPv6 /128) from a
    public repository and creates or updates corresponding
    IP-based Conditional Access Named Locations in Entra ID.

    Before execution, the current Microsoft Graph tenant context is checked.
    Optionally, the expected TenantId value can be enforced to avoid misconfigurations
    in multi-tenant environments.

    The script is idempotent:
    - Existing Named Locations are updated
    - Non-existent Named Locations are created
    - No duplicate entries are created

.REQUIRES
    - PowerShell 7+
    - Microsoft.Graph.Authentication
    - Microsoft.Graph.Identity.SignIns
    - Microsoft Graph Application Permission:
        * Policy.ReadWrite.ConditionalAccess

.AUTHOR
    Stefan Redlin
#>

### Initialize Microsoft Graph connection using Managed Identity ###
Connect-MgGraph -Identity -NoWelcome
# Replace with your expected TenantId
$ExpectedTenantId = Get-AutomationVariable -Name 'ExpectedTenantId'

function Get-TorExitNodeIPv4List {
    <#
        .SYNOPSIS
            Get the current Tor exit node IPv4 list as /32 networks.

        .DESCRIPTION
            Downloads the current list of Tor exit nodes from
            https://raw.githubusercontent.com/Enkidu-6/tor-relay-lists/main/exits-v4.txt
            and returns each IP address in /32 CIDR notation.

        .INPUTS
            None

        .OUTPUTS
            String[] containing IP addresses in CIDR format (x.x.x.x/32).

        .NOTES
            Author:   Stefan Redlin

        .EXAMPLE
            Get-TorExitNodeIPv4List
    #>
    [CmdletBinding()]
    param ()

    $uri = 'https://raw.githubusercontent.com/Enkidu-6/tor-relay-lists/main/exits-v4.txt'

    try {
        $response = Invoke-RestMethod -Method Get -Uri $uri -ErrorAction Stop
    }
    catch {
        throw "Failed to retrieve the Tor exit node list from '$uri'. $_"
    }

    $response -split "`n" |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -and ($_ -match '^\d{1,3}(\.\d{1,3}){3}$') } |
    ForEach-Object { "{0}/32" -f $_ } |
    Sort-Object -Unique
}

function Get-TorExitNodeIPv6List {
    <#
        .SYNOPSIS
            Get the current Tor exit node IPv6 list as /128 networks.

        .DESCRIPTION
            Downloads the current list of Tor exit nodes from
            https://raw.githubusercontent.com/Enkidu-6/tor-relay-lists/main/exits-v6.txt
            and returns each IP address in /128 CIDR notation.

        .INPUTS
            None

        .OUTPUTS
            String[] containing IP addresses in CIDR format (x:x::x/128).

        .NOTES
            Author:   Stefan Redlin

        .EXAMPLE
            Get-TorExitNodeIPv4List
    #>
    [CmdletBinding()]
    param ()

    $uri = 'https://raw.githubusercontent.com/Enkidu-6/tor-relay-lists/main/exits-v6.txt'

    try {
        $response = Invoke-RestMethod -Method Get -Uri $uri -ErrorAction Stop
    }
    catch {
        throw "Failed to retrieve the Tor IPv6 exit node list from '$uri'. $_"
    }

    $response -split "`n" |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -and ($_ -match '^[0-9A-Fa-f:]+$') } |
    ForEach-Object { "{0}/128" -f $_ } |
    Sort-Object -Unique
}

function Confirm-MgTenantContext {
    <#
    .SYNOPSIS
        Validates the active Microsoft Graph tenant context and optionally prompts for confirmation.

    .DESCRIPTION
        Retrieves the current Microsoft Graph context using Get-MgContext and validates that
        a connection to Microsoft Graph is established.

        The function outputs a single informational status message indicating the connected
        account, tenant, and environment. Optionally, it can prompt the user to confirm that
        the active tenant is correct.

        For automation scenarios, interactive confirmation can be suppressed and an expected
        TenantId can be enforced as a safety guardrail.

    .PARAMETER SkipTenantConfirmation
        Suppresses the interactive tenant confirmation prompt.
        Intended for non-interactive or automated execution scenarios.

    .PARAMETER ExpectedTenantId
        Specifies the expected TenantId.
        If provided, the function throws an error when the current Graph context is connected
        to a different tenant.

    .INPUTS
        None

    .OUTPUTS
        None

    .EXAMPLE
        Confirm-MgTenantContext

        Validates the current Graph tenant context and prompts for confirmation.

    .EXAMPLE
        Confirm-MgTenantContext -SkipTenantConfirmation

        Validates the tenant context without prompting for user confirmation.

    .EXAMPLE
        Confirm-MgTenantContext -ExpectedTenantId '00000000-0000-0000-0000-000000000000'

        Validates that the current Graph connection is established against the specified tenant.

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
        throw "No Microsoft Graph context found. Please run Connect-MgGraph first."
    }

    if ($ExpectedTenantId -and ($ctx.TenantId -ne $ExpectedTenantId)) {
        throw "Connected tenant mismatch. Expected TenantId '$ExpectedTenantId' but current context is '$($ctx.TenantId)'."
    }

    # Single-line status message (always)
    Write-Host (
        "Successfully connected with account '{0}' to tenant '{1}' (Environment: {2})." -f `
            $ctx.Account, $ctx.TenantId, $ctx.Environment
    ) -ForegroundColor Green

    if (-not $SkipTenantConfirmation) {
        $answer = Read-Host "Is this the correct tenant? Type 'Y' to proceed"
        if ($answer -ne 'Y') {
            throw "Aborted by user. Tenant context not confirmed."
        }
    }

    return
}

function Invoke-TorExitNodesNamedLocation {
    <#
    .SYNOPSIS
        Create or update the "Tor Exit Nodes IPv4" and "Tor Exit Nodes IPv6" named locations in Entra ID.

    .DESCRIPTION
        Adds a tenant-context confirmation step prior to execution using Confirm-MgTenantContext.
        The function fetches current Tor exit node IP ranges and creates or updates IP-based Conditional Access named locations in Entra ID.
        Interactive tenant confirmation can be suppressed for automation scenarios, and a specific TenantId can be enforced as a safety guardrail.

    .PARAMETER IPv4
        Process IPv4 exit nodes only.

    .PARAMETER IPv6
        Process IPv6 exit nodes only.

    .PARAMETER SkipTenantConfirmation
        Suppresses the interactive tenant confirmation prompt. Intended for automation scenarios such as Azure Automation, scheduled tasks, or CI/CD pipelines.

    .PARAMETER ExpectedTenantId
        Enforces that the current Microsoft Graph context is connected to this TenantId. The function will terminate if the tenant does not match.

    .INPUTS
        None

    .OUTPUTS
        PSCustomObject with action details (Created or Updated) for each named location.

    .EXAMPLE
        Invoke-TorExitNodesNamedLocation

        Runs interactively. Prompts for tenant confirmation and updates both IPv4 and IPv6 named locations.

    .EXAMPLE
        Invoke-TorExitNodesNamedLocation -IPv4

        Runs interactively and processes IPv4 exit nodes only.

    .EXAMPLE
        Invoke-TorExitNodesNamedLocation -IPv6

        Runs interactively and processes IPv6 exit nodes only.

    .EXAMPLE
        Invoke-TorExitNodesNamedLocation -SkipTenantConfirmation -ExpectedTenantId '00000000-0000-0000-0000-000000000000'

        Automation-friendly execution. Skips interactive tenant confirmation and enforces the expected TenantId.

    .EXAMPLE
        Invoke-TorExitNodesNamedLocation -IPv4 -SkipTenantConfirmation

        Processes IPv4 exit nodes only without tenant prompt. Intended for controlled automation environments.

    .NOTES
        Author: Stefan Redlin
        Requires: - Microsoft.Graph.Identity.SignIns - Microsoft.Graph.Authentication - Connect-MgGraph with Policy.ReadWrite.ConditionalAccess permission
    #>

    [CmdletBinding()]
    param (
        [switch]$IPv4,
        [switch]$IPv6,

        [switch]$SkipTenantConfirmation,
        [string]$ExpectedTenantId
    )

    Confirm-MgTenantContext -SkipTenantConfirmation:$SkipTenantConfirmation -ExpectedTenantId $ExpectedTenantId

    # Internal constants for named location display names
    $displayNameIPv4 = 'Tor Exit Nodes IPv4'
    $displayNameIPv6 = 'Tor Exit Nodes IPv6'

    if ($IPv4 -and $IPv6) {
        throw "You cannot use -IPv4 and -IPv6 together, use either one or none to do both."
    }

    $doV4 = -not $IPv6
    $doV6 = -not $IPv4

    function Update-OrCreateTorNamedLocation {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory)][string]$DisplayName,
            [Parameter(Mandatory)][string[]]$Cidrs,
            [Parameter(Mandatory)][ValidateSet('IPv4', 'IPv6')][string]$AddressFamily
        )

        if (-not $Cidrs -or $Cidrs.Count -eq 0) {
            throw "Tor exit node list for $AddressFamily is empty – aborting for '$DisplayName'."
        }

        $newCidrs = $Cidrs | ForEach-Object { $_.ToLower() } | Sort-Object -Unique

        Write-Verbose "Checking for existing named location '$DisplayName' ($AddressFamily)..."
        $existingLocation = Get-MgIdentityConditionalAccessNamedLocation -All |
        Where-Object { $_.DisplayName -eq $DisplayName } |
        Select-Object -First 1

        $rangeType = if ($AddressFamily -eq 'IPv4') { '#microsoft.graph.iPv4CidrRange' } else { '#microsoft.graph.iPv6CidrRange' }

        $ipRanges = foreach ($cidr in $newCidrs) {
            @{ '@odata.type' = $rangeType; cidrAddress = $cidr }
        }

        $body = @{
            '@odata.type' = '#microsoft.graph.ipNamedLocation'
            displayName   = $DisplayName
            isTrusted     = $false
            ipRanges      = $ipRanges
        }

        if ($existingLocation) {
            $null = Update-MgIdentityConditionalAccessNamedLocation -NamedLocationId $existingLocation.Id -BodyParameter $body
            Write-Host "Updated named location '$DisplayName' ($AddressFamily) (Id: $($existingLocation.Id))." -ForegroundColor Green

            [PSCustomObject]@{
                Action          = 'Updated'
                DisplayName     = $DisplayName
                AddressFamily   = $AddressFamily
                NamedLocationId = $existingLocation.Id
            }
        }
        else {
            $result = New-MgIdentityConditionalAccessNamedLocation -BodyParameter $body
            Write-Host "Created named location '$DisplayName' ($AddressFamily) (Id: $($result.Id))." -ForegroundColor Green

            [PSCustomObject]@{
                Action          = 'Created'
                DisplayName     = $DisplayName
                AddressFamily   = $AddressFamily
                NamedLocationId = $result.Id
            }
        }
    }

    $results = @()

    if ($doV4) {
        Write-Verbose "Retrieving Tor exit node IPv4 list..."
        $cidrListV4 = Get-TorExitNodeIPv4List
        $results += Update-OrCreateTorNamedLocation -DisplayName $displayNameIPv4 -Cidrs $cidrListV4 -AddressFamily 'IPv4'
    }

    if ($doV6) {
        Write-Verbose "Retrieving Tor exit node IPv6 list..."
        $cidrListV6 = Get-TorExitNodeIPv6List
        $results += Update-OrCreateTorNamedLocation -DisplayName $displayNameIPv6 -Cidrs $cidrListV6 -AddressFamily 'IPv6'
    }

    return $results
}
# Excecute the function with desired parameters

Invoke-TorExitNodesNamedLocation -SkipTenantConfirmation -ExpectedTenantId $ExpectedTenantId
