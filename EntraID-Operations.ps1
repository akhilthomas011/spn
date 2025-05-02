function New-ServicePrincipal {
    <#
    .SYNOPSIS
    Creates a new Service Principal Name (SPN) in Microsoft Entra ID (Azure AD) and assigns it specified RBAC roles in a given subscription.

    .DESCRIPTION
    This script checks if an SPN with a specific name already exists in Microsoft Entra ID. If it does not exist, the script creates the SPN. 
    Additionally, it assigns the SPN the specified RBAC roles in the specified Azure subscription if the role assignments do not already exist. 

    .PARAMETER spnName
    The name of the Service Principal Name (SPN) to be created. This is a required parameter.

    .PARAMETER subscriptionId
    The Azure subscription ID where the SPN will be assigned the specified roles. This is a required parameter.

    .PARAMETER roles
    An array of RBAC roles to assign to the SPN in the specified subscription. This is a required parameter.

    .EXAMPLE
    # Example usage of the script
    . .\EntraID-Operations.ps1
    New-ServicePrincipal -spnName "MydemoServicePrincipal" -subscriptionId 361e9cf5-a5de-4ac8-8d6f-4f0349463032 -roles @("Owner")

    This command creates an SPN named "MyServicePrincipal" in Microsoft Entra ID and assigns it the 'Owner' role in the subscription 
    with ID "361e9cf5-a5de-4ac8-8d6f-4f0349463032", if these do not already exist.

    .NOTES
    - Ensure that you are logged into Azure CLI with sufficient permissions to create SPNs and assign roles.
    - The script uses Azure CLI commands, so Azure CLI must be installed and configured on the system.
    - The script outputs the SPN name and application ID upon successful execution.
    - Permissions needed in Entra ID to run the script:
        - Application.ReadWrite.All
        - Directory.ReadWrite.All
        - RoleManagement.ReadWrite.Directory

    .OUTPUTS
    The script outputs the following details:
    - SPN Name
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$spnName,

        [Parameter(Mandatory = $false)]
        [string]$subscriptionId,

        [Parameter(Mandatory = $false)]
        [string[]]$roles
    )

    $ErrorActionPreference = "Stop" 

    try {
        # Check if SPN already exists
        $existingSPN = az ad sp list --display-name $spnName | ConvertFrom-Json
        if ($? -eq $false) {
            throw 'Failed to check SPN.'
        }
    }
    catch {
        Write-Error "Failed to check if SPN '$spnName' exists: $_"
        throw
    }

    if (-not $existingSPN) {
        try {
            Write-Verbose "SPN '$spnName' does not exist. Creating a new SPN..."
            $spn = az ad sp create-for-rbac --name $spnName | ConvertFrom-Json
            if ($? -eq $false) {
                throw 'Failed to create SPN.'
            }
            Write-Verbose "SPN '$spnName' created successfully."
        }
        catch {
            Write-Error "Failed to create SPN '$spnName': $_"
            throw
        }
    }
    else {
        $spn = $existingSPN[0]
        Write-Verbose "SPN '$spnName' already exists. Skipping creation."
    }

    if ($subscriptionId) {
        try {
            # Check if the subscription exists
            $subscription = az account list --query "[?id=='$subscriptionId']" | ConvertFrom-Json
            if ($? -eq $false) {
                throw 'Subscription listing failed.'
            }
        }
        catch {
            Write-Error "Failed to check if subscription '$subscriptionId' exists: $_"
            throw
        }

        if (-not $subscription) {
            Write-Verbose "Subscription '$subscriptionId' does not exist. Skipping role assignment."
            return
        }

        if ($roles) {
            foreach ($role in $roles) {
                # Check if the SPN has the specified role assignment in the subscription
                try {
                    $roleAssignment = az role assignment list --assignee $spn.appId --scope "/subscriptions/$subscriptionId" --role $role | ConvertFrom-Json
                    if ($? -eq $false) {
                        throw 'Role assignment do not exist.'
                    }
                }
                catch {
                    Write-Error "Failed to check role assignment for SPN '$spnName' and role '$role': $_"
                    throw
                }

                if (-not $roleAssignment) {
                    try {
                        Write-Verbose "Assigning '$role' role to SPN '$spnName' in subscription '$subscriptionId'..."
                        az role assignment create --assignee $spn.appId --role $role --scope "/subscriptions/$subscriptionId" | Out-Null
                        if ($? -eq $false) {
                            throw 'Role assignment failed.'
                        }
                        else {
                            Write-Verbose "'$role' role assigned successfully."
                        }
                        
                    }
                    catch {
                        Write-Error "Failed to assign '$role' role to SPN '$spnName': $_"
                        throw
                    }
                }
                else {
                    Write-Verbose "SPN '$spnName' already has '$role' role in subscription '$subscriptionId'. Skipping role assignment."
                }
            }
        }
        else {
            Write-Verbose "No roles specified. Skipping role assignment."
        }
    }
    else {
        Write-Verbose "No subscription ID specified. Skipping role assignment."
    }

    # Output SPN details
    return @{
        SPNName  = $spnName
        ObjectId = $spn.id
        TenantId = $spn.tenant
    }
}


function New-SecurityGroup {
    <#
    .SYNOPSIS
    Creates a new security group in Microsoft Entra ID (Azure AD) if it does not already exist.
    .DESCRIPTION
    This script checks if a security group with a specific name already exists in Microsoft Entra ID. If it does not exist, the script creates the security group.
    .PARAMETER groupName
    The name of the security group to be created. This is a required parameter.
    .EXAMPLE
    # Example usage of the script
    . .\EntraID-Operations.ps1
    New-SecurityGroup -groupName "MyDemoSecurityGroup"
    This command creates a security group named "MyDemoSecurityGroup" in Microsoft Entra ID if it does not already exist.
    .NOTES
    - Ensure that you are logged into Azure CLI with sufficient permissions to create security groups.
    - The script uses Azure CLI commands, so Azure CLI must be installed and configured on the system.
    - The script outputs the security group name and object ID upon successful execution
    - Permissions needed in Entra ID to run the script:
        - Group.ReadWrite.All
        - Directory.ReadWrite.All
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$groupName
    )

    $ErrorActionPreference = "Stop"

    try {
        # Check if the security group already exists
        $existingGroup = az ad group list --filter "displayName eq '$groupName'" | ConvertFrom-Json
        if ($? -eq $false) {
            throw 'Failed to check security group.'
        }
    }
    catch {
        Write-Error "Failed to check if security group '$groupName' exists: $_"
        throw
    }

    if (-not $existingGroup) {
        try {
            Write-Verbose "Security group '$groupName' does not exist. Creating a new security group..."
            $group = az ad group create --display-name $groupName --mail-nickname $groupName | ConvertFrom-Json
            if ($? -eq $false) {
                throw 'Failed to create security group.'
            }
            Write-Verbose "Security group '$groupName' created successfully."
        }
        catch {
            Write-Error "Failed to create security group '$groupName': $_"
            throw
        }
    }
    else {
        $group = $existingGroup[0]
        Write-Verbose "Security group '$groupName' already exists. Skipping creation."
    }

    return @{ Name = $group.displayName; ObjectId = $group.id }
}

function Add-SPNToSecurityGroup {
    <#
    .SYNOPSIS
    Adds a Service Principal Name (SPN) to a specified security group in Microsoft Entra ID (Azure AD).
    .DESCRIPTION
    This script checks if a security group with a specific name exists in Microsoft Entra ID. If it does, the script checks if the specified SPN is already a member of the group. If not, it adds the SPN to the group.
    .PARAMETER groupName
    The name of the security group to which the SPN will be added. This is a required parameter.
    .PARAMETER spnObjectId
    The object ID of the Service Principal Name (SPN) to be added to the security group. This is a required parameter.
    .EXAMPLE
    # Example usage of the script
    . .\EntraID-Operations.ps1
    Add-SPNToSecurityGroup -groupName "MyDemoSecurityGroup" -spnObjectId "12345678-1234-1234-1234-123456789012"
    This command adds the SPN with object ID "12345678-1234-1234-1234-123456789012" to the security group named "MyDemoSecurityGroup" in Microsoft Entra ID if it is not already a member of the group.
    .NOTES
    - Ensure that you are logged into Azure CLI with sufficient permissions to add SPNs to security groups.
    - The script uses Azure CLI commands, so Azure CLI must be installed and configured on the system.
    - The script outputs a message indicating whether the SPN was added successfully or if it was already a member of the group.
    - Permissions needed in Entra ID to run the script:
        - Group.ReadWrite.All
        - Directory.ReadWrite.All
        - User.ReadWrite.All
    .OUTPUTS
    - Retuns true if the SPN was added successfully, otherwise returns false.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$groupName,

        [Parameter(Mandatory = $true)]
        [string]$spnObjectId
    )

    $ErrorActionPreference = "Stop"

    try {
        # Check if the security group exists
        $existingGroup = az ad group list --filter "displayName eq '$groupName'" | ConvertFrom-Json
        if ($? -eq $false) {
            throw 'Failed to check security group.'
        }
    }
    catch {
        Write-Error "Failed to check if security group '$groupName' exists: $_"
        throw
    }

    if (-not $existingGroup) {
        Write-Error "Security group '$groupName' does not exist. Cannot add SPN."
        return $false
    }

    try {
        # Check if SPN is already a member of the security group
        $groupObjectId = $existingGroup[0].id
        $isGroupMember = az ad group member check --group $groupObjectId --member-id $spnObjectId | ConvertFrom-Json
        if ($? -eq $false) {
            throw 'Failed to list group members.'
        }
        if ($($isGroupMember.value)) {
            Write-Verbose "SPN with Object ID '$spnObjectId' is already a member of security group '$groupName'."
            return $true
        }

        # Add SPN to the security group
        Write-Verbose "Adding SPN with Object ID '$spnObjectId' to security group '$groupName'..."
        az ad group member add --group $groupName --member-id $spnObjectId | Out-Null
        if ($? -eq $false) {
            throw 'Failed to add SPN to security group.'
        }
        Write-Verbose "SPN added to security group '$groupName' successfully."
        return $true
    }
    catch {
        Write-Error "Failed to add SPN to security group '$groupName': $_"
        throw
    }
}