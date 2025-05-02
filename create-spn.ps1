# create-spn.ps1

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
.\create-spn.ps1 -spnName "MyServicePrincipal" -subscriptionId "12345" -roles @("Owner", "Contributor")

This command creates an SPN named "MyServicePrincipal" in Microsoft Entra ID and assigns it the 'Owner' and 'Contributor' roles in the subscription 
with ID "12345", if these do not already exist.

.NOTES
- Ensure that you are logged into Azure CLI with sufficient permissions to create SPNs and assign roles.
- The script uses Azure CLI commands, so Azure CLI must be installed and configured on the system.
- The script outputs the SPN name and application ID upon successful execution.

.OUTPUTS
The script outputs the following details:
- SPN Name
#>

function New-ServicePrincipal {
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
            Write-Host "SPN '$spnName' does not exist. Creating a new SPN..."
            $spn = az ad sp create-for-rbac --name $spnName | ConvertFrom-Json
            if ($? -eq $false) {
                throw 'Failed to create SPN.'
            }
            Write-Host "SPN '$spnName' created successfully."
        }
        catch {
            Write-Error "Failed to create SPN '$spnName': $_"
            throw
        }
    }
    else {
        $spn = $existingSPN[0]
        Write-Host "SPN '$spnName' already exists. Skipping creation."
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
            Write-Host "Subscription '$subscriptionId' does not exist. Skipping role assignment."
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
                        Write-Host "Assigning '$role' role to SPN '$spnName' in subscription '$subscriptionId'..."
                        az role assignment create --assignee $spn.appId --role $role --scope "/subscriptions/$subscriptionId" | Out-Null
                        if ($? -eq $false) {
                            throw 'Role assignment failed.'
                        }
                        else {
                            Write-Host "'$role' role assigned successfully."
                        }
                        
                    }
                    catch {
                        Write-Error "Failed to assign '$role' role to SPN '$spnName': $_"
                        throw
                    }
                }
                else {
                    Write-Host "SPN '$spnName' already has '$role' role in subscription '$subscriptionId'. Skipping role assignment."
                }
            }
        }
        else {
            Write-Host "No roles specified. Skipping role assignment."
        }
    }
    else {
        Write-Host "No subscription ID specified. Skipping role assignment."
    }

    # Output SPN details
    Write-Host "SPN Name: $spnName"
}