# create-spn.ps1

<#
.SYNOPSIS
Creates a new Service Principal Name (SPN) in Microsoft Entra ID (Azure AD) and assigns it the 'Owner' role in a specified subscription.

.DESCRIPTION
This script checks if an SPN with a specific name already exists in Microsoft Entra ID. If it does not exist, the script creates the SPN. 
Additionally, it assigns the SPN the specified RBAC role in the specified Azure subscription if the role assignment does not already exist. 

.PARAMETER spnName
The name of the Service Principal Name (SPN) to be created. This is a required parameter.

.PARAMETER subscriptionId
The Azure subscription ID where the SPN will be assigned the 'Owner' role. This is a required parameter.

.EXAMPLE
# Example usage of the script
.\create-spn.ps1 -spnName "MyServicePrincipal" -subscriptionId "12345"

This command creates an SPN named "MyServicePrincipal" in Microsoft Entra ID and assigns it the 'Owner' role in the subscription with ID "12345", 
if these do not already exist.

.NOTES
- Ensure that you are logged into Azure CLI with sufficient permissions to create SPNs and assign roles.
- The script uses Azure CLI commands, so Azure CLI must be installed and configured on the system.
- The script outputs the SPN name and application ID upon successful execution.

.OUTPUTS
The script outputs the following details:
- SPN Name
- SPN Application ID
#>

function New-SPN {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$spnName,

        [Parameter(Mandatory = $true)]
        [string]$subscriptionId
    )

    try {
        # Check if SPN already exists
        $existingSPN = az ad sp list --display-name $spnName | ConvertFrom-Json
    }
    catch {
        Write-Error "Failed to check if SPN '$spnName' exists: $_"
        throw
    }

    if (-not $existingSPN) {
        try {
            Write-Host "SPN '$spnName' does not exist. Creating a new SPN..."
            $spn = az ad sp create-for-rbac --name $spnName --skip-assignment | ConvertFrom-Json
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

    # Check if the SPN has 'Owner' role assignment in the subscription
    try {
        $roleAssignment = az role assignment list --assignee $spn.appId --scope "/subscriptions/$subscriptionId" --role "Owner" | ConvertFrom-Json
    }
    catch {
        Write-Error "Failed to check role assignment for SPN '$spnName': $_"
        throw
    }

    if (-not $roleAssignment) {
        try {
            Write-Host "Assigning 'Owner' role to SPN '$spnName' in subscription '$subscriptionId'..."
            az role assignment create --assignee $spn.appId --role "Owner" --scope "/subscriptions/$subscriptionId"
            Write-Host "'Owner' role assigned successfully."
        }
        catch {
            Write-Error "Failed to assign 'Owner' role to SPN '$spnName': $_"
            throw
        }
    }
    else {
        Write-Host "SPN '$spnName' already has 'Owner' role in subscription '$subscriptionId'. Skipping role assignment."
    }

    # Output SPN details
    Write-Host "SPN Name: $spnName"
    Write-Host "SPN Application ID: $($spn.appId)"
}