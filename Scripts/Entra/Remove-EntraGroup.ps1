function Remove-EntraGroup {
<#
.SYNOPSIS
    Small function to remove multiple Entra groups.
.DESCRIPTION
    Small function to remove multiple Entra groups.
.PARAMETER AccessToken
    The access token to authenticate with the Microsoft Graph API.
.PARAMETER GroupId
    An array of Group IDs to be removed.
.EXAMPLE
    PS> $token = az account get-access-token --resource-type ms-graph | ConvertFrom-Json -Depth 2 | % accessToken
    PS> Remove-EntraGroup -AccessToken $token -GroupId @("group-id-1", "group-id-2")
    This command will remove the specified groups from Entra ID.
#>
    param (
        [string]$AccessToken,
        [Guid[]]$GroupId
    )

    # Loop through each Group ID and send a DELETE request
    foreach ($id in $GroupId) {
        $uri = "https://graph.microsoft.com/v1.0/groups/{0}" -f $id
        Write-Verbose "Working on group ID: $id"

        try {
            $response = Invoke-RestMethod -Uri $uri -Method Delete -Headers @{
                "Authorization" = "Bearer $AccessToken"
                "Content-Type"  = "application/json"
            }

            Write-Output "Successfully deleted group: $id"
        } catch {
            Write-Error "Failed to delete group: $id. Error: $_"
        }
    }
}
