function calluserinfofromgraphapi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName = 'UserPrincipalName')]
        [ValidatePattern('[\w-\.]+@([\w-]+\.)+[\w-]{2,4}')]
        [string]
        $UserPrincipalName,
        [Parameter(Mandatory, ParameterSetName = 'UserId')]
        [guid]
        $UserId,
        [parameter(Mandatory)]
        $ClientId,
        [parameter(Mandatory)]
        $ClientSecret,
        [parameter(Mandatory)]
        $TenantId,
        [parameter(Mandatory)]
        [string] $OBOToken
    )

    $OBOToken = $OBOToken.ToString().Replace('Bearer ', '')
    $GraphToken = Get-EntraToken -OnBehalfFlowWithSecret -ClientId $ClientId -ClientSecret $ClientSecret -UserAssertion $OBOToken -Resource GraphAPI -Permissions 'User.Read.All' -TenantId $TenantId | % AccessToken
    $Headers = @{
        'Authorization' = $("Bearer $GraphToken")
    }
    
    if ($PSBoundParameters.ContainsKey('UserPrincipalName')) {
        $uri = "https://graph.microsoft.com/v1.0/users/$UserPrincipalName"
    }
    else{
        $uri = "https://graph.microsoft.com/v1.0/users/$UserId"
    }
    #Removed the retry count to avoid slow things down. A not found is considered as an error.
    $Params = @{
        Headers     = $Headers
        uri         = $uri
        Body        = $null
        method      = 'Get'
        ErrorAction = 'Stop'
        Verbose     = $false
    }
    try {
        Invoke-RestMethod @Params
    }
    catch [Microsoft.PowerShell.Commands.HttpResponseException] {
        if ($_.Exception.Message -eq 'Response status code does not indicate success: 404 (Not Found).') {
            return $null
        }
        else {
            $_.Exception.Message
        }
    }
    catch {
        $_.Exception.Message
    }
}