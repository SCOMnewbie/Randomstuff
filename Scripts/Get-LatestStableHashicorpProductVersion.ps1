Function Get-LatestStableHashicorpProductVersion {
<#
.SYNOPSIS

Return the latest stable version of several Hashicorp products.

.DESCRIPTION

Return the latest stable version of several Hashicorp products.

.PARAMETER Product
Specify the product you're interrested in.

.EXAMPLE
PS> Get-LatestStableHashicorpProductVersion -Product vault
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [ValidateSet('Terraform','Vault','Consul','Nomad','Packer')]
        [String] $Product
    )
    
    $Regex = '^\/.*\/(?<version>\d+\.\d+\.\d+)\/.*$'
    $Url = 'https://releases.hashicorp.com/{0}' -f $Product.ToLower()

    Write-Verbose "[$((Get-Date).TimeOfDay)] Url is: $Url"
    $FetchUrl = Invoke-WebRequest $Url

    # Select the first 20 links, make sure we select only the stable versions (not beta, alpha...) then catch all versions only and select the first one
    $FetchUrl.links.href | Select-Object -First 20 | Select-String -Pattern $Regex -AllMatches | ForEach-Object matches | ForEach-Object Groups | Where-Object Name -EQ Version | ForEach-Object value | Select-Object -First 1
}