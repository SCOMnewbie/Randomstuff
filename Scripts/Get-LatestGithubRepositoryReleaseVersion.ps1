Function Get-LatestGithubRepositoryReleaseVersion {
    <#
.SYNOPSIS

Return the latest version of a Github released repository artifact.

.DESCRIPTION

A lot of repositories expose their releases. Github is providing a simple way to fetch the latest released versions. https://docs.github.com/en/repositories/releasing-projects-on-github/linking-to-releases

.PARAMETER RepositoryName
Specify the repository to use.

.PARAMETER OrganizationName
Specify the organization to use.

.EXAMPLE
PS> Get-LatestGithubRepositoryReleaseVersion -OrganizationName aquasecurity -RepositoryName trivy

.EXAMPLE
PS> Get-LatestGithubRepositoryReleaseVersion -OrganizationName project-copacetic -RepositoryName copacetic
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [String] $OrganizationName,
        [Parameter(Mandatory)]
        [String] $RepositoryName
    )
    
    $Regex = '.*tag/v(?<version>.*)'
    $Url = 'https://github.com/{0}/{1}/releases/latest' -f $OrganizationName.ToLower(),$RepositoryName.ToLower()

    Write-Verbose "[$((Get-Date).TimeOfDay)] Url is: $Url"
    $FetchUrl = Invoke-WebRequest $Url

    $FetchUrl.BaseResponse.RequestMessage.RequestUri.AbsoluteUri -match $Regex | Out-Null
    $Matches.version
}