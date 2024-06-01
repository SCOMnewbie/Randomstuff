Function Set-sshPrivateKey {
    <#
.SYNOPSIS

This function will use a prvate key we pass as parameter and set it on the disk.

.DESCRIPTION

This function will use a prvate key we pass as parameter and set it on the disk.

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
        [String] $PrivateKey,
        [Parameter(Mandatory)]
        [String] $VirtualMachineName,
        [String] $PrivateKeyFilePath = "/root/.ssh"
    )
    
    if(Test-path $PrivateKeyFilePath){
        Write-Verbose ".ssh folder already exist, no need to create it"
    }
    else{
        Write-Verbose ".ssh folder does not exist, let's create it"
        New-Item -Path $PrivateKeyFilePath -ItemType Directory -Force | Out-Null
    }

    New-Item -Path $PrivateKeyFilePath -Name $VirtualMachineName -Value $PrivateKey -Force | Out-Null


    chmod 400 $(Join-Path $PrivateKeyFilePath $VirtualMachineName)
}