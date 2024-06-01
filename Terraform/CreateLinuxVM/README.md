https://learn.microsoft.com/en-us/azure/virtual-machines/linux/quick-create-terraform?tabs=azure-cli

docker run -it --rm -v /mnt/c/Git/Public/Randomstuff/Terraform/CreateLinuxVM:/root/scripts ghcr.io/scomnewbie/admintools:latest

az login
cd /root/scripts/
terraform init -upgrade
terraform plan -out main.tfplan
terraform apply "main.tfplan"

$tfInfo = terraform output -json | ConvertFrom-Json
$PrivateKey = az keyvault secret show --vault-name $tfInfo.keyvault_name.value -n $tfInfo.virtual_machine_name.value | ConvertFrom-Json | % value
. ./functions.ps1
Set-sshPrivateKey -PrivateKey $PrivateKey -VirtualMachineName $tfInfo.virtual_machine_name.value -Verbose
ssh -i "/root/.ssh/$($tfInfo.virtual_machine_name.value)" azureadmin@$($tfInfo.public_ip_address.value)

terraform destroy -auto-approve