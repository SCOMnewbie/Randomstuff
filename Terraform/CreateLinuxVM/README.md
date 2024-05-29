https://learn.microsoft.com/en-us/azure/virtual-machines/linux/quick-create-terraform?tabs=azure-cli

docker run -it --rm -v /mnt/c/Git/Public/Randomstuff/Terraform/CreateLinuxVM:/root/scripts ghcr.io/scomnewbie/admintools:latest

az login
cd /root/scripts/
terraform init -upgrade
terraform plan -out main.tfplan
terraform apply "main.tfplan"

terraform destroy -auto-approve

Store ssh key locally

$VaultName = "kv1039c37bb5c87bef"
$PrivateKey = az keyvault secret show --vault-name $VaultName -n myvm | ConvertFrom-Json | % value

. ./functions.ps1
Set-sshPrivateKey -PrivateKey $PrivateKey -VirtualMachineName myVM -Verbose
ssh -i /root/.ssh/myVM azureadmin@13.82.145.27