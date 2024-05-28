https://learn.microsoft.com/en-us/azure/virtual-machines/linux/quick-create-terraform?tabs=azure-cli

docker run -it --rm -v /mnt/c/Git/Public/Randomstuff/Terraform/CreateLinuxVM:/home/root/scripts ghcr.io/scomnewbie/admintools:latest

az login
cd /home/root/scripts/
terraform init -upgrade
terraform plan -out main.tfplan
terraform apply "main.tfplan"

