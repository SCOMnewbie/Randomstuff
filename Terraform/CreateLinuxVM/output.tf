output "resource_group_name" {
  value = azurerm_resource_group.rg.name
}

output "public_ip_address" {
  value = azurerm_linux_virtual_machine.my_terraform_vm.public_ip_address
}

output "keyvault_url" {
  value = azurerm_key_vault.keyvault
}


#output "private_key_data" {
#  value = azapi_resource_action.ssh_public_key_gen.output.privateKey
#}

#output "key_data" {
#  value = azapi_resource_action.ssh_public_key_gen.output.publicKey
#}


