data "azurerm_client_config" "current" {}

resource "random_pet" "rg_name" {
  prefix = var.resource_group_name_prefix
}

resource "azurerm_resource_group" "rg" {
  location = var.resource_group_location
  name     = random_pet.rg_name.id
}

# Create virtual network
resource "azurerm_virtual_network" "my_terraform_network" {
  name                = "myVnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

# Create subnet
resource "azurerm_subnet" "my_terraform_subnet" {
  name                 = "mySubnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.my_terraform_network.name
  address_prefixes     = ["10.0.1.0/24"]
}

# Create public IPs
resource "azurerm_public_ip" "my_terraform_public_ip" {
  name                = "myPublicIP"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Dynamic"
}

# Create Network Security Group and rule
resource "azurerm_network_security_group" "my_terraform_nsg" {
  name                = "myNetworkSecurityGroup"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  security_rule {
    name                       = "SSH"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = var.myipaddress
    destination_address_prefix = "*"
  }
}

# Create network interface
resource "azurerm_network_interface" "my_terraform_nic" {
  name                = "myNIC"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "my_nic_configuration"
    subnet_id                     = azurerm_subnet.my_terraform_subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.my_terraform_public_ip.id
  }
}

# Connect the security group to the network interface
resource "azurerm_network_interface_security_group_association" "example" {
  network_interface_id      = azurerm_network_interface.my_terraform_nic.id
  network_security_group_id = azurerm_network_security_group.my_terraform_nsg.id
}

# Generate random text for a unique storage account name
resource "random_id" "random_id" {
  keepers = {
    # Generate a new ID only when a new resource group is defined
    resource_group = azurerm_resource_group.rg.name
  }

  byte_length = 8
}

# Create storage account for boot diagnostics
resource "azurerm_storage_account" "my_storage_account" {
  name                     = "diag${random_id.random_id.hex}"
  location                 = azurerm_resource_group.rg.location
  resource_group_name      = azurerm_resource_group.rg.name
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

# Create virtual machine
resource "azurerm_linux_virtual_machine" "my_terraform_vm" {
  name                  = "myVM"
  location              = azurerm_resource_group.rg.location
  resource_group_name   = azurerm_resource_group.rg.name
  network_interface_ids = [azurerm_network_interface.my_terraform_nic.id]
  size                  = "Standard_DS1_v2"

  os_disk {
    name                 = "myOsDisk"
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  computer_name  = "hostname"
  admin_username = var.username

  admin_ssh_key {
    username   = var.username
    public_key = azapi_resource_action.ssh_public_key_gen.output.publicKey
  }

  identity {
    type = "SystemAssigned"
  }

  boot_diagnostics {
    storage_account_uri = azurerm_storage_account.my_storage_account.primary_blob_endpoint
  }

  custom_data = base64encode(<<EOF
  #cloud-config
  write_files:
    - content: |
        new-item -Path "/home/azureadmin/git/$(Get-Date -format "yyyyMMddmmss").txt"
      path: "/home/azureadmin/git/mycommand.ps1"
      permissions: '770'
    - content: |
        [Unit]
        Description=My desc here to run my script

        [Service]
        ExecStart=pwsh -command "/home/azureadmin/git/mycommand.ps1"

        [Install]
        WantedBy=multi-user.target
      path: "/etc/systemd/system/mycommand.service"
      permissions: '770'
  runcmd:
    - apt-get -y update
    - sudo systemctl enable mycommand.service
    - wget https://raw.githubusercontent.com/PowerShell/PowerShell/master/tools/install-powershell.sh
    - chmod 755 install-powershell.sh
    - ./install-powershell.sh
    - sudo chown -R azureadmin: /home/azureadmin
    - git config --global user.name "scomnewbie"
    - git config --global user.email "leon.francois75@gmail.com"
    - git clone "https://${var.gitPat}@github.com/SCOMnewbie/PesterPOC.git" /home/azureadmin/git/PesterPOC
    - apt-get -y clean
    - apt-get -y autoremove --purge
    - reboot
  package_upgrade: true
  packages:
  - curl
  package_reboot_if_required: true
  power_state:
    delay: now
    mode: reboot
    message: Rebooting the OS
    condition: if [ -e /var/run/reboot-required ]; then exit 0; else exit 1; fi
  EOF
  )
}

resource "azurerm_key_vault" "keyvault" {
  name                        = "kv${random_id.random_id.hex}"
  location                    = azurerm_resource_group.rg.location
  resource_group_name         = azurerm_resource_group.rg.name
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  public_network_access_enabled = true
  enable_rbac_authorization = true
  soft_delete_retention_days  = 7
  purge_protection_enabled    = true
  sku_name                    = "standard"
}

resource "azurerm_role_assignment" "assign_current_user_kv_secret_officier" {
  scope              = azurerm_key_vault.keyvault.id
  role_definition_id = "/providers/Microsoft.Authorization/roleDefinitions/b86a8fe4-44ce-4948-aee5-eccb2c155cd7" #Key vault secret officier
  principal_id       = data.azurerm_client_config.current.object_id
}

resource "azurerm_role_assignment" "assign_vm_kv_secret_officier" {
  scope              = azurerm_key_vault.keyvault.id
  role_definition_id = "/providers/Microsoft.Authorization/roleDefinitions/b86a8fe4-44ce-4948-aee5-eccb2c155cd7" #Key vault secret officier
  principal_id       = azurerm_linux_virtual_machine.my_terraform_vm.identity[0].principal_id
}

resource "azurerm_key_vault_secret" "add_private_key_to_kv" {
  name         = "myVM"
  value        = azapi_resource_action.ssh_public_key_gen.output.privateKey
  key_vault_id = azurerm_key_vault.keyvault.id

  depends_on = [
    azurerm_role_assignment.assign_current_user_kv_secret_officier
  ]
}