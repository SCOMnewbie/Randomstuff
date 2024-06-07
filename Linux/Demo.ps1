throw "Don't press F5"

# Add a binary in system path
sudo mv /home/zyxia/opa /user/local/bin #restart session
notepad.exe 
#create fullpath
mkdir -p /root/.config/powershell/
notepad.exe /root/.config/powershell/Microsoft.PowerShell_profile.ps1 #thx wsl
# Add oh-my-posh init pwsh | Invoke-Expression

#Add Cloud init in WSL
https://docs.cloud-init.io/en/latest/tutorial/wsl.html


#List shells
cat /etc/shells
#force new shell
sudo chsh
add ->>> /usr/bin/pwsh