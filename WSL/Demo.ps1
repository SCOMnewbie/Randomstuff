throw "Don't press F5"

# IMPORTANT
# Most demo file has been copied from John savill demo: https://raw.githubusercontent.com/johnthebrit/RandomStuff/master/WSL/Demo.ps1

# TLDR
<#
# Make sure the base image is up to date on regular basis
wsl -d Ubuntu-22.04 sudo apt update `&`& sudo apt upgrade   # Make sure to escape the & on powershell
# export "goldimage"
wsl --export Ubuntu-22.04 C:\WSL\Updated-Ubuntu2204.vhdx --vhd
# Create a new wsl sandbox distro
wsl --import sandbox01 $env:USERPROFILE\.wsl\sandbox01 C:\WSL\Updated-Ubuntu2204.vhdx --vhd
# connect on it
wsl -d sandbox01
notepad.exe 
#>

# Main documentation
Start-process https://learn.microsoft.com/en-us/windows/wsl/

#Enable virtualization platform
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart

#Install WSL
#Don't do this as this in the inbox and not latest
#dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart

#INSTALL WSL FROM THE STORE FOR LATEST VERSION, i.e. v2
wsl --install #will use the store version and install a default distribution
wsl --install --no-distribution #no default distribution
#OR
https://www.microsoft.com/store/productId/9P9TQF7MRM4R

#This is the distribution architecture. Leverages virtualization for the kernel instead of a translation layer (WSL1)
wsl --set-default-version 2

#What is the version of this app I'm running
wsl --version #if this does not work you need to get the store version
wsl --status

wsl --help #note are -<char> and --<term> for most

wsl --update #to update
#Will also update from the store including the kernel
#and would update from in-windows to the store version


#Global settings such as maximum resource, customizing kernel at
code %userprofile%/.wslconfig

#Can see the impact within distro
#Processor
lscpu
nproc --all
cat /proc/cpuinfo

#Memory
cat /proc/meminfo
free
#Both
top


#View available distributions
wsl --list --online
wsl --install kali-linux

#View all distributions installed
wsl --list --verbose
#or
wsl -l -v

#Check current location
$DistroName = 'Ubuntu'
(Get-ChildItem -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss | Where-Object { $_.GetValue("DistributionName") -eq $DistroName }).GetValue("BasePath") + "\ext4.vhdx"

#To move to custom location

#Terminate specific distribution
wsl -t Ubuntu
#Shutdown WSL (all)
wsl --shutdown

# download appx packages from https://learn.microsoft.com/en-us/windows/wsl/install-manual#downloading-distributions
Invoke-RestMethod -Uri 'https://aka.ms/wslubuntu2204' -OutFile Ubuntu2204.appx
Add-AppxPackage -Path .\Ubuntu2204.appx
# sideload windows store app
rm .\Ubuntu2204.appx

#export
wsl --export Ubuntu-22.04 C:\WSL\Updated-Ubuntu2204.vhdx
C:\WSL\Updated-Ubuntu2204.vhdx

#Then
wsl --unregister Ubuntu

#Import to location of your choice
mkdir $env:USERPROFILE\.wsl
wsl --import Ubuntu01 $env:USERPROFILE\.wsl\Ubuntu01 C:\WSL\Updated-Ubuntu2204.vhdx

wsl --list --verbose

#Can change the default
wsl --set-default Ubuntu

#Start and connect to distribution
wsl -d Ubuntu

#To avoid entering password at every sudo
sudo visudo
<#
Add to end of file
john    ALL=(ALL) NOPASSWD:ALL
#>

#See our processes. Note we are running in our own namespace in a shared kernel. init -> bash
#We see multiple init forked processes as it has multiple functions such as actual init then interoperability services and others
#Also the plan9 for file system sharing from Linux to Windows
ps -ef

#Can see the full services for a distribution
wsl --system -d Ubuntu ps -ef

# Install docker without docker desktop
start-process https://docs.docker.com/engine/install/ubuntu/#install-using-the-repository


#File system mount of the ext4.vhdx -> /mnt/wslg
Wsl --system -d ubuntu df -h /mnt/wslg/distro #Windows
#Linux
df -h
ls /mnt/wslg/distro
cat /mnt/wslg/distro/etc/os-release
cat /etc/os-release


#File systems
ls /mnt/s #on Linux to view Windows

ls \\wsl.localhost\Ubuntu\proc #on Windows to view the Linux
#Distro specific configurations
cat \\wsl.localhost\Docker\etc\wsl.conf #note will be pause if not running as it starts it
#Global settings in %userprofile%\.wslconfig
#In explorer can just navigate then launch pwsh.exe to be in that folder and even view processes etc

#Systemd support
sudo -e /etc/wsl.conf
<#ADD
[boot]
systemd=true
#>
cat /etc/wsl.conf
wsl -t Ubuntu #from command then restart

#Graphical
sudo apt install firefox #uses snap which needs systemd enabled
snap install firefox
firefox
sudo apt install gnome-mahjongg
sudo apt install x11-apps -y && xeyes


#Network port mapping
sudo apt update
sudo apt install nodejs
node -v
hostname -I #check my IP
#In my RandomStuff repo location
cd /mnt/c/Users/john/OneDrive/projects/GIT/RandomStuff
node ./doggos/doggoecho.js 80 127.0.0.1
#On Windows host
netstat -ab #Note wslrelay.exe has the port mapped!
#Open on my Windows box to http://127.0.0.1
