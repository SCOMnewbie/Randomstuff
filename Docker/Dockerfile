FROM mcr.microsoft.com/powershell:latest

ARG TERRAFORM_VERSION=1.5.7
ARG TERRAFORM_VERSION_URL=https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip

SHELL ["pwsh", "-command", "$ErrorActionPreference = 'Stop';"]
# Install azcopy
RUN invoke-webrequest -Uri https://aka.ms/downloadazcopy-v10-linux -OutFile /tmp/azcopy.tar.gz && \
    tar -xvf /tmp/azcopy.tar.gz --exclude=*.txt -C /tmp/ && \
    cp /tmp/azcopy_linux_amd64_*/azcopy /usr/bin/

# Install required pwsh modules
RUN Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
RUN Install-module az.accounts, az.resources, pester, PSMSALNet

# Install AWS CLI
RUN Invoke-WebRequest -Uri "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -OutFile /tmp/awscli.zip && \
    Expand-Archive /tmp/awscli.zip /tmp && \
    /tmp/aws/install

# Install Az CLI
RUN Invoke-WebRequest -Uri "https://aka.ms/InstallAzureCLIDeb" -OutFile /tmp/deb_install.sh && \
    bash /tmp/deb_install.sh

# Install Terraform 
RUN Invoke-WebRequest -Uri $env:TERRAFORM_VERSION_URL -OutFile /tmp/terraform.zip && \
    Expand-Archive /tmp/terraform.zip /usr/bin

# Clean the image
RUN Remove-Item /tmp/* -Recurse -Force -Confirm:$false