# How to use Windows Server to Create App Control Code Signing Certificate

> [!IMPORTANT]\
> [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) can [easily and quickly generate](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Build-New-Certificate) a Code Signing certificate to be used for signing App Control policies.
>
> This guide is only for those who want to learn how to setup a Windows Server with Active Directory and Certification Authority roles and create their own CA.

## Introduction

* By deploying a **Signed** App Control for Business policy, a system will be secure and resistant to any form of tampering ([if coupled with BitLocker and other built-in security features](https://github.com/HotCakeX/Harden-Windows-Security)), in a way that **even the system administrator can't tamper or disable this security policy.**

* The [**only** way for this security feature](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/disable-appcontrol-policies#removing-app-control-policies) to be turned off, modified, updated or disabled will be to have access to the certificate's private keys used to sign it.

* [Refer to Microsoft's website](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/appcontrol-design-guide) or [my other wiki posts](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Introduction) If you want to learn about App Control itself and how to create a customized App Control policy for your own environment.

* Always test and deploy your App Control policy in Audit mode or Unsigned mode first to make sure it works correctly, before deploying the Signed version of it.
    - The [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-App-Control-Policy) has a ***Test Mode*** option when creating policies that will create/deploy the policies with ***Boot Audit on Failure*** and ***Advanced Boot Options Menu*** policy rule options. [You can also add those options to other policies that have already been created.](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Configure-Policy-Rule-Options).

* Keep the xml file(s) of the deployed base policy(s) in a safe place, they are needed, along with the certificate that signed them, if you decide to disable or modify the signed deployed App Control policy later on.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## TL;DR (Short version)

1. Install the latest Windows Server, Install AD/DS and AD/CS roles on it. (≈15 mins depending on hardware and if downloaded ISO or VHDX)
2. Use the Enterprise CA's code signing template to create a customized certificate template for App Control Signing (≈5 minutes)
3. Generate the certificate and use it to sign the App Control Policy (≈3 minutes)

That's essentially everything we have to do. So, if you are already familiar with the concepts, you can go straight to the bottom of this page and use the resources section to refer to Microsoft's guides to create and deploy the Signed App Control policy.

But if you aren't familiar, keep reading as I've thoroughly explained every step to set up Windows Server, generate signing certificate and sign the App Control policy. It takes about 20 minutes for me and depending on the hardware, it can even take less time.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Prerequisites

Latest Windows Server, it's free for 180 days for evaluation and comes in ISO and VHDX formats.

* [Download Windows Server 2025](https://www.microsoft.com/en-us/evalcenter/download-windows-server-2025) from [Microsoft Evaluation Center](https://www.microsoft.com/en-us/evalcenter).

Once we have our Windows installation media (ISO or VHDX), we need to set up a Hyper-V VM on our host. For this guide, our host is a Windows 11 Pro for workstations machine.

Create a Hyper-V VM with these specifications:

* Secure Boot
* Trusted Platform Module (vTPM)
* At least 4 virtual processors
* At least 4 GB RAM
* At least ~20 GB storage
* Connect the Default Switch to the VM or create a Private Virtual switch in Virtual Switch Manager of Hyper-V manager, then add it as network adapter hardware to the VM.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Windows Server VM setup

After Windows Server installation has finished, you can create a [Hyper-V standard checkpoint](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/checkpoints) so you'll be able to restore the VM's state to this point in time if you misconfigure something later on.

<br>

### Rename the server

Choose a meaningful name, like `CAServer`. Use this [PowerShell cmdlet](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/rename-computer) to easily do that, it will restart the server to apply the new name.

```powershell
Rename-Computer CAServer -Restart
```

<br>

### Using GUI: Install Active Directory Domain Services

From Server Manager => Add Roles and Features => Role-based or feature-based installation => Select the current server you are on => Select Active Directory Domain Services from the list => Select "Add Features" => Continue the rest of the steps by selecting Next.

After installation is over, open the notifications in the Server Manager, (there will probably be a yellow icon on it), Select "Promote this server to a domain controller".

In the Deployment Configuration window that will be opened, select "Add a new forest" and in the Root domain name, enter a domain name.

It can be anything, even `Bing.com`, but for our usage let's use `CAServer.com`. On the next step, set a password for DSRM (Directory Services Restore Mode), It needs to have uppercase, lowercase and numbers (e.g., Bing6969), write this password down somewhere, like in Sticky notes app on your host.

Next, choose a NetBIOS domain name, the default one will be OK. Confirm and proceed with the rest of the steps by selecting Next and at the end select Install. Wait for the installation to finish. It will restart the Server once the Installation is finished.

<br>

### Using PowerShell: Install Active Directory Domain Services

Install (AD DS) role

```powershell
Install-windowsfeature -name AD-Domain-Services -IncludeManagementTools
```

Install a forest and set a forest password

```powershell
$password = ConvertTo-SecureString 'Bing6969' -AsPlainText -Force

Install-ADDSForest -DomainName CAServer.com -DomainNetbiosName CASERVER0 -SafeModeAdministratorPassword $password -InstallDNS:$false -Force
```

<br>

### Using GUI: Install Active Directory Certification Service and set up an Enterprise root CA (Certificate Authority)

From Server Manager => Add Roles and Features => Role-based or feature-based installation => Select the current server we are on => Select Active Directory Certification Service => Select Next for the rest of the steps and finally select install.

After installation is over, open the notifications in the Server Manager, (there will probably be a yellow icon on it), Select "Configure Active Directory Certificate Service on the destination server".

On the newly opened configuration window, on credentials section select next, on the Role services section check the box for `Certification Authority` and select next.

Select `Enterprise CA` (because Standalone CA does not support certificate templates that we are going to use) and select Next. On the CA Type section select `Root CA`. On the Private Key section select `Create a new private key`.

On the Cryptography section, for Cryptographic Provider choose `RSA#Microsoft Software Key Storage Provider`, for Key length choose `4096`, for Hash Algorithm choose `SHA512` and select Next. On the CA name section select next. On the Validity Period section set validity period to something like 50 Years. Select next for the rest of the sections and finally select Configure.

<br>

### Using PowerShell: Install Active Directory Certification Services and set up an Enterprise root CA

Install Active Directory Certificate Services

```powershell
Install-WindowsFeature Adcs-Cert-Authority -IncludeAllSubFeature
```

Install a new Enterprise CA

```powershell
Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -KeyLength 4096 -HashAlgorithmName SHA512 -ValidityPeriod Years -ValidityPeriodUnits 50 -Force
```

Restart the server because it is required, and Server Manager says it too

```powershell
Restart-Computer
```

Lastly do this so that Certification Authority option will be added to Server Manager => Tools and its GUI will become accessible and visible

```powershell
Add-WindowsFeature Adcs-Cert-Authority -IncludeManagementTools
```

<br>

### Configure the Validity period of the issued certificates on the server

[Microsoft's guide for this](https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/change-certificates-expiration-date)

We Increase the validity period of the certificates issued by the CA to 30 years:

```powershell
certutil -setreg ca\ValidityPeriod "Years"
certutil -setreg ca\ValidityPeriodUnits "30"
```

*Restart the Server after this step.*

You can verify and confirm the results using these commands:

```powershell
certutil -getreg ca\ValidityPeriod
certutil -getreg ca\ValidityPeriodUnits
```

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Follow the official guide to create certificate template and generate the signing certificate

Now open Certification Authority, you can do so by searching for it in Windows search or from Server Manager => Tools.
Once you open it, you can follow [the guide from Microsoft](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/create-code-signing-cert-for-appcontrol) to create the certificate template for App Control policy signing and then request and create a certificate.

<br>

Note that If the Server doesn't have at least 1 network adapter connected to it, then Certificate Templates don't load,
<details><summary>Screenshot</summary>

<img src="https://user-images.githubusercontent.com/118815227/219699959-fdf7b0df-ddae-45f8-ab2e-4381e88cefb0.png" alt="Screenshot of the error message showing that Hyper-V VM Server needs at least one Virtual Network Adapter.">

</details>

That's why our Hyper-V VM Server needs at least one Virtual Network Adapter.

<br>

The [guide suggests](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/create-code-signing-cert-for-appcontrol) using a client computer to request and create the certificate but since we are going to use the certificate for non-domain-joined computers and don't need to use the Active Directory, we can perform all of the steps on the same Windows Server VM.

These are some optional ***deviations*** from the [official guide](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/create-code-signing-cert-for-appcontrol) that **result in creating a successful and more secure certificate** for our App Control policy signing:

* On the Compatibility tab, you can select Windows Server 2016 from the Certification Authority list and select Windows 10 / Windows Server 2016 from the Certificate recipient list.

* On the General tab, you can set the Validity period to 30 years and Renewal period to 22 years. (The maximum allowed Renewal period for the validity period we chose.)

* On the Cryptography tab, you can set the Provider Category to `Key Storage Provider` [(KSP)](https://learn.microsoft.com/en-us/windows/win32/secgloss/c-gly?redirectedfrom=MSDN#_security_cryptographic_service_provider_gly). Set the Algorithm Name to `RSA`. Set the Minimum key size to `4096`. Set Request hash to `SHA512`.

As the [Microsoft's guide](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/create-code-signing-cert-for-appcontrol) suggests, you need to go to security tab to verify account access of the user(s) requesting the certificate, but since we are requesting and creating our certificate on the same CA server, we don't need to change anything there.

<br>

<details>
<summary> If we want to use a 2nd PC to do this, as described in Microsoft document (Totally Unnecessary) </summary>

<h3> Additional steps to perform on Windows Server </h3>

If you are going to create a new user account in "Active Directory Users and Computers" for use on the client VM, in Certification Authority when duplicating the certificate template, go to Security Tab and set the correct permissions for that user account so that it will be able to request and enroll the certificate.

For instance, since you are the only person who is going to use the Active Directory, you can even give `Full Control` permission to `Authenticated Users` group.

Alternatively, you can use the same administrator account that you are currently using on Windows Server, which exists by default in the Active Directory, to log into the other client computer. One can log into multiple computers with the same user account across an Active Directory domain. There is no limit by default to how many concurrent logins an active directory user can have.

Make sure the Windows Server and Windows client VMs both use the same Hyper-V Private Virtual switch network adapter. The VMs need to have static IP addresses on the same subnet in order to communicate with each other.

Go to Windows Settings => Network & Internet => Ethernet => in "IP Assignment" select "Edit" => Set it to "Manual" => Toggle the IPv4 => in IP Address Enter `10.10.10.1` and in Subnet Mask enter `255.0.0.0`. Without configuring anything else, save it.

Use the Edit button for DNS server assignment, set it to Manual, toggle the IPv4 button and in the Preferred DNS field enter `127.0.0.1`. Save everything and exit settings.

<br>

<h3> Steps to perform on Client VM </h3>

Make sure the client VM is running the latest version of Windows, and it follows the same prerequisites explained above.

Go to Windows Settings => Network & Internet => Ethernet => in "IP Assignment" select "Edit" => Set it to "Manual" => Toggle the IPv4 => in IP Address Enter `10.10.10.2` and in Subnet Mask enter `255.0.0.0`. Without configuring anything else, save it.

Now use the Edit button for DNS server assignment, set it to Manual, toggle the IPv4 button and in the Preferred DNS field enter the static IP address of the Windows Server VM, which was `10.10.10.1`. Save everything and exit settings.

Open an elevated PowerShell and <a href="https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/add-computer">enter this</a> to join the Active Directory domain:

```powershell
Add-Computer -DomainName <Domain> -Restart
```

You will be asked for credentials. If you are going to use the same Administrator account from Windows Server, use `Administrator` for username and enter the password of the Windows Server in the password field, otherwise use the password you set when creating the new user account in Active Directory Users and Computers.

After the client machine restarted, use `Other user` option on the lock screen and this time you will be using the Active Directory credentials to log into the machine. If using the built-in Administrator account, the password will be the same as the password on Windows Server account, but the username will be in the <Username@Domain> format, so in this case, it will be `Administrator@CAServer.com`.

Since you are using Administrator account, you can by default use Enhanced session in Hyper-V too.

To request the certificate and enroll it, you can follow <a href="https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/create-code-signing-cert-for-appcontrol">the Microsoft's guide</a>.

<br>

</details>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Create a Signed App Control policy

Once we have the certificate in the User Certificates store of either the Windows Server or a client machine, Right-click on it => All tasks => Export. Export the **Private key** and export all the Extended Properties, set a password for the certificate and set Encryption to `AES256-SHA256`. Select a location to export and it will create a `.pfx` file.

You also need to export the certificate **without private key**, in `DER encoded binary X.509` format which will create a `.cer` certificate file. We need this certificate to sign the App Control policy.

It is important to keep these 2 files, specially `.pfx` that contains the private key, in a safe place, such as [Azure Key Vault Managed HSM](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/overview) or [OneDrive Personal Vault](https://support.microsoft.com/en-us/office/protect-your-onedrive-files-in-personal-vault-6540ef37-e9bf-4121-a773-56f98dce78c4), so that if you delete all the VMs you created, you will be able to continue using the same certificate to sign further App Control policies and supplemental policies, at least for the next 22 years, before it needs a renewal. As you can see, all of that setup must be done just once ***every few decades.***

The [Personal Information Exchange (.pfx)](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/personal-information-exchange---pfx--files) file has great importance because it contains the Public key and **Private key** of the certificate so anyone who has access to this file [can disable](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/disable-appcontrol-policies#removing-app-control-policies) the deployed Signed App Control policy. It should never be shared with anyone outside your circle of trust. It is a password-protected file by nature.

<br>

## Use [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) to sign and deploy App Control policies

> [!TIP]\
> AppControl Manager has everything built-in for you. You can [**Deploy**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Deploy-App-Control-Policy), [**Modify**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Allow-New-Apps) and [**Remove**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/System-Information#policy-removal) Signed policies.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Extras

### How to interact with the hidden EFI partition

Using [Diskpart](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/diskpart), Open an elevated PowerShell console and run these commands **one by one**:

```powershell
diskpart
list disk
# double check to make sure it's the correct disk if you have more than 1
select disk 0
list part
# The EFI partitions type is System, and its size is approximately 100MB, make sure you choose the correct one
select part 1
assign letter=z
```

<br>

The `EFI` partition will be available in This PC with letter `Z`, but you can't access it without modifying permissions. There is however an easier way to access it and manually copy the Signed App Control policy binary to it. Open Task Manager as admin, select `Run New Task`, select `Browse` and now you can access drive `Z` (`EFI` partition) and copy the Signed `.cip` file in `Z:\EFI\Microsoft\Boot\CIPolicies\Active`.

<br>

### How to find the FQDN (Fully Qualified Domain Name) of the Windows Server

Using PowerShell

```powershell
(Get-ADComputer $(hostname)).DNSHostName
```

or

```powershell
"$env:computername.$env:userdnsdomain"
```

You can also use GUI of Server Manager => Local Server

The syntax is: `Computer_Name.Domain`

So, if:

* Computer Name: `CAServer`
* Domain: `CAServer.com`

then FQDN is: `CAServer.CAServer.com`

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Resources

* [Use signed policies to protect App Control for Business against tampering](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/use-signed-policies-to-protect-appcontrol-against-tampering)
* [Create a code signing cert for App Control for Business](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/create-code-signing-cert-for-appcontrol)
* [Deploying signed policies](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/deploy-appcontrol-policies-with-script#deploying-signed-policies)
* [App Control Policy Wizard](https://webapp-wdac-wizard.azurewebsites.net/)
* [Application Control - Australian Government](https://blueprint.asd.gov.au/security-and-governance/essential-eight/application-control/)
* [Understand App Control for Business policy rules and file rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create)
* [Install Active Directory Domain Services](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/install-active-directory-domain-services--level-100-)
* [Install-AdcsCertificationAuthority](https://learn.microsoft.com/en-us/powershell/module/adcsdeployment/install-adcscertificationauthority)
* [Install the Certification Authority](https://learn.microsoft.com/en-us/windows-server/networking/core-network-guide/cncg/server-certs/install-the-certification-authority)
* [Comparison of Windows Server editions](https://learn.microsoft.com/en-us/windows-server/get-started/editions-comparison)
* [Remove App Control for Business policies](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/disable-appcontrol-policies)
