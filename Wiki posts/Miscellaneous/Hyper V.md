# Hyper-V Tips and Tricks

## How to Import and Export TPM-enabled Hyper-V VM certificates with PowerShell

TPM requirement, which is a great security feature, was added to Windows 11. On the host, it is managed by the OS and UEFI, but when you create a Virtual Machine (VM) that runs an OS like Windows 11, you have to know how to manage it properly so that your VM will stay secure everywhere and you will maintain your access to your VM even if you import/export it to a different Hyper-V host or reinstall your host OS.

Here is a screenshot of my Hyper-V VM on Windows 11 with the following [security features](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/learn-more/Generation-2-virtual-machine-security-settings-for-Hyper-V) enabled:

1. Secure Boot
2. Trusted Platform Module (TPM)

![image](https://user-images.githubusercontent.com/118815227/233047257-c2aece42-dfd7-4f9b-b0e4-4db7938a995c.png)

<br>

When a VM uses TPM, Windows creates 2 certificates in the `Local Machine Certificate Store => Shielded VM Local Certificates => Certificates`

One of them is for encryption and the other one is for signing. They both contain private keys. If these 2 certificates don't exist in that folder in the Local Machine Certificate store of a Hyper-V host, your VM won't be able to start

What you need to do is to export those 2 certificates (with private keys) and store them in a safe place (such as OneDrive's personal Vault) as a backup.

If you completely reinstall Windows or move the VMs to a different Hyper-V host and Import the certificates, you will be able to continue using your VMs, but when you create new TPM enabled VMs **on the new host**, 2 more certificates will be added  to the `Local Machine Certificate Store => Shielded VM Local Certificates => Certificates`, so you will have 4 certificates in total, 2 of which are tied to your old VMs and the other 2 are tied to the new VMs. Each generated certificate has 10 years expiry date from the time it was created.

<br>

You can Import/Export the certificates using GUI, but here I'm going to show how to automate it using PowerShell:

### Export all the available Host Guardian service certificates with private keys and extended properties

```powershell
$CertificatePassword = ConvertTo-SecureString -String "hotcakex" -Force -AsPlainText
Get-Item "Cert:\LocalMachine\Shielded VM Local Certificates\*" | ForEach-Object {
Export-PfxCertificate -Cert $_ -FilePath ".\$($_.Issuer)-$($_.Thumbprint).pfx" -Password $CertificatePassword -CryptoAlgorithmOption AES256_SHA256}
```

<br>

### Import the certificates with private keys

```powershell
$ShieldedCertsPath = 'Cert:\LocalMachine\Shielded VM Local Certificates'
if (-NOT (Test-Path $ShieldedCertsPath)) { New-Item -Path $ShieldedCertsPath -Force }
$CertificatePassword = 'hotcakex' | ConvertTo-SecureString -AsPlainText -Force
Get-Item "C:\Users\$($env:USERNAME)\OneDrive\Desktop\Hyper-V Guardian certificates\*.pfx" | Import-PfxCertificate -CertStoreLocation $ShieldedCertsPath -Password $CertificatePassword -Exportable
```

<br>

You should change the values for `$CertificateLocation` and `$CertificatePassword` varaibles according to your own needs and environment.

- You can find more info about those commands here:

  - [Import-PfxCertificate](https://learn.microsoft.com/en-us/powershell/module/pki/import-pfxcertificate?view=windowsserver2022-ps)
  - [Export-PfxCertificate](https://learn.microsoft.com/en-us/powershell/module/pki/export-pfxcertificate?view=windowsserver2022-ps)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## How to Enable Nested Virtualization for All the VMs on the Hyper-V Host

Use the following command to enable Nested Virtualization for a single VM

```powershell
Set-VMProcessor -VMName <VMName> -ExposeVirtualizationExtensions $true
```

<br>

Use the following command to automatically enable Nested Virtualization for all VMs

```powershell
(Get-VM).name | ForEach-Object {Set-VMProcessor -VMName $_ -ExposeVirtualizationExtensions $true}
```

> All of the VMs must be in Off state when enabling nested virtualization for them

<br>

This is how to verify Nested Virtualization is enabled for all of your VMs

```powershell
(Get-VM).name | ForEach-Object {get-VMProcessor -VMName $_} | Select-Object -Property VMName,ExposeVirtualizationExtensions
```

<br>

* [Source](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/nested-virtualization)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Confidential Computing on Azure

Azure confidential computing makes it easier to trust the cloud provider, by reducing the need for trust across various aspects of the compute cloud infrastructure. Azure confidential computing minimizes trust for the host OS kernel, the hypervisor, the VM admin, and the host admin.

### Continue reading

* [Confidential Computing on Azure](https://learn.microsoft.com/en-us/azure/confidential-computing/overview-azure-products)

* [Azure confidential computing](https://azure.microsoft.com/en-us/solutions/confidential-compute/)

<br>

### Shielded VMs are deprecated concepts

[They are deprecated starting with Windows Server 2022](https://learn.microsoft.com/en-us/windows-server/get-started/removed-deprecated-features-windows-server-2022#features-were-no-longer-developing). They were prone to modern attacks such as side-channel.

<details>
<summary>The following details about Shielded VMs are old and no longer valid</summary>

<br>

<ul>
<li><p>Shielded VMs can't be simply moved to another Hyper-V host and used there, nor can they be de-shielded in another host, if the certificate is not in place on the new host. This results in the error "the key protector could not be unwrapped", which is desired.</p>
</li>
<li><p>Shielding a VM is for keeping bad actors or malware out of the VM, not for keeping malware inside VM. i.e., Shielding a VM is for keeping the VM secure, not for keeping the host secure.</p>
</li>
<li><p>You can use the command below to get details about your Hyper-V host, including checks whether your host runs in local/standalone mode or is part of a <a href="https://learn.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-and-shielded-vms">Guarded Fabric</a></p>
</li>
</ul>

```powershell
HgsClientConfiguration
```

<br>

<p>Note that this configuration is for standalone systems. an actual shielded virtual machine is a lot more secure because the host's security and health is properly attested in a Guarded Fabric, using <a href="https://learn.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-and-shielded-vms-top-node">Host Guardian Service (HGS)</a> on a <a href="https://www.microsoft.com/en-us/windows-server/">Windows Server</a>.</p>
<ul>
<li><p>Here is an official video about the feature and how it protects your VMs:</p>
<ul>
<li><p><a href="https://www.youtube.com/watch?v=Vp5E1-4Ks8E">Introduction to Shielded Virtual Machines in Windows Server 2016 - YouTube</a></p>
</li>
<li><p><a href="https://www.youtube.com/@MSFTMechanics">Microsoft Mechanics</a></p>
</li>
</ul>
</li>
</ul>

</details>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Scenario: Hyper-V, Enhanced session mode, no authentication in the VM's OS

When you create a VM in Hyper-V that doesn't have any authentication method for login such as Password or PIN, and use Enhanced session-mode to connect to it, there might be an issue where the RDP disconnects once after each restart of the VM and Hyper-V virtual machine connection asks you to connect to the VM again by clicking/tapping on the connect button. **To fix this, set a local password for the user account of the OS in VM.**

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Native boot Hyper-V VMs, VHDX

There are [guides](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/deploy-windows-on-a-vhd--native-boot?view=windows-11) for native booting a VHDX and it's very easy to do. If you already have a Hyper-V VM, you can add it to the Windows boot manager so that during a reboot you will have the option to boot the VHDX.

### You need to pay attention to a few things though:

1. The VHDX should be on a drive that is NTFS formatted, for now booting from ReFS is not supported.

2. The drive that hosts the VHDX file must have more free space than the assigned size of the VHDX. The size you see in the file explorer is not the same as the size of the disk you assigned to the VHDX when creating it. It's easier if you have a fixed size VHDX instead of a dynamically expanding one. To find the real size of the VHDX, you can boot it in Hyper-V and check the drives inside it.

3. Merge all checkpoints and delete them before attempting to native boot VHDX.

<br>

### VHDX native booting is very easy and flexible, you can do it even if:

1. Your host has Secure boot enabled

2. You use Signed App Control policies

3. Your VM wasn't [SysPrepped](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/sysprep--generalize--a-windows-installation) before natively booting it on physical machine

4. VM has secure boot and TPM

<br>

### How to make the VHDX bootable:

1. Double-click/tap on the VHDX file to mount it
2. Run this in CMD or PowerShell

```
bcdboot D:\Windows /d
```

> [Bcdboot](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/bcdboot-command-line-options-techref-di)

> Use the /d option to preserve the existing boot order.

<br>

### Verify the change by running this command

```
bcdedit /enum
```

> [Bcdedit](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/bcdedit)

<br>

The description of the boot entry is the same one you see during OS selection menu. You can change it with this command in PowerShell:

```
bcdedit /set '{default}' description 'VHDX Boot'
```

or in CMD:

```
bcdedit /set {default} description 'VHDX Boot'
```

If `{default}` is not the correct identifier, then change it according to the result of the `bcdedit /enum`

There are three different identifiers: The chosen default OS has identifier {default}, the current OS you are signed in at the moment is {current}. All other entries have a long hexadecimal identifier.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Some Hyper-v Nested Virtualization Screenshots

To display how optimized and powerful Hyper-V hypervisor is (including any feature that runs on it such as Windows Sandbox, WSL, WSA, MDAG and more), here are some screenshots taken on a very old hardware, hardware that is not even officially supported by Windows 11, yet you can virtualize 5 operating systems nested in each other, and the last nested virtualized OS still has full functionality including direct file copy from host to guest, full Internet connectivity, ability to listen to music, do tasks and so on.

#### Hardware specs - All from 2016-2017, couldn't find any older to test

1. CPU: Intel Core I7 7700k
2. RAM: 16GB
3. GPU: N/A (Intel IGPU)
4. SSD: 256 GB M.2

<details>

<summary>
<img width="30" src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/diamond-7.gif" alt="Diamond spinning 1 gif">
Click/Tap here to see the screenshots
<img width="30" src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/diamond-7.gif" alt="Diamond spinning 2 gif">
</summary>

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Hyper-V%20Nested%20Virtualization/1%20(1).png" alt="Hyper-V nested virtualization on a very old and weak hardware - 1">

<br>

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Hyper-V%20Nested%20Virtualization/1%20(2).png" alt="Hyper-V nested virtualization on a very old and weak hardware - 2">

<br>

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Hyper-V%20Nested%20Virtualization/1%20(3).png" alt="Hyper-V nested virtualization on a very old and weak hardware - 3">

<br>

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Hyper-V%20Nested%20Virtualization/1%20(4).png" alt="Hyper-V nested virtualization on a very old and weak hardware - 4">

</details>

<br>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Important Hyper-V Related Documents

* [Hyper-V Integration Services](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/reference/integration-services)

* [High Level Overview of Nested Virtualization](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/nested-virtualization)

* [Virtual Secure Mode](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/vsm)

<br>
