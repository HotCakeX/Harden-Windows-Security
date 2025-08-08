# Windows Networking | Harden System Security

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Readme%20Categories/Windows%20Networking/Windows%20Networking.png" alt="Windows Networking - Harden Windows Security GitHub repository" width="500"></p>

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Disables NetBIOS over TCP/IP](https://learn.microsoft.com/windows-hardware/customize/desktop/unattend/microsoft-windows-netbt-interfaces-interface-netbiosoptions) on all network interfaces.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Disables Smart Multi-Homed Name Resolution because it uses NetBIOS and LLMNR, [protocols that shouldn't be used](https://techcommunity.microsoft.com/t5/networking-blog/aligning-on-mdns-ramping-down-netbios-name-resolution-and-llmnr/bc-p/3644260/highlight/true#M515) anymore. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-dnsclient#dns_smartmultihomednameresolution)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> Disables [LMHOSTS lookup protocol](https://learn.microsoft.com/openspecs/windows_protocols/ms-nbte/bec3913a-c359-4e6f-8c7e-40c2f43f546b#gt_5f0744c1-5105-4e4a-b71c-b9c7ecaed910) on all network adapters, legacy feature that's not used anymore.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Disables [Printing over HTTP](https://learn.microsoft.com/troubleshoot/windows-server/printing/manage-connect-printers-use-web-browser) because HTTP is not encrypted and it's an old feature that's not used anymore. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-connectivity?WT.mc_id=Portal-fx#diableprintingoverhttp)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Clears all the entries in [Remotely accessible registry paths](https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/network-access-remotely-accessible-registry-paths).

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Clears all the entries in [Remotely accessible registry paths and subpaths](https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/network-access-remotely-accessible-registry-paths-and-subpaths).

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Sets the minimum required SMB version for [**Client**](https://learn.microsoft.com/windows-server/storage/file-server/manage-smb-dialects?tabs=group-policy#smb-client) to `3.1.1` which is the latest available version at the moment and was introduced years ago with Windows 10.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Sets the minimum required SMB version for [**Server**](https://learn.microsoft.com/windows-server/storage/file-server/manage-smb-dialects?tabs=group-policy#smb-server) to `3.1.1` which is the latest available version at the moment and was introduced years ago with Windows 10.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/discord-verify-gradient.gif" width="25" alt="Rotating green checkmark denoting Subcategory"> Blocks NTLM completely. This sub-category applies the following 4 policies:

   * [For SMB](https://techcommunity.microsoft.com/t5/storage-at-microsoft/smb-ntlm-blocking-now-supported-in-windows-insider/ba-p/3916206).

   * [For all incoming connections](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-incoming-ntlm-traffic).

   * [For all outgoing connections](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-outgoing-ntlm-traffic-to-remote-servers). - **This can prevent you from using RDP (Remote Desktop) remotely via IP address which is insecure as it needs public exposed ports and uses NTLM.** You can use Quick Assist or [Bastion for Azure VMs](https://github.com/HotCakeX/Harden-Windows-Security/wiki/How-to-Securely-Connect-to-Azure-VMs-and-Use-RDP#bastion) which are more secure alternatives. Local RDP such as for Hyper-V enhanced session is not affected.

   * Disables the RPC Endpoint Mapper Client Authentication policy. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-remoteprocedurecall#rpcendpointmapperclientauthentication). It is [recommended to be disabled](https://learn.microsoft.com/windows-server/security/rpc-interface-restrict) when NTLM is completely blocked.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Requires encryption](https://learn.microsoft.com/windows-server/storage/file-server/configure-smb-client-require-encryption) for SMB client/workstation.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> [Enables encryption](https://learn.microsoft.com/windows-server/storage/file-server/smb-security) for SMB Server. Its status can be checked using the following PowerShell command: `(get-SmbServerConfiguration).EncryptData`. If the returned value is `$True` then SMB Encryption is turned on.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables [QUIC](https://learn.microsoft.com/windows-server/storage/file-server/smb-over-quic) for SMB Client.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables [QUIC](https://learn.microsoft.com/windows-server/storage/file-server/smb-over-quic) for SMB Server.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Configures the Cipher Suites from the default value of `AES_128_GCM,AES_128_CCM,AES_256_GCM,AES_256_CCM` to `AES_256_GCM,AES_256_CCM,AES_128_GCM,AES_128_CCM` for the SMB Client. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-lanmanworkstation#pol_ciphersuiteorder)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Configures the Cipher Suites from the default value of `AES_128_GCM,AES_128_CCM,AES_256_GCM,AES_256_CCM` to `AES_256_GCM,AES_256_CCM,AES_128_GCM,AES_128_CCM` for the SMB Server. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-lanmanserver#pol_ciphersuiteorder)

<br>
