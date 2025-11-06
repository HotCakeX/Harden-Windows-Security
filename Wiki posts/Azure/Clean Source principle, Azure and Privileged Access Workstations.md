<div align="center">
<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/4efd.jpg" width="600" alt="AI girl">
</div>

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/3434.gif" width="300000" height="50" alt="Blue gif line break">

<br>

# Clean Source principle

The [clean source principle](https://aka.ms/cleansource) states that all security dependencies must be as trustworthy as the object being secured. The source of the control and/or trust must have an equal or higher level of trustworthiness and/or security than the destination.

This article reveals the significance of the clean source principle, common shortcomings, and how it radically transforms the security architecture paradigm.

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/superslowfds.gif" width="300000" height="50" alt="Blue gif line break">

## A Case Study of Using BitLocker and TPM with Nested VMs in Azure

Now that you are generally aware of the Clean Source principle, you might want to try to make an architecture that is resistant to tamper/compromise from upstream systems or identities.

We will examine a scenario that may appear very secure and advanced but is still susceptible to side channel attacks because of not adhering to the clean source principle. In this hypothetical scenario, the Global Admin account is compromised, and we want to safeguard our data from admin abuse.

Let us assume that you create an Azure VM, which we will refer to as the “Host VM”. We will also create another virtual machine inside of the Host VM using Hyper-V. We will refer to this new guest VM as the “Nested VM”. The nested VM’s operating system volume is encrypted with BitLocker. You configure the Key Protectors to be Startup PIN, TPM and a recovery password. Only you have access to the PIN and recovery password of the BitLocker encrypted drive.

### How to Use BitLocker in Azure

You can utilize BitLocker in Azure to encrypt the disks of the virtual machines. The service is called [Azure Disk Encryption](https://learn.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-overview), and it employs Key Vault to store the key instead of a TPM.

Key Vaults are extremely economical, and disk encryption does not incur any licensing fees, only Key Vault hosting, which is negligible.

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/superslowfds.gif" width="300000" height="50" alt="Blue gif line break">

## Flaws of the Above-Mentioned Scenario

None of the protections mentioned in the scenario can defend against a compromised admin which has gotten Host VM admin permissions. They can install Command and Control (C2) software using the Azure VM guest agent.

Once the host VM is compromised, the C2 software can be used as a key logger to steal the startup PIN and authentication credentials of the Nested VM. After the PIN and/or the credentials are stolen, the threat actor can use  [PowerShell Direct](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/powershell-direct)  to access the virtual machine through the host's hypervisor if it is already booted, or they can boot the Nested VM themselves using the PIN they skimmed.

At this point, the nested virtual machine can be booted up, and no brute forcing is needed.

Another attack path is if they download the Nested VM’s disks, they can offline attack the VM once they gain access to the recovery key or the key that is stored in the vTPM of the Nested VM’s hypervisor which is on the disk of the host VM. All software based KSPs just get decoded at runtime and there are tools to skim the decoded value.

When the nested VM is running, the system sees the disk as plain text, not encrypted. BitLocker encryption is transparent drive encryption, not encryption in use. (For encryption in use, I recommend something like [Microsoft Purview](https://learn.microsoft.com/en-us/purview/purview) on the data itself.)

BitLocker is not easy to brute force if the right algorithms are configured (XTS-AES-256) so they would not want to go that direction in most cases.

### What if You Deploy a Signed App Control Policy on the Host VM?

You could, but what would prevent the threat actor from disabling it on the host? The host is controlled by the threat actor in this scenario and not having the private keys of the deployed signed policy won't matter.

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/superslowfds.gif" width="300000" height="50" alt="Blue gif line break">

## So, What Alternative Will the Threat Actor Pursue?

They could simply download the VHDX of the main host (Azure virtual machine), extract the nested VHDX that pertains to the guest operating system, construct a new operating system with your data in it but devoid of security, upload that and await your login. You would remain oblivious to the tampering since the operating system is identical but bereft of security, or the threat actor can even deploy their own signed policy on the new operating system.

Bear in mind, host compromise entails all security dependencies are also compromised. So, you must presume through some black magic that your guest is compromised. What happens if they alter Hyper-V's binaries to perform custom stuff?

You can technically insert custom guest firmware. Custom firmware is not officially supported and is usually used by pirates to get ACPI tables altered to activate Windows for free.

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/superslowfds.gif" width="300000" height="50" alt="Blue gif line break">

## Clean Source and Assume Breach Principle, a Match Made in Heaven

It is not only virtual machines that are mistaken to be secure, but also jump boxes (RDP) and session manager apps (PAM) are insufficiently secure. The problem with RDP and PAMs is session hijacking. You can use keyboard and mouse takeover capabilities to control anything downstream without having to install any malware, because the system that is running the RDP client / session manager app is technically in charge of the secure system.

The control and/or trust that is being originated from hardware is insecure and propagated downstream through the remote-control apps. So, all insecure states can be transmitted onto the secure systems, and you do not even have to install anything on the remote systems to compromise them.

Clean source done right will prevent session takeovers, because the system hosting the session will be as secure as the upstream system requires.

However, on [Azure](https://www.microsoft.com/insidetrack/blog/protecting-high-risk-environments-with-secure-admin-workstations/), things are much [superior](https://www.microsoft.com/insidetrack/blog/improving-security-by-protecting-elevated-privilege-accounts-at-microsoft/). Azure is a hosting [fabric](https://www.microsoft.com/insidetrack/blog/using-shielded-virtual-machines-to-help-protect-highvalue-assets/) that receives commands from an admin. The admin must be hosted on a secure system, which is where the PAW comes in. Azure fabric itself is more secure than anything you can provide.

The guest has to abide by the rules of its host, and the host has to conform to the rules of Azure, and Azure adheres to the rules of the admins, so by proxy, the guest complies with the rules of the admins, because the chain of control/trust flows through the host virtual machine. Any type of **direct** guest guarding is futile.

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/superslowfds.gif" width="300000" height="50" alt="Blue gif line break">

## So, What Is the Solution?

What you desire is to create something that can remain protected in most hostile environments and preserve its integrity.

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/superslowfds.gif" width="300000" height="50" alt="Blue gif line break">

## Introducing Privileged Access Workstations (PAW)

PAW is the highest security configuration designed for extremely sensitive roles that would have a significant or material impact on the organization if their account was compromised. The PAW configuration includes security controls and policies that restrict local administrative access and productivity tools to minimize the attack surface to only what is absolutely needed for performing sensitive jobs or tasks.

Often, the servers are considerably less secure than the PAW itself. Likewise with intermediaries, they are usually less secure than the PAW itself. Consequently, the session host and/or client is not the weakest chain link. Which also implies that the clean source principle is kept at least on the start of the chain.

For more of a do-it-yourself experience, check out my harden windows security repository over at [GitHub](https://github.com/HotCakeX/Harden-Windows-Security).

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/superslowfds.gif" width="300000" height="50" alt="Blue gif line break">

## Azure Confidential Compute

[Confidential computing](https://learn.microsoft.com/en-us/azure/confidential-computing/overview) is an industry term defined by the Confidential Computing Consortium (CCC) - a foundation dedicated to defining and accelerating the adoption of confidential computing. The CCC defines confidential computing as: The protection of data in use by performing computations in a hardware-based Trusted Execution Environment (TEE).

Unlike [Guarded hosts](https://learn.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-and-shielded-vms), [Azure confidential](https://azure.microsoft.com/en-us/solutions/confidential-compute/#overview  ) compute VMs use [Intel SGX](https://learn.microsoft.com/en-us/azure/confidential-computing/virtual-machine-solutions-sgx) or [AMD's Secure](https://learn.microsoft.com/en-us/azure/confidential-computing/virtual-machine-solutions-amd) Encrypted Virtualization-Secure Nested Paging, or [SEV-SNP](https://www.amd.com/system/files/documents/sev-tio-whitepaper.pdf).

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/superslowfds.gif" width="300000" height="50" alt="Blue gif line break">

## Conclusion

In this article, we have explored the clean source principle, which states that all security dependencies must be as trustworthy as the object being secured. We have seen how this principle can help us design more secure architectures and avoid common pitfalls that can compromise our data and systems.

We have also learned about some of the solutions that Microsoft offers to help us achieve clean source, such as Privileged Access Workstations (PAW) and Azure Confidential Compute. These solutions leverage advanced technologies such as Intel SGX and AMD SEV-SNP to protect our sensitive workloads from upstream attacks and side channel threats.

By following the clean source principle and using these solutions, we can enhance our security posture and reduce our risk exposure in the cloud and beyond.

<br>
