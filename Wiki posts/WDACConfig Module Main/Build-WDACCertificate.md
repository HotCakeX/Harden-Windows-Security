# Build-WDACCertificate available parameters

![Build-WDACCertificate demo](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Build-WDACCertificate/Build-WDACCertificate.gif)

## Syntax

```powershell
Build-WDACCertificate
    [[-CommonName] <String>]
    [[-FileName] <String>]
    [[-BuildingMethod] <String>]
    [[-Password] <SecureString>]
    [-Force]
    [-SkipVersionCheck]
    [<CommonParameters>]
```

## Description

This cmdlet constructs self-signed certificates that adhere to [Microsoft's specifications](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/use-signed-policies-to-protect-appcontrol-against-tampering) for WDAC policy signing. With this cmdlet, you can dispense with [Windows Server with a CA role](https://github.com/HotCakeX/Harden-Windows-Security/wiki/How-to-Create-and-Deploy-a-Signed-WDAC-Policy-Windows-Defender-Application-Control) to generate a certificate.

The generated certificates type is Code Signing, they employ `SHA2-512` hashing algorithm with `RSA 4096-bit` encryption (the maximum supported key size for WDAC signing.)

Upon constructing a certificate, the cmdlet stores it in the Current User's personal store, then it exports that certificate in 2 files. One of the files has a `.cer` extension and encompasses only the public key, the other file has a `.pfx` extension and encompasses both public and private keys.

The PFX file is encrypted with `SHA-256` encryption and safeguarded with the password supplied by the user. After the 2 files are exported, the cmdlet eliminates the certificate from Current Users personal store and then re-imports it using the PFX file, but this time it will store the private key using [VSM](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/vsm) (Virtual Secure Mode). In this method, the private keys are stored in the TPM and are highly secured with [VBS](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs) (Virtualized-Based Security). The entire process happens in just few seconds.

## Parameters

### -CommonName

The common name of the certificate, it will also be assigned as the friendly name of the certificate.

> [!TIP]\
> If you enter a CommonName but do not enter a FileName, the FileName will be set to the same value as the CommonName for better user experience.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | `Code Signing Certificate` |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -FileName

The name of the `.cer` and `.pfx` files that will be generated.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | `Code Signing Certificate` |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -BuildingMethod

2 methods are used to build the certificates. Method 1 uses the [Certreq](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certreq_1) and the Method 2 uses the [New-SelfSignedCertificate](https://learn.microsoft.com/en-us/powershell/module/pki/new-selfsignedcertificate).

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | `Method2` |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -Password

The password to be employed to encrypt the `.pfx` file that encompasses the private and public keys of the certificate. It necessitates being in Secure String type. If it’s not supplied, the user will be prompted to input a password (and a second time to verify it). The minimum password length is 5 characters.

<div align='center'>

| Type: |[SecureString](https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -Force

The cmdlet verifies whether there is any certificate with the identical common name as the certificate that is being created, on the system. If it detects one, it will prompt the user to for permission to remove them. If this parameter is employed, the prompt will be omitted as it will presume that the user acquiesced.

<div align='center'>

| Type: |[SwitchParameter](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.switchparameter)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

#### Related Resources

* [X500NameFlags enumeration](https://learn.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-x500nameflags?redirectedfrom=MSDN)
* [Local Machine and Current User Certificate Stores](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/local-machine-and-current-user-certificate-stores)
* [Trusted Root Certification Authorities Certificate Store](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/trusted-root-certification-authorities-certificate-store)
* [X509BasicConstraintsExtension Class](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509basicconstraintsextension)
* [Internet X.509 Public Key Infrastructure Certificate and CRL Profile - RFC2459](https://www.rfc-editor.org/rfc/rfc2459)

<br>

## Additional Resources

To enhance the security and safeguarding of your certificate further, you can remove the certificate from the Personal store of the Current User certificates and then utilize the PFX file to import it anew in the same location, but this time you will mark additional boxes in the import wizard.

This video illustrates how to safeguard the Code Signing Certificate generated by the WDACConfig module, so that you will be compelled to either enter your security password or verify your identity every time the certificate is employed. By storing the certificate in this manner, only your user account will have access to it, and you will inherently possess administrator privileges to implement the signed App Control policy on the system.

These options are only accessible in GUI and they are to deter automatic scripts from utilizing the certificates without authentication, this is why the `Build-WDACCertificate` cmdlet does not activate this security feature by default.

<br>

<div align="center">
<a href="https://www.youtube.com/watch?v=nrRiAJt-_6E">
<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/How%20to%20safely%20store%20the%20WDAC%20Code%20Signing%20Certificate%20in%20Windows%20-%20WDACConfig%20module%20thumbnail.gif" alt="How to safely store the App Control Code Signing Certificate in Windows WDACConfig module thumbnail" width="700">
</a>
</div>

<br>

## HSM (Hardware Security Module)

The most secure method of storing code signing certificates is to use a hardware security module (HSM) or a similar device. Furthermore, obtaining certificates from a regulated or publicly trusted certificate authority (CA) requires the use of an HSM. The HSMs must also comply with the Federal Information Processing Standards (FIPS).

<br>
