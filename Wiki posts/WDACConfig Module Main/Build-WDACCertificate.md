# Build-WDACCertificate available parameters

![Build-WDACCertificate demo](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Build-WDACCertificate/Build-WDACCertificate.gif)

```powershell
Build-WDACCertificate [[-CommonName] <String>] [[-FileName] <String>] [[-BuildingMethod] <String>] [[-Password]
<SecureString>] [-Force] [-SkipVersionCheck] [<CommonParameters>]
```

<br>

This cmdlet constructs self-signed certificates that adhere to [Microsoft's specifications](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/deployment/use-signed-policies-to-protect-wdac-against-tampering) for WDAC policy signing. With this cmdlet, you can dispense with [Windows Server with a CA role](https://github.com/HotCakeX/Harden-Windows-Security/wiki/How-to-Create-and-Deploy-a-Signed-WDAC-Policy-Windows-Defender-Application-Control) to generate a certificate.

The generated certificates type is Code Signing, they employ `SHA2-512` hashing algorithm with `RSA 4096-bit` encryption (the maximum supported key size for WDAC signing.)

Upon constructing a certificate, the cmdlet stores it in the Current User's personal store, then it exports that certificate in 2 files. One of the files has a `.cer` extension and encompasses only the public key, the other file has a `.pfx` extension and encompasses both public and private keys. The PFX file is encrypted with `SHA-256` encryption and safeguarded with the password supplied by the user. After the 2 files are exported, the cmdlet eliminates the certificate from Current Users personal store and then re-imports it using the PFX file, but this time it will store the private key using [VSM](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/vsm) (Virtual Secure Mode). In this method, the private keys are stored in the TPM and are highly secured with [VBS](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs) (Virtualized-Based Security). The entire process happens in just few seconds.

<br>

### 5 Optional Parameters

* `-CommonName`: The common name of the certificate, it will also be assigned as the friendly name of the certificate. If it's not provided, the default value of `Code Signing Certificate` will be used.

* `-FileName`: The name of the `.cer` and `.pfx` files that will be generated. If it's not provided, the default value of `Code Signing Certificate` will be used. The files are saved in the current working directory.

* `-BuildingMethod`: 2 methods are used to build the certificates. Method 1 uses the [Certreq](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certreq_1) and the Method 2 uses the [New-SelfSignedCertificate](https://learn.microsoft.com/en-us/powershell/module/pki/new-selfsignedcertificate). Method 2 is the default value.

* `-Password`: The password to be employed to encrypt the `.pfx` file that encompasses the private and public keys of the certificate. It necessitates being in Secure String type. If it’s not supplied, the user will be prompted to input a password (and a second time to verify it). The minimum password length is 5 characters.

* `-Force`: The cmdlet verifies whether there is any certificate with the identical common name as the certificate that is being created, on the system. If it detects one, it will prompt the user to for permission to remove them. If this parameter is employed, the prompt will be omitted as it will presume that the user acquiesced.

<br>

#### Related Resources

* [X500NameFlags enumeration](https://learn.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-x500nameflags?redirectedfrom=MSDN)
* [Local Machine and Current User Certificate Stores](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/local-machine-and-current-user-certificate-stores)
* [Trusted Root Certification Authorities Certificate Store](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/trusted-root-certification-authorities-certificate-store)
* [X509BasicConstraintsExtension Class](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509basicconstraintsextension)

<br>
