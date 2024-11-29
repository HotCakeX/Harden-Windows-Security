# Build New Certificate

Use this page in [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) to build a new Code Signing certificate that is suitable for signing App Control policies according to the [Microsoft's requirements](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/use-signed-policies-to-protect-appcontrol-against-tampering). This page offers multiple options to configure the generated certificate according to your needs and requirements. The keys use `SHA2-512` hashing algorithm.

You will see a prompt asking for password during certificate building process. This is the password that will be used to protect the certificate's private key on your system. You can uncheck the box for passwords and only use confirmation prompts. The password or confirmation prompt will be displayed to you every time the private key of the certificate is going to be used to sign a file.

<br>

## Configuration Details

* **Key Size**: The cryptographic key's length, measured in bits, defines the strength and security of private key encryption. Bigger key sizes take more time and processing power to generate. It uses RSA algorithm.

> [!IMPORTANT]\
> App Control only supports key sizes up to `4096` so do not change the key size if you want to use the generated code signing certificate for App Control policy signing.

* **Common Name**: The Common Name (CN) is a field in a certificate that specifies the fully qualified domain name (FQDN) or identifier the certificate is issued for.

* **Validity**: The time period (in years) during which a certificate is considered valid and trusted.

* **PFX Encryption Password**: A secure passphrase used to encrypt and protect access to the private key and certificate data within a PFX (Personal Information Exchange) file.

<br>

> [!NOTE]\
> HSM (Hardware Security Module)
>
> The most secure method of storing code signing certificates is to use a hardware security module (HSM) or a similar device. Furthermore, obtaining certificates from a regulated or publicly trusted certificate authority (CA) requires the use of an HSM. The HSMs must also comply with the Federal Information Processing Standards (FIPS).

<br>
