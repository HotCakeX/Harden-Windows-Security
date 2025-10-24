# Build New Certificate

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/AppControl%20Manager%20page%20screenshots/Build%20New%20Certificate.png" alt="AppControl Manager Application's Build New Certificate Page">

</div>

<br>

<br>

Use this page in [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) to build a new Code Signing certificate that is suitable for signing App Control policies according to the [Microsoft's requirements](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/use-signed-policies-to-protect-appcontrol-against-tampering). This page offers multiple options to configure the generated certificate according to your needs and requirements. The keys use `SHA2-512` hashing algorithm.

You will see a prompt asking for password during certificate building process. This is the password that will be used to protect the certificate's private key on your system. You can uncheck the box for passwords and only use confirmation prompts. The password or confirmation prompt will be displayed to you every time the private key of the certificate is going to be used to sign a file.

After building the certificate, 2 files will be created in the `C:\Program Files\WDACConfig` directory with `.cer` and `.pfx` extensions and the same name as the common name you selected.

   * The file with the `.cer` extension contains the public key of the certificate.

   * The file with the `.pfx` extension contains the private key of the certificate. You need make sure you will have access to these files when [deploying signed policies](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Deploy-App-Control-Policy#configuration-details-for-signed-deployment) because they will be needed whenever you need to [change](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Allow-New-Apps) or [remove a signed policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/System-Information#removing-signed-base-policies) from the system.

<br>

## Configuration Details

* **Key Size**: The cryptographic key's length, measured in bits, defines the strength and security of private key encryption. Bigger key sizes take more time and processing power to generate. It uses the RSA algorithm. App Control only supports key sizes up to `4096`.

* **Common Name**: The Common Name (CN) is a field in a certificate that specifies the fully qualified domain name (FQDN) or identifier the certificate is issued for.

* **Validity**: The time period (in years) during which a certificate is considered valid and trusted.

* **PFX Encryption Password**: A secure passphrase used to encrypt and protect access to the private key and certificate data within a PFX (Personal Information Exchange) file.

<br>

> [!NOTE]\
> HSM (Hardware Security Module)
>
> The most secure method of storing code signing certificates is to use a hardware security module (HSM) or a similar device. Furthermore, obtaining certificates from a regulated or publicly trusted certificate authority (CA) requires the use of an HSM. The HSMs must also comply with the Federal Information Processing Standards (FIPS).

<br>
