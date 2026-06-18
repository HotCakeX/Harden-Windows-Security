# Build New Certificate

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/AppControl%20Manager%20page%20screenshots/Build%20New%20Certificate.png" alt="AppControl Manager Application's Build New Certificate Page">

</div>

<br>

<br>

Use this page in [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) to build a new Code Signing certificate that is suitable for signing App Control policies according to the [Microsoft's requirements](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/use-signed-policies-to-protect-appcontrol-against-tampering). This page offers multiple options to configure the generated certificate according to your needs and requirements.

You will see a prompt asking for password during certificate building process. This is the password that will be used to protect the certificate's private key on your system. You can uncheck the box for passwords and only use confirmation prompts. The password or confirmation prompt will be displayed to you every time the private key of the certificate is going to be used to sign a file.

After building the certificate, 2 files will be created in the `C:\Program Files\AppControl Manager` directory with `.cer` and `.pfx` extensions and the same name as the common name you selected.

   * The file with the `.cer` extension contains the public key of the certificate.

   * The file with the `.pfx` extension contains the private key of the certificate. You need make sure you will have access to these files when [deploying signed policies](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Deploy-App-Control-Policy#configuration-details-for-signed-deployment) because they will be needed whenever you need to [change](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Allow-New-Apps) or [remove a signed policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/System-Information#removing-signed-base-policies) from the system.

<br>

## Configuration Details

* **Key Size**: The cryptographic key's length, measured in bits, defines the strength and security of private key encryption. Bigger key sizes take more time and processing power to generate. It uses the RSA algorithm. App Control only supports key sizes up to `4096`.

* **Algorithm**: The cryptographic algorithm used for encryption. `SHA2-512` is the default and is the most secure option supported by App Control policies at this time. There are other algorithms you can use such as SHA-3 family of hashes.

* **Common Name**: The Common Name (CN) is a field in a certificate that specifies the fully qualified domain name (FQDN) or identifier the certificate is issued for.

* **Validity**: The time period (in years) during which a certificate is considered valid and trusted.

* **PFX Encryption Password**: A secure passphrase used to encrypt and protect access to the private key and certificate data within a PFX (Personal Information Exchange) file.

<br>

> [!NOTE]\
> HSM (Hardware Security Module)
>
> The most secure method of storing code signing certificates is to use a hardware security module (HSM) or a similar device. Furthermore, obtaining certificates from a regulated or publicly trusted certificate authority (CA) requires the use of an HSM. The HSMs must also comply with the Federal Information Processing Standards (FIPS).

<br>

## Signing

The **Signing** section lets you sign selected files directly from the Build New Certificate page by using an existing Code Signing certificate from the Windows certificate stores.

### Signing workflow

1. Select individual files or folders that contain files you want to sign.
2. Confirm the **Signing Certificate Common Name**.
   * When a new certificate is built on this page, its common name is automatically copied to the signing common name field.
   * If the signing common name field is empty, the app loads the certificate common name saved in the user configuration.
3. Optionally enter a timestamp server URL.
   * Host-only timestamp values are treated as HTTP URLs.
   * If a timestamp URL is provided, the signer requests an RFC 3161 timestamp.
4. Optionally enable **Page Hashing** from the Sign button flyout.
   * Page hashing is intended for PE files.
5. Select **Sign** to start the signing process.

### Supported file types

The signing section filters selected files and files from selected folders to the following extensions:

* `.sys`
* `.exe`
* `.com`
* `.dll`
* `.msi`
* `.js`
* `.ps1`
* `.psm1`
* `.psd1`

### Certificate requirements

The selected signing certificate must:

* Be available in either the Current User or Local Machine personal certificate store.
* Match the common name entered in the signing common name field.
* Include the Code Signing Enhanced Key Usage OID.
* Have an accessible private key.

### Timestamping

The timestamp URL is optional. If it is supplied, the signing operation normalizes the URL and uses it for RFC 3161 timestamping.

### Page hashing

The **Page Hashing** option enables page hashes during Authenticode signing. This option is intended for PE files such as `.sys`, `.exe`, `.com`, and `.dll` files.

### Signing results

The selected files are signed in place. The page displays progress in the information bar and shows a completion message when signing finishes.
