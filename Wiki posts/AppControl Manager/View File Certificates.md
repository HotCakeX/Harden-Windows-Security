# View File Certificates

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/9b60b35b98cd998537202f7893fdc711a3507688/Pictures/PNG%20and%20JPG/AppControl%20Manager%20page%20screenshots/View%20File%20Certificates.png" alt="AppControl Manager Application's View File Certificates Page">

</div>

<br>

<br>

Use this [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) page to view highly detailed information about the certificates that are embedded in the signed files on your system. This feature will display the complete chains of all of the signers of a signed file.

<br>

The following data is displayed for each member of the certificate chain:

| Name                | Description                                                                                         |
|---------------------|-----------------------------------------------------------------------------------------------------|
| Signer Number       | A unique identifier assigned to the certificate's signer. If the file is signed by multiple certificates, then each of them will have a different number, allowing you to easily differentiate between them. |
| Type                | Specifies the type of certificate: root, intermediate, or leaf.           |
| Subject Common Name | The Common Name (CN) field in the certificate's subject. |
| Issuer Common Name  | The Common Name (CN) field of the certificate's issuer.    |
| Not Before          | The starting date and time when the certificate becomes valid.                                      |
| Not After           | The expiration date and time when the certificate is no longer valid.                               |
| Hashing Algorithm   | The cryptographic algorithm used to create a hash of the certificate's contents.     |
| Serial Number       | A unique numeric identifier assigned to the certificate by the issuing Certificate Authority (CA).  |
| Thumbprint          | A unique hash value (fingerprint) derived from the entire certificate, used to verify integrity.     |
| TBS Hash            | The hash of the "To Be Signed" (TBS) portion of the certificate, ensuring its integrity before signing. |
| Extension OIDs      | Object Identifiers (OIDs) that define optional extensions, such as key usage, policies, or constraints. |

<br>
