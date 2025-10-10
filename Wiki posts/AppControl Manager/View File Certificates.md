# View File Certificates

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/9b60b35b98cd998537202f7893fdc711a3507688/Pictures/PNG%20and%20JPG/AppControl%20Manager%20page%20screenshots/View%20File%20Certificates.png" alt="AppControl Manager Application's View File Certificates Page">

</div>

<br>

Use this [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) page to inspect, search, sort, copy, and export highly detailed information about the public key certificates found in signed content on your system. The page can display the complete chains (Leaf, Intermediate, Root) for each signer of a signed file, as well as parse standalone certificates and signed App Control policy packages.

> [!TIP]\
> You can verify the signing certificates inside `.CIP` files (signed App Control policies) and standalone `.cer` certificate files.

> [!NOTE]\
> This feature supports files signed via Security Catalogs (.cat). When enabled, it can resolve certificates via the Windows catalog store if a file has no embedded signer.

<br>

## What You Can Analyze

- Any file with an embedded Authenticode signature
- Files signed via Security Catalogs (when "Include Security Catalogs" is enabled)
- Signed App Control policy packages (`.CIP`)
- Standalone X.509 certificate files (`.cer`)

<br>

## Getting Started

- Browse: Click "Browse for file" and pick a file to analyze.
- Drag and Drop: You can drag a file onto the page when the app is not elevated.
- Include Security Catalogs: Toggle on to resolve signers from Windows catalogs when a file has no embedded signature.
- CMS Details: For `.CIP` files, click "CMS details" to view CMS metadata (version, content type, sizes, etc.).
- Export: Click "Export to JSON" to save the data as a JSON file.

<br>

## Security Catalog Support

When "Include Security Catalogs" is enabled and a target file has no embedded signature:
- The app computes the file's Code Integrity hashes (SHA-1 and SHA-256) and searches the Windows catalog store for a matching entry.
- If found, the catalog file is used to resolve and display the signer's full certificate chain.
- If a catalog hash mismatch is encountered, it is logged; the UI continues processing other sources.

This is useful for system files and drivers which are often signed via catalogs.

<br>

## CMS Details for .CIP Files

When analyzing a `.CIP` file, the page decodes the CMS (`PKCS#7`) package and shows:

- CMS Version: The CMS structure version.
- Is Detached: Indicates whether the signature is detached.
- Content Type (Friendly Name): Friendly name of the CMS content type OID.
- Content Type (OID): The raw OID value of the CMS content type.
- Raw CMS Data Length: Total size in bytes of the CMS blob.
- ContentInfo Data Length: Size in bytes of the inner `ContentInfo.Content`.

These values are only meaningful for `.CIP`. For other file types, these values are blank/zero.

<br>

## Columns and Data Reference

Each row represents one certificate in a signer's chain. Columns:

| Name | Description |
|------|-------------|
| Signer Number | A unique identifier assigned to the certificate's signer. If the file is signed by multiple certificates, then each of them will have a different number, allowing you to easily differentiate between them. |
| Type | Certificate role in the chain: Leaf, Intermediate, or Root. |
| Subject Common Name | The Subject CN of the certificate. |
| Issuer Common Name | The Issuer CN of the certificate. For Root, this is the same as Subject. |
| Not Before | The date/time when the certificate becomes valid. |
| Not After | The date/time when the certificate expires. |
| Hashing Algorithm | The signature algorithm used by the certificate (e.g., SHA256RSA, ECDSA). |
| Serial Number | Unique serial number assigned by the issuing CA. |
| Thumbprint | Digest of the entire certificate (fingerprint), used for quick identification. |
| TBS Hash | Hash of the "To Be Signed" portion of the certificate. Useful for integrity checks. |
| Extension OIDs | List of extension OIDs present on the certificate, with friendly names when available. |
| Version | X.509 version of the certificate. |
| Has Private Key | Indicates whether a private key is associated with this certificate in the current context. |
| Archived | Whether the certificate is marked as archived. |
| Certificate Policies | Decoded certificate policies extension, when present. |
| Authority Information Access | Decoded AIA extension, when present (e.g., CA issuers/OCSP). |
| CRL Distribution Points | Decoded CRL distribution points, when present. |
| Basic Constraints | Indicates CA capability and path length constraints (if any). |
| Key Usage | Decoded Key Usage or Enhanced Key Usage information, when present. |
| Authority Key Identifier | Raw AKI, shown as a hex string when present. |
| Subject Key Identifier | SKI value, when present. |
| Raw Data Length | Length (in bytes) of the DER-encoded certificate. |
| Public Key Length | Public key size in bits (e.g., RSA/ECDSA key size), when determinable. |

<br>

## Copy to Clipboard

Right-click a row to open the context menu:
- Copy row: Copies the selected row(s) as labeled text (all columns) to the clipboard.
- Copy individual items: Copy a single column value from the selected row.

Keyboard shortcut:
- Ctrl+C copies the currently selected row(s) in labeled format.

<br>

## Tips

- If you see no rows for a signed file, try enabling "Include Security Catalogs" (common for drivers/system files).
- Root certificates show the same value for Subject and Issuer (self-signed).
- Some extensions may be unavailable or displayed as raw hex if decoding is not applicable.
- Catalog hash mismatches are logged and skipped gracefully.
