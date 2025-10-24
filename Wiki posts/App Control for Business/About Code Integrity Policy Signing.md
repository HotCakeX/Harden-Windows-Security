# About Code Integrity Policy Signing

## Introduction

A Code Integrity policy, also known as [Application Control for Business policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Introduction), is a binary file containing the rules that define which applications, files or drivers are allowed to run on the operating system. They can be cryptographically signed which adds extra benefits and protections against tampering. [You can find more information about that here.](https://github.com/HotCakeX/Harden-Windows-Security/wiki/The-Strength-of-Signed-App-Control-Policies)

<br>

## Signing a Code Integrity Policy

To sign a Code Integrity policy, you need a code signing certificate whose specifications is detailed [in this article](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/deployment/use-signed-policies-to-protect-appcontrol-against-tampering). You could use SignTool.exe from the Windows SDK to sign the policy but this article explores how to do it without the `SignTool.exe` program.

The operating system requires a specific OID for the content of the certificate. The OID is `1.3.6.1.4.1.311.79.1` and is specific to Code Integrity policies. The following C# code demonstrates the signing process:

```csharp
byte[] fileContent = File.ReadAllBytes(filePath);
const string contentTypeOid = "1.3.6.1.4.1.311.79.1";
ContentInfo contentInfo = new(new Oid(contentTypeOid), fileContent);
SignedCms signedCms = new(contentInfo, false);
CmsSigner signer = new(signingCertificate);
signer.DigestAlgorithm = new Oid("Certificate's Hashing algorithm OID");
signer.IncludeOption = X509IncludeOption.EndCertOnly;
signer.SignerIdentifierType = SubjectIdentifierType.IssuerAndSerialNumber;
signedCms.ComputeSignature(signer, false);
byte[] signedBytes = signedCms.Encode();
File.Delete(filePath);
File.WriteAllBytes(filePath, signedBytes);
```

The C# code above successfully signs the Code Integrity file, but the resulting file will not be recognized by the operating system after deployment. The reason is that the signed CIP file's certificate uses Cryptographic Message Syntax (CMS) version 3 while the operating system expects version 1.

[.NET marks](https://source.dot.net/#System.Security.Cryptography.Pkcs/System/Security/Cryptography/Pkcs/CmsSigner.cs,351) each individual signer as `v3` if they use `SubjectIdentifierType.SubjectKeyIdentifier`, otherwise v1.

Additionally, [.NET also marks the whole document](https://source.dot.net/#System.Security.Cryptography.Pkcs/System/Security/Cryptography/Pkcs/SignedCms.cs,566054fd1b504405) as `v3` if the document content type isn't `1.2.840.113549.1.7.1`, or if any signer is `v3`, otherwise `v1`.

If we look at [RFC5652](https://datatracker.ietf.org/doc/html/rfc5652#section-5.1), we see this part:

```
 IF ((certificates is present) AND
            (any certificates with a type of other are present)) OR
            ((crls is present) AND
            (any crls with a type of other are present))
         THEN version MUST be 5
         ELSE
            IF (certificates is present) AND
               (any version 2 attribute certificates are present)
            THEN version MUST be 4
            ELSE
               IF ((certificates is present) AND
                  (any version 1 attribute certificates are present)) OR
                  (any SignerInfo structures are version 3) OR
                  (encapContentInfo eContentType is other than id-data)
               THEN version MUST be 3
               ELSE version MUST be 1
```

With the important bits being:

```
(encapContentInfo eContentType is other than id-data)
```

Which makes it clear that if we use custom content type OID, the document should be marked as `v3`.

<br>

## The Workaround

Since the version value of the CMS is outside the signed portion of the data block, we can find the `02 01 03` and replace it with `02 01 01` in order to make the CIP file usable by the operating system. The CMS version number is really just telling a reader "this uses a feature from the future". For example, if the reader only knows about CMS v3 but it sees `SignedData.version == 5`, it can just say: "nope, I won't know how to read that, let's stop now."

The strange thing about this requirement is that custom encapsulated data types seem to have come in version 3, so the OS is basically saying "I only understand v1, but I also understand that you are using a custom encapsulated data type, which is a V3 feature."

[AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) implements this workaround in [its signing process](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/AppControl%20Manager/Signing/Main.cs) so it can produce CIP files that are both signed and usable by the operating system.

Keep in mind that if you deploy a signed CIP file with `CMS V3` certificate, the system will reject it and boot failure might occur.

<br>

## Signing via SignTool.exe

If you prefer to use the `SignTool.exe` program, you can download it from [NuGet](https://www.nuget.org/packages/Microsoft.Windows.SDK.BuildTools/) or the [Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/).

The following [command](https://learn.microsoft.com/en-us/dotnet/framework/tools/signtool-exe#sign-command-options) can be used to sign a CIP file with `SignTool.exe`:

```csharp
$"sign /v /n \"{certCN}\" /p7 . /p7co 1.3.6.1.4.1.311.79.1 /fd certHash \"{ciPath.Name}\"";
```

* `/n` specifies the certificate's common name (CN) in the certificate store, we supply it via `certCN` variable.
* `/p7` specifies that the file should be signed using PKCS #7.
* `/p7co` specifies the content type OID for the signed content.
* `/fd` specifies the file digest algorithm to use, which should match the certificate's hashing algorithm.
* `/v` enables verbose output.
* `ciPath.Name` variable is the path to the CIP file to be signed.
