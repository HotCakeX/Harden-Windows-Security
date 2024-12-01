# EKUs in App Control for Business Policies

<p align="Center">
<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/ef5d1.png" alt="AI generated cat girl on the root in a rainy cloudy day" height="600">
</p>

## Introduction

EKU stands for Extended Key Usage, which is an extension of X.509 certificates that delineates the functions for which the public key of the certificate can be employed. EKUs are designated by Object Identifiers (OIDs), which are sequences of digits that distinctly characterize a kind of usage.

The EKUs extension can be either critical or non-critical. If the extension is critical, it implies that the certificate must be utilized solely for the functions indicated by the EKUs. If the extension is non-critical, it implies that the certificate can be employed for other functions as well, provided that they are not prohibited by other extensions or policies.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## A Detailed Analysis of Object Identifiers and Their Usage

Let's consider `1.3.6.1.4.1.311.61.4.1` as an example which is an OID accountable for ELAM EKU. An Object Identifier (OID) is a method of denominating distinguishing objects in a hierarchical fashion. OIDs are frequently employed in cryptography, security, and networking protocols to indicate various kinds of data or algorithms.

Each cluster of digits in an OID is termed an arc. The arcs are separated by dots and constitute a tree structure. The first arc is the root of the tree, and the last arc is the leaf. The arcs in between are denoted as nodes. Each arc has a designation and a numeral, which are allocated by different authorities or standards organizations.

* `1`: This is the root arc, and it is attributed to the International Organization for Standardization (ISO).
* `3`: This signifies that the object pertains to the identified-organization branch of the ISO tree, which encompasses OIDs attributed to various organizations.
* `6`: This is the third arc, and it is attributed to the US Department of Defense (DoD), which is the executive branch department accountable for the military and national security of the United States.
* `1`: This is the fourth arc, signifies that the object pertains to the internet sub-branch, which encompasses OIDs pertaining to internet protocols and standards.
* `4`: This is the fifth arc, signifies that the object pertains to the private sub-branch, which encompasses OIDs allocated to private enterprises and organizations.
* `1`: This signifies that the object pertains to the enterprise sub-branch, which encompasses OIDs assigned to specific enterprises by IANA (Internet Assigned Numbers Authority). Each enterprise can devise its own sub-tree under its assigned OID.
* `311`: This is the Microsoft arc, which is employed for Microsoft-specific purposes.
* `61`: This is the Windows System Component Verification arc, which is employed for Windows system components that necessitate special verification.
* `4.1`: This is the Early Launch EKU arc, which is employed for the Extended Key Usage (EKU) of Early Launch Anti-Malware (ELAM) drivers. ELAM drivers are special drivers that can load prior to other drivers and verify their integrity and signatures. They are mandated to be signed by Microsoft and have a certificate that contains this EKU.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## EKUs in App Control Policies

EKUs are employed in App Control policies to indicate the functions for which a certificate can be employed. Consider EKUs as a whitelist of permitted functions. If a certificate does not encompass any of the EKUs indicated in the App Control policy, it will be discarded. They can be employed to confine the range of a certificate to a specific function.

For instance, if a certificate is issued to an individual or an organization solely for code signing functions, it cannot be employed for high-value operations such as Early Launch AntiMalware (ELAM) driver signing. To have the capacity to sign ELAM drivers, the certificate must encompass the ELAM EKU which is only attained by fulfilling specific requirements [demonstrated by Microsoft](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/elam-driver-requirements).

We can readily verify this in the subsequent example. Let's assume you have deployed the DefaultWindows template policy on a machine, and now you want to enable a 3rd party application such as OBS to be allowed to run. You create a supplemental policy by scanning the components of the OBS software. If we now open the generated XML file, we can observe that there are signer rules in there.

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Wiki%20About%20EKUs/1.png" alt="OBS Certificate in App Control policy supplemental" />

<br>

<br>

And if we open the properties of one of those signed files, we can observe that they are signed by a certificate that was issued to an individual for Code Signing function only.

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Wiki%20About%20EKUs/2.png" alt="A file in OBS software and its Certificate info" />

<br>

<br>

If we append an EKU that is not supported by this certificate, such as ELAM, to one of the signer rules in the supplemental policy, the OBS software will no longer be permitted by the Code Integrity to run because the certificate the components of the OBS software are signed with does not encompass the ELAM EKU.

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Wiki%20About%20EKUs/3.png" alt="Adding fake EKU to the OBS Signer rule in a App Control supplemental policy" />

<br>

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Wiki%20About%20EKUs/4.png" alt="ELAM EKU in App Control supplemental policy" />

<br>

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Wiki%20About%20EKUs/5.png" alt="Error message when Code Integrity in Windows blocks an executable" />

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## How to Obtain the OID of an EKU by Knowing Its Friendly Name and Vice Versa

If you know the OID or the friendly name of an EKU, you can readily obtain the other one by using the following [PowerShell command](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.oid)

```powershell
[Security.Cryptography.Oid]::new($OIDOrFriendlyName)
```

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Wiki%20About%20EKUs/6.png" alt="PowerShell screenshot getting EKU Friendly name from OID and vice versa" />

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## How to Convert an OID to Hexadecimal Format for App Control Policies

In an App Control Policy XML file, each EKU must be defined in the `EKUs` node. For each EKU, there are 3 available attributes, 2 of which are mandatory and 1 is optional. The mandatory attributes are `ID` and `Value`, and the optional attribute is `FriendlyName`.

* The `ID` attribute is a unique identifier for the EKU and should begin with `ID_EKU_`.
* The `Value` attribute is the hexadecimal representation of the OID of the EKU.
* The `FriendlyName` attribute is a human-readable name for the EKU.

#### We can convert the OID of an EKU to its hexadecimal representation by using the following PowerShell function:

```powershell
# Import the System.Formats.Asn1 namespaces
using namespace System.Formats.Asn1
Function Convert-OIDToHex {
  [CmdletBinding()]
  Param (
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [ValidateNotNullOrEmpty()][System.String]$OID
  )
  <#
.SYNOPSIS
  Converts an OID to a hexadecimal string
.PARAMETER OID
  The OID to convert
.EXAMPLE
  Convert-OIDToHex -OID '1.3.6.1.4.1.311.10.3.5'
.INPUTS
  System.String
.OUTPUTS
  System.String
  #>

  # Create an AsnWriter object with the default encoding rules
  [AsnWriter]$AsnWriter = New-Object -TypeName AsnWriter -ArgumentList ([AsnEncodingRules]::BER)
  # Write the OID as an ObjectIdentifier
  $AsnWriter.WriteObjectIdentifier("$OID")
  # Get the encoded bytes as an array
  [System.Byte[]]$NumArray = $AsnWriter.Encode()
  # Check if the first byte is 6, otherwise throw an exception
  if ($NumArray[0] -ne 6) {
    throw 'Invalid OID encoding'
  }
  # Change the first byte to 1
  $NumArray[0] = 1
  # Create a StringBuilder to store the hexadecimal value
  [System.Text.StringBuilder]$StringBuilder = New-Object -TypeName System.Text.StringBuilder -ArgumentList ($NumArray.Length * 2)

  # Loop through the bytes and append them as hex strings
  for ($Index = 0; $Index -lt $NumArray.Length; $Index++) {
    # Convert each byte to a two-digit hexadecimal string using the invariant culture
    # The invariant culture is a culture that is culture-insensitive and independent of the system settings
    # This ensures that the hexadecimal string is consistent across different locales and platforms
    # The 'X2' format specifier indicates that the byte should be padded with a leading zero if necessary
    # The ToString method returns the hexadecimal string representation of the byte
    [System.String]$Hex = $NumArray[$Index].ToString('X2', [System.Globalization.CultureInfo]::InvariantCulture)
    # Append the hexadecimal string to the StringBuilder object
    # The StringBuilder class provides a mutable string buffer that can efficiently concatenate strings
    # The Out-Null cmdlet suppresses the output of the Append method, which returns the StringBuilder object itself
    $StringBuilder.Append($Hex) | Out-Null
  }

  # Return the hexadecimal value as string
  return [System.String]$StringBuilder.ToString().Trim()
}
```

* [OBJECT IDENTIFIER](https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier?redirectedfrom=MSDN)
* [System.Formats.Asn1 Namespace](https://learn.microsoft.com/en-us/dotnet/api/system.formats.asn1)
* [AsnWriter Class](https://learn.microsoft.com/en-us/dotnet/api/system.formats.asn1.asnwriter)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## How to Convert the Hexadecimal Format to an OID for App Control Policies

The following PowerShell function does the exact opposite of the previous function. It converts the hexadecimal representation of an OID to the OID itself.

```powershell
# Import the System.Formats.Asn1 namespaces
# This allows you to use the AsnReader and AsnWriter classes
using namespace System.Formats.Asn1

Function Convert-HexToOID {
  [CmdletBinding()]
  [OutputType([System.String])]
  Param (
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [ValidateNotNullOrEmpty()][System.String]$Hex
  )
  <#
.SYNOPSIS
  Converts a hexadecimal string to an OID
.DESCRIPTION
  Used for converting hexadecimal values found in the EKU sections of the App Control policies to their respective OIDs.
.PARAMETER Hex
  The hexadecimal string to convert to an OID
.EXAMPLE
  Convert-HexToOID -Hex '010a2b0601040182374c0301'

  Returns '1.3.6.1.4.1.311.76.3.1'
.INPUTS
  System.String
.OUTPUTS
  System.String
  #>

  begin {
    # Convert the hexadecimal string to a byte array by looping through the string in pairs of two characters
    # and converting each pair to a byte using the base 16 (hexadecimal) system
    [System.Byte[]]$NumArray = for ($Index = 0; $Index -lt $Hex.Length; $Index += 2) {
      [System.Convert]::ToByte($Hex.Substring($Index, 2), 16)
    }
  }

  process {
    # Change the first byte from 1 to 6 because the hexadecimal string is missing the tag and length bytes
    # that are required for the ASN.1 encoding of an OID
    # The tag byte indicates the type of the data, and for an OID it is 6
    # The length byte indicates the number of bytes that follow the tag byte
    # and for this example it is 10 (0A in hexadecimal)
    $NumArray[0] = 6

    # Create an AsnReader object with the default encoding rules
    # This is a class that can read the ASN.1 BER, CER, and DER data formats
    # BER (Basic Encoding Rules) is the most flexible and widely used encoding rule
    # CER (Canonical Encoding Rules) is a subset of BER that ensures a unique encoding
    # DER (Distinguished Encoding Rules) is a subset of CER that ensures a deterministic encoding
    # The AsnReader object takes the byte array as input and the encoding rule as an argument
    [AsnReader]$AsnReader = New-Object -TypeName AsnReader -ArgumentList ($NumArray, [AsnEncodingRules]::BER)

    # Read the OID as an ObjectIdentifier
    # This is a method of the AsnReader class that returns the OID as a string
    # The first two numbers are derived from the first byte of the encoded data
    # The rest of the numbers are derived from the subsequent bytes using a base 128 (variable-length) system
    [System.String]$OID = $AsnReader.ReadObjectIdentifier()
  }

  End {
    # Return the OID value as string
    return $OID
  }
}
```

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Common EKUs in App Control Policies

```xml
<EKU ID="ID_EKU_WINDOWS" FriendlyName="Windows System Component Verification - 1.3.6.1.4.1.311.10.3.6" Value="010A2B0601040182370A0306" />
<EKU ID="ID_EKU_WHQL" FriendlyName="Windows Hardware Quality Labs (WHQL) - 1.3.6.1.4.1.311.10.3.5" Value="010A2B0601040182370A0305" />
<EKU ID="ID_EKU_ELAM" FriendlyName="Early Launch Anti Malware - 1.3.6.1.4.1.311.61.4.1" Value="010A2B0601040182373D0401" />
<EKU ID="ID_EKU_HAL_EXT" FriendlyName="HAL Extension - 1.3.6.1.4.1.311.61.5.1" Value="010A2B0601040182373D0501" />
<EKU ID="ID_EKU_RT_EXT" FriendlyName="Windows RT - 1.3.6.1.4.1.311.10.3.21" Value="010a2b0601040182370a0315" />
<EKU ID="ID_EKU_STORE" FriendlyName="Windows Store - 1.3.6.1.4.1.311.76.3.1" Value="010a2b0601040182374c0301" />
<EKU ID="ID_EKU_DCODEGEN" FriendlyName="Dynamic Code Generation - 1.3.6.1.4.1.311.76.5.1" Value="010A2B0601040182374C0501" />
<EKU ID="ID_EKU_AM" FriendlyName="AntiMalware - 1.3.6.1.4.1.311.76.11.1" Value="010a2b0601040182374c0b01" />
<EKU ID="ID_EKU_IUM" FriendlyName="Isolated User Mode - 1.3.6.1.4.1.311.10.3.37" Value="010A2B0601040182370A0325" />
```

<br>

### OIDs for Common Microsoft EKUs

* **[Microsoft OIDs](https://www.iana.org/assignments/enterprise-numbers/?q=microsoft) start with `1.3.6.1.4.1.311`**
* Protected Process Light Verification: `1.3.6.1.4.1.311.10.3.22`
* Windows TCB Component: `1.3.6.1.4.1.311.10.3.23`
* Code Signing OID (generic): `1.3.6.1.5.5.7.3.3`

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Wiki%20About%20EKUs/7.png" alt="EKUs in MsMpEng.exe" />

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Wiki%20About%20EKUs/8.png" alt="EKUs in WdBoot.sys which has ELAM EKU" />

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## How EKUs Are Used by the App Control Engine for Validation

Regarding the incorporation of EKUs in file validation, App Control verifies that the file's leaf certificate (File's signer) possesses identical EKUs as the signer element's EKUs. Regardless of whether the Signer's CertRoot (TBS value) and name (CN of the certificate) match with file's root, intermediate or leaf certificates, the EKUs only need to match with the leaf certificate.

For example, in the Default Windows template policy, the `Kernel32.dll` is authorized by the following signer:

```xml
<Signer ID="ID_SIGNER_WINDOWS_PRODUCTION" Name="Microsoft Product Root 2010 Windows EKU">
  <CertRoot Type="Wellknown" Value="06" />
  <CertEKU ID="ID_EKU_WINDOWS" />
</Signer>
```

<br>

* `Microsoft Product Root 2010 Windows EKU`: Matches the common name of the file's root certificate (`Microsoft Root Certificate Authority 2010`) through well known roots.

* `CertRoot`: Matches the TBS and Common name of the file's root certificate using well known roots.

* `CertEKU`: Only requires the file's signer, the leaf certificate, to have an EKU with the OID of `1.3.6.1.4.1.311.10.3.6`.

<br>

#### You can see the details in the screenshots below

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Wiki%20About%20EKUs/9.png" alt="Windows kernel32dll certificates">

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Wiki%20About%20EKUs/10.png" alt="Windows kernel32dll EKUs">

<br>

### The Placement of the CertEKU Elements

In every Signer, the `CertEKU` node should only be placed directly after `CertRoot`. It is against the Code Integrity schema for any other nodes to exist between them. Below is a example of such configuration

```xml
<Signer ID="ID_SIGNER_F_1" Name="Microsoft Windows Production PCA 2011">
  <CertRoot Type="TBS" Value="TBS Hash" />
  <CertEKU ID="ID_EKU_WINDOWS" />
  <CertEKU ID="ID_EKU_RT_EXT" />
  <CertEKU ID="ID_EKU_ELAM" />
  <CertEKU ID="ID_EKU_WHQL" />
  <CertPublisher Value="Microsoft Windows" />
  <FileAttribRef RuleID="ID_FILEATTRIB_F_1" />
</Signer>
```

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Continue Reading

* [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager)
* [App Control Policy for BYOVD Kernel Mode Only Protection](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-BYOVD-Kernel-mode-only-protection)
* [WDAC Notes](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Notes)

<p align="center">
<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/thankyou.gif" alt="Thank You Gif">
</p>
