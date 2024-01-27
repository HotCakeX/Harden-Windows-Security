# EKUs in WDAC, App Control for Business, Policies

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

## EKUs in WDAC Policies

EKUs are employed in WDAC policies to indicate the functions for which a certificate can be employed. Consider EKUs as a whitelist of permitted functions. If a certificate does not encompass any of the EKUs indicated in the WDAC policy, it will be discarded. They can be employed to confine the range of a certificate to a specific function.

For instance, if a certificate is issued to an individual or an organization solely for code signing functions, it cannot be employed for high-value operations such as Early Launch AntiMalware (ELAM) driver signing. To have the capacity to sign ELAM drivers, the certificate must encompass the ELAM EKU which is only attained by fulfilling specific requirements [demonstrated by Microsoft](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/elam-driver-requirements).

We can readily verify this in the subsequent example. Let's assume you have deployed the DefaultWindows template policy on a machine, and now you want to enable a 3rd party application such as OBS to be allowed to run. You create a supplemental policy by scanning the components of the OBS software. If we now open the generated XML file, we can observe that there are signer rules in there.

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Wiki%20About%20EKUs/1.png" alt="OBS Certificate in WDAC policy supplemental" />

<br>

<br>

And if we open the properties of one of those signed files, we can observe that they are signed by a certificate that was issued to an individual for Code Signing function only.

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Wiki%20About%20EKUs/2.png" alt="A file in OBS software and its Certificate info" />

<br>

<br>

If we append an EKU that is not supported by this certificate, such as ELAM, to one of the signer rules in the supplemental policy, the OBS software will no longer be permitted by the Code Integrity to run because the certificate the components of the OBS software are signed with does not encompass the ELAM EKU.

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Wiki%20About%20EKUs/3.png" alt="Adding fake EKU to the OBS Signer rule in a WDAC supplemental policy" />

<br>

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Wiki%20About%20EKUs/4.png" alt="ELAM EKU in WDAC supplemental policy" />

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

## How to Convert an OID to Hexadecimal Format for WDAC Policies

In a WDAC Policy XML file, each EKU must be defined in the `EKUs` node. For each EKU, there are 3 available attributes, 2 of which are mandatory and 1 is optional. The mandatory attributes are `ID` and `Value`, and the optional attribute is `FriendlyName`.

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

## Common EKUs in WDAC Policies

```xml
<EKU ID="ID_EKU_WINDOWS" FriendlyName="Windows System Component Verification - 1.3.6.1.4.1.311.10.3.6" Value="010A2B0601040182370A0306" />
<EKU ID="ID_EKU_WHQL" FriendlyName="Windows Hardware Quality Labs (WHQL) - 1.3.6.1.4.1.311.10.3.5" Value="010A2B0601040182370A0305" />
<EKU ID="ID_EKU_ELAM" FriendlyName="Early Launch Anti Malware - 1.3.6.1.4.1.311.61.4.1" Value="010A2B0601040182373D0401" />
<EKU ID="ID_EKU_HAL_EXT" FriendlyName="HAL Extension - 1.3.6.1.4.1.311.61.5.1" Value="010A2B0601040182373D0501" />
<EKU ID="ID_EKU_RT_EXT" FriendlyName="Windows RT - OID ?" Value="010a2b0601040182370a0315" />
<EKU ID="ID_EKU_STORE" FriendlyName="Windows Store - 1.3.6.1.4.1.311.76.3.1" Value="010a2b0601040182374c0301" />
<EKU ID="ID_EKU_DCODEGEN" FriendlyName="Dynamic Code Generation - 1.3.6.1.4.1.311.76.5.1" Value="010A2B0601040182374C0501" />
<EKU ID="ID_EKU_AM" FriendlyName="AntiMalware - 1.3.6.1.4.1.311.76.11.1" Value="010a2b0601040182374c0b01" />
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

## Continue Reading

* [WDAC Policy for BYOVD Kernel Mode Only Protection](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-BYOVD-Kernel-mode-only-protection)
* [WDAC Notes](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Notes)
* [WDACConfig Module](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig)

<p align="center">
<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/thankyou.gif" alt="Thank You Gif">
</p>
