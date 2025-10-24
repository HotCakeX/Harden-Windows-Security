## Introduction

This document provides an exhaustive exploration of the processes involved in transforming a System Integrity Policy (SiPolicy, aka App Control Policy, aka WDAC policy) from an XML representation into a binary format with a `.cip` extension, and subsequently reversing that transformation to reconstruct the original XML from the binary data. The XML format serves as a human-readable structure for defining policies that dictate system security and integrity within the Windows operating system. In contrast, the binary format is a compact, machine-readable rendition optimized for enforcement by the operating system kernel. Understanding these conversions is paramount for ensuring that policies are accurately interpreted, applied, and maintained across different states of representation.

The transformations involve intricate manipulations at the byte level, precise structuring of data, and conditional logic to accommodate various policy components. This guide delves into each step of these processes, elucidating the rationale behind design choices, the versioning mechanism that governs which blocks are present, and the mechanisms that preserve data integrity throughout the conversions.

> [!TIP]
> Everything explained in this document is implemented in the [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager).
>
> [**Download it from the Microsoft Store**](https://apps.microsoft.com/detail/9PNG1JDDTGP8)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width="300000" alt="horizontal super thin rainbow RGB line">

<br>

## Overview of XML ⇄ Binary Workflow

1. **XML → Object Model**

   Deserialize the policy XML into a strongly typed `SiPolicy` object graph that is language agnostic.

2. **Object Model → Binary**

   Write a phased header (with a 32-bit _version identifier_ followed by GUIDs, flags, counts, and a body-offset placeholder) and then a body stream containing policy data in sequential, versioned blocks.

3. **Binary → XML**

   Read the 32-bit version identifier to determine which body blocks are present, parse header metadata, then sequentially parse each versioned block to reconstruct the `SiPolicy` object, and finally serialize that back to XML.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width="300000" alt="horizontal super thin rainbow RGB line">

<br>

## 1. XML to Binary Transformation

### 1.1 Deserialization of XML

- Open the XML file via a `FileStream`.
- Serialize it to map XML elements into the `SiPolicy` object hierarchy.
- Optional or missing XML elements are preserved as `null` or default values, enabling conditional encoding of versioned blocks downstream.

### 1.2 Binary File Structure

The `.cip` binary is composed of two concatenated parts:

1. **Header Stream**
   A fixed-width preamble containing:
   - A 32-bit _Version Identifier_ (indicates the highest versioned block written).
   - Two 16-byte GUIDs: PolicyTypeID and PlatformID.
   - 32-bit option flags.
   - 32-bit counts for EKUs, FileRules, Signers, SigningScenarios.
   - 64-bit policy version.
   - 32-bit body-offset placeholder.

2. **Body Stream**
   A variable-length, in-memory buffer that serializes policy data in discrete, _versioned blocks_. Upon body completion, its length and offset are back-patched into the header, and the two streams are merged.

### 1.3 Header Layout and Version Identifier

<div align="center">

| Offset | Size | Field                                                      |
|-------:|:----:|:-----------------------------------------------------------|
| 0x00   | 4    | Version identifier (`uint32`) → denotes highest V-block    |
| 0x04   | 16   | PolicyTypeID GUID (from `BasePolicyID`)                    |
| 0x14   | 16   | PlatformID GUID (zeroed if unspecified)                    |
| 0x24   | 4    | Option flags (`uint32`)                                    |
| 0x28   | 4    | Count of EKUs (`uint32`)                                   |
| 0x2C   | 4    | Count of FileRules                                         |
| 0x30   | 4    | Count of Signers                                           |
| 0x34   | 4    | Count of SigningScenarios                                  |
| 0x38   | 8    | Policy version (two `uint32` from `VersionEx`)             |
| 0x40   | 4    | Body-offset placeholder (`uint32`)                         |
| …      | …    | (continues into Body Stream)                               |

</div>

<br>

The **Version Identifier** serves to signal exactly which subsequent versioned blocks (V3, V4, …, V8) are encoded in the body. This is a brilliant implementation done by Microsoft which enables backward compatibility: older policies omit higher-numbered blocks, preventing attempts to read beyond EOF.

### 1.4 Body Serialization

#### Common Conventions

- 32-bit unsigned length prefixes for strings and byte arrays.
- UTF-16LE encoding for all text.
- 4-byte alignment: pad with zero bytes so each data element boundary is aligned.
- Zero terminators (`uint32 = 0`) after optional strings.

#### Sections and Versioned Blocks

1. **EKU Section**
   - For each EKU, write its DER bytes via `WritePaddedCountedBytes`.
   - ID in XML is generated as `ID_EKU_<MD5("EKU:" + Base64(value))>`.

2. **FileRules Section**
   - Sorted by rule type and key properties.
   - For each rule:
     - `uint32 Type` (0 = Deny, 1 = Allow, 2 = FileAttrib, 3 = FileRule).
     - Optional `FileName` string.
     - `UInt64 MinimumFileVersion` (two `uint32`s).
     - Hash byte array.
   - Later V-blocks append metadata (max version, AppIDs, internal names, etc.).

3. **Signers Section**
   - Certificate root indicator + data.
   - EKU index references.
   - Issuer, Publisher, OEM ID strings.
   - FileAttribRef index array.
   - Later V3 block adds `SignTimeAfter`.

4. **SigningScenarios Section**
   - For each scenario:
     - `uint32 Value`, inherited-scenarios index array, minimum-hash-algorithm, allowed/denied/test signer groups.

5. **HVCI Options**
   - Single `uint32` bitmask.

6. **Secure Settings**
   - Sorted by provider, key, value-name.
   - Each record: provider, key, value-name strings; type tag; typed value.

7. **Versioned Extension Blocks**
   - **V3 (tag=3)**: MaximumFileVersion + AppIDs for each FileRule; `SignTimeAfter` per Signer.
   - **V4 (tag=4)**: FileRule metadata (InternalName, FileDescription, ProductName).
   - **V5 (tag=5)**: PackageFamilyName + PackageVersion.
   - **V6 (tag=6)**: Final PolicyID & BasePolicyID GUIDs and SupplementalPolicySigners.
   - **V7 (tag=7)**: FilePath for each FileRule.
   - **V8 (tag=8)**: AppSettings region (AppRoot + individual AppSetting entries).
   - **End Tag** = `version + 1` marks termination.

### 1.5 Finalizing the Binary

1. Compute `bodyLength` and overwrite the header’s size placeholder.
2. Back-patch the header’s body-offset with the start position of the body.
3. Concatenate header and body into the final `.cip` file.

### 1.6 Data Exclusions

Elements not serialized into the CIP binary:

- Generated IDs (SignerID, FileRuleID) are only created during parsing.
- `FriendlyName` attributes.
- `Signer.Name` (human-friendly certificate name).

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width="300000" alt="horizontal super thin rainbow RGB line">

<br>

## 2. Binary to XML Transformation

The reverse process reconstructs the XML from the binary format, requiring conditional parsing based on the version identifier, and mapping byte-level data back into the `SiPolicy` object model.

### 2.1 Extract Raw CIP Content

- Read raw bytes from `.cip`.
- If detected as PKCS#7 SignedData, decode and extract `ContentInfo.Content`; otherwise use raw bytes directly.

### 2.2 Header Parsing

1. Read the 32-bit **Version Identifier**.
2. Read PolicyTypeID and PlatformID GUIDs.
3. Read option flags and element counts (EKU, FileRule, Signer, Scenario).
4. Read policy version (two `uint32` → `UInt64` → dotted string).
5. Read body-offset, seek there, and read the 32-bit body length.

### 2.3 Body Parsing

Parse only blocks `N` where `N <= version`:

1. **EKUs**: `ReadCountedAlignedBytes` → reconstruct `EKU.Value` → generate IDs.
2. **FileRules**: read type, name, minimum version, hash → instantiate rule objects.
3. **Signers**: reconstruct certificate root, indices, strings, FileAttribRefs.
4. **V3** (if `version >= 3`): read max versions, AppIDs for FileRules; read `SignTimeAfter` per Signer.
5. **V4**: internal names, descriptions, product names for FileRules.
6. **V5**: package info for FileRules.
7. **V6**: final GUIDs, SupplementalPolicySigners.
8. **V7**: file paths.
9. **V8**: `ParseAppSettings`.
10. Read end tag = `version + 1` to confirm policy termination.

### 2.4 Reconstruction into Object Model

- Map numeric indices back to string IDs.
- Populate arrays and optional elements only if parsed.
- Elements not present in earlier versions remain unset or default.

### 2.5 XML Serialization

- Serialize only fields present in the object graph.
- The resulting XML mirrors the original structure, enriched with generated IDs and version-specific extensions.
- The following data will not be included in the XML since they weren't included in the XML in the first place:

   - Signer Name
   - FriendlyName
   - ID

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width="300000" alt="horizontal super thin rainbow RGB line">

<br>

## 3. Appendix: Version Tags Reference

<div align="center">

Version  | Block Tag | Contents
-------- | --------- | ------------------------------------------------------------------
1–2      | —         | Core header + EKUs + FileRules + Signers + Scenarios + Settings
3        | 3         | MaxFileVersion & AppIDs (FileRules); SignTimeAfter (Signers)
4        | 4         | FileRule metadata (InternalName, FileDescription, ProductName)
5        | 5         | PackageFamilyName & PackageVersion
6        | 6         | PolicyID/BasePolicyID GUIDs; SupplementalPolicySigners
7        | 7         | FilePath for each FileRule
8        | 8         | AppSettings region (AppRoot + AppSetting entries)
End      | version+1 | Terminator tag

</div>

<br>
