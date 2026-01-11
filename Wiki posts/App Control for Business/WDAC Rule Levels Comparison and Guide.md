# App Control Rule Levels Comparison and Guide

This document lists all of the levels of App Control rules. **From Top to bottom, from the most secure to the least secure**, the levels are:

## 0. Hash

- File's SHA2-256 Authenticode hash

- File's SHA2-256 Page hash

## 1. WHQLFilePublisher

- One of the Intermediate certificates of the file

- Leaf certificate of the file

- File's version

- Another attribute of the file (FileDescription, InternalName, OriginalFileName, PackageFamilyName, ProductName, Filepath)

- File's WHQL EKU OID

## 2. FilePublisher

- One of the Intermediate certificates of the file

- Leaf certificate of the file

- File's version

- Another attribute of the file (FileDescription, InternalName, OriginalFileName, PackageFamilyName, ProductName, Filepath)

## 3. WHQLPublisher

- One of the Intermediate certificates of the file

- Leaf certificate of the file

- File's WHQL EKU OID

## 4. SignedVersion

- One of the Intermediate certificates of the file

- Leaf certificate of the file

- File's version

## 5. Publisher

- One of the Intermediate certificates of the file

- Leaf certificate of the file

## 6. WHQL

- Intermediate certificate of the file that belongs to Microsoft as part of the WHQL program

- File's WHQL EKU OID

## 7. LeafCertificate

- Leaf certificate of the file

## 8. PcaCertificate

- One of the Intermediate certificates of the file

## 9. RootCertificate

- One of the Intermediate certificates of the file

## 10. FileName

- One of the attributes of the file (FileDescription, InternalName, OriginalFileName, PackageFamilyName, ProductName, Filepath)

> [!IMPORTANT]
> These properties are mutable.

## 11. FilePath

- Path of the file on disk

## About SpecificFileNameLevel Options

App Control creates file rules based on file attributes when you scan a folder using a level such as `FilePublisher`. Each file rule has a `MinimumVersion` and **only** one of the six `SpecificFileNameLevels`.

For instance, suppose a folder has 10 signed files with identical signatures and product names (or File Descriptions etc.). In that case, App Control creates a single file rule with the product name (or File Description etc.) and the lowest version of the 10 files. This file rule is sufficient to allow all 10 files.

The `MinimumVersion` is the smallest version among the files with the same signature and SpecificFileNameLevel in the folder.

Find more information in [Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create)
