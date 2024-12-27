# App Control Rule Levels Comparison and Guide

This document lists all of the levels of App Control rules. **From Top to bottom, from the most secure to the least secure**, the levels are:

## <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/Neon%20numbers%20and%20letters/number0.gif" width="40" alt="Neon number"> Hash

* File's SHA2-256 Authenticode hash

* File's SHA2-256 Page hash

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/Neon%20numbers%20and%20letters/number1.gif" width="40" alt="Neon number"> WHQLFilePublisher

* One of the Intermediate certificates of the file

* Leaf certificate of the file

* File's version

* Another attribute of the file (FileDescription, InternalName, OriginalFileName, PackageFamilyName, ProductName, Filepath)

* File's WHQL EKU OID

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/Neon%20numbers%20and%20letters/number2.gif" width="40" alt="Neon number"> FilePublisher

* One of the Intermediate certificates of the file

* Leaf certificate of the file

* File's version

* Another attribute of the file (FileDescription, InternalName, OriginalFileName, PackageFamilyName, ProductName, Filepath)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/Neon%20numbers%20and%20letters/number3.gif" width="40" alt="Neon number"> WHQLPublisher

* One of the Intermediate certificates of the file

* Leaf certificate of the file

* File's WHQL EKU OID

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/Neon%20numbers%20and%20letters/number4.gif" width="40" alt="Neon number"> SignedVersion

* One of the Intermediate certificates of the file

* Leaf certificate of the file

* File's version

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/Neon%20numbers%20and%20letters/number5.gif" width="40" alt="Neon number"> Publisher

* One of the Intermediate certificates of the file

* Leaf certificate of the file

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/Neon%20numbers%20and%20letters/number6.gif" width="40" alt="Neon number"> WHQL

* Intermediate certificate of the file that belongs to Microsoft as part of the WHQL program

* File's WHQL EKU OID

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/Neon%20numbers%20and%20letters/number7.gif" width="40" alt="Neon number"> LeafCertificate

* Leaf certificate of the file

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/Neon%20numbers%20and%20letters/number8.gif" width="40" alt="Neon number"> PcaCertificate

* One of the Intermediate certificates of the file

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/Neon%20numbers%20and%20letters/number9.gif" width="40" alt="Neon number"> RootCertificate

* One of the Intermediate certificates of the file

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/Neon%20numbers%20and%20letters/Reduced%20padding/number1.gif" width="20" alt="Neon number"> <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/Neon%20numbers%20and%20letters/Reduced%20padding/number0.gif" width="25" alt="Neon number"> FileName

* One of the attributes of the file (FileDescription, InternalName, OriginalFileName, PackageFamilyName, ProductName, Filepath)

> [!IMPORTANT]\
> These properties are mutable.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/Neon%20numbers%20and%20letters/Reduced%20padding/number1.gif" width="20" alt="Neon number"> <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/Neon%20numbers%20and%20letters/Reduced%20padding/number1.gif" width="20" alt="Neon number"> FilePath

* Path of the file on disk

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/Neon%20numbers%20and%20letters/symbolexclamation.gif" width="40" alt="Neon number"> About SpecificFileNameLevel Options

App Control creates file rules based on file attributes when you scan a folder using a level such as `FilePublisher`. Each file rule has a `MinimumVersion` and **only** one of the six `SpecificFileNameLevels`.

For instance, suppose a folder has 10 signed files with identical signatures and product names (or File Descriptions etc.). In that case, App Control creates a single file rule with the product name (or File Description etc.) and the lowest version of the 10 files. This file rule is sufficient to allow all 10 files.

The `MinimumVersion` is the smallest version among the files with the same signature and SpecificFileNameLevel in the folder.

Find more information in [Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create)

<br>
