# Update

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/AppControl%20Manager%20page%20screenshots/Update.png" alt="AppControl Manager Application's Update Page">

</div>

<br>

<br>

In the [AppControl Manager's](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) and [Harden System Security's](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden-System-Security) update page you can configure the apps to automatically check for updates at startup. Updates are installed from the Microsoft Store. You also have the option to rate and review the apps on the Microsoft Store.

## Install App Packages

### Package Installation

This section, which is available when running elevated (aka as an Administrator), allows you to install any MSIX/MSIXBundle package on your system. If the package you're trying to install is signed then it will be directly installed. If it is not signed, its designated certificate common name and hashing algorithm will be detected from its manifest, a unique matching certificate will be generated on your system in order to sign the package and then install it. This significantly simplifies any app package installation by abstracting and automating the entire process.

* Hardened Update Procedure: when this option is enabled, the temporary private key of the on-device generated certificate used to sign the unsigned MSIX/MSIXBundle package, will be linked to the user's account, requiring confirmation of prompts before it can be used for signing.

### Remove Package Signatures

Use this section if you have a signed MSIX or MSIXBundle and you want to remove its signature.

### Package Explorer

This section offers a read-only of the package contents, including files insided of embedded bundles, allowing you to view what's inside each package.

### Package Versions

This section allows you to modify an app package's version or a bundle's version. When you select a bundle, you will be able to modify each embedded package's version individually as well.

### Create an unsigned MSIX Package

This section offers a feature that makes it easier for you to quickly test apps during development or just make it possible to install an app without signature on a system. For further information, please visit [the following page](https://learn.microsoft.com/windows/msix/package/unsigned-package).

<br>
