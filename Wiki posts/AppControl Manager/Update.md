# Update

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/AppControl%20Manager%20page%20screenshots/Update.png" alt="AppControl Manager Application's Update Page">

</div>

<br>

<br>

In the [AppControl Manager's](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) update page you can configure the app to automatically check for updates at startup. Updates are installed from the Microsoft Store. You also have the option to rate and review the AppControl Manager on the Store.

## Install App Packages

This section, which is available when running elevated (aka as an Administrator), allows you to install any MSIX/MSIXBundle package on your system. If the package you're trying to install is signed then it will be directly installed. If it is not signed, its designated certificate common name and hashing algorithm will be detected from its manifest, a unique matching certificate will be generated on your system in order to sign the package and then install it. This significantly simplifies any app package installation by abstracting and automating the entire process.

* Hardened Update Procedure: when this option is enabled, the temporary private key of the on-device generated certificate used to sign the unsigned MSIX/MSIXBundle package, will be linked to the user's account, requiring confirmation of prompts before it can be used for signing.

<br>
