# Certificate Checking | Harden System Security

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/.github/0180bc6ace1ea086653cc405f142d1aada424150/Pictures/Readme%20Categories/Certificate%20Checking/Certificate%20Checking.svg" alt="Certificate Checking Commands - Harden Windows Security" width="550"></p>

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> In this category, [the app](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden-System-Security) downloads and runs [sigcheck64.exe](https://learn.microsoft.com/sysinternals/downloads/sigcheck) from [Sysinternals](https://learn.microsoft.com/sysinternals/), then lists valid certificates not rooted to the [Microsoft Certificate Trust List](https://learn.microsoft.com/windows/win32/seccrypto/certificate-trust-list-overview) in the [User and Machine certificate stores](https://learn.microsoft.com/windows-hardware/drivers/install/local-machine-and-current-user-certificate-stores). **Except for some possible Microsoft certificates, Windows insider builds certificates or certificates that have your own computer's name, which are perfectly safe and should not be deleted,** All other certificates that will be listed should be treated as dangerous and removed from your system immediately.

<br>
