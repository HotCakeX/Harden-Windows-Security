# Git GitHub Desktop and Mandatory ASLR

Git executables are among the few poorly written programs that have problem with Mandatory ASLR (Address Space Layout Randomization) Exploit protection feature. When you turn on Mandatory ASLR in Microsoft Defender (which is off by default), those executables fail to run.

The same Git executables are bundled with GitHub desktop app. In order to use Git in Visual Studio Code or use GitHub desktop app, we need to exclude Git executables from Mandatory ASLR and let them bypass it. Executables can be excluded from Mandatory ASLR rebootlessly.

Use the [Harden System Security app](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Exploit-Mitigations) to easily exclude executables (`.exe` files) from one or more exploit protections.

* Location of the GitHub desktop Git binaries: `C:\Users\UserName\AppData\Local\GitHubDesktop\*\resources\app\git\*.exe`

* Location of the Git binaries installed using standalone installer: `C:\Program Files\Git\*.exe`

<br>
