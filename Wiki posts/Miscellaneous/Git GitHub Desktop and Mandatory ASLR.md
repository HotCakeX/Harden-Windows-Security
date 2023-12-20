# Git GitHub Desktop and Mandatory ASLR

Git executables are among few poorly written programs that have problem with Mandatory ASLR (Address Space Layout Randomization) Exploit protection feature. When you turn on Mandatory ASLR in Microsoft Defender (which is off by default), those executables fail to run.

The same Git executables are bundled with GitHub desktop app. In order to use Git in Visual Studio Code or use GitHub desktop app, we need to exclude Git executables from Mandatory ASLR and let them bypass it. Executables can be excluded from Mandatory ASLR rebootlessly.

You can use the following PowerShell commands to automatically add all Git executables bundled with GitHub desktop or Git itself, to the exclusion for Mandatory ASLR

<br>

## For GitHub desktop Git binaries

```powershell
Get-ChildItem -Recurse -Path "C:\Users\$env:username\AppData\Local\GitHubDesktop\*\resources\app\git\*.exe" | ForEach-Object -Process { Set-ProcessMitigation -Name $_.Name -Disable ForceRelocateImages }
```

<br>

## For Git binaries installed using standalone installer

```powershell
Get-ChildItem -Recurse -File -Path 'C:\Program Files\Git\*.exe' | ForEach-Object -Process { Set-ProcessMitigation -Name $_.Name -Disable ForceRelocateImages }
```

<br>
