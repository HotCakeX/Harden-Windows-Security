# Basic PowerShell Tricks and Notes Part 5

The following PowerShell series is designed for newcomers to PowerShell who want to quickly learn the essential basics, the most frequently used syntaxes, elements and tricks. It can also be used by advanced users as a quick reference or those who want to sharpen their skills.

The main source for learning PowerShell is Microsoft Learn websites. There are extensive and complete guides about each command/cmdlet with examples.

[PowerShell core at Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/)

You can also use the Windows Copilot for asking any PowerShell related questions, code examples etc.

This is part 5 of this series, find other parts here:

* [Part 1](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-tricks-and-notes)
* [Part 2](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-Tricks-and-Notes-Part-2)
* [Part 3](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-Tricks-and-Notes-Part-3)
* [Part 4](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-Tricks-and-Notes-Part-4)
* [Part 5](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-Tricks-and-Notes-Part-5)

<br>

## Never Use Relative Path When Working With .NET Methods In PowerShell

When you are working with .NET methods in PowerShell, you should never use relative paths. Always use the full path to the file or directory. The reason is that the following command:

```powershell
[System.Environment]::CurrentDirectory
```

Always remembers the first directory the PowerShell instance was started in. If you use `cd` or `Set-Location` to change the current working directory, it will not change that environment variable, which is what .NET methods use when you pass in a relative path such as `.\file.txt`. That means .NET methods always consider that environment variable when you pass in a relative path from PowerShell, not the current working directory in PowerShell.

<br>
