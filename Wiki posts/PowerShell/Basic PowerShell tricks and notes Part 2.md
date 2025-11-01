# Basic PowerShell Tricks and Notes Part 2

The following PowerShell series is designed for newcomers to PowerShell who want to quickly learn the essential basics, the most frequently used syntaxes, elements and tricks. It can also be used by advanced users as a quick reference or those who want to sharpen their skills.

The main source for learning PowerShell is Microsoft Learn websites. There are extensive and complete guides about each command/cmdlet with examples.

[PowerShell core at Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/)

You can also use the Windows Copilot for asking any PowerShell related questions, code examples etc.

This is part 2 of this series, find other parts here:

* [Part 1](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-tricks-and-notes)
* [Part 2](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-Tricks-and-Notes-Part-2)
* [Part 3](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-Tricks-and-Notes-Part-3)
* [Part 4](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-Tricks-and-Notes-Part-4)
* [Part 5](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-Tricks-and-Notes-Part-5)

<br>

## View All Predictive Intellisense Suggestions Based on Past History

Press F2 to see the complete list of the Predictive IntelliSense suggestions as you type on the PowerShell console.

[More info](https://learn.microsoft.com/en-us/powershell/scripting/learn/shell/using-predictors)

<br>

## Where Is the Powershell Command History Stored?

In this directory

```powershell
$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine
```

There is a file called `ConsoleHost_history.txt` and it contains the history of all the commands you've ever typed in PowerShell on your device. If you want to clear it, open the file, delete all of its content. If PowerShell is already open, close and reopen it to see the change.

<br>

You can open the file with this command

```powershell
Invoke-Item -Path "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
```

<br>

You can use the following command to set the maximum remembered history to 1

```powershell
Set-PSReadLineOption -MaximumHistoryCount 1
```

<br>

## How to Clear the Automatic Error Variable in Powershell

```powershell
$error.clear()
```

<br>

## How to Get the Last Error Type in Powershell

```powershell
$Error[0].Exception.GetType().FullName
```

<br>

## How to Display All Environment Variables and Their Values in Powershell

```powershell
gci env:
```

* The `env:` drive is a PowerShell provider that exposes the environment variables as a hierarchical file system.

* The `gci` command is an alias for the `Get-ChildItem` cmdlet.

<br>

## List All MSCs and CPLs for Microsoft Management Console and Control Panels in Powershell

```powershell
Get-ChildItem -Path C:\Windows\system32\* -Include *.msc, *.cpl | Sort-Object -Property Extension | Select-Object -Property Name | Format-Wide -Column 2
```

<br>

## How to Mount the EFI System Partition?

```powershell
mountvol u: /s
```

This isn't a native PowerShell cmdlet, it uses [mountvol CLI.](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/mountvol)

With that command you can mount the EFI partition and assign the letter `U` to it, it will appear in This PC. You can browse it in PowerShell as admin.

<br>

## How to Check if a File Is in Use in Powershell?

Here is an example function that tries to rename files given to it with the same names and if it was successful, it will consider that file not in use.

```powershell
function IsFileAccessible {
    param ([System.String]$FullFileName)
    [System.Boolean]$IsAccessible = $false
    try {
        Rename-Item $FullFileName $FullFileName -ErrorVariable LockError -ErrorAction Stop
        $IsAccessible = $true
    }
    catch {
        $IsAccessible = $false
    }
    return $IsAccessible, $FullFileName
}
```

You can use it like this:

```powershell
(Get-ChildItem -Path 'C:\Program Files\Windows Defender' -Filter '*.exe*').FullName | ForEach-Object { IsFileAccessible -FullFileName $_ }
```

<br>

## Choosing Between Powershell and Powershell Preview

Use PowerShell Preview if you want to test new features and don't need to call PowerShell with its alias, pwsh, from CMD. If you do need to call it like that, use PowerShell stable.

Use cases for it are when you need to use `pwsh.exe` in Windows Task Scheduler.

PowerShell Preview by default doesn't set its `pwsh.exe` available system-wide, the path to that file isn't added to the system environment variables, only PowerShell stable does that, but of course if you want to use PowerShell preview you can manually modify the PATH environment variable to have `pwsh.exe` of PowerShell Preview be available system-wide.

<br>

## Variable Types in Powershell

PowerShell variables can have types and type accelerator. The following command lists all of the types and their equivalent type accelerators. The fully qualified type names replace implicit with explicit.

```powershell
[PSObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')::Get
```

<br>

## Success Codes and Error Codes

In PowerShell, or for programming languages in general, 0 = success, 1 or anything else means failure/error.

<br>

## How to Get the Names and AppIDs of Installed Apps of the Current User in Powershell?

```powershell
Get-StartApps
```

[More info](https://learn.microsoft.com/en-us/powershell/module/startlayout/get-startapps)

<br>

## Difference Between Async and Sync

Async is faster than Sync

* Sync = waits for the previous task to finish before starting a new one

* Async = starts multiple tasks simultaneously

PowerShell supports sync/async commands workflows, also known as parallel.

> [!NOTE]\
> A comment under this [answer](https://stackoverflow.com/a/748189):
>
> Oddly enough "Synchronously" means "using the same clock" so when two instructions are synchronous they use the same clock and must happen one after the other. "Asynchronous" means "not using the same clock" so the instructions are not concerned with being in step with each other. That's why it looks backwards, the term is not referring to the instructions relationship to each other. It's referring to each instructions relationship to the clock.

<br>

## How to Enable a Disabled Event Log Using Powershell

First we create a new `EventLogConfiguration` object and pass it the name of the log we want to configure, then we set it to enabled and save the changes.

```powershell
$LogName = 'Microsoft-Windows-DNS-Client/Operational'
$Log = New-Object -TypeName System.Diagnostics.Eventing.Reader.EventLogConfiguration -ArgumentList $LogName
$Log.IsEnabled = $true
$Log.SaveChanges()
```

We can confirm the change by running this command:

```powershell
Get-WinEvent -ListLog Microsoft-Windows-DNS-Client/Operational | Format-List -Property *
```

Using the same method we can configure many other options of the log file, just take a look at the `EventLogConfiguration` Class for a list of configurable properties.

<br>

## Find the Current User’s Username in Powershell

```powershell
[Environment]::UserName
```

```powershell
$env:username
```

```powershell
whoami
```

```powershell
[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
```

*Most secure way*

Example

```powershell
$UserSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().user.value
(Get-LocalUser | Where-Object -FilterScript { $_.SID -eq $UserSID }).name
```

<br>

## How to Access Properties of an Object in Powershell

For example, you can first assign the entire object to a variable:

```powershell
$Preferences = Get-MpPreference
```

Then call properties of that variable

```powershell
$Preferences.PUAProtection
```

Another method is this:

```powershell
$(Get-MpPreference).puaprotection
```

<br>

## Dot-Sourcing

To dot-source a PowerShell function in the same script file, you can use the dot operator `.` followed by the path of the script file containing the function. The path can be relative or absolute. Here's an example:


```powershell
# Contents of MyFunctions.ps1
function New-Function {
    Write-Host "Hello World!"
}

# Contents of Main.ps1
. .\MyFunctions.ps1

New-Function
```

In this example, `Main.ps1` dot-sources `MyFunctions.ps1` using the dot operator and then calls `MyFunction`. When you run `Main.ps1`, it will output `Hello World!` to the console.

The dot operator tells PowerShell to execute the script file in the current scope instead of a new scope. This means that any functions or variables defined in the script file will be available in the current scope.

<br>

## A Custom Script to Generate Random Words in Powershell

```powershell
# Generate four variables with random names
$TotallyRandomNamesArray = @() # Create an empty array to store the names
for ($i = 0; $i -lt 4; $i++) {
    # Loop four times
    $Chars = [CHAR[]](Get-Random -Minimum 97 -Maximum 123 -Count 11) # Generate random English letters
    $Chars[0] = [CHAR]::ToUpper($Chars[0]) # Change the first character to upper-case
    $TotallyRandomNamesArray += -join $Chars # Add the name to the array
}
# Assign the names from the Names array to the individual variables
$TotallyRandomName1, $TotallyRandomName2, $TotallyRandomName3, $TotallyRandomName4 = $TotallyRandomNamesArray
```

<br>

## How to See All the Shared Folders and Drives

```powershell
Get-CimInstance -Class Win32_Share
```

There are other ways that are not native PowerShell cmdlets, such as

```
net view \\$env:computername /all
```

And

```
net share
```

> Also visible from Computer => System Tools => Shared Folders => Shares

<br>

## An Example of Using -F Format Operator

```powershell
Write-output("The drivername {0} is vulnerable with a matching SHA256 hash of {1}" -f $Filename, $SHA256)
```

[More info](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_operators?view=powershell-7.3#format-operator--f)

<br>

## How to List All of the Positional Parameters of a Cmdlet

In this example we use the

```powershell
Get-Help -Name 'Get-ChildItem' -Parameter * |
Sort-Object -Property position |
Select-Object -Property name, position
```

<br>

## How to Get the Number of Fans and Details About Them in Powershell

```powershell
(Get-CimInstance -Namespace root/CIMV2 -ClassName Win32_Fan).count
Get-CimInstance -Namespace root/CIMV2 -ClassName Win32_Fan
```

> P.S VMs don't have fans.

<br>

## How to Get the Last Reboot Time in Powershell

```powershell
[System.DateTime](Get-CimInstance -ClassName win32_operatingsystem -ComputerName $_.Name).LastBootUpTime
```

<br>

## How to Add a PS Custom Object to Another PS Custom Object

You can use the `Add-Member` cmdlet with the `-InputObject` parameter. The `-InputObject` parameter specifies the custom object that you want to add a property to, and the `-Value` parameter specifies the custom object that you want to add as a property. For example, you can use this code to add the `$CustomObject` to another custom object called `$ParentObject`:

```powershell
$HashTable = @{
    Name = 'Alice'
    Age = 25
    Occupation = 'Teacher'
}
$CustomObject = [PSCustomObject]$HashTable

# Create another custom object
$ParentObject = [PSCustomObject]@{
    ID = 123
    Location = 'London'
}

# Add the $CustomObject as a property to the $ParentObject
Add-Member -InputObject $ParentObject -MemberType NoteProperty -Name Child -Value $CustomObject
```

<br>

## Use CRLF Instead of LF for End of Line Characters

In Visual Studio Code for example, you can see at the bottom right corner whether your end of line sequence is set to CRLF or LF, Windows uses CRLF.

When you upload a PowerShell script to GitHub you need to make sure it's set to CRLF. PowerShell codes that are signed have big signature blocks at the end of them. PowerShell expects CRLF when doing authenticode signatures. You can also add those scripts to a `.gitattribute` config to your repo so that PowerShell files are uploaded with CRLF and not with LF.

<br>

## How to Securely Get the Temp Directory's Path

```powershell
[System.IO.Path]::GetTempPath()
```

<br>

A less secure way is this

```powershell
$env:Temp
```

The problem with the 2nd method is that if the path is long, contains too many spaces or contains non-English characters, it might lead to pattern matching using `~1`.

<br>

## How to Securely Get the User Directory's Path

The `Get-CimInstance` cmdlet can query the `Win32_UserProfile` class and filter by the current user's SID to get the LocalPath property, which is the path of the current user's profile directory. This method is more accurate than using the environment variable.

```powershell
(Get-CimInstance Win32_UserProfile -Filter "SID = '$([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)'").LocalPath
```

<br>

A less secure or accurate way is this

```powershell
$env:USERPROFILE
```

<br>

## How to Run Multiple Kernel Drivers In PowerShell

If you have a folder full of `.bin` driver files, you can use the following command to create a kernel service and run them one by one.

This can be useful for testing drivers against a deployed WDAC policy.

```powershell
(Get-ChildItem "C:\drivers").FullName | ForEach-Object -begin {$global:i=1} -Process {
    sc create "DriverTest$global:i" type=kernel binpath="$_"
    Start-Sleep -Seconds 1
    Start-Service -Name "DriverTest$global:i" -ErrorAction SilentlyContinue
    $global:i++
}
```

<br>

## How to Run PowerShell Code in CMD/Batch

Example, the code has no double quotes inside it

```powershell
powershell.exe -Command "$UserSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().user.value;(Get-LocalUser | where-object {$_.SID -eq $UserSID}).name"
```

<br>

Example, the code has double quotes inside it. We have to escape double quotes with `\"`

```powershell
powershell.exe -Command "$UserSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().user.value;$UserName = (Get-LocalUser | where-object {$_.SID -eq $UserSID}).name;Get-Process | where-object {$_.path -eq "\"C:\Users\$UserName\AppData\Local\Microsoft\Edge SxS\Application\msedge.exe\""} | ForEach-Object {Stop-Process -Id $_.id -Force -ErrorAction SilentlyContinue}"
```

<br>

A good related answer from [StackOverflow](https://stackoverflow.com/a/66847929/21243735)

<br>
