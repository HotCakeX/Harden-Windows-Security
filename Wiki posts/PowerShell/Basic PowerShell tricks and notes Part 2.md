# Basic PowerShell tricks and notes Part 2

This page is part 2 of the **Basic PowerShell tricks and notes** series. You can find the [part 1 here.](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-tricks-and-notes)

Designed for beginners and newcomers to PowerShell who want to quickly learn the essential basics, the most frequently used syntaxes, elements and tricks. It should help you jump start your journey as a PowerShell user.

The main source for learning PowerShell is Microsoft Learn websites. There are extensive and complete guides about each command/cmdlet with examples.

[PowerShell core at Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/?view=powershell-7.4)

**Also Use Bing Chat for your PowerShell questions. The AI is fantastic at creating code and explaining everything.**

<br>

## View all Predictive IntelliSense suggestions based on past history

Press F2 to see the complete list of the Predictive IntelliSense suggestions as you type on the PowerShell console.

[More info](https://learn.microsoft.com/en-us/powershell/scripting/learn/shell/using-predictors)

<br>

## Where is the PowerShell command history stored?

In this directory

`$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine`

There is a file called `ConsoleHost_history.txt` and it contains the history of all the commands you've ever typed in PowerShell on your device. If you want to clear it, open the file, delete all of its content. If PowerShell is already open, close and reopen it to see the change.

<br>

## How to clear the automatic error variable in PowerShell

```powershell
$error.clear()
```

<br>

## How to get the last error type in PowerShell

```powershell
$Error[0].Exception.GetType().FullName
```

<br>

## How to display all environment variables and their values in PowerShell

```powershell
gci env:
```

* The `env:` drive is a PowerShell provider that exposes the environment variables as a hierarchical file system.

* The `gci` command is an alias for the `Get-ChildItem` cmdlet.

<br>

## List all MSCs and CPLs for Microsoft Management Console and Control Panels in PowerShell

```powershell
Get-ChildItem -Path C:\Windows\system32\* -Include *.msc, *.cpl | Sort-Object -Property Extension | Select-Object -Property Name | Format-Wide -Column 2
```

<br>

## How to mount the EFI system partition?

```powershell
mountvol u: /s
```

This isn't a native PowerShell cmdlet, it uses [mountvol CLI.](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/mountvol)

With that command you can mount the EFI partition and assign the letter `U` to it, it will appear in This PC. You can browse it in PowerShell as admin.

<br>

## How to check if a file is in use in PowerShell?

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

## Choosing between PowerShell and PowerShell Preview

Use PowerShell Preview if you want to test new features and don't need to call PowerShell with its alias, pwsh, from CMD. If you do need to call it like that, use PowerShell stable.

Use cases for it are when you need to use `pwsh.exe` in Windows Task Scheduler.

PowerShell Preview by default doesn't set its `pwsh.exe` available system wide, the path to that file isn't added to the system environment variables, only PowerShell stable does that, but of course if you want to use PowerShell preview you can manually modify the PATH environment variable to have `pwsh.exe` of PowerShell Preview be available system wide.

<br>

## Variable types in PowerShell

PowerShell variables can have types and type accelerator. The following command lists all of the types and their equivalent type accelerators. The fully qualified type names replace implicit with explicit.

```powershell
[PSObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')::Get
```

<br>

## Success codes and error codes

In PowerShell, or for programming languages in general, 0 = success, 1 or anything else means failure/error.

<br>

## How to get the names and AppIDs of installed apps of the current user in PowerShell?

```powershell
Get-StartApps
```

[More info](https://learn.microsoft.com/en-us/powershell/module/startlayout/get-startapps)

<br>

## Difference between Async and Sync

Async is faster than Sync

* Sync = waits for the previous task to finish before starting a new one

* Async = starts multiple tasks simultaneously

PowerShell supports sync/async commands workflows, also known as parallel.

<br>

## How to enable a disabled event log using PowerShell

First we create a new `EventLogConfiguration` object and pass it the name of the log we want to configure, then we set it to enabled and save the changes.

```powershell
$logName = 'Microsoft-Windows-DNS-Client/Operational'  

$log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $logName 
$log.IsEnabled=$true 
$log.SaveChanges() 
```

We can confirm the change by running this command:

```powershell
Get-WinEvent -ListLog Microsoft-Windows-DNS-Client/Operational | Format-List *
```

Using the same method we can configure many other options of the log file, just take a look at the `EventLogConfiguration` Class for a list of configurable properties.

<br>

## Find the current user's username in PowerShell

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

<br>

## How to access properties of an object in PowerShell

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

## Dot-sourcing

To dot-source a PowerShell function in the same script file, you can use the dot operator `.` followed by the path of the script file containing the function. The path can be relative or absolute. Here's an example:


```powershell
# Contents of MyFunctions.ps1
function MyFunction {
    Write-Host "Hello World!"
}

# Contents of Main.ps1
. ./MyFunctions.ps1
MyFunction
```

In this example, `Main.ps1` dot-sources `MyFunctions.ps1` using the dot operator and then calls `MyFunction`. When you run `Main.ps1`, it will output `Hello World!` to the console.

The dot operator tells PowerShell to execute the script file in the current scope instead of a new scope. This means that any functions or variables defined in the script file will be available in the current scope.

<br>

## A custom script to generate random words in PowerShell

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

## How to see all the shared folders and drives

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

## An example of using -f format operator

```powershell
Write-output("The drivername {0} is vulnerable with a matching SHA256 hash of {1}" -f $Filename, $SHA256)
```

[More info](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_operators?view=powershell-7.3#format-operator--f)

<br>

## How to list all of the Positional Parameters of a Cmdlet

In this example we use the 

```powershell
Get-Help -Name "Get-ChildItem" -Parameter * |
Sort-Object -Property position |
Select-Object -Property name, position
```

<br>

## How to get the number of fans and details about them in PowerShell

```powershell
(Get-CimInstance -Namespace root/CIMV2 -ClassName Win32_Fan).count
Get-CimInstance -Namespace root/CIMV2 -ClassName Win32_Fan
```

> P.S VMs don't have fans.

<br>

## How to get the last reboot time in PowerShell

```powershell
[datetime](Get-CimInstance -ClassName win32_operatingsystem -ComputerName $_.Name).LastBootUpTime
```

<br>

## How to add a PS custom object to another PS custom object

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
