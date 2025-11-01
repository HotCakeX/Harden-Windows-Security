# Basic PowerShell Tricks and Notes

The following PowerShell series is designed for newcomers to PowerShell who want to quickly learn the essential basics, the most frequently used syntaxes, elements and tricks. It can also be used by advanced users as a quick reference or those who want to sharpen their skills.

The main source for learning PowerShell is Microsoft Learn websites. There are extensive and complete guides about each command/cmdlet with examples.

[PowerShell core at Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/)

You can also use the Windows Copilot for asking any PowerShell related questions, code examples etc.

This is part 1 of this series, find other parts here:

* [Part 1](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-tricks-and-notes)
* [Part 2](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-Tricks-and-Notes-Part-2)
* [Part 3](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-Tricks-and-Notes-Part-3)
* [Part 4](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-Tricks-and-Notes-Part-4)
* [Part 5](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-Tricks-and-Notes-Part-5)

<br>

## Pipeline Variable

`$_`  is the variable for the current value in the pipeline.

[Examples](https://stackoverflow.com/questions/3494115/what-does-mean-in-powershell)

<br>

## Filtering Data With Where-Object

`?` which is an alias for `Where-Object`, is used to filter all the data given to it.

[Where-Object](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/where-object)

Example

```powershell
Get-PSDrive | ?{$_.free -gt 1}
```

Example

```powershell
Get-PSDrive | Where-Object {$_.free -gt 1}
```

<br>

## Show the Properties of an Object Selectively

`Select` or `Select-Object` show the properties that we want to see from an object

If we use `*` then all of the properties will be shown and from there we can choose which properties to add.

Example:

```powershell
Get-PSDrive | Where-Object {$_.free -gt 1} | Select-Object -Property *

Get-PSDrive | Where-Object {$_.free -gt 1} | Select-Object -Property root, used, free
```

<br>

## Looping Using Foreach-Object

The [ForEach-Object](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/foreach-object) cmdlet performs an operation on each item in a collection of input objects. The input objects can be piped to the cmdlet or specified using the InputObject parameter.

In other words: for every item in the pipe, run this line.

Examples:

```powershell
Get-PSDrive | Where-Object { $_.free -gt 1 } | Select-Object -Property root, used, free | ForEach-Object { 'zebra' }
```

```powershell
Get-PSDrive | Where-Object { $_.free -gt 1 } | Select-Object -Property root, used, free | ForEach-Object { Write-Host 'Free Space for ' $_.Root 'is' ($_.free / 1gb ) }
```

The parenthesis, `($_.free/1gb )` must be there if we want to modify one of the output strings.

<br>

## To Get Online Help About Any Cmdlet

These commands open the webpage for the specified cmdlet or command

```powershell
Get-help <cmdlet> –online
```

```powershell
Get-Help dir –online
```

```powershell
Get-Help ForEach-Object –online
```

<br>

This shows the full help on the PowerShell console

```powershell
Get-help Get-Service -full
```

<br>

This opens a new window showing the full help content and offers other options such as Find

```powershell
Get-help Get-Service -ShowWindow
```

<br>

## To Query Windows Services

This gets any Windows service that has the word "Xbox" in it.

```powershell
Get-Service "*xbox*"
```

This gets any Windows service that has the word "x" in it.

```powershell
Get-Service "*x*"
```

Putting `*` around the word or letter finds anything that contains it.

```powershell
Get-Service "*x*" | Sort-Object status
```

Example syntax:

```powershell
Get-Service [[-Name] <System.String[]>] [-ComputerName <System.String[]>] [-DependentServices] [-Exclude <System.String[]>] [-Include <System.String[]>] [-RequiredServices] [<CommonParameters>]
```

In this part

```powershell
Get-Service [[-Name] <System.String[]>]
```

The `-Name` Parameter accepts `<System.String[]>`, which is a StringList, and when [] is included, that means there can be multiple inputs/strings, separated by comma `,`.

So `[[-Name] <System.String[]>]` can be used like this:

```powershell
Get-Service -Name WinRM,BITS,*Xbox*
```

Also in another similar example syntax:

```powershell
Get-Service [-ComputerName <System.String[]>] [-DependentServices] -DisplayName <System.String[]> [-Exclude <System.String[]>] [-Include <System.String[]>] [-RequiredServices] [<CommonParameters>]
```

Everything is inside a bracket except for -DisplayName, that means it is mandatory. **If a parameter is inside a bracket, that means it is optional.**

<br>

## How to Suppress Errors in Powershell

```powershell
-ErrorAction SilentlyContinue
```

[Everything you wanted to know about exceptions](https://learn.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-exceptions)

Try/Catch will only 'trigger' on a terminating exception. Most cmdlets in PowerShell, by default, won't throw terminating exceptions. You can set the error action with the `-ErrorAction` or `-ea` parameters:

```powershell
Do-Thing 'Stuff' -ErrorAction Stop
```

Be careful when using `-ErrorAction Stop`. If using it in loops like with `ForEach-Object`, it will stop the entire loop after the first encounter of error.

[Handling Errors the PowerShell Way](https://devblogs.microsoft.com/scripting/handling-errors-the-powershell-way/)

Tip: If you set

```powershell
$ErrorActionPreference = 'Stop'
```

In your PowerShell code, either locally or globally for the entire script, `Write-Error` will cause the script to stop because it will be like throwing an error.

<br>

## Get File Signature of All of the Files in a Folder

This will check all of the files' signatures in the current directory

```powershell
Get-ChildItem -File | ForEach-Object -Process {Get-AuthenticodeSignature -FilePath $_}
```

[More info about Get-ChildItem cmdlet](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-childitem)

<br>

## Write Output to a File or String

```powershell
> output.txt
```

Example:

```powershell
ipconfig /all > mynetworksettings.txt
```

[about_Redirection](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_redirection)

<br>

## How to Add Delay/Pause to the Execution of Powershell Script

To sleep a PowerShell script for 5 seconds, you can run the following command

```powershell
Start-Sleep -Seconds 5
```

You can also use the `-milliseconds` parameter to specify how long the resource sleeps in milliseconds.

```powershell
Start-Sleep -Milliseconds 25
```

[Start-Sleep](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/start-sleep)

<br>

## How to Stop/Kill a Process or (.exe) Executable in Powershell

Using native PowerShell cmdlet

```powershell
Stop-Process -Name "Photoshop"
```

[Stop-Process](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/stop-process)

Using `taskkill.exe`

```cmd
taskkill /IM "photoshop app.exe" /F
```

[taskkill](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/taskkill)

<br>

## Automatically Answer “Yes” to a Prompt in Powershell

Use `–force` at the end of the command

<br>

## Displays All Information in the Current Access Token

The command below displays all information in the current access token, including the current user name, security identifiers (SID), privileges, and groups that the current user belongs to.

```cmd
whoami /all
```

[whoami](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/whoami)

<br>

## Display All the Tcp and Udp Ports on Which the Computer Is Listening

```cmd
netstat -a
```

[netstat](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netstat)

<br>

## Copy the Result of a Command to Clipboard Automatically

Add `| clip` at the end the command

Example:

```powershell
Get-TimeZone | clip
```

Example:

```cmd
rg -i -F URL: | clip
```

<br>

## How to Scan 2 Text Files for Differences and Pipe the Difference to a Third File

```powershell
$File1 = "C:\Scripts\Txt1.txt"
$File2 = "C:\Scripts\Txt2.txt"
$Location = "C:\Scripts\Txt3.txt"

Compare-Object -ReferenceObject (Get-Content -Path $File1) -DifferenceObject (Get-Content -Path $File2) | Format-List | Out-File -FilePath $Location
```

[Compare-Object](https://learn.microsoft.com/en-gb/powershell/module/Microsoft.PowerShell.Utility/Compare-Object)

<br>

## Difference Between Strings and StringLists

This is Stringlist in PowerShell:

`[String[]]`

And this is a string

`[String]`

When we define Stringlist in a parameter, then the argument will keep asking for multiple values instead of 1, if we want to stop adding arguments for the parameter, we have to enter twice.

<br>

## How to Run a Powershell (.PS1) Script ?

* Method 1:

```powershell
&"Path\To\PS\Script.ps1"
```

Using the `&` [Call operator](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_operators#call-operator-)

* Method 2:

```powershell
Set-Location 'Path\To\Folder\OfThe\Script'
.\Script.ps1
```

* Method 3

```powershell
pwsh.exe -File 'Path\To\Folder\OfThe\Script.ps1'
```

*This example uses PowerShell Core*

<br>

## Enclosing Strings That Have a Lot of Single and Double Quotation Marks

```powershell
$string =@"

Some string text

"@

$string
```

the markers `@"` and `"@` indicating the beginning and end of the string must be on separate lines.

<br>

## How to Find the Type of the Output of a Command in Powershell

Using `GetType()`

Examples:

```powershell
(Get-BitlockerVolume -MountPoint "C:").KeyProtector.keyprotectortype.GetType()
```

```powershell
(Get-NetTCPConnection).GetType()
```

<br>

## Make Sure to Use Pascal Case for Variable Names

Pascal Case requires variables made from compound words and have the first letter of each appended word written with an uppercase letter.

Example: `$Get-CurrentTime`

This will make your code readable and more understandable.

<br>

## Some Popular Resources and Cmdlets

* [Out-Null](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/out-null)

* [Test-Path](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/test-path)

* [Add-Content](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/add-content)

* [New-Item](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-item)

* [Everything you wanted to know about arrays](https://learn.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-arrays)

* [about_Split](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_split)

* [Start-Process](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-process)

* [about_Parsing](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_parsing)

* [about_Quoting_Rules](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_quoting_rules)

* [about_PowerShell_exe](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe)

* [about_Comparison_Operators](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_comparison_operators)

* [Everything you wanted to know about hashtables](https://learn.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-hashtable)

* [about_Hash_Tables](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_hash_tables)

* [about_Operators](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_operators)

* [ForEach-Object](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/foreach-object)

* [about_Foreach](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_foreach)

* [Set-Acl](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-acl)

* [Set-Content](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-content)

* [icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)

* [Get-Process](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-process)

* [about_Environment_Variables](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)

* [Everything you wanted to know about the if statement](https://learn.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-if)

* [Tee-Object](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/tee-object)

* [about_Signing](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_signing)

* [CIM Classes (WMI)](https://learn.microsoft.com/en-us/windows/win32/wmisdk/cimclas)

* [Get-CimInstance](https://learn.microsoft.com/en-us/powershell/module/cimcmdlets/get-ciminstance)

* [ConvertFrom-Json](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/convertfrom-json)

* [PowerShell scripting performance considerations](https://learn.microsoft.com/en-us/powershell/scripting/dev-cross-plat/performance/script-authoring-considerations)

* [Creating Get-WinEvent queries with FilterHashtable](https://learn.microsoft.com/en-us/powershell/scripting/samples/creating-get-winevent-queries-with-filterhashtable)

* [Checkpoint-Computer](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/checkpoint-computer)

  * [Restore Point Description Text](https://learn.microsoft.com/en-us/windows/win32/sr/restore-point-description-text)

* [Get-ComputerRestorePoint](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-computerrestorepoint)

* [Pop-Location](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/pop-location)

* [Invoke-Expression](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression)

* [about_Script_Blocks](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_script_blocks)

* [about_Functions_Advanced_Parameters](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_functions_advanced_parameters)

* [about_Functions_CmdletBindingAttribute](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_functions_cmdletbindingattribute)

* [Add-Computer](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/add-computer)

* [Get-Unique](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-unique)

* [Sort-Object](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/Sort-Object)

* [about_Comment_Based_Help](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_comment_based_help)

* [Get-Date](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-date)

* [about_Parameters_Default_Values](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_parameters_default_values)

* [about_Parameter_Sets](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_parameter_sets)

* [about_Automatic_Variables](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_automatic_variables)

* [about_Functions_Argument_Completion](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_functions_argument_completion)

* [Using tab-completion in the shell](https://learn.microsoft.com/en-us/powershell/scripting/learn/shell/tab-completion)

* [about_Continue](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_continue)

* [Trim Your Strings with PowerShell](https://devblogs.microsoft.com/scripting/trim-your-strings-with-powershell/)

<br>
