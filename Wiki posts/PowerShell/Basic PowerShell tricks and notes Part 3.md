# Basic PowerShell Tricks and Notes Part 3

The following PowerShell series is designed for newcomers to PowerShell who want to quickly learn the essential basics, the most frequently used syntaxes, elements and tricks. It can also be used by advanced users as a quick reference or those who want to sharpen their skills.

The main source for learning PowerShell is Microsoft Learn websites. There are extensive and complete guides about each command/cmdlet with examples.

[PowerShell core at Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/)

You can also use the Windows Copilot for asking any PowerShell related questions, code examples etc.

This is part 3 of this series, find other parts here:

* [Part 1](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-tricks-and-notes)
* [Part 2](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-Tricks-and-Notes-Part-2)
* [Part 3](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-Tricks-and-Notes-Part-3)
* [Part 4](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-Tricks-and-Notes-Part-4)
* [Part 5](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-Tricks-and-Notes-Part-5)

<br>

## How to Get Unique Items From a List of Objects Based on a Specific Property Only

Let's create some dummy data first

```powershell
# Create an array of 10 objects with 4 properties each
$Objects = @()
for ($i = 1; $i -le 10; $i++) {
    $Object = New-Object -TypeName PSObject -Property @{
        'Name'         = "Person$i"
        'Age'          = Get-Random -Minimum 20 -Maximum 40
        'Gender'       = Get-Random -InputObject @('Male', 'Female')
        'Occupation'   = Get-Random -InputObject @('Teacher', 'Engineer', 'Doctor', 'Lawyer', 'Journalist', 'Chef', 'Artist', 'Writer', 'Student', 'Manager')
        'RandomNumber' = Get-Random -InputObject @('694646152', '9846152', '3153546')
    }
    $Objects += $Object
}
```

Then we can display that data like this in a table

```powershell
$objects | Format-Table -AutoSize
```

<br>

Now we want to filter the result to get the unique values, but the uniqueness should be based on a specific property, which here is "RandomNumber". We don't want more than 1 object with the same "RandomNumber" property.

To do that, we use this method in PowerShell

```powershell
$Objects | Group-Object -Property RandomNumber | ForEach-Object -Process { $_.Group[0] } | Format-Table -AutoSize
```

<br>

You can use the Group-Object cmdlet to group the objects by the property you want to filter, and then select the first object from each group. This way, you will get one object for each "RandomNumber" property ***with all the properties intact.*** Using other methods such as `Get-Unique` or `Select-Object -Unique` won't work in this particular case.

You can find more information about the Group-Object cmdlet and its parameters in [this article](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/group-object).

<br>

## Install Big Powershell Modules System-Wide

Modules such as [Az](https://www.powershellgallery.com/packages/AZ/) or [Microsoft.Graph.Beta](https://www.powershellgallery.com/packages/Microsoft.Graph.Beta/) are big, can have thousands of files and take more than 1GB space after installation.

By default modules are installed in the Documents directory and when you use OneDrive, everything in there is synced automatically.

You can install such modules system-wide so that they won't be stored in the `Documents\PowerShell` directory and instead will be stored in `C:\Program Files\PowerShell\Modules` (for PowerShell core). This will also improve security since Administrator privileges will be required to change module files in that directory.

To do this, you need to use the `-Scope AllUsers` parameter.

```powershell
Install-Module Az -Scope AllUsers

Install-Module Microsoft.Graph.Beta -Scope AllUsers
```

* [Parameter Info](https://learn.microsoft.com/en-us/powershell/module/powershellget/install-module)

<br>

## Variable Scopes in ForEach-Object -Parallel

When using `ForEach-Object -Parallel`, the variables from the parent scope are read-only within the parallel script block when accessed with the `$using:` scope modifier. You cannot write to them or modify them inside the parallel script block. If you do not use the `$using:` scope modifier, they won't be available in the parallel script block at all.

If you need to collect or aggregate results from each parallel run, you should output the results to the pipeline, and then collect them after the parallel execution. Here's an example of how you can do that:

```powershell
[System.String[]]$AnimalsList = @()
$AnimalsList = 'Cat', 'Dog', 'Zebra', 'Horse', 'Mouse' | ForEach-Object -Parallel {
    $_
}
```

In that example, the count of the `$AnimalsList` will be 5 and it will contain the animals in the input array.

<br>

This example however would not work:

```powershell
[System.String[]]$AnimalsList = @()
'Cat', 'Dog', 'Zebra', 'Horse', 'Mouse' | ForEach-Object -Parallel {
    $AnimalsList += $_
}
```
Because the `$AnimalsList` variable is read-only in the parallel script block and only available in the local scriptblock's scope.

<br>

## How to Get the SID of All of the Accounts on the System

SID stands for Security Identifier. It is a unique value of variable length that is used to identify a security principal or security group in Windows operating systems. SIDs are used in access control lists (ACLs) and in the user manager database (SAM) in Windows operating systems.

You can get the SID of all the accounts on the system using the following PowerShell script:

```powershell
(Get-CimInstance -Class Win32_UserAccount -Namespace 'root\cimv2').Name | ForEach-Object -Process {
    [System.Security.Principal.NTAccount]$ObjSID = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList $_
    [System.Security.Principal.SecurityIdentifier]$ObjUser = $ObjSID.Translate([System.Security.Principal.SecurityIdentifier])
    [PSCustomObject]@{
        User = $_
        SID  = $ObjUser.Value
    }
}
```

### How To Convert a SID to User Name

```powershell
[System.String]$SID = 'S-1-5-21-348961611-2991266383-1085979528-1004'
$ObjSID = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $SID
$ObjUser = $ObjSID.Translate([System.Security.Principal.NTAccount])
Write-Host -Object 'Resolved user name: ' $ObjUser.Value -ForegroundColor Magenta
```

### How To Convert a User Name to SID

```powershell
[System.String]$UserName = 'HotCakeX'
$ObjUser = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList $UserName
$ObjSID = $ObjUser.Translate([System.Security.Principal.SecurityIdentifier])
Write-Host -Object "Resolved User's SID: " $ObjSID.Value -ForegroundColor Magenta
```

<br>

## How To Block Edge Traversal For All of the Firewall Rules

```powershell
Get-NetFirewallRule | Where-Object -FilterScript { $_.EdgeTraversalPolicy -ne 'Block' } | ForEach-Object -Process {
    Set-NetFirewallRule -Name $_.Name -EdgeTraversalPolicy Block
}
```

Edge Traversal controls whether an application or service the firewall rule applies to can receive unsolicited traffic from the internet. Unsolicited traffic is traffic that is not a response to a request from the computer or user and is originated from the Internet. Solicited traffic is initiated by the computer or user.

You can read more about it [here](https://learn.microsoft.com/en-us/windows/win32/winsock/ipv6-protection-level)

<br>

## Function Manipulation With Variables And ScriptBlocks

Suppose you have this function

```powershell
Function Write-Text {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)][System.String]$InputText
    )
    Write-Output -InputObject $InputText
}
```

<br>

You can store the function in a variable like this

```powershell
[System.Management.Automation.FunctionInfo]$Function = Get-Item -Path 'Function:Write-Text'
```

<br>

Or do it in bulk like this. In this example, `$SyncHash` is a synchronized hashtable used for communications between runspaces and `ExportedFunctions` is a nested hashtable that stores the functions inside of it.

```powershell
'Function-1', 'Function-2', 'Function-3' | ForEach-Object -Process {
  $SyncHash['ExportedFunctions']["$_"] = Get-Item -Path "Function:$_"
}
```

<br>

You can redefine the function using the same name or a different name like this. This is useful for passing the function to a different RunSpace or session.

```powershell
New-Item -Path 'Function:\Write-TextAlt' -Value $Function -Force
```

<br>

Redefining the functions in bulk just like the previous bulk operation above.

> [!TIP]\
> This is the recommended method of redefining the function in a different RunSpace because it completely strips its ScriptBlock of its affinity to the original RunSpace, so it'll just run on whatever the current RunSpace is without attempting to marshal.
>
> The affinity is about which RunSpace the script block was created in (rather than is allowed to run on).
>
> Basically when a scriptblock is created in a RunSpace, it knows where it came from, and when invoked outside of that RunSpace, the engine tries to send it back. This often fails because the main RunSpace is busy. So after a ~200ms time out, it will sometimes just run it on the current thread against the busy RunSpace, that causes a lot of issues, one of which is the inability to see it's parent scope. So it just forgets all commands exist and the result will be unexpected.
>
> Thanks to [SeeminglyScience](https://github.com/SeeminglyScience) for providing this additional info.

```powershell
New-Item -Path "Function:\$($_.Key)" -Value $_.Value.ScriptBlock.Ast.Body.GetScriptBlock() -Force | Out-Null
```

<br>

> [!TIP]\
> This method isn't recommended as it will maintain the ScriptBlock's affinity to the original RunSpace.

```powershell
$SyncHash.ExportedFunctions.GetEnumerator() | ForEach-Object -Process {
    New-Item -Path "Function:\$($_.Key)" -Value $_.Value.ScriptBlock -Force | Out-Null
}
```

<br>

Invoke the function using its new name, just as you would with the original function.

```powershell
Write-Text -InputText 'Hello from the original function!'
Write-TextAlt -InputText 'Hello from the new function!'
```

<br>

You can also create a scriptblock from the function using the following approach

```powershell
$ScriptBlock = [System.Management.Automation.ScriptBlock]::Create($Function.Definition)
```

<br>

And then call the scriptblock like this

```powershell
&$ScriptBlock 'Hello from the ScriptBlock! (direct call)'
. $ScriptBlock 'Hello from the ScriptBlock! (dot sourced)'
Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList 'Hello from the ScriptBlock! (Invoke-Command)'
```

<br>

> [!TIP]\
> When orchestrating tasks across multiple RunSpaces with synchronized Hashtables, it's crucial to ensure seamless function transfer. Follow these steps for optimal results:
>
> 1. Convert the desired function into a ScriptBlock.
> 2. Store the ScriptBlock in the synchronized Hashtable.
> 3. Redefine the ScriptBlock in the target RunSpace.
>
> This approach is necessary because simply saving the function to a variable, redefining it as a function in the destination RunSpace, and executing it won't replicate the original function's behavior outside the RunSpace context.
>
> Alternatively, you can define your code as ScriptBlocks instead of functions from the beginning.

<br>

## How To Achieve Pseudo-Lexical Variable Scoping in PowerShell

Lexical Scoping means:

* Nested functions have access to variables declared in their outer scope.
* Variables declared in an outer scope are accessible within nested functions.

PowerShell does not have true lexical scoping, but you can achieve pseudo-lexical scoping using C# types. Here's an example where we define a C# class with static members to store variables.

```powershell
# A path defined in the parent scope
$SomePath = 'C:\FolderName\FolderName2'

Add-Type -TypeDefinition @"
namespace NameSpace
{
    public static class ClassName
    {
        public static int SomeNumber = 456;
        public static string path = $("`"$($SomePath -replace '\\', '\\')`"");
    }
}
"@ -Language CSharp
```

The benefit of this approach is that **you can access the variables from any scope across the PowerShell App Domain**. That means any RunSpace you create, or any job started by either `Start-ThreadJob` or `Start-Job` cmdlets, without having to pass them as arguments.

<br>

Another great feature of this approach is that you don't need to set the value of the variables in the C# code, you can simply define the variable in C# and then assign the values in PowerShell side.

In this example, I'm only defining the variables:

```powershell
Add-Type -TypeDefinition @"
namespace NameSpace
{
    public static class ClassName
    {
        public static int SomeNumber;
        public static string path;
        public static object MDAVConfigCurrent;
    }
}
"@ -Language CSharp
```

And now I can set any value to the variables in PowerShell side

```powershell
[NameSpace.ClassName]::SomeNumber = 123
[NameSpace.ClassName]::path = 'C:\FolderName\FolderName2'
[NameSpace.ClassName]::MDAVConfigCurrent = Get-MpPreference
```

You can now use the variables anywhere by accessing them

```powershell
Write-Host -Object ([NameSpace.ClassName]::SomeNumber)
Write-Host -Object ([NameSpace.ClassName]::path)
Write-OutPut -InputObject ([NameSpace.ClassName]::MDAVConfigCurrent)
```

<br>
