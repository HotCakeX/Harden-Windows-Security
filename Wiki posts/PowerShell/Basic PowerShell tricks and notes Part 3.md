# Basic PowerShell Tricks and Notes Part 3

This page is designed for beginners and newcomers to PowerShell who want to quickly learn the essential basics, the most frequently used syntaxes, elements and and tricks. It should help you jump start your journey as a PowerShell user.

The main source for learning PowerShell is Microsoft Learn websites. There are extensive and complete guides about each command/cmdlet with examples.

[PowerShell core at Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/)

You can also use the Windows Copilot for asking any PowerShell related questions, code examples etc.

This is part 3 of this series, find other parts here:

* [Part 1](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-tricks-and-notes)
* [Part 2](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-Tricks-and-Notes-Part-2)

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

## Install Big Powershell Modules System Wide

Modules such as [Az](https://www.powershellgallery.com/packages/AZ/) or [Microsoft.Graph.Beta](https://www.powershellgallery.com/packages/Microsoft.Graph.Beta/) are big, can have thousands of files and take more than 1GB space after installation.

By default modules are installed in the Documents directory and when you use OneDrive, everything in there is synced automatically.

You can install such modules system wide so that they won't be stored in the `Documents\PowerShell` directory and instead will be stored in `C:\Program Files\PowerShell\Modules` (for PowerShell core). This will also improve security since Administrator privileges will be required to change module files in that directory.

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
