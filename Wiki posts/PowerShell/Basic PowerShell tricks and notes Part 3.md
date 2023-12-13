# Basic PowerShell Tricks and Notes Part 3

This page is part 3 of the **Basic PowerShell tricks and notes** series.

  * [part 1 here](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-tricks-and-notes)
  * [part 2 here](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-tricks-and-notes-Part-2)

Designed for beginners and newcomers to PowerShell who want to quickly learn the essential basics, the most frequently used syntaxes, elements and tricks. It should help you jump start your journey as a PowerShell user.

The main source for learning PowerShell is Microsoft Learn websites. There are extensive and complete guides about each command/cmdlet with examples.

[PowerShell core at Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/?view=powershell-7.4)

**Also Use Bing Chat for your PowerShell questions. The AI is fantastic at creating code and explaining everything.**

<br>

## How to Get Unique Items From a List of Objects Based on a Specific Property Only

Let's create some dummy data first

```powershell
# Create an array of 10 objects with 4 properties each
$objects = @()
for ($i = 1; $i -le 10; $i++) {
    $object = New-Object -TypeName PSObject -Property @{
        "Name" = "Person$i"
        "Age" = Get-Random -Minimum 20 -Maximum 40
        "Gender" = Get-Random -InputObject @("Male", "Female")
        "Occupation" = Get-Random -InputObject @("Teacher", "Engineer", "Doctor", "Lawyer", "Journalist", "Chef", "Artist", "Writer", "Student", "Manager")
        "RandomNumber" = Get-Random -InputObject @("694646152","9846152","3153546")
    }
    $objects += $object
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
$objects | Group-Object -Property RandomNumber | ForEach-Object { $_.Group[0] } | Format-Table -AutoSize
```

<br>

You can use the Group-Object cmdlet to group the objects by the property you want to filter, and then select the first object from each group. This way, you will get one object for each "RandomNumber" property ***with all the properties intact.*** Using other methods such as `Get-Unique` or `Select-Object -Unique` won't work in this particular case.

You can find more information about the Group-Object cmdlet and its parameters in [this article](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/group-object).

<br>

## Install Big Powershell Modules System Wide

Modules such as [Az](https://www.powershellgallery.com/packages/AZ/) or [Microsoft.Graph.Beta](https://www.powershellgallery.com/packages/Microsoft.Graph.Beta/) are big, can have thousands of files and take more than 1GB space after installation.

By default modules are installed in the Documents directory and when you use OneDrive, everything in there is synced automatically.

You can install such modules system wide so that they won't be stored in the `Documents\PowerShell` directory and instead will be stored in `C:\Program Files\PowerShell\Modules` (for PowerShell core). This will also improve security since Administrator privileges will be required to change module files.

To do this, you need to use the `-Scope AllUsers` parameter.

```powershell
Install-Module Az -Scope AllUsers

Install-Module Microsoft.Graph.Beta -Scope AllUsers
```

* [Parameter Info](https://learn.microsoft.com/en-us/powershell/module/powershellget/install-module)

<br>
