# PowerShell Best Practices To Follow When Coding

It is important to follow best practices when coding in PowerShell to ensure that your code is efficient, maintainable, and secure.

<br>

## Specify The Variable Types Explicitly

🚫 Don't do this
```powershell
$Var = 5
```

✅ Do this instead
```powershell
[System.Int32]$Var = 5
```

<br>

## Use Full Type Names Instead of Type Accelerators

🚫 Don't do this
```powershell
[String]$Var = 'Hello'
```

✅ Do this instead
```powershell
[System.String]$Var = 'Hello'
```

<br>

## Use Single Quotes Instead of Double Quotes Unless Absolutely Necessary

🚫 Don't do this
```powershell
$Var = "Hello"
```

✅ Do this instead
```powershell
$Var = 'Hello'
```

This is because double quotes allow for string interpolation, which can be a security risk if the string is not sanitized properly and also slightly slower than single quotes.

<br>

## Use Full Cmdlet Names Instead of Aliases

🚫 Don't do this
```powershell
Gci
cls
```

✅ Do this instead
```powershell
Get-ChildItem
Clear-Host
```

<br>

## Use Pascal Casing for Everything

🚫 Don't do this
```powershell
$myvariable
get-childitem
new-item
```

🚫 or this (camelCase)

```powershell
$myVariable
get-ChildItem
new-Item
```


✅ Do this instead
```powershell
$MyVariable
Get-ChildItem
New-Item
```

<br>

## Use Regions to Organize Your Code

✅ Using regions like this allows you to collapse and expand sections of your code for better readability.

```powershell
#Region Functions
function Get-MyFunction1 {
    # Function code here
}
function Get-MyFunction2 {
    # Function code here
}
function Get-MyFunction3 {
    # Function code here
}
#EndRegion
```

<br>

## Use Visual Studio Code PowerShell Extension For Automatic Best Practice Formatting

You can access the settings page of [PowerShell extension in VS Code](https://code.visualstudio.com/docs/languages/powershell) and enable options that automatically apply some of the aforementioned best practices when you format your code with (CTRL + Shift + F) shortcut.

<br>

## Refrain From Defining and Using Global Variables as Much as Possible

Global variables are not recommended in general because of security implications. They can be overwritten by the user on console as well.

If you need to define global variables, make sure you set them as [constants or read-only](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/new-variable#-option) so that they cannot be overwritten once they are defined.

<br>

## Use C# If You Need Custom Global Classes

If you need custom types in PowerShell and want them to be globally available to your module, It's recommended to use C# and define custom classes with **specific and unique Namespace and Class names** so that there won't be any possible conflicts with other classes/types that belong to 3rd party modules.

<br>

### How Would You Make PowerShell Classes Globally Available?

Even though it's not recommended, here is how you can make custom classes globally available in PowerShell. Classes will be available process-wide and therefore also in other runspaces, defining them with the `[NoRunspaceAffinity()]` attribute.

* [Read more](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_classes#exporting-classes-with-type-accelerators)

<br>

```powershell
[NoRunspaceAffinity()]
Class Items : System.Management.Automation.IValidateSetValuesGenerator {
    [System.String[]] GetValidValues() {
        $Items = ('Item1', 'Item2', 'Item3')
        return [System.String[]]$Items
    }
}

[NoRunspaceAffinity()]
Class BasePolicyNames : System.Management.Automation.IValidateSetValuesGenerator {
    [System.String[]] GetValidValues() {

        [System.String[]]$BasePolicyNames = foreach ($Policy in (&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies) {
            if ($Policy.IsSystemPolicy -ne 'True') {
                if ($Policy.PolicyID -eq $Policy.BasePolicyID) {
                    $Policy.FriendlyName
                }
            }
        }
        return $BasePolicyNames
    }
}

# Define the types to export with type accelerators.
[System.Reflection.TypeInfo[]]$ExportableTypes = @(
    [Items]
    [BasePolicyNames]
)

# Get the non-public TypeAccelerators class for defining new accelerators.
[System.Reflection.TypeInfo]$TypeAcceleratorsClass = [psobject].Assembly.GetType('System.Management.Automation.TypeAccelerators')

# Add type accelerators for every exportable type.
$ExistingTypeAccelerators = $TypeAcceleratorsClass::Get

foreach ($Type in $ExportableTypes) {

    # !! $TypeAcceleratorsClass::Add() quietly ignores attempts to redefine existing
    # !! accelerators with different target types, so we check explicitly.
    $Existing = $ExistingTypeAccelerators[$Type.FullName]

    if (($null -ne $Existing) -and ($Existing -ne $Type)) {
        throw "Unable to register type accelerator [$($Type.FullName)], because it is already defined with a different type ([$Existing])."
    }
    $TypeAcceleratorsClass::Add($Type.FullName, $Type)
}
```

<br>

## More Resources From Microsoft That You Should Check Out

- [Cmdlet Development Guidelines](https://learn.microsoft.com/en-us/powershell/scripting/developer/cmdlet/cmdlet-development-guidelines)
- [Required Development Guidelines](https://learn.microsoft.com/en-us/powershell/scripting/developer/cmdlet/required-development-guidelines)
- [Strongly Encouraged Development Guidelines](https://learn.microsoft.com/en-us/powershell/scripting/developer/cmdlet/strongly-encouraged-development-guidelines)
- [Advisory Development Guidelines](https://learn.microsoft.com/en-us/powershell/scripting/developer/cmdlet/advisory-development-guidelines)

<br>
