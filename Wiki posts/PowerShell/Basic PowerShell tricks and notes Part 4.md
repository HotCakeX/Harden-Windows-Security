# Basic PowerShell Tricks and Notes Part 4

This page is designed for beginners and newcomers to PowerShell who want to quickly learn the essential basics, the most frequently used syntaxes, elements and tricks. It should help you jump start your journey as a PowerShell user.

The main source for learning PowerShell is Microsoft Learn websites. There are extensive and complete guides about each command/cmdlet with examples.

[PowerShell core at Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/)

You can also use the Windows Copilot for asking any PowerShell related questions, code examples etc.

This is part 4 of this series, find other parts here:

* [Part 1](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-tricks-and-notes)
* [Part 2](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-Tricks-and-Notes-Part-2)
* [Part 3](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-Tricks-and-Notes-Part-3)

<br>

## How To Bypass PowerShell Constant Variables And How To Prevent The Bypass

When using [Set-Variable](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/set-variable) cmdlet to create a constant variable, you can't change the value of that variable later in the script by simple assignments, but there is a way to bypass this limitation using reflection.

```PowerShell
Set-Variable -Name 'MyConstantVariable' -Value 'Hello World' -Option 'Constant'
$MyConstantVariable

$PSVar = Get-Variable -Name 'MyConstantVariable'
$PSVar.GetType().GetField('_value', [System.Reflection.BindingFlags] 'NonPublic, Instance').SetValue($PSVar, 'Wut')
$MyConstantVariable

$PSVar.GetType().GetField('_options', [System.Reflection.BindingFlags] 'NonPublic, Instance').SetValue($PSVar, [System.Management.Automation.ScopedItemOptions]::None)
$MyConstantVariable = 'Lolz'
$MyConstantVariable
```

> Shout out to [Santiago Squarzon](https://github.com/santisq) for this trick.

<br>

The way you can prevent this bypass is by defining constant variables in C# code in PowerShell. The reflection method demonstrated above won't work on this type of constant variables.

```powershell
Add-Type -TypeDefinition @'
namespace NS
{
    public static class Const
    {
        public const int myConst = 66;
    }
}
'@ -Language CSharp

([NS.Const]::myConst)
```

<br>

## How To Prevent PowerShell Optimization From Being Disabled

In PowerShell, the presence of the following commands in a ScriptBlock will completely disable optimizations in that ScriptBlock:

```PowerShell
New-Variable
Remove-Variable
Set-Variable
Set-PSBreakpoint
# Also Dot-Sourcing
. .\file.ps1
# Also if any type of breakpoint is already set
```

Also usage of any [AllScope](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_scopes#the-allscope-option) variable in a ScriptBlock will disable optimization in there.

You can view those commands [in here too](https://github.com/PowerShell/PowerShell/blob/bd8b0bd42163a9a6f3fc32001662d845b7f7fff0/src/System.Management.Automation/engine/parser/VariableAnalysis.cs#L48-L62).

> Shout out to [SeeminglyScience](https://github.com/SeeminglyScience) for this info.

<br>

Any PowerShell code at some point will run and be in a ScriptBlock. Functions are their own ScriptBlock, modules (.psm1 files) are their own ScriptBlock, script files (.ps1 files) are their own ScriptBlock, ScriptBlocks themselves are their own ScriptBlock and so on.

So the presence of the above methods and commands inside a ScriptBlock in the context explained above will disable optimization in that ScriptBlock, you can however use them outside of the ScriptBlock and then utilize them inside which **will not** disable optimization in that ScriptBlock.

<br>
