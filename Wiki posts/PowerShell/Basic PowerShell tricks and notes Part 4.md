# Basic PowerShell Tricks and Notes Part 4

The following PowerShell series is designed for newcomers to PowerShell who want to quickly learn the essential basics, the most frequently used syntaxes, elements and tricks. It can also be used by advanced users as a quick reference or those who want to sharpen their skills.

The main source for learning PowerShell is Microsoft Learn websites. There are extensive and complete guides about each command/cmdlet with examples.

[PowerShell core at Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/)

You can also use the Windows Copilot for asking any PowerShell related questions, code examples etc.

This is part 4 of this series, find other parts here:

* [Part 1](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-tricks-and-notes)
* [Part 2](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-Tricks-and-Notes-Part-2)
* [Part 3](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-Tricks-and-Notes-Part-3)
* [Part 4](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-Tricks-and-Notes-Part-4)
* [Part 5](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-Tricks-and-Notes-Part-5)

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

## The Fastest Way To Enumerate All Files In Directories Based On Specific Extensions

This example will enumerate all files in an array of directories based on specific extensions and return an array of FileInfo objects. This is potentially the fastest and most optimized way to do this. This command takes ~9 seconds to complete on my system.

```PowerShell
# Define a HashSet of file extensions to filter by
$Extensions = [System.Collections.Generic.HashSet[System.String]]@('.sys', '.exe', '.com', '.dll', '.rll', '.ocx', '.msp', '.mst', '.msi', '.js', '.vbs', '.ps1', '.appx', '.bin', '.bat', '.hxs', '.mui', '.lex', '.mof')
# Define an array of directory paths to scan through
[System.IO.DirectoryInfo[]]$Paths = 'C:\ProgramData\Microsoft', 'C:\Program Files\Windows Defender', 'C:\Program Files\Hyper-V'
# Define a HashSet to store the initial output
$Output = [System.Collections.Generic.HashSet[System.IO.FileInfo]]@()
# Define the GetFiles parameters
$Options = [System.IO.EnumerationOptions]@{
    IgnoreInaccessible    = $true
    # This is equal to -Recurse parameter in Get-ChildItem cmdlet
    RecurseSubdirectories = $true
    # By default is skips hidden and system files, here we just skip the System files
    # https://learn.microsoft.com/en-us/dotnet/api/system.io.fileattributes
    # https://learn.microsoft.com/en-us/dotnet/api/system.io.enumerationoptions.attributestoskip
    AttributesToSkip      = 'System'
}

# Loop over each path and add the files to the output HashSet using UnionWith
foreach ($Path in $Paths) {
    $Output.UnionWith((Get-Item -LiteralPath $Path).GetFiles('*', $Options))
}
# Define a HashSet to store the filtered output - Making sure the comparison is case-insensitive since "Get-ChildItem -Include" is case-insensitive as well and we don't want to miss files with ".DLL" extension and so on
$OutputAfterFiltering = [System.Collections.Generic.HashSet[System.IO.FileInfo]]@( $Output.Where({ $Extensions.Contains($_.Extension.ToLower()) }))
```

<br>

This is an improved variation of the script above that handles inaccessible directories better but takes a few seconds (~3) more to complete.

```PowerShell
# Define a HashSet of file extensions to filter by
$Extensions = [System.Collections.Generic.HashSet[System.String]]::new(
    [System.String[]] ('.sys', '.exe', '.com', '.dll', '.rll', '.ocx', '.msp', '.mst', '.msi', '.js', '.vbs', '.ps1', '.appx', '.bin', '.bat', '.hxs', '.mui', '.lex', '.mof'),
    # Make it case-insensitive
    [System.StringComparer]::InvariantCultureIgnoreCase
)
# Define an array of directory paths to scan through
[System.IO.DirectoryInfo[]]$Paths = 'C:\ProgramData\Microsoft', 'C:\Program Files\Windows Defender', 'C:\Program Files\Hyper-V'
# Define a HashSet to store the initial output
$Output = [System.Collections.Generic.HashSet[System.IO.FileInfo]]@()
# Define the GetFiles parameters
$Options = [System.IO.EnumerationOptions]@{
    IgnoreInaccessible    = $true
    # This is equal to -Recurse parameter in Get-ChildItem cmdlet
    RecurseSubdirectories = $true
    # This is equal to -Force parameter in Get-ChildItem cmdlet
    AttributesToSkip      = 'None'
}

$Output = foreach ($Path in $Paths) {
    [System.IO.Enumeration.FileSystemEnumerator[System.IO.FileInfo]]$Enum = $Path.EnumerateFiles('*', $Options).GetEnumerator()
    while ($true) {
        try {
            # Move to the next file
            if (-not $Enum.MoveNext()) {
                # If we reach the end of the enumeration, we break out of the loop
                break
            }
            # Check if the file extension is in the Extensions HashSet
            if ($Extensions.Contains($Enum.Current.Extension)) {
                # Pass the file to the output
                $Enum.Current
            }
        }
        catch {}
    }
}
```

> Shout out to [Santiago Squarzon](https://github.com/santisq) for providing this method.

<br>

For comparison, the following command takes ~20 minutes to complete on my system and produces the same exact output as the scripts above but it's 100x times slower.

```PowerShell
[System.IO.DirectoryInfo[]]$Paths = 'C:\ProgramData\Microsoft', 'C:\Program Files\Windows Defender', 'C:\Program Files\Hyper-V'
[System.String[]]$Extensions = @('*.sys', '*.exe', '*.com', '*.dll', '*.rll', '*.ocx', '*.msp', '*.mst', '*.msi', '*.js', '*.vbs', '*.ps1', '*.appx', '*.bin', '*.bat', '*.hxs', '*.mui', '*.lex', '*.mof')
[System.IO.FileInfo[]]$Output = Get-ChildItem -Recurse -File -LiteralPath $Paths -Include $Extensions -Force -ErrorAction SilentlyContinue
```

<br>

## How To View The Loaded Assemblies In PowerShell

```PowerShell
[System.AppDomain]::CurrentDomain.GetAssemblies() |
Where-Object -FilterScript { $_.Location } |
Sort-Object -Property FullName |
Select-Object -Property FullName, Location, GlobalAssemblyCache, IsFullyTrusted |
Out-GridView -OutputMode Multiple
```

* [Read more](https://learn.microsoft.com/en-us/dotnet/api/system.appdomain)

<br>

### How To Load All DLLs That Come With PowerShell

```powershell
foreach ($Dll in (Convert-Path -Path ("$([psobject].Assembly.Location)\..\*.dll"))) {
    try {
        Add-Type -Path $Dll
    }
    catch {}
}
```

<br>

#### Alternative Method

```powershell
foreach ($Dll in Get-ChildItem -File -Filter '*.dll' -Path $PSHOME) {
    try {
        Add-Type -AssemblyName ($Dll.Name).Replace($Dll.Extension, '')
    }
    catch {}
}
```

<br>

Utilizing a try/catch block is essential in this scenario where not all DLLs located at the root of PowerShell are importable. This code is compatible with PowerShell installed through the Store or the MSI file.

Manually importing DLLs can be advantageous, particularly when transitioning from writing code in VS Code to executing it in PowerShell within Windows Terminal. In VS Code, the integrated extension automatically loads necessary assemblies, ensuring smooth operation. However, this automatic process is absent outside of VS Code, potentially leading to discrepancies in code behavior. To mitigate this, manually identifying and importing the missing assemblies is required. By importing all DLLs preemptively, you eliminate the concern of missing assemblies.

To streamline this process, incorporate that code into your `RootModule.psm1` or `ScriptsToProcess.ps1` file. This ensures the code executes solely during the module's import phase, optimizing performance.

> [!NOTE]\
> The `-ReferencedAssemblies` in `Add-Type -Path <Paths> -ReferencedAssemblies <Assemblies>` uses lazy loading, if a referenced assembly is not part of the type being added or the type doesn't reference a member from that assembly, nothing really happens. This lazy loading behavior improves load times.
>
> Shout out to [SeeminglyScience](https://github.com/SeeminglyScience) for providing this info.

<br>

## Instead of PSCustomObjects, Define And Use Custom Types Wherever Possible

If you don't need the extra features of PSCustomObjects such as dynamically adding/removing properties then consider defining and using custom classes in `C#` and use them in PowerShell. They are at least twice faster and this is very visible in loops. Run the benchmark below to see the difference.

<br>

```PowerShell
# Define a C# class in PowerShell
Add-Type -TypeDefinition @'
public class CustomCSharpClass {
    public string Property { get; set; }
    public CustomCSharpClass(string property) {
        Property = property;
    }
}
'@

# Benchmark PSCustomObject creation
$psCustomObjectTime = Measure-Command {
    for ($i = 0; $i -lt 10000; $i++) {
        $obj = [PSCustomObject]@{Property = 'Value' }
    }
}

# Benchmark C# class object creation
$csharpClassTime = Measure-Command {
    for ($i = 0; $i -lt 10000; $i++) {
        $obj = [CustomCSharpClass]::new(
            'Value'
        )
    }
}

# Output the results
"PSCustomObject creation time: $($psCustomObjectTime.TotalMilliseconds) ms"
"C# class object creation time: $($csharpClassTime.TotalMilliseconds) ms"
```

<br>

## For Performance Reasons Avoid Using The Following Operators And Cmdlets For Loops

* `+=` operator
* `Where-Object` cmdlet
* `ForEach-Object` cmdlet

**Instead, use `Foreach` loop with Direct Assignment. It's a language construct, it's always faster than the cmdlets and has less overhead.**

Here is a small benchmark you can run to see the difference in timing

```powershell
# Define your collection
$Y = 1..10000

# First script
$firstScript = {
    $array = foreach ($X in $Y) {
        $X
    }
}

# Second script
$secondScript = {
    $array = @()
    foreach ($X in $Y) {
        $array += $X
    }
}

# Third script
$thirdScript = {
    $array = New-Object -TypeName 'System.Collections.Generic.List[psobject]'
    foreach ($X in $Y) {
        $array.Add($X)
    }
}

# Measure the time taken by the first script
$firstScriptTime = Measure-Command -Expression $firstScript

# Measure the time taken by the second script
$secondScriptTime = Measure-Command -Expression $secondScript

# Measure the time taken by the third script
$thirdScriptTime = Measure-Command -Expression $thirdScript

# Output the results
"First script execution time: $($firstScriptTime.TotalMilliseconds) ms"
"Second script execution time: $($secondScriptTime.TotalMilliseconds) ms"
"Third script execution time: $($thirdScriptTime.TotalMilliseconds) ms"
```

<br>
