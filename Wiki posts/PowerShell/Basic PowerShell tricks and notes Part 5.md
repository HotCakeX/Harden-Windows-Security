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

## Downloading PowerShell Files From Low Integrity Untrusted Sources

If you download your PowerShell scripts or module files from a Low Integrity source, such as a sandboxed browser, they will be deemed Untrusted. These files will possess Mark Of The Web (MotW) Zone Identifiers, marking them as such. Consequently, you must unblock them before utilization.

Failure to unblock these files, thereby removing their MotW designation, can result in complications and errors within PowerShell. For instance, they may generate errors such as `AuthorizationManager check failed`, a situation particularly prevalent when incorporating C# code in PowerShell via `Add-Type`.

Another issue arising from executing PowerShell files from Untrusted sources is the necessity for a more permissive execution policy such as `Bypass`; otherwise, you will encounter incessant prompts for confirmation.

<br>

## Executing PowerShell Cmdlets in C# Within PowerShell

Indeed, you can execute PowerShell cmdlets within `C#` directly inside PowerShell. By leveraging `Add-Type`, you can seamlessly integrate `C#` code into PowerShell, enabling it to run PowerShell cmdlets. This can be particularly useful in various scenarios, so here is an illustrative example.

Consider the following code snippet, which demonstrates how to create a PowerShell instance:

```csharp
using (PowerShell powerShell = PowerShell.Create())
{
    powerShell.AddScript("Write-Verbose 'Hello World!'");
    var results = powerShell.Invoke();
}
```

The version of the PowerShell instance created will correspond to the version in which you run the `C#` code via `Add-Type`. For instance, if you execute the `C#` code within Windows PowerShell, the `.Create()` method will instantiate a PowerShell instance using the Windows PowerShell assemblies. Conversely, if you execute the same code within PowerShell Core (`pwsh.exe`), it will instantiate a PowerShell Core instance.

This behavior ensures that your PowerShell instance is consistent with the environment in which your `C#` code is executed, providing seamless integration and execution across different PowerShell versions.

<br>

## Make Regex Faster In PowerShell

The Compiled option in Regex is beneficial when you need to reuse the same pattern multiple times, especially within loops. This option improves performance by compiling the regex pattern into a more efficient, executable form. Here, we'll explore the technical advantages and provide a practical example in PowerShell to demonstrate its efficacy.

When working with regular expressions in tight loops, the overhead of interpreting the pattern each time can significantly impact performance. The Compiled option mitigates this by converting the regex pattern into an intermediate language, which the .NET runtime can execute more swiftly.

#### Best Practices

* Pattern Reuse: Utilize the Compiled option when the same regex pattern is used repeatedly.

* Defined Outside Loops: Ensure the regex pattern is defined outside the loop.

```powershell
$Pattern = [regex]::new('Insert Regex Pattern', [System.Text.RegularExpressions.RegexOptions]::Compiled)
$Pattern.IsMatch($Data)
```

<br>

## How To See The .NET Version Of The Current PowerShell Instance

Use the following command to determine the .NET version of the current PowerShell core instance:

```powershell
[System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription
```

<br>

## Note About PSReadLine Module

If you install or uninstall a [PSReadLine](https://learn.microsoft.com/en-us/powershell/module/psreadline/about/about_psreadline) version, totally exit the Terminal or VS Code if using the IDE. That's one of those modules that can't be unloaded normally.

<br>

## How To Display Modern Toast Notifications In PowerShell

### Prerequisites

You need to first have the following DLL files in one directory:

* **Microsoft.Toolkit.Uwp.Notifications.dll**

  * from [Microsoft.Toolkit.Uwp.Notifications](https://www.nuget.org/packages/Microsoft.Toolkit.Uwp.Notifications/)

  * found in `microsoft.toolkit.uwp.notifications.7.1.3\lib\net5.0-windows10.0.17763\Microsoft.Toolkit.Uwp.Notifications.dll`

* **Microsoft.Win32.SystemEvents.dll**

  * from [Microsoft.Win32.SystemEvents](https://www.nuget.org/packages/Microsoft.Win32.SystemEvents/)

  * found in `microsoft.win32.systemevents.8.0.0\lib\net8.0\Microsoft.Win32.SystemEvents.dll`

* **Microsoft.Windows.SDK.NET.dll**

  * from [Microsoft.Windows.SDK.NET.Ref](https://www.nuget.org/packages/Microsoft.Windows.SDK.NET.Ref)

  * found in `microsoft.windows.sdk.net.ref.10.0.26100.42\lib\net8.0\Microsoft.Windows.SDK.NET.dll`

* **WinRT.Runtime.dll**

  * from [Microsoft.Windows.SDK.NET.Ref](https://www.nuget.org/packages/Microsoft.Windows.SDK.NET.Ref)

  * found in `microsoft.windows.sdk.net.ref.10.0.26100.42\lib\net8.0\WinRT.Runtime.dll`

* **System.Drawing.Common.dll**

  * from [System.Drawing.Common](https://www.nuget.org/packages/System.Drawing.Common/)

  * found in `system.drawing.common.8.0.8\lib\net8.0\System.Drawing.Common.dll`

Then you can use the following PowerShell code to natively display the toast notifications

> [!NOTE]\
> Change `D:\notifications` to the correct folder in your computer where the DLLs exist.

<br>

```powershell
# Load the required assemblies
Add-Type -Path 'D:\notifications\Microsoft.Toolkit.Uwp.Notifications.dll'
Add-Type -Path 'D:\notifications\System.Drawing.Common.dll'

# Create an instance of the ToastContentBuilder class
$toastContentBuilderType = [Type]::GetType('Microsoft.Toolkit.Uwp.Notifications.ToastContentBuilder, Microsoft.Toolkit.Uwp.Notifications')
$toastContentBuilder = [Activator]::CreateInstance($toastContentBuilderType)

# Add text elements
$toastContentBuilder.AddText('Main Notification Title') | Out-Null
$toastContentBuilder.AddText('This is the first line of content with summary details.') | Out-Null
$toastContentBuilder.AddText('Additional line of content.') | Out-Null

# Add Attribution Text
$toastContentBuilder.AddAttributionText('Brought to you by Your Company') | Out-Null

# Add Header
$toastContentBuilder.AddHeader('6289', 'Camping!!', 'action=openConversation&id=6289') | Out-Null

# Add Hero Image
$heroImagePath = 'D:\notifications\2.jpg'
$toastContentBuilder.AddHeroImage([Uri]::new($heroImagePath)) | Out-Null

# Add Inline Image
$inlineImagePath = 'D:\notifications\1.jpg'
$toastContentBuilder.AddInlineImage([Uri]::new($inlineImagePath)) | Out-Null

# Show the notification
$toastContentBuilder.Show() | Out-Null
```

<br>

You can also use the following C# code in PowerShell to do the same

```PowerShell
[System.String[]]$Assemblies = @(
    'D:\notifications\Microsoft.Toolkit.Uwp.Notifications.dll',
    'D:\notifications\Microsoft.Win32.SystemEvents.dll',
    'D:\notifications\Microsoft.Windows.SDK.NET.dll',
    'D:\notifications\System.Drawing.Common.dll',
    'D:\notifications\WinRT.Runtime.dll'
)
Add-Type -TypeDefinition @'
using System;
using Microsoft.Toolkit.Uwp.Notifications;

public class Notification {
    public static void ShowNotif()
    {
        new ToastContentBuilder()
            .AddAppLogoOverride(new Uri("file:///D:/notifications/2.jpg"), ToastGenericAppLogoCrop.Circle)
            .AddText("Main Notification Title")
            .AddText("This is the first line of content with summary details.")
            .AddText("Main Notification Title")
            .AddHeroImage(new Uri("file:///D:/notifications/1.jpg"))
            .AddInlineImage(new Uri("file:///D:/notifications/3.jpg"))
            .AddButton(new ToastButton()
                .SetContent("View Details")
                .AddArgument("action", "viewDetails")
                .SetImageUri(new Uri("file:///D:/notifications/view_icon.jpg")))
            .AddButton(new ToastButton()
                .SetContent("Dismiss")
                .AddArgument("action", "dismiss")
                .SetImageUri(new Uri("file:///D:/notifications/view_icon.jpg")))
            .AddButton(new ToastButton()
                .SetContent("Open App")
                .AddArgument("action", "openApp")
                .SetImageUri(new Uri("file:///D:/notifications/view_icon.jpg")))
            .AddButton(new ToastButton()
                .SetContent("Open App")
                .AddArgument("action", "openApp")
                .SetImageUri(new Uri("file:///D:/notifications/view_icon.jpg")))
            .AddButton(new ToastButton()
                .SetContent("Open App")
                .AddArgument("action", "openApp")
                .SetImageUri(new Uri("file:///D:/notifications/view_icon.jpg")))
            .AddAudio(new Uri("ms-winsoundevent:Notification.SMS"))
            .AddAttributionText("Brought to you by Your Company")
            .AddHeader("6289", "Camping!!", "action=openConversation&id=6289")
            .Show();
    }
}
'@ -ReferencedAssemblies $Assemblies -CompilerOptions '/nowarn:1701'

$Assemblies | ForEach-Object {Add-Type -Path $_}

[Notification]::ShowNotif()
```

<br>

#### Related Documentation

* [Send a local toast notification from a C# app](https://learn.microsoft.com/en-us/windows/apps/design/shell/tiles-and-notifications/send-local-toast)

* [App notification content](https://learn.microsoft.com/en-us/windows/apps/design/shell/tiles-and-notifications/adaptive-interactive-toasts)

* [audio (Toast XML Schema)](https://learn.microsoft.com/en-us/uwp/schemas/tiles/toastschema/element-audio)

* [Toast headers](https://learn.microsoft.com/en-us/windows/apps/design/shell/tiles-and-notifications/toast-headers)

* [ToastContentBuilder Class](https://learn.microsoft.com/en-us/dotnet/api/microsoft.toolkit.uwp.notifications.toastcontentbuilder)

<br>

## Don't Use 'New' as the Name of a C# Method That You Want To Call In PowerShell

In PowerShell, `New` is reserved for constructors, and constructors have specific handling. When you call a method such as `[NameSpace.Class]::New($SomeArgument)` in PowerShell, it's looking for a constructor with the given argument, not a static method named `New`, so that will fail and throw an error.

This is not a problem if you want to use the C# method called `New` in C# itself and not import it via `Add-Type` in PowerShell.

<br>

## Do Not Use $null in PowerShell To Pass An Argument To A C# Method That Accepts Nullable String

Let's say you have a C# method that accepts a nullable string

```csharp
using System;
#nullable enable
public class MyClass
{
    public static void MethodName(string? Path)
    {
        if (Path is not null)
        {
            Console.WriteLine("Path is not null");
        }
        else
        {
            Console.WriteLine("Path is null");
        }
    }
}
```

In C# itself, you can call that method normally and pass null to it when calling it

```csharp
MyClass.MethodName(null)
```

And you will see `Path is null` on the console.

However, in PowerShell, if you used `Add-Type` to import that method and called it like this

```powershell
[MyClass]MethodName($null)
```

You will see `Path is not null` on the console.

The reason is that powerShell converts `$null` to an empty string `""` and not the true `null`. So the C# method will get `""` and since it's an empty string and not an actual null, it will fail the null check.

In this situation you have at least 2 options:

1. In PowerShell, instead of passing `$null`, use `[NullString]::Value`: `[MyClass]::MethodName([NullString]::Value)`.

2. In C#, instead of checking for null, check for `IsNullOrEmpty` or `IsNullOrWhiteSpace`.

<br>
