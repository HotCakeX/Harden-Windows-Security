# DISM API in Packaged Apps and the Mechanics of Child Process Identity

## Intro

The Deployment Image Servicing and Management [(DISM) APIs](https://learn.microsoft.com/windows-hardware/manufacture/desktop/dism/using-the-dism-api) are tools for managing Windows images. However, using these APIs in packaged applications presents unique challenges due to the sandboxed nature of these apps. This article explores the process of integrating DISM APIs into packaged apps, highlighting the obstacles faced and the solutions implemented.

## Examples

### Reproducing in PowerShell

When attempting to use DISM APIs in the [PowerShell app](https://apps.microsoft.com/detail/9MZ1SNWT0N5D) installed from the Microsoft Store, you will encounter a "Class not registered" error.

```powershell
Get-WindowsOptionalFeature -Online
```

There is an old (5+ years) and still open/unresolved [GitHub Issue](https://github.com/PowerShell/PowerShell/issues/13866) in the PowerShell's repository about this problem. Naturally, this problem only occurs when PowerShell is installed as a packaged app from the Microsoft Store or Winget with `msstore` as the source. If you install PowerShell using the MSI or exe installer then it won't be packaged and the command will work as expected.

### Reproducing in WinAppSDK

Start by creating a new [WinUI3 project](https://learn.microsoft.com/en-us/windows/apps/tutorials/winui-notes/intro) in Visual Studio and then use the code below as the code-behind of the main window that should have a simple button to trigger the DISM API call:

```csharp
using Microsoft.UI.Xaml;
using System;
using System.Runtime.InteropServices;
namespace PackagedDISM;

internal sealed partial class MainWindow : Window
{
    internal MainWindow() => InitializeComponent();
    internal enum DismLogLevel
    {
        DismLogError = 0,
        DismLogErrorWarning,
        DismLogErrorWarningInfo,
        DismLogErrorWarningInfoDebug
    }
    private void Button_Click(object sender, RoutedEventArgs e)
    {
        int hr = NativeMethods.DismInitialize(DismLogLevel.DismLogErrorWarningInfo, null, null);
        if (hr != 0)
            throw new InvalidOperationException($"Failed to initialize DISM. Error code: 0x{hr:X8}, HR: {hr}");

        hr = NativeMethods.DismOpenSession("DISM_{53BFAE52-B167-4E2F-A258-0A37B57FF845}", null, null, out IntPtr session);
        if (hr != 0)
            throw new InvalidOperationException($"Failed to open DISM session. Error code: 0x{hr:X8}, HR: {hr}");
    }
    internal static partial class NativeMethods
    {
        [LibraryImport("DismApi.dll", StringMarshalling = StringMarshalling.Utf16)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        internal static partial int DismInitialize(
            DismLogLevel LogLevel,
            [MarshalAs(UnmanagedType.LPWStr)] string? LogFilePath,
            [MarshalAs(UnmanagedType.LPWStr)] string? ScratchDirectory);

        [LibraryImport("DismApi.dll", StringMarshalling = StringMarshalling.Utf16)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        internal static partial int DismOpenSession(
            [MarshalAs(UnmanagedType.LPWStr)] string ImagePath,
            [MarshalAs(UnmanagedType.LPWStr)] string? WindowsDirectory,
            [MarshalAs(UnmanagedType.LPWStr)] string? SystemDrive,
            out IntPtr Session);
    }
}
```

After clicking on the button, the program will wait for about half a minute and then you will get an error for `DismInitialize` call:

```
Error code: 0x80040154, HR: -2147221164
```

## Root Cause

When we call `DismInitialize`, it calls `CreateProcess` internally to create another process for `dismhost.exe`. Even though the newly created process, `dismhost.exe`, is a child process of our main packaged app process, it doesn't have our app's identity and as a result, the COM interface that is newly created by it cannot be found by our main packaged app process because our app is virtualized, so it keeps trying to find it in a loop and that's why it hangs for a long time before finally giving up and throwing the class not registered error.

## Some Background

MSIX packaged apps do not have direct access to the system registry, many of the writes and reads to specific registry keys are [virtualized by the OS](https://learn.microsoft.com/windows/msix/desktop/desktop-to-uwp-behind-the-scenes) to provide a sandboxed environment for the app.

The logic is implemented in the [kernel](https://learn.microsoft.com/windows-hardware/drivers/kernel/registering-for-notifications), a specific routine `nt!VrpRegistryCallback` is invoked that causes all of the read/write requests to specific registry keys to be redirected to a completely isolated hive.

The differencing hive, which is used for containerization, is located in `\Registry\WC\Silo{GUID}` and is only accessible to the packaged app's main process; child processes cannot access it unless they explicitly inherit the package identity. It cannot be accessed by path either unless we have an explicit handle to one of the keys in that hive.

When a packaged app is launched, the system assigns it a unique identity based on its package manifest. This identity is used to create a security token for the app's main process, which includes special token claims attributes that indicate the app's identity and permissions.

The Kernel automatically strips off all of the special token claims attributes from any child process that does not have the same app identity as the parent process. Those special token claims attributes are what allow the app to access its virtualized registry hive and to tell the system that it is a store app and not a regular one.

## Solution

### For Windows App SDK apps

I've implemented the solution [here](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/Harden%20System%20Security/ViewModels/OptionalWindowsFeaturesVM.cs) in the [Harden System Security](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden-System-Security) app's code.

### For PowerShell

Paste the code below into an elevated packaged PowerShell process and run it. It will launch a new instance of PowerShell with the correct identity so that the DISM cmdlets work as expected.

```powershell
$Def = @"
using System; using System.Runtime.InteropServices;
public class Win32 {
    [StructLayout(LayoutKind.Sequential)] public struct SI { public int cb; public IntPtr r; public IntPtr d; public IntPtr t; public int x; public int y; public int xs; public int ys; public int xc; public int yc; public int fa; public int f; public short sw; public short cb2; public IntPtr r2; public IntPtr hi; public IntPtr ho; public IntPtr he; }
    [StructLayout(LayoutKind.Sequential)] public struct SIE { public SI s; public IntPtr la; }
    [StructLayout(LayoutKind.Sequential)] public struct PI { public IntPtr hp; public IntPtr ht; public int pid; public int tid; }
    [DllImport("kernel32", SetLastError=true)] public static extern bool InitializeProcThreadAttributeList(IntPtr l, int c, int f, ref IntPtr s);
    [DllImport("kernel32", SetLastError=true)] public static extern bool UpdateProcThreadAttribute(IntPtr l, uint f, IntPtr a, IntPtr v, IntPtr s, IntPtr p, IntPtr r);
    [DllImport("kernel32", SetLastError=true)] public static extern bool CreateProcess(string a, string c, IntPtr pa, IntPtr ta, bool i, uint f, IntPtr e, string d, ref SIE si, out PI pi);
    [DllImport("kernel32")] public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32")] public static extern void DeleteProcThreadAttributeList(IntPtr l);

    public static void Launch() {
        IntPtr sz = IntPtr.Zero;
        InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref sz);
        IntPtr al = Marshal.AllocHGlobal(sz);
        InitializeProcThreadAttributeList(al, 1, 0, ref sz);

        IntPtr val = Marshal.AllocHGlobal(4);
        Marshal.WriteInt32(val, 6);

        UpdateProcThreadAttribute(al, 0, (IntPtr)0x00020012, val, (IntPtr)4, IntPtr.Zero, IntPtr.Zero);

        SIE si = new SIE();
        si.s.cb = Marshal.SizeOf(typeof(SIE));
        si.la = al;

        PI pi;
        if (CreateProcess(null, "pwsh.exe", IntPtr.Zero, IntPtr.Zero, false, 0x80010, IntPtr.Zero, null, ref si, out pi)) {
            CloseHandle(pi.hp); CloseHandle(pi.ht);
        } else {
            Console.WriteLine("Launch failed: " + Marshal.GetLastWin32Error());
        }

        DeleteProcThreadAttributeList(al);
        Marshal.FreeHGlobal(al); Marshal.FreeHGlobal(val);
    }
}
"@
Add-Type -TypeDefinition $Def
[Win32]::Launch()
```

### Further Explanation

The [CreateProcessW API](https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw) allows us to configure the `PROC_THREAD_ATTRIBUTE_DESKTOP_APP_POLICY` attribute, which controls how the desktop app runtime environment (virtualization) is applied to new processes. This is handled internally by `wcnfs.sys` (File System Virtualization Filter Driver).

The following line sets the policy:

```c
DWORD policy = PROCESS_CREATION_DESKTOP_APP_BREAKAWAY_DISABLE_PROCESS_TREE | PROCESS_CREATION_DESKTOP_APP_BREAKAWAY_OVERRIDE;
```

This combination `(0x06)` enforces two distinct behaviors required for DISM to function:

* `PROCESS_CREATION_DESKTOP_APP_BREAKAWAY_OVERRIDE` (0x04): Ensures the process being created (the new instance of the packaged app) runs inside the desktop app runtime environment. This applies only to the immediate process being created, preventing it from breaking away from the package identity.

* `PROCESS_CREATION_DESKTOP_APP_BREAKAWAY_DISABLE_PROCESS_TREE` (0x02): Ensures that any child processes created by that new process (such as `dismhost.exe`) are also created inside the desktop app runtime environment. Unlike the override flag, this policy is inherited by descendant processes, ensuring the entire process tree maintains access to the virtualized registry hive.

### Special Thanks

To my dear friend **Naceri** who helped me a lot in understanding the problem and solution.

> In general, people don't help you, which is totally okay, but the ones that do are special. ~ *Alex Karp*

<br>
