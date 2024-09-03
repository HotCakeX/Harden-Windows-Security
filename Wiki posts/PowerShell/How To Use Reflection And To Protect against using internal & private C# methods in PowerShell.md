# How To Use Reflection And Prevent Using Internal & Private C# Methods in PowerShell

## Introduction to Reflection in .NET

Reflection in [.NET](https://dotnet.microsoft.com/en-us/download) is a powerful feature that allows a program to inspect and interact with its own metadata, types, and assemblies at runtime. This capability is part of the [System.Reflection namespace](https://learn.microsoft.com/en-us/dotnet/api/system.reflection) and is integral to many advanced programming tasks, such as dynamic type loading, runtime method invocation, and metadata inspection.

> [!IMPORTANT]\
> This is a research article demoing only one of many ways to use reflection and to prevent it. It isn't designed to be used in production code nor does it 100% protect against reflection usage.

## What Reflection Is

* Runtime Type Inspection: Reflection allows you to examine the types defined in an assembly at runtime. This includes finding out which classes, interfaces, methods, properties, and fields are available, and retrieving metadata about them.

* Dynamic Invocation: Reflection enables the invocation of methods, constructors, and fields, even if they are marked as private or internal. This bypasses traditional access control mechanisms in C#, allowing for dynamic execution of code that would normally be inaccessible.

## How Reflection Bypasses Access Modifiers

* Access Modifiers in C#: In C#, [access modifiers](https://learn.microsoft.com/en-us/dotnet/csharp/programming-guide/classes-and-structs/access-modifiers) such as private, internal, protected, and public control the visibility and accessibility of types and members within code. For instance, a private method is accessible only within the class it's defined, and an internal method is accessible only within the same assembly.

* Reflection's Power: Reflection, however, *operates at a lower level of abstraction*. It doesn't follow the same rules that the C# compiler enforces at compile-time. Instead, it can be used to query and interact with any method or member, regardless of its access level. This is because reflection directly manipulates the type metadata, which is *always* accessible at runtime, even for non-public members.

This means that with reflection, you can programmatically discover and invoke methods and properties that would otherwise be hidden or inaccessible according to the usual C# access rules. This capability, while powerful, can also pose stability risks if used improperly, as it can break encapsulation, violate class design intentions, and even access sensitive or untested code paths.

<br>

## Demo Time

Let's say you have the following C# code and you imported it in PowerShell via `Add-Type`

```csharp
namespace HardenWindowsSecurity
{
    internal sealed class Test
    {
        private static string ReturnRandom()
        {
            return "Random!";
        }
    }
}
```

<br>

If you try to access the class or the method like this, you will get an error about the type not being found

```powershell
[HardenWindowsSecurity.Test]::ReturnRandom()
```

<br>

but you can access it via reflection, effectively bypassing the internal or private nature of the method and class.

```powershell
# Get all loaded assemblies
$Assemblies = [AppDomain]::CurrentDomain.GetAssemblies()

# Find the assembly where the type is defined
$Assembly = $Assemblies | Where-Object -FilterScript { $_.GetTypes() | Where-Object -FilterScript { $_.FullName -eq 'HardenWindowsSecurity.Test' } }

if ($null -eq $Assembly) {
    throw "Assembly containing the type 'HardenWindowsSecurity.Test' not found."
}

# Get the Type object for the Test class
$Type = $Assembly.GetType('HardenWindowsSecurity.Test')

if ($null -eq $Type) {
    throw "Type 'HardenWindowsSecurity.Test' not found."
}

# Get the MethodInfo object for the 'ReturnRandom' method
$Method = $Type.GetMethod('ReturnRandom', [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Static)

if ($null -eq $Method) {
    throw "Method 'ReturnRandom' not found."
}

# Invoke the method
$Result = $Method.Invoke($null, $null)

# Display the result
$Result
```

<br>

One way to prevent that is by implementing a method that checks for reflection usage and throws an error once detected. This method can be called at the beginning of any method that you want to protect against reflection-based access.

<br>

```csharp
using System;
using System.Diagnostics;
using System.Linq;

#nullable enable

namespace HardenWindowsSecurity
{
    public static class ReflectionGuard
    {
        public static void EnsureNotCalledFromReflection()
        {
            System.Diagnostics.StackTrace? stackTrace = new System.Diagnostics.StackTrace();
            System.Diagnostics.StackFrame[]? frames = stackTrace.GetFrames();

            if (frames == null) return;

            foreach (StackFrame frame in frames)
            {
                var method = frame.GetMethod();
                if (method!.DeclaringType != null &&
                    (method.DeclaringType.FullName?.StartsWith("System.Reflection", StringComparison.OrdinalIgnoreCase) == true ||
                     method.DeclaringType.FullName?.StartsWith("Microsoft.PowerShell", StringComparison.OrdinalIgnoreCase) == true))
                {
                    throw new InvalidOperationException("Access denied: This method cannot be called via reflection.");
                }
            }
        }
    }
}
```

<br>

Then you will implement it like this

```csharp
namespace HardenWindowsSecurity
{
    internal sealed class Test
    {
        private static string ReturnRandom()
        {
            HardenWindowsSecurity.ReflectionGuard.EnsureNotCalledFromReflection();
            return "Random!";
        }
    }
}
```

And now if you attempt the same reflection based invocation of the private method, you will get an error.

<br>

## How the Reflection Guard Method Works

* Call Stack Inspection: The [System.Diagnostics.StackTrace](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.stacktrace) class provides a way to examine the call stack at runtime. The call stack is essentially a history of method calls leading to the current point in execution. By analyzing this stack, you can determine how a particular method was reached.

* Reflection Detection: The [StackTrace.GetFrames()](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.stacktrace.getframes) method returns an array of StackFrame objects, each representing a method call in the stack. By iterating over these frames, you can inspect the [DeclaringType](https://learn.microsoft.com/en-us/dotnet/api/system.type.declaringtype) of each method in the stack. If any method in the call stack belongs to the `System.Reflection` namespace (or any other namespace associated with reflection or dynamic invocation, like `Microsoft.PowerShell`), it's a strong indication that the current method was called via reflection.

* Throwing an Exception: If reflection usage is detected, the method throws an [InvalidOperationException](https://learn.microsoft.com/en-us/dotnet/api/system.invalidoperationexception), effectively stopping execution and signaling that reflection-based access is not permitted. This mechanism ensures that methods can only be called through regular, direct code paths, enforcing the intended encapsulation and access control.

<br>
