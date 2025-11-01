# C# Tips And Tricks Part 1

This is part 1 of the **C# Tips And Tricks series**. These are not tutorials, but rather a collection of notes and tips that can be useful for beginners. They are updated regularly with more info.

<br>

## Do Not Manually Reference Assemblies or DLLs

When working in the modern IDE, Visual Studio 2025 and with .NET, you do not need to reference .NET dlls manually, they will be available to your project automatically.

If you need to reference a DLL that is not part of the .NET by default, then use the [NuGet](https://www.nuget.org/) package manager to add it.

So if you have lines like this in your `.csproj` file, remove them completely.

```xml
<ItemGroup>
   <Reference Include="Security.Cryptography">
       <HintPath>"Path To .DLL file"</HintPath>
   </Reference>
   <Reference Include="System">
       <HintPath>"Path To .DLL file"</HintPath>
   </Reference>
</ItemGroup>
```

<br>

NuGet Package references look like this

```xml
<ItemGroup>
    <PackageReference Include="System.Management" Version="9.0.0" />
    <PackageReference Include="System.Management.Automation" Version="7.5.0" />
</ItemGroup>
```

<br>

## How To Activate WPF and WinForms in Your C# Project

When working with WPF or Windows Forms, additional assemblies need to be made available to your project.

Use the following line in your `.csproj` file to enable WPF assemblies

```xml
<UseWpf>true</UseWpf>
```

Use the following line in your `.csproj` file to enable Windows Forms assemblies

```xml
<UseWindowsForms>true</UseWindowsForms>
```

They are MSBuild properties, you can [read more about them on this page](https://learn.microsoft.com/en-us/dotnet/core/project-sdk/msbuild-props-desktop).

<br>

## How To Make Non-Code Files In Your Solution Available To Your Code After Compilation

If you have non-code files in your solution explorer, such as `.XML`, `.CSV`, `.JSON` files etc. that you want to be available to your code after compilation, maybe because they rely on them and they are important resources for your application, you can configure your project to automatically copy them to the output folder after compilation.

For example, use the following code in your `.csproj` file to make everything in the `Resources` folder, which is in the `Main` folder, copied to the output folder after compilation. The exact folder structure will be preserved.

```xml
<ItemGroup>
    <Content Include="Main\Resources\**">
        <CopyToOutputDirectory>PreserveNewest</CopyToOutputDirectory>
    </Content>
</ItemGroup>
```

<br>

### Alternative Way | Copying To The Output Directory

You can navigate to an individual file in your solution explorer, right-click on it and select Properties, in the *Copy To Output Directory* property select *Copy always*.

<div align="center">
<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Copy%20To%20output%20Directory.png" alt="Visual Studio file properties">
</div>

<br>

You can access the output directory using the following variable

```csharp
AppDomain.CurrentDomain.BaseDirectory
```

So in the example above, the files will be in the following directory

```csharp
Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Main", "Resources")
```

<br>

### Alternative Way | Embedding

There are of course other options, such as designating/embedding the file as a resource of your application.

To do that first navigate to the file and right-click on it, select Properties, and in the *Build Action* property select *Embedded Resource*.

Then you can access the file using the following code

```csharp
using System;
using System.IO;
using System.Reflection;

namespace HardenWindowsSecurity
{
    class Program
    {
        static void Main(string[] args)
        {
            // Specify the resource name
            string resourceName = "HardenWindowsSecurity.Main_files.Resources.XAML.Main.xaml";

            // Load the resource from the assembly
            var assembly = Assembly.GetExecutingAssembly();
            using (Stream stream = assembly.GetManifestResourceStream(resourceName))
            using (StreamReader reader = new StreamReader(stream))
            {
                // Read the content of the XAML file as a string
                string xamlContent = reader.ReadToEnd();
                // Print the content to the console
                Console.WriteLine(xamlContent);
            }
        }
    }
}
```

<br>

Or use this code to load the XAML GUI

```csharp
using System;
using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Markup;

namespace HardenWindowsSecurity
{
    class Program
    {
        [STAThread]
        static void Main()
        {
            System.Windows.Application app = new System.Windows.Application();

            // Get the current assembly
            Assembly assembly = Assembly.GetExecutingAssembly();

            // Define the resource path
            string resourcePath = "HardenWindowsSecurity.Main_files.Resources.XAML.Main.xaml";

            // Load the XAML file as a stream
            using (Stream stream = assembly.GetManifestResourceStream(resourcePath))
            {
                if (stream == null)
                {
                    Console.WriteLine("Failed to load XAML resource.");
                    return;
                }

                // Load the XAML from the stream
                Window window = (Window)XamlReader.Load(stream);

                // Show the window as a dialog
                window.ShowDialog();
            }
        }
    }
}
```

<br>

Or use this code to get the name of the embedded resources

```csharp
using System;
using System.Reflection;

namespace HardenWindowsSecurity
{
    class Program
    {
        [STAThread]
        static void Main()
        {
            // Get the current assembly
            Assembly assembly = Assembly.GetExecutingAssembly();

            // List all resource names
            foreach (string resourceName in assembly.GetManifestResourceNames())
            {
                Console.WriteLine(resourceName);
            }
        }
    }
}
```

<br>

* When you set a file as an *Embedded Resource* in Visual Studio, it gets compiled into the assembly (i.e., your project's output file, such as .exe or .dll). This means the file becomes a part of the compiled binary and can be accessed programmatically using reflection.

* The resource name is critical as it follows a specific pattern: Namespace.FolderStructure.Filename.

* If your project's default namespace is `YourNamespace`, and your XAML file is located in `"Main files"/Resources/XAML/Main.xaml`, the resource name would be `YourNamespace.Main_files.Resources.XAML.Main.xaml`.

* `Assembly.GetExecutingAssembly()`: This method returns the assembly that contains the code currently executing. This is important because your embedded resource is part of this assembly.

* `GetManifestResourceStream`: This method retrieves the resource stream (a sequence of bytes) of the embedded resource based on its name. The method returns a Stream object that you can use to read the content of the resource.

* `StreamReader`: This class is used to read characters from a stream. Since `GetManifestResourceStream` returns a stream, we wrap it in a `StreamReader` to easily read the text content.

<br>

### Why Use Embedded Resources?

* Portability: Since the resource is embedded in the assembly, you don't have to worry about distributing external files with your application.

* Security: The resource is somewhat protected since it’s part of the compiled binary, making it harder (though not impossible) for others to tamper with the file.

* Ease of Access: Accessing resources via the assembly makes it straightforward, as you don't need to deal with file paths, especially when deploying your application.

* This method is powerful for scenarios where you want to package files directly within your application and access them as needed.

<br>

## Static vs Non-Static Classes

Static classes have fewer functionalities compared to non-static classes. They are designed to serve specific purposes, such as defining global constants, variables, utility functions, or methods that perform similar operations. Because a static class is meant to be a container for these static members, it cannot be instantiated. This means that you cannot create objects from a static class. Instead, all its members must be accessed using the class name itself.

Non-static classes, on the other hand, are much more versatile. **They can do everything a static class can do and offer many additional features.** For example, non-static classes can be instantiated, meaning you can create objects from them. These objects can represent custom types, holding state and behavior specific to each instance. This allows you to create multiple objects from the same class, each with its own unique state and/or property.

**Non-static classes can contain both static and non-static members.** Static members of a non-static class are shared among all instances and are accessed using the class name, just like in a static class. Instance members, however, belong to each specific object and are accessed through that object.

To access static members in both static and non-static classes, you use the same syntax: `ClassName.Member`. This allows consistent access patterns, regardless of whether the class is static or not.

<br>

## A Less Known Reason Why XAML Hot Reload Might Not Work In Visual Studio And Visual Studio Blend

Microsoft has a [troubleshooting documentation](https://learn.microsoft.com/en-us/troubleshoot/developer/visualstudio/tools-utilities/xaml-hot-reload-troubleshooting) for [XAML Hot Reload](https://learn.microsoft.com/en-us/visualstudio/xaml-tools/xaml-hot-reload) feature but there is one important thing they don't mention, your WPF GUI needs to be using the Application context/object, not Window, for Hot Reload feature to function.

If your WPF GUI only uses the Window object, then the Hot Reload feature will not work.

<br>

## Define The Size of the Collections Whenever You Can

When creating a collection such as `List<T>`, `ObservableCollection<T>` and so on, define their capacity in the constructor in order to pre-size them to the number of items you know you will be adding. That produces the least growths and the most efficient additions.

## Use `IEnumerable<T>` Between Methods As Much As Possible

The standard and most basic way to represent a "collection" is an `IEnumerable<T>`. If you require something more specific you force your users to allocate a copy before passing the collection to your method. You don't want to force your users into giving you a specific collection type as input. Just make sure you don't iterate over it twice because the item must not be materialized more than once or else performance will be degraded. E.g., if we are looping over the data more than once, convert `IEnumerable` to a `list`.

<br>
