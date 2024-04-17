# Powershell Dynamic Parameters and How to Add Them to the Get-Help Syntax

PowerShell has a feature called dynamic parameters that allows you to add parameters to a cmdlet based on the value of another parameter. This is useful when you have a parameter that can take multiple values and you want to add additional parameters based on the value of the first parameter.

Dynamic parameters also allow you to make a parameter conditionally mandatory based on different criteria.

They are very powerful but have a downside: since they are runtime-defined, they are not displayed in the Get-Help output. This can be a problem if you want to provide help to users of your cmdlet and inform them of all of the available parameters that your cmdlet supports, including the dynamic ones.

Usually, PowerShell developers use [comment-based help](https://learn.microsoft.com/en-us/powershell/scripting/developer/help/examples-of-comment-based-help) inside of the cmdlet's function to provide help content to the user, however that approach doesn't allow us to control all aspects of the help content, such as the syntax. If you want to add the dynamic parameters to the Get-Help output's syntax, you will need to switch to [XML-based help](https://learn.microsoft.com/en-us/powershell/utility-modules/platyps/create-help-using-platyps).

<br>

## PlatyPS

PlatyPS is a module that allows you to generate XML-based help for your cmdlets. It can be used to add dynamic parameters to the Get-Help output's syntax. You will be editing a Markdown file which is convenient and the module will automatically generate the XML help file for you.

### Create a Markdown file Based on your Cmdlet

```powershell
New-MarkdownHelp -Command 'YourCmdletName' -OutputFolder ".\docs"
```

After you've created a markdown file based on your current cmdlet's parameters and details, you can start adding the dynamic parameters to it and modify the syntax, because dynamic parameters are not automatically added to it. Once you are done, you can run the following command to generate the XML help file.

### Generate the XML Help File from the Markdown file

```powershell
New-ExternalHelp -Path "Path-To-Markdown-File.md" -OutputPath "Path-To-XML-File.xml" -Force
```

After creating your XML-based help file, you will then have to reference it in your cmdlet's function like this

```powershell
.EXTERNALHELP .\Help\Cmdlet-Name.xml
```

The path doesn't accept variables but it can be either relative or full path to the XML help file. Once you reference that, you can either remove all of the comment-based help from the function or keep them, the XML-based help takes precedence over the comment-based help when both types of help content are present.

* [PlatyPS on GitHub](https://github.com/PowerShell/platyps)
* [PlatyPS on PowerShell Gallery](https://www.powershellgallery.com/packages/platyPS)
* [PlatyPS cmdlet guides on Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/platyps)
* [How to add syntax to a cmdlet help topic](https://learn.microsoft.com/en-us/powershell/scripting/developer/help/how-to-add-syntax-to-a-cmdlet-help-topic)
* [Writing Help for PowerShell Cmdlets](https://learn.microsoft.com/en-us/powershell/scripting/developer/help/writing-help-for-windows-powershell-cmdlets)

<br>
