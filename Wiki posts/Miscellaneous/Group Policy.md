# Group Policy usage in this GitHub repository

## Microsoft Security Compliance Toolkit

This set of tools allows enterprise security administrators to download, analyze, test, edit and store Microsoft-recommended security configuration baselines for Windows and other Microsoft products, while comparing them against **other security configurations**.

Microsoft Security Compliance Toolkit includes multiple files and useful programs that are required for the Harden Windows Security Module to operate.

* [Official link to download Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319)

* [Microsoft Security Compliance Toolkit 1.0 - How to use](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/security-compliance-toolkit-10)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Microsoft Security Baseline

Microsoft is dedicated to providing its customers with secure operating systems, such as Windows and Windows Server, and secure apps, such as Microsoft 365 apps for enterprise and Microsoft Edge. In addition to the security assurance of its products, Microsoft also enables you to have fine control over your environments by providing various configuration capabilities.

Even though Windows and Windows Server are designed to be secure out-of-the-box, many organizations still want more granular control over their security configurations.
[Continue reading more in the Microsoft website](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/windows-security-baselines)

When you unzip the Microsoft Security Baseline file, you will find this folder structure:

1. **Documentation**  - contains PDF and Excel files describing the differences between the previous baseline release and the new settings that were added. contains the default `policyrules` file, which is used with the Security Compliance Toolkit, you can view it using Policy Analyzer program.
2. **GP Reports** - contains reports in HTML format, describes the GPO settings that can be applied for each category.
3. **GPOs** – contains GPO objects for different scenarios, these are the actual policies that will be applied.
4. **Scripts** - contains multiple PowerShell scripts for different scenarios and helps us easily import GPO settings to our system. The most important PowerShell script here is `Baseline-LocalInstall.ps1`.
5. **Templates** – contains additional Group Policy Object templates that are not available by default on Windows, such as `MSS-legacy.admx`, these are in `ADMX` and `ADML` formats. They will be copied to `C:\Windows\PolicyDefinitions`, where they belong, so that the new Security Baselines GPOs can be interpreted.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## LGPO

Quoting from the PDF file supplied by LGPO:

> LGPO.exe is a command-line utility that is designed to help automate management of Local Group Policy. It can import and apply settings from Registry Policy (Registry.pol) files, security templates, Advanced Auditing backup files, as well as from formatted "LGPO text" files and Policy Analyzer '.PolicyRules' XML files.
>
> It can export local policy to a GPO backup. It can export the contents of a Registry Policy file to the 'LGPO textformat' that can then be edited, and can build a Registry Policy file from an LGPO text file. (The syntax for LGPO text files is described later in this document.)
>
> LGPO.exe has four command-line forms: for importing and applying settings to local policy – including to Multiple Local Group Policy Objects (MLGPO)1 ; for creating a GPO backup; for parsing a Registry Policy file and outputting "LGPO" text; for producing a Registry Policy file from an LGPO text file.
>
> All output is written to LGPO.exe's standard output, and all diagnostic and error information is written to its standard error. Both can be redirected to files using standard command shell operations. To support batch file use, LGPO.exe's exit code is 0 on success and non-zero on any error.

<br>

`LGPO` is the most crucial program for our workflow, it is part of the Security Compliance Toolkit (SCT)

[What is the Local Group Policy Object (LGPO) tool?](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/security-compliance-toolkit-10#what-is-the-local-group-policy-object-lgpo-tool)

[LGPO.exe - Local Group Policy Object Utility](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/lgpo-exe-local-group-policy-object-utility-v1-0/ba-p/701045)

<br>

### How to Manually Back up Group Policy Objects From a System Using LGPO.exe

Use this command to back up the currently set local group policies to drive `C`

```powershell
.\LGPO.exe /b C:
```

#### How to Import Group Policy Objects From a Backup, Created Using LGPO.exe, to the Local System

```powershell
.\LGPO.exe /g 'Path to the backup'
```

Example:

```powershell
.\LGPO.exe /g 'C:\{841474E6-33EC-418C-B884-EA0F7C8195DB}'
```

#### How to Import Only the Settings From a Registry Policy File Into Computer (Machine) Configuration

*(This only contains everything in Computer (Machine) Configuration -> Administrative Templates and some policies in Computer Configuration -> Windows Settings)*

[Registry Policy File Format](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/registry-policy-file-format)

```powershell
.\LGPO.exe /m <Path to registry.pol file>
```

#### How to Import only the Security policies file into Computer (Machine) Configuration

*(This only contains everything in Computer (Machine) Configuration -> Windows Settings => Security Settings => everything in the subfolders except for the [Advanced Audit Policy Configuration](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/secpol-advanced-security-audit-policy-settings))*

[Security policy settings](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/security-policy-settings)

```powershell
.\LGPO.exe /s ".\GPOX\DomainSysvol\GPO\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf"
```

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Policy Analyzer

Quoting from the PDF file supplied by Policy Analyzer:

> Policy Analyzer is a lightweight utility for analyzing and comparing sets of Group Policy Objects (GPOs). It can highlight when a set of Group Policies has redundant settings or internal inconsistencies and can highlight the differences between versions or sets of Group Policies.
>
> It can also compare one or more GPOs against local effective state. You can export all its findings to a Microsoft Excel spreadsheet.
>
> Policy Analyzer lets you treat a set of GPOs as a single unit, and represents all settings in one or more GPOs in a single ".PolicyRules" XML file. You can also use .PolicyRules files with LGPO.exe v3.0 to apply those GPOs to a computer's local policy, instead of having to copy GPO backups around.

[What is the Policy Analyzer tool?](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/security-compliance-toolkit-10#what-is-the-policy-analyzer-tool)

[Policy Analyzer Tool](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/new-tool-policy-analyzer/ba-p/701049)

<br>

### About Compare to Effective State

In Policy Analyzer, there is an option called `Compare to Effective State`. Quoting from the PDF file that ships with Policy Analyzer program regarding that option:

> Enable one or more of the Policy Rule sets' checkboxes and click "Compare to Effective State" to compare the selected baselines against the local computer's current configured state. The operation will require UAC elevation if any of the selected baselines include security template or advanced auditing settings that require elevation to retrieve.
>
> The Policy Viewer will show the combined settings from all the selected Policy Rule sets in one column under the heading "Baseline(s)," and the corresponding current settings on the local computer and the logged-on user in a separate column under the heading "Effective state."
>
> The effective state settings are also saved to a new .PolicyRules file with a name combining "EffectiveState_," the current computer name, and the current date and time in the format "yyyyMMdd- HHmmss." For example, "EffectiveState_WKS51279_20200210-183947.PolicyRules."

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## How Are Group Policies Used by the Harden Windows Security Module?

1. The module downloads the official Microsoft Security Baselines from Microsoft servers and applies them to the system.

2. It then uses the group policies included in the Module files for security measures explained on the readme page and applies them to the system, on top of Microsoft Security Baselines, so where there is a conflict of policy, the module will replace the configurations set by Microsoft Security Baselines.

3. When applying the Microsoft Security Baselines, you have the option to apply the optional overrides too, [you can find the details of those overrides in here,](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Overrides-for-Microsoft-Security-Baseline), they are required to be applied if you are using Harden Windows Security Module in Azure VMs and highly recommended in general.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## How Are Group Policies for the Module Created and Maintained?

### How I Created Them for the First Time

1. Installed the newest available Windows build on a fresh Hyper-V VM, fully updated it, created a standard checkpoint.

2. Opened Group Policy editor and started applying security measures described in the Readme page.

3. After completing each category, used `LGPO.exe /b C:` to backup Group Policies of the system by creating a full GPO.

4. Then I took only files needed from the backup, `registry.pol` and `GptTmpl.inf` and put them in a folder, renamed it to `Security-Baselines-X`

### How I Maintain Them

1. As long as the VM is still using the latest available build of Windows, I use the standard checkpoint I had created to revert the VM back to that new state. If there is a newer build of Windows available, I delete that old VM, download the new Windows ISO file from Microsoft servers, then I create a fresh Hyper-V VM using it.

2. I copy the Group Policy files, `registry.pol` or `GptTmpl.inf` to the VM, import them by using `.\LGPO.exe /m "path"` for `registry.pol` files or `.\LGPO.exe /s "path"` for `GptTmpl.inf` files.

3. Open Group Policy editor and change anything that is needed, once I'm done, I create a full backup of the Group Policies of the system using `LGPO.exe /b C:` command, again take out the modified file, either `registry.pol` or `GptTmpl.inf`.

4. Use `PolicyAnalyzer` to double check everything by comparing the old file with the new one and making sure the correct changes are applied.

5. Replace the old Group Policy file with the new file in the Security-Baselines-X directory and upload it to the GitHub repository.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## We Can Use Policy Analyzer for Verification and Comparison

### To Verify the Settings Are Applied Correctly by The Module

1. Use folder options in Control Panel or File Explorer to show hidden files and folder.

2. Open Policy Analyzer program, Navigate to Add -> File -> Add files from GPO(s)... -> Browse for this folder "C:\Windows\System32\GroupPolicy", Select the folder -> Import -> save the Policy Rules file in `\Documents\PolicyAnalyzer\`

3. Back at the main window, use View/Compare button to view applied Group Policies. The result that you will see is all of the Group Policies that are applied to your system.

Another way to verify the applied Group Policies is to perform the 3 tasks above; What it will give you is the Policy Rules file which is generated from Group Policy state after using the module. If we take this policy rules file to a different machine where we just clean installed Windows and use Policy Analyzer to compare it to the Effective State of the system, we will see what Group Policy settings have changed as a result of using the module.

<br>

Note: At first, when we clean install Windows, the Group Policy folder `C:\Windows\System32\GroupPolicy` is empty, it will get populated with empty folders and a `1kb` file that contains only 1 word when we first open the local Group Policy editor. It will get more populated with actual policies once we start modifying any group policies.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## How to verify Security-Baselines-X directory and 100% trust it?

1. Download [the files from here](https://github.com/HotCakeX/Harden-Windows-Security/tree/main/Harden-Windows-Security%20Module/Main%20files/Resources/Security-Baselines-X).
2. Open the Policy Analyzer, Navigate to Add -> File -> Select either `Add User Configuration (registry.pol)` or `Add Security Template (*.inf)` -> Browse for the `Security-Baselines-X` directory, navigate to the category you want.
3. Select either `.pol` or `.inf` file, Import it, give it a name, save it in `\Documents\PolicyAnalyzer\`

4. Back at the main window, use "Compare to Effective State" button to view what policies are included in the file.

5. As you will see, everything is according to what has been explicitly stated in the [GitHub's Readme page](https://github.com/HotCakeX/Harden-Windows-Security).

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Using Configuration Service Providers (CSPs) and Provisioning Packages (Work in Progress)

This command gets the information about all installed provisioning packages on your system.

```powershell
Get-ProvisioningPackage -AllInstalledPackages
```

<br>

* [Configuration service providers for IT pros](https://learn.microsoft.com/en-us/windows/configuration/provisioning-packages/how-it-pros-can-use-configuration-service-providers)

* [Settings changed when you uninstall a provisioning package](https://learn.microsoft.com/en-us/windows/configuration/provisioning-packages/provisioning-uninstall-package)

* [Why Intune and CSPs are the future of Windows management instead of Group Policy](https://learn.microsoft.com/en-us/mem/intune/configuration/group-policy-analytics)

<br>

Download Windows Configuration Designer from [Microsoft Store](https://apps.microsoft.com/store/detail/windows-configuration-designer/9NBLGGH4TX22) or from [Windows ADK](https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-install) or from [Windows insiders ADK](https://www.microsoft.com/en-us/software-download/windowsinsiderpreviewADK), to easily [create provisioning packages](https://learn.microsoft.com/en-us/windows/configuration/provisioning-packages/provisioning-create-package) for your device(s)

You can use [gpresult](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/gpresult) to see more info about Group Policies on your computer

```powershell
# What policies are applied to your computer:
gpresult /z
# or
gpresult /v

# What policies are applied to the current user:
gpresult /scope user /v
```

We can manually backup and restore Group Policy settings by copying this folder and all of its content:

`C:\Windows\System32\GroupPolicy`

<br>

### How to Get All CIM Namespaces, Their Methods and Properties in PowerShell

```powershell
# Defining the custom class for CIM instance classes
class CimClassInfo {
    [System.String]$ClassName
    [System.Collections.Generic.List[System.String]]$Methods
    [System.Collections.Generic.List[System.String]]$Properties

    CimClassInfo([System.String]$ClassName) {
        $this.ClassName = $ClassName
        $this.Methods = [System.Collections.Generic.List[System.String]]::new()
        $this.Properties = [System.Collections.Generic.List[System.String]]::new()
    }
}

# Defining the custom class for namespaces
class NamespaceInfo {
    [System.String]$NamespaceName
    [System.Collections.Generic.List[CimClassInfo]]$Classes

    NamespaceInfo([System.String]$NamespaceName) {
        $this.NamespaceName = $NamespaceName
        $this.Classes = [System.Collections.Generic.List[CimClassInfo]]::new()
    }
}

function Get-NamespaceInfo {
    [OutputType([System.Collections.Generic.List[NamespaceInfo]])]
    param (
        [System.String]$RootNamespace = 'root',
        [System.String]$OutputFile = $null
    )

    # Initialize a list to hold NamespaceInfo objects
    $NamespaceInfos = [System.Collections.Generic.List[NamespaceInfo]]::new()

    # Initialize a list to hold namespaces
    $Namespaces = [System.Collections.Generic.List[System.String]]::new()
    $Namespaces.Add($RootNamespace)

    # Initialize an index to track the current namespace
    $Index = 0

    # Loop through namespaces
    while ($Index -lt $Namespaces.Count) {
        # Get the current namespace
        $CurrentNamespace = $Namespaces[$Index]

        # Create a new NamespaceInfo object
        $NamespaceInfo = [NamespaceInfo]::new($CurrentNamespace)

        # Get child namespaces of the current namespace
        $ChildNamespaces = Get-CimInstance -Namespace $CurrentNamespace -ClassName __Namespace

        # Add child namespaces to the list
        foreach ($ChildNamespace in $ChildNamespaces.Name) {
            $Namespaces.Add("$CurrentNamespace\$ChildNamespace")
        }

        # Get classes in the current namespace
        $Classes = Get-CimClass -Namespace $CurrentNamespace

        # Add classes to the NamespaceInfo object
        foreach ($Class in $Classes) {
            # Create a new CimClassInfo object
            $CimClassInfo = [CimClassInfo]::new($Class.CimClassName)

            # Get methods of the class
            $Methods = ($Class.CimClassMethods).Name

            # Add methods to the CimClassInfo object
            foreach ($Method in $Methods) {
                $CimClassInfo.Methods.Add($Method)
            }

            # Get properties of the class
            $Properties = ($Class.CimClassProperties).Name

            # Add properties to the CimClassInfo object
            foreach ($Property in $Properties) {
                $CimClassInfo.Properties.Add($Property)
            }

            # Add the CimClassInfo object to the NamespaceInfo object
            $NamespaceInfo.Classes.Add($CimClassInfo)
        }

        # Add the NamespaceInfo object to the list
        $NamespaceInfos.Add($NamespaceInfo)

        # Move to the next namespace
        $Index++
    }

    # Export to JSON too if OutputFile is specified
    if ($OutputFile) {
        $NamespaceInfos | ConvertTo-Json -Depth 100 | Out-File -FilePath $OutputFile
    }

    return $NamespaceInfos
}

$NamespaceInfo = Get-NamespaceInfo -RootNamespace 'root' -OutputFile 'NamespaceInfo.json'
$NamespaceInfo

```

<br>
