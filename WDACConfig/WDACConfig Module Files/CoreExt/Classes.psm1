# Classes will be available process-wide and therefore also in other runspaces, defining them with the [NoRunspaceAffinity()] attribute.
# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_classes#exporting-classes-with-type-accelerators

# argument tab auto-completion and ValidateSet for Levels and Fallbacks parameters in the entire module
[NoRunspaceAffinity()]
Class ScanLevelz : System.Management.Automation.IValidateSetValuesGenerator {
    [System.String[]] GetValidValues() {
        $ScanLevelz = ('Hash', 'FileName', 'SignedVersion', 'Publisher', 'FilePublisher', 'LeafCertificate', 'PcaCertificate', 'RootCertificate', 'WHQL', 'WHQLPublisher', 'WHQLFilePublisher', 'PFN', 'FilePath', 'None')
        return [System.String[]]$ScanLevelz
    }

    [System.Void] NewEmptyMethod() {
        # This is an empty method
    }
}

# argument tab auto-completion and ValidateSet for Non-System Policy names
[NoRunspaceAffinity()]
Class BasePolicyNamez : System.Management.Automation.IValidateSetValuesGenerator {
    [System.String[]] GetValidValues() {

        [System.String[]]$BasePolicyNamez = foreach ($Policy in (&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies) {
            if ($Policy.IsSystemPolicy -ne 'True') {
                if ($Policy.PolicyID -eq $Policy.BasePolicyID) {
                    $Policy.FriendlyName
                }
            }
        }
        return $BasePolicyNamez
    }

    [System.Void] NewEmptyMethod() {
        # This is an empty method
    }
}

# Argument completer and ValidateSet for CertCNs
[NoRunspaceAffinity()]
Class CertCNz : System.Management.Automation.IValidateSetValuesGenerator {
    [System.String[]] GetValidValues() {

        $Output = [System.Collections.Generic.HashSet[System.String]]@()

        # Loop through each certificate in the current user's personal store
        foreach ($Cert in (Get-ChildItem -Path 'Cert:\CurrentUser\My')) {

            # Make sure it uses RSA algorithm (Because ECDSA is not supported for signing WDAC policies)
            if ($Cert.PublicKey.Oid.FriendlyName -eq 'RSA') {

                # Get its Subject Common Name (CN)
                $CN = [WDACConfig.CryptoAPI]::GetNameString($Cert.Handle, [WDACConfig.CryptoAPI]::CERT_NAME_SIMPLE_DISPLAY_TYPE, $null, $false)

                # Add the CN to the output set and warn if there is already CN with the same name in the HashSet
                if (!$Output.Add($CN)) {
                    Write-Warning -Message "There are more than 1 certificates with the common name '$CN' in the Personal certificate store of the Current User, delete one of them if you want to use it."
                }
            }
        }
        # The ValidateSet attribute expects a unique set of values, and it will throw an error if there are duplicates
        Return $Output
    }

    [System.Void] NewEmptyMethod() {
        # This is an empty method
    }
}

# a class to define valid policy rule options
[NoRunspaceAffinity()]
Class RuleOptionsx : System.Management.Automation.IValidateSetValuesGenerator {
    [System.String[]] GetValidValues() {

        #Region Validating current Intel data
        # Get the CI Schema content
        [System.Xml.XmlDocument]$SchemaData = Get-Content -Path ([WDACConfig.GlobalVars]::CISchemaPath)
        [System.Collections.Hashtable]$Intel = ConvertFrom-Json -AsHashtable -InputObject (Get-Content -Path "$([WDACConfig.GlobalVars]::ModuleRootPath)\Resources\PolicyRuleOptions.Json" -Raw -Force)

        # Get the valid rule options from the schema
        $ValidOptions = [System.Collections.Generic.HashSet[System.String]] @(($SchemaData.schema.simpleType | Where-Object -FilterScript { $_.name -eq 'OptionType' }).restriction.enumeration.Value)

        # Perform validation to make sure the current intel is valid in the CI Schema
        foreach ($Key in $Intel.Values) {
            if (-NOT $ValidOptions.Contains($Key)) {
                Throw "Invalid Policy Rule Option detected that is not part of the Code Integrity Schema: $Key"
            }
        }

        foreach ($Option in $ValidOptions) {
            if (-NOT $Intel.Values.Contains($Option)) {
                Write-Verbose -Message "Set-CiRuleOptions: Rule option '$Option' exists in the Code Integrity Schema but not being used by the module."
            }
        }
        #Endregion Validating current Intel data

        $RuleOptionsx = @($Intel.Values)
        return [System.String[]]$RuleOptionsx
    }

    [System.Void] NewEmptyMethod() {
        # This is an empty method
    }
}

# Define the types to export with type accelerators.
[System.Reflection.TypeInfo[]]$ExportableTypes = @(
    [ScanLevelz]
    [CertCNz]
    [BasePolicyNamez]
    [RuleOptionsx]
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
