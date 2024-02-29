# Since the quasi-exported classes will be available process-wide
# and therefore also in other runspaces, defining them with the [NoRunspaceAffinity()] attribute.
# https://stackoverflow.com/a/78078461/21243735
# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_classes?view=powershell-7.4#exporting-classes-with-type-accelerators

# argument tab auto-completion and ValidateSet for Levels and Fallbacks parameters in the entire module
[NoRunspaceAffinity()]
Class ScanLevelz : System.Management.Automation.IValidateSetValuesGenerator {
    [System.String[]] GetValidValues() {
        $ScanLevelz = ('Hash', 'FileName', 'SignedVersion', 'Publisher', 'FilePublisher', 'LeafCertificate', 'PcaCertificate', 'RootCertificate', 'WHQL', 'WHQLPublisher', 'WHQLFilePublisher', 'PFN', 'FilePath', 'None')
        return [System.String[]]$ScanLevelz
    }
}

# argument tab auto-completion and ValidateSet for Non-System Policy names
[NoRunspaceAffinity()]
Class BasePolicyNamez : System.Management.Automation.IValidateSetValuesGenerator {
    [System.String[]] GetValidValues() {
        $BasePolicyNamez = ((&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.IsSystemPolicy -ne 'True' } | Where-Object -FilterScript { $_.PolicyID -eq $_.BasePolicyID }).Friendlyname
        return [System.String[]]$BasePolicyNamez
    }
}

# Argument completer and ValidateSet for CertCNs
[NoRunspaceAffinity()]
Class CertCNz : System.Management.Automation.IValidateSetValuesGenerator {
    [System.String[]] GetValidValues() {
        # Cannot define the custom type 'WDACConfig.CryptoAPI' since we're in a class definition and it does not support it, hence using Add-Type with -PassThru
        $CryptoAPI = Add-Type -Path "$global:ModuleRootPath\C#\Crypt32CertCN.cs" -PassThru

        [System.String[]]$Output = @()

        # Loop through each certificate that uses RSA algorithm (Because ECDSA is not supported for signing WDAC policies) in the current user's personal store and extract the relevant properties
        foreach ($Cert in (Get-ChildItem -Path 'Cert:\CurrentUser\My' | Where-Object -FilterScript { $_.PublicKey.Oid.FriendlyName -eq 'RSA' })) {

            $CN = $CryptoAPI::GetNameString($Cert.Handle, $CryptoAPI::CERT_NAME_SIMPLE_DISPLAY_TYPE, $null, $false)

            if ($CN -in $Output) {
                Write-Warning -Message "There are more than 1 certificates with the common name '$CN' in the Personal certificate store of the Current User, delete one of them if you want to use it."
            }
            $Output += $CN
        }
        # The ValidateSet attribute expects a unique set of values, and it will throw an error if there are duplicates
        Return ($Output | Select-Object -Unique)
    }
}

# Define the types to export with type accelerators.
[System.Reflection.TypeInfo[]]$ExportableTypes = @(
    [ScanLevelz]
    [CertCNz]
    [BasePolicyNamez]
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
