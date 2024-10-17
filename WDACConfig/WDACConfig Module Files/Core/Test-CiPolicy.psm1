Function Test-CiPolicy {
    [CmdletBinding()]
    param(
        [ArgumentCompleter([WDACConfig.ArgCompleter.XmlFilePathsPicker])]
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'XML File')]
        [System.IO.FileInfo]$XmlFile,

        [ArgumentCompleter([WDACConfig.ArgCompleter.AnyFilePathsPicker])]
        [ValidateScript({ [System.IO.File]::Exists($_) })]
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'CIP File')]
        [System.IO.FileInfo]$CipFile
    )
    [WDACConfig.LoggerInitializer]::Initialize($VerbosePreference, $DebugPreference, $Host)
    # If a CI XML file is being tested
    if ($PSCmdlet.ParameterSetName -eq 'XML File' -and $PSBoundParameters.ContainsKey('XmlFile')) {
        [WDACConfig.CiPolicyTest]::TestCiPolicy($XmlFile, $null)
    }
    # If a CI binary is being tested
    elseif ($PSCmdlet.ParameterSetName -eq 'CIP File' -and $PSBoundParameters.ContainsKey('CipFile')) {
        [WDACConfig.CiPolicyTest]::TestCiPolicy($null, $CipFile)
    }
    <#
.SYNOPSIS
    Tests the Code Integrity Policy XML file against the Code Integrity Schema.
    It can also display the signer information from a signed Code Integrity policy .CIP binary file. Get-AuthenticodeSignature cmdlet does not show signers in .CIP files.
.DESCRIPTION
    The Test-CiPolicy cmdlet can test a Code Integrity (WDAC) Policy.
    If you input a XML file, it will validate it against the Schema file located at: "$Env:SystemDrive\Windows\schemas\CodeIntegrity\cipolicy.xsd"
    and returns a boolean value indicating whether the XML file is valid or not.

    If you input a signed binary Code Integrity Policy file, it will return the signer information from the file.
.PARAMETER XmlFile
    The Code Integrity Policy XML file to test. Supports file picker GUI.
.PARAMETER CipFile
    The binary Code Integrity Policy file to test for signers. Supports file picker GUI.
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Test-CiPolicy
.INPUTS
    [System.IO.FileInfo]
.OUTPUTS
    System.Boolean
    System.Security.Cryptography.X509Certificates.X509Certificate2[]
.EXAMPLE
    Test-CiPolicy -XmlFile "C:\path\to\policy.xml"
.EXAMPLE
    Test-CiPolicy -CipFile "C:\Users\Admin\{C5F45D1A-97F7-42CF-84F1-40755F1AEB97}.cip"
    #>
}
