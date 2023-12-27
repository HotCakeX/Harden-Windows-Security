Function Confirm-CertCN {
    <#
    .SYNOPSIS
        Function to check Certificate Common name - used mostly to validate values in UserConfigurations.json
    .PARAMETER CN
        Common name of the certificate to check
    .INPUTS
        System.String
    .OUTPUTS
        System.Boolean
    #>
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true)]
        [System.String]$CN
    )
    # Importing the $PSDefaultParameterValues to the current session, prior to everything else
    . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

    # Create an empty array to store the output objects
    [System.Object[]]$Output = @()

    # Loop through each certificate that uses RSA algorithm (Because ECDSA is not supported for signing WDAC policies) in the current user's personal store and extract the relevant properties
    foreach ($Cert in (Get-ChildItem -Path 'Cert:\CurrentUser\My' | Where-Object -FilterScript { $_.PublicKey.Oid.FriendlyName -eq 'RSA' })) {

        # Takes care of certificate subjects that include comma in their CN
        # Determine if the subject contains a comma
        if ($Cert.Subject -match 'CN=(?<RegexTest>.*?),.*') {
            # If the CN value contains double quotes, use split to get the value between the quotes
            if ($matches['RegexTest'] -like '*"*') {
                $SubjectCN = ($Element.Certificate.Subject -split 'CN="(.+?)"')[1]
            }
            # Otherwise, use the named group RegexTest to get the CN value
            else {
                $SubjectCN = $matches['RegexTest']
            }
        }
        # If the subject does not contain a comma, use a lookbehind to get the CN value
        elseif ($Cert.Subject -match '(?<=CN=).*') {
            $SubjectCN = $matches[0]
        }

        # Create a custom object with the certificate thumbprint, subject, friendly name and subject CN
        $Output += [PSCustomObject]@{
            Thumbprint   = [System.String]$Cert.Thumbprint
            Subject      = [System.String]$Cert.Subject
            FriendlyName = [System.String]$Cert.FriendlyName
            SubjectCN    = [System.String]$SubjectCN
        }
    }

    return [System.Boolean]([System.String[]]$Output.SubjectCN -contains $CN ? $true : $false)
}

# Export external facing functions only, prevent internal functions from getting exported
Export-ModuleMember -Function 'Confirm-CertCN'
