#Requires -RunAsAdministrator       
function New-DenyWDACConfig {
    [CmdletBinding(      
        DefaultParameterSetName = 'Drivers',
        PositionalBinding = $false,
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High'
    )]
    Param(
        # Main parameters for position 0
        [Alias('N')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')][Switch]$Normal,
        [Alias('D')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Drivers')][Switch]$Drivers,
        [Alias('P')]
        [parameter(mandatory = $false, ParameterSetName = 'Installed AppXPackages')][switch]$InstalledAppXPackages,

        [parameter(Mandatory = $true, ParameterSetName = 'Installed AppXPackages', ValueFromPipelineByPropertyName = $true)]
        [System.String]$PackageName,

        [ValidatePattern('^[a-zA-Z0-9 ]+$', ErrorMessage = 'The Supplemental Policy Name can only contain alphanumeric characters and spaces.')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)] # Used by all the entire Cmdlet     
        [System.String]$PolicyName, 
   
        [ValidateScript({ Test-Path $_ -PathType 'Container' }, ErrorMessage = 'The path you selected is not a folder path.')]            
        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Drivers')]
        [System.String[]]$ScanLocations,

        [ValidateSet([Levelz])]
        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Drivers')]
        [System.String]$Level = 'FilePublisher', # Setting the default value for the Level parameter

        [ValidateSet([Fallbackz])]
        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Drivers')]
        [System.String[]]$Fallbacks = 'Hash', # Setting the default value for the Fallbacks parameter

        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [Switch]$AllowFileNameFallbacks,
        
        [ValidateSet('OriginalFileName', 'InternalName', 'FileDescription', 'ProductName', 'PackageFamilyName', 'FilePath')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [System.String]$SpecificFileNameLevel,

        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [Switch]$NoUserPEs,

        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [Switch]$NoScript,

        [Parameter(Mandatory = $false)] # Used by all the entire Cmdlet
        [Switch]$Deployit,
        
        [Parameter(Mandatory = $false)][Switch]$SkipVersionCheck # Used by all the entire Cmdlet
    )

    begin {    

        # Importing resources such as functions by dot-sourcing so that they will run in the same scope and their variables will be usable
        . "$psscriptroot\Resources.ps1"

        # Detecting if Debug switch is used, will do debugging actions based on that
        $Debug = $PSBoundParameters.Debug.IsPresent

        # argument tab auto-completion and ValidateSet for Fallbacks
        Class Fallbackz : System.Management.Automation.IValidateSetValuesGenerator {
            [System.String[]] GetValidValues() {
                $Fallbackz = ('Hash', 'FileName', 'SignedVersion', 'Publisher', 'FilePublisher', 'LeafCertificate', 'PcaCertificate', 'RootCertificate', 'WHQL', 'WHQLPublisher', 'WHQLFilePublisher', 'PFN', 'FilePath', 'None')
           
                return [System.String[]]$Fallbackz
            }
        }
        
        # argument tab auto-completion and ValidateSet for level
        Class Levelz : System.Management.Automation.IValidateSetValuesGenerator {
            [System.String[]] GetValidValues() {
                $Levelz = ('Hash', 'FileName', 'SignedVersion', 'Publisher', 'FilePublisher', 'LeafCertificate', 'PcaCertificate', 'RootCertificate', 'WHQL', 'WHQLPublisher', 'WHQLFilePublisher', 'PFN', 'FilePath', 'None')
               
                return [System.String[]]$Levelz
            }
        }

        # Stop operation as soon as there is an error anywhere, unless explicitly specified otherwise
        $ErrorActionPreference = 'Stop'
        if (-NOT $SkipVersionCheck) { . Update-self }       
    }
    
    process {
        # Create deny supplemental policy for general files, apps etc.
        if ($Normal) {
            # remove any possible files from previous runs
            Remove-Item -Path '.\ProgramDir_ScanResults*.xml' -Force -ErrorAction SilentlyContinue
            # An array to hold the temporary xml files of each user-selected folders
            $PolicyXMLFilesArray = @()

            ######################## Process Program Folders From User input #####################
            for ($i = 0; $i -lt $ScanLocations.Count; $i++) {

                # Creating a hash table to dynamically add parameters based on user input and pass them to New-Cipolicy cmdlet
                [System.Collections.Hashtable]$UserInputProgramFoldersPolicyMakerHashTable = @{
                    FilePath             = ".\ProgramDir_ScanResults$($i).xml"
                    ScanPath             = $ScanLocations[$i]
                    Level                = $Level
                    Fallback             = $Fallbacks
                    MultiplePolicyFormat = $true
                    UserWriteablePaths   = $true
                    Deny                 = $true
                }
                # Assess user input parameters and add the required parameters to the hash table
                if ($AllowFileNameFallbacks) { $UserInputProgramFoldersPolicyMakerHashTable['AllowFileNameFallbacks'] = $true }
                if ($SpecificFileNameLevel) { $UserInputProgramFoldersPolicyMakerHashTable['SpecificFileNameLevel'] = $SpecificFileNameLevel }
                if ($NoScript) { $UserInputProgramFoldersPolicyMakerHashTable['NoScript'] = $true }                      
                if (!$NoUserPEs) { $UserInputProgramFoldersPolicyMakerHashTable['UserPEs'] = $true } 

                # Create the supplemental policy via parameter splatting
                New-CIPolicy @UserInputProgramFoldersPolicyMakerHashTable
            }            

            Write-Debug -Message 'The Deny policy with the following configuration is being created'
            if ($Debug) { $UserInputProgramFoldersPolicyMakerHashTable }
            
            # Merge-cipolicy accept arrays - collecting all the policy files created by scanning user specified folders
            $ProgramDir_ScanResults = Get-ChildItem '.\' | Where-Object { $_.Name -like 'ProgramDir_ScanResults*.xml' }                
            foreach ($file in $ProgramDir_ScanResults) {
                $PolicyXMLFilesArray += $file.FullName
            
            }

            # Adding the AllowAll default policy path to the array of policy paths
            $PolicyXMLFilesArray += 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml'
            # creating the final Deny base policy from the xml files in the paths array
            Merge-CIPolicy -PolicyPaths $PolicyXMLFilesArray -OutputFilePath ".\DenyPolicy $PolicyName.xml" | Out-Null
                            
            $policyID = Set-CIPolicyIdInfo -FilePath "DenyPolicy $PolicyName.xml" -ResetPolicyID -PolicyName "$PolicyName"
            $policyID = $policyID.Substring(11)
            Set-CIPolicyVersion -FilePath "DenyPolicy $PolicyName.xml" -Version '1.0.0.0'
            
            @(0, 2, 5, 6, 11, 12, 16, 17, 19, 20) | ForEach-Object {
                Set-RuleOption -FilePath "DenyPolicy $PolicyName.xml" -Option $_ }
                
            @(3, 4, 9, 10, 13, 18) | ForEach-Object {
                Set-RuleOption -FilePath "DenyPolicy $PolicyName.xml" -Option $_ -Delete }        
            
            Set-HVCIOptions -Strict -FilePath "DenyPolicy $PolicyName.xml"        
            ConvertFrom-CIPolicy "DenyPolicy $PolicyName.xml" "$policyID.cip" | Out-Null
            [PSCustomObject]@{
                DenyPolicyFile = "DenyPolicy $PolicyName.xml"
                DenyPolicyGUID = $PolicyID
            }
            
            if (!$Debug) {
                Remove-Item -Path '.\ProgramDir_ScanResults*.xml' -Force
            }
            
            if ($Deployit) {                
                CiTool --update-policy "$policyID.cip" -json | Out-Null               
                Write-Host -NoNewline "`n$policyID.cip for " -ForegroundColor Green
                Write-Host -NoNewline "$PolicyName" -ForegroundColor Magenta
                Write-Host ' has been deployed.' -ForegroundColor Green                
                Remove-Item -Path "$policyID.cip" -Force
            }
        }
        # Create Deny base policy for Driver files
        elseif ($Drivers) {           

            powershell.exe {
                $DriverFilesObject = @()
                # loop through each user-selected folder paths
                foreach ($ScanLocation in $args[0]) {
                    # DriverFile object holds the full details of all of the scanned drivers - This scan is greedy, meaning it stores as much information as it can find
                    # about each driver file, any available info about digital signature, hash, FileName, Internal Name etc. of each driver is saved and nothing is left out    
                    $DriverFilesObject += Get-SystemDriver -ScanPath $ScanLocation -UserPEs            
                }

                [System.Collections.Hashtable]$PolicyMakerHashTable = @{
                    FilePath             = '.\DenyPolicy Temp.xml'
                    DriverFiles          = $DriverFilesObject
                    Level                = $args[1]
                    Fallback             = $args[2]
                    MultiplePolicyFormat = $true
                    UserWriteablePaths   = $true
                    Deny                 = $true
                }
                # Creating a base policy using the DriverFile object and specifying which detail about each driver should be used in the policy file
                New-CIPolicy @PolicyMakerHashTable
            
            } -args $ScanLocations, $Level, $Fallbacks
            
            # Merging AllowAll default policy with our Deny temp policy
            Merge-CIPolicy -PolicyPaths 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml', '.\DenyPolicy Temp.xml' -OutputFilePath ".\DenyPolicy $PolicyName.xml" | Out-Null

            Remove-Item -Path '.\DenyPolicy Temp.xml' -Force
            $policyID = Set-CIPolicyIdInfo -FilePath "DenyPolicy $PolicyName.xml" -ResetPolicyID -PolicyName "$PolicyName"
            $policyID = $policyID.Substring(11)
            Set-CIPolicyVersion -FilePath "DenyPolicy $PolicyName.xml" -Version '1.0.0.0'
            
            @(0, 2, 5, 6, 11, 12, 16, 17, 19, 20) | ForEach-Object {
                Set-RuleOption -FilePath "DenyPolicy $PolicyName.xml" -Option $_ }
                
            @(3, 4, 9, 10, 13, 18) | ForEach-Object {
                Set-RuleOption -FilePath "DenyPolicy $PolicyName.xml" -Option $_ -Delete }
           
            Set-HVCIOptions -Strict -FilePath "DenyPolicy $PolicyName.xml"        
            ConvertFrom-CIPolicy "DenyPolicy $PolicyName.xml" "$policyID.cip" | Out-Null
            
            [PSCustomObject]@{
                DenyPolicyFile = "DenyPolicy $PolicyName.xml"
                DenyPolicyGUID = $PolicyID
            } 
            if ($Deployit) {                
                CiTool --update-policy "$policyID.cip" -json | Out-Null             
                Write-Host -NoNewline "`n$policyID.cip for " -ForegroundColor Green
                Write-Host -NoNewline "$PolicyName" -ForegroundColor Magenta
                Write-Host ' has been deployed.' -ForegroundColor Green                
                Remove-Item -Path "$policyID.cip" -Force
            }   
        }

        # Creating Deny rule for Appx Packages
        if ($InstalledAppXPackages) {
            do {
                Get-AppxPackage -Name $PackageName
                Write-Debug -Message "This is the Selected package name $PackageName"
                $Question = Read-Host "`nIs this the intended results based on your Installed Appx packages? Enter 1 to continue, Enter 2 to exit`n"                              
            } until (
                (($Question -eq 1) -or ($Question -eq 2))
            )
            if ($Question -eq 2) { break }

            powershell.exe { 
                # Get all the packages based on the supplied name
                $Package = Get-AppxPackage -Name $args[0]               

                # Create rules for each package
                foreach ($item in $Package) {
                    $Rules += New-CIPolicyRule -Deny -Package $item
                }
                
                # Generate the supplemental policy xml file
                New-CIPolicy -MultiplePolicyFormat -FilePath '.\AppxDenyPolicyTemp.xml' -Rules $Rules
            } -args $PackageName

            # Merging AllowAll default policy with our Deny temp policy
            Merge-CIPolicy -PolicyPaths 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml', '.\AppxDenyPolicyTemp.xml' -OutputFilePath ".\AppxDenyPolicy $PolicyName.xml" | Out-Null

            # Removing the temp deny policy
            Remove-Item -Path '.\AppxDenyPolicyTemp.xml' -Force
            $policyID = Set-CIPolicyIdInfo -FilePath ".\AppxDenyPolicy $PolicyName.xml" -ResetPolicyID -PolicyName "$PolicyName"
            $policyID = $policyID.Substring(11)
            Set-CIPolicyVersion -FilePath ".\AppxDenyPolicy $PolicyName.xml" -Version '1.0.0.0'
 
            @(0, 2, 6, 11, 12, 16, 17, 19, 20) | ForEach-Object {
                Set-RuleOption -FilePath ".\AppxDenyPolicy $PolicyName.xml" -Option $_ }
                
            @(3, 4, 8, 9, 10, 13, 14, 15, 18) | ForEach-Object {
                Set-RuleOption -FilePath ".\AppxDenyPolicy $PolicyName.xml" -Option $_ -Delete }

            Set-HVCIOptions -Strict -FilePath ".\AppxDenyPolicy $PolicyName.xml"        
            ConvertFrom-CIPolicy ".\AppxDenyPolicy $PolicyName.xml" "$policyID.cip" | Out-Null
           
            [PSCustomObject]@{
                DenyPolicyFile = ".\AppxDenyPolicy $PolicyName.xml"
                DenyPolicyGUID = $PolicyID
            }
            
            if ($Deployit) {                
                CiTool --update-policy "$policyID.cip" -json | Out-Null
                &$WritePink "A Deny Base policy with the name $PolicyName has been deployed."
                Remove-Item -Path "$policyID.cip" -Force
            }            
        }
    } 
   
    <#
.SYNOPSIS
Creates Deny base policies (Windows Defender Application Control)

.LINK
https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-DenyWDACConfig

.DESCRIPTION
Using official Microsoft methods to create Deny base policies (Windows Defender Application Control)

.COMPONENT
Windows Defender Application Control, ConfigCI PowerShell module

.FUNCTIONALITY
Using official Microsoft methods, Removes Signed and unsigned deployed WDAC policies (Windows Defender Application Control)

.PARAMETER Normal
Creates a Deny standalone base policy by scanning a directory for files. The base policy created by this parameter can be deployed side by side any other base/supplemental policy.

.PARAMETER Drivers
Creates a Deny standalone base policy for drivers only by scanning a directory for driver files. The base policy created by this parameter can be deployed side by side any other base/supplemental policy.

.PARAMETER InstalledAppXPackages
Creates a Deny standalone base policy for an installed App based on Appx package family names

.PARAMETER SkipVersionCheck
Can be used with any parameter to bypass the online version check - only to be used in rare cases

#>
}

# Importing argument completer ScriptBlocks
. "$psscriptroot\ArgumentCompleters.ps1"
# Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
Set-PSReadLineKeyHandler -Key Tab -Function MenuComplete
Register-ArgumentCompleter -CommandName 'New-DenyWDACConfig' -ParameterName 'ScanLocations' -ScriptBlock $ArgumentCompleterFolderPathsPicker
Register-ArgumentCompleter -CommandName 'New-DenyWDACConfig' -ParameterName 'PackageName' -ScriptBlock $ArgumentCompleterAppxPackageNames