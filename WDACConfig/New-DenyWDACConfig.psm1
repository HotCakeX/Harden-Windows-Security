#Requires -RunAsAdministrator       
function New-DenyWDACConfig {
    [CmdletBinding(      
        DefaultParameterSetName = "Drivers",
        PositionalBinding = $false,
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High'
    )]
    Param(
        # Main parameters for position 0
        [Alias("N")]
        [Parameter(Mandatory = $false, ParameterSetName = "Normal")][Switch]$Normal,

        [Alias("D")]
        [Parameter(Mandatory = $false, ParameterSetName = "Drivers")][Switch]$Drivers,

        [ValidatePattern('^[a-zA-Z0-9 ]+$', ErrorMessage = "The Supplemental Policy Name can only contain alphanumeric characters and spaces.")]
        [parameter(Mandatory = $true, ParameterSetName = "Normal", ValueFromPipelineByPropertyName = $true)]
        [parameter(Mandatory = $true, ParameterSetName = "Drivers", ValueFromPipelineByPropertyName = $true)]        
        [System.String]$PolicyName,
   
        [ValidateScript({ Test-Path $_ -PathType 'Container' }, ErrorMessage = "The path you selected is not a folder path.")]            
        [parameter(Mandatory = $true, ParameterSetName = "Normal")]
        [parameter(Mandatory = $true, ParameterSetName = "Drivers")]
        [System.String[]]$ScanLocations,

        [ValidateSet([Levelz])]
        [Parameter(Mandatory = $false, ParameterSetName = "Normal")]
        [Parameter(Mandatory = $false, ParameterSetName = "Drivers")]
        [System.String]$Level = "FilePublisher", # Setting the default value for the Level parameter

        [ValidateSet([Fallbackz])]
        [Parameter(Mandatory = $false, ParameterSetName = "Normal")]
        [Parameter(Mandatory = $false, ParameterSetName = "Drivers")]
        [System.String[]]$Fallbacks = "Hash", # Setting the default value for the Fallbacks parameter

        [Parameter(Mandatory = $false, ParameterSetName = "Normal")]
        [Switch]$AllowFileNameFallbacks,
        
        [ValidateSet("OriginalFileName", "InternalName", "FileDescription", "ProductName", "PackageFamilyName", "FilePath")]
        [Parameter(Mandatory = $false, ParameterSetName = "Normal")]
        [System.String]$SpecificFileNameLevel,

        [Parameter(Mandatory = $false, ParameterSetName = "Normal")]
        [Switch]$NoUserPEs,

        [Parameter(Mandatory = $false, ParameterSetName = "Normal")]
        [Switch]$NoScript,

        [Parameter(Mandatory = $false, ParameterSetName = "Normal")]
        [Parameter(Mandatory = $false, ParameterSetName = "Drivers")]
        [Switch]$Deployit,
        
        [Parameter(Mandatory = $false)][Switch]$SkipVersionCheck
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
            Remove-Item -Path ".\ProgramDir_ScanResults*.xml" -Force -ErrorAction SilentlyContinue
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

            Write-Debug -Message "The Deny policy with the following configuration is being created"
            if ($Debug) { $UserInputProgramFoldersPolicyMakerHashTable }
            
            # Merge-cipolicy accept arrays - collecting all the policy files created by scanning user specified folders
            $ProgramDir_ScanResults = Get-ChildItem ".\" | Where-Object { $_.Name -like 'ProgramDir_ScanResults*.xml' }                
            foreach ($file in $ProgramDir_ScanResults) {
                $PolicyXMLFilesArray += $file.FullName
            
            }

            # Creating an empty policy that only contains 2 allow rules, going to be merged with the Deny only base policy
            New-AllowAllPolicy | Out-File '.\AllowAllPolicy.xml'
            # Adding the AllowAll policy path to the array of policy paths
            $PolicyXMLFilesArray += '.\AllowAllPolicy.xml'
            # creating the final Deny base policy from the xml files in the paths array
            Merge-CIPolicy -PolicyPaths $PolicyXMLFilesArray -OutputFilePath ".\DenyPolicy $PolicyName.xml" | Out-Null
                            
            $policyID = Set-CiPolicyIdInfo -FilePath "DenyPolicy $PolicyName.xml" -ResetPolicyID -PolicyName "$PolicyName"
            $policyID = $policyID.Substring(11)
            Set-CIPolicyVersion -FilePath "DenyPolicy $PolicyName.xml" -Version "1.0.0.0"
            
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
                Remove-Item -Path ".\ProgramDir_ScanResults*.xml" -Force
                Remove-Item -Path '.\AllowAllPolicy.xml' -Force
            }
            
            if ($Deployit) {                
                CiTool --update-policy "$policyID.cip" -json
                Remove-Item -Path "$policyID.cip" -Force
                Write-host -NoNewline "`n$policyID.cip for " -ForegroundColor Green
                Write-host -NoNewline "$PolicyName" -ForegroundColor Magenta
                Write-host " has been deployed." -ForegroundColor Green
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
                    FilePath             = ".\DenyPolicy Temp.xml"
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

            # Creating an empty policy that only contains 2 allow rules, going to be merged with the Deny only base policy
            New-AllowAllPolicy | Out-File '.\AllowAllPolicy.xml'

            # Letting the AllowAll policy be first so that its AllowAll rules will be on top of each node for better visibility
            Merge-CIPolicy -PolicyPaths '.\AllowAllPolicy.xml', ".\DenyPolicy Temp.xml" -OutputFilePath ".\DenyPolicy $PolicyName.xml" | Out-Null

            Remove-Item -Path ".\DenyPolicy Temp.xml" -Force
            Remove-Item -Path '.\AllowAllPolicy.xml' -Force

            $policyID = Set-CiPolicyIdInfo -FilePath "DenyPolicy $PolicyName.xml" -ResetPolicyID -PolicyName "$PolicyName"
            $policyID = $policyID.Substring(11)
            Set-CIPolicyVersion -FilePath "DenyPolicy $PolicyName.xml" -Version "1.0.0.0"
            
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
                CiTool --update-policy "$policyID.cip" -json
                Remove-Item -Path "$policyID.cip" -Force
                Write-host -NoNewline "`n$policyID.cip for " -ForegroundColor Green
                Write-host -NoNewline "$PolicyName" -ForegroundColor Magenta
                Write-host " has been deployed." -ForegroundColor Green
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

.PARAMETER SkipVersionCheck
Can be used with any parameter to bypass the online version check - only to be used in rare cases

#>
}

# Importing argument completer ScriptBlocks
. "$psscriptroot\ArgumentCompleters.ps1"
# Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete
Register-ArgumentCompleter -CommandName "New-DenyWDACConfig" -ParameterName "ScanLocations" -ScriptBlock $ArgumentCompleterFolderPathsPicker
