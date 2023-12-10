# You can download official Windows ADMX files from here
# https://www.microsoft.com/en-us/download/details.aspx?id=105390

# Define the path of the XML file
$xmlFile = "C:\New Folder\WindowsDefender.admx"

# Load the XML content into a variable
$xmlContent = [xml](Get-Content $xmlFile)

# Create an empty array to store the results
$results = @()

# Loop through each policy element in the XML content
foreach ($policy in $xmlContent.policyDefinitions.policies.policy) {
    # Check if the policy has a valueName attribute
    if ($policy.valueName) {
        # Check if the policy's class is class="Machine"
        if ($policy.class -eq "Machine") {
            # Add HKEY_LOCAL_MACHINE to the beginning of the key
            $key = "HKLM:\" + $policy.key
        }
        else {
            # Use the key as it is
            Write-Error "Class is not machine"
        }

        # Create a PSCustomObject with two properties: RegDirectory and RegKey
        $result = [PSCustomObject]@{
            Category     = "Microsoft Defender"
            RegistryKey  = $key
            RegistryName = $policy.valueName
        }

        # Check if the registry key exists and get its value
        try {
            $regValue = Get-ItemPropertyValue -Path $key -Name $policy.valueName -ErrorAction Stop

            # Add the value as a property of the PSCustomObject
            $result | Add-Member -MemberType NoteProperty -Name 'RegValue' -Value $regValue
        }
        catch {
            # If the registry key does not exist, add a null value as a property of the PSCustomObject
            $result | Add-Member -MemberType NoteProperty -Name 'RegValue' -Value $null
        }

        # Add the result to the array
        $results += $result
    }
}

# Output the array of PSCustomObjects
$results | Where-Object { $null -ne $_.RegValue }