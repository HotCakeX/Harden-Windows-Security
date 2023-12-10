cls

# Load the xml file into a variable
$xml = [xml](Get-Content -Path ".\GPResult.xml")

# An array to store each Group Policy as a separate object
$RegistryOutput = @()
# Use dot notation to access the Policy element
$xml.Rsop.ComputerResults.ExtensionData.Extension.RegistrySetting | Where-Object { $null -ne $_.Value.Name } | ForEach-Object {

    $RegistryOutput += [PSCustomObject]@{
        KeyPath = $_.KeyPath
        Name    = $_.Value.Name
        Number  = $_.Value.Number
    }
}

$RegistryOutput

$RegistryOutput.Count

