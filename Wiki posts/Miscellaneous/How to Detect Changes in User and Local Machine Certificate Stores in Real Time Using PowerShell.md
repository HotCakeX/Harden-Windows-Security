# How to Detect Changes in User and Local Machine Certificate Stores in Real Time Using PowerShell

Here is a PowerShell script that can display the changes in User and Local Machine Certificate Stores in Real Time. It performs the check every 3 seconds. The script is published to [PowerShell Gallery](https://www.powershellgallery.com/packages/Certificates-Change-Detection) and you can easily install it using the following command:

```powershell
Install-Script -Name Certificates-Change-Detection -Force
```

<br>

## The Code used in the script

```powershell
#Requires -RunAsAdministrator
#Requires -Version 7.3

# Custom colors
[scriptblock]$WritePink = { Write-Output "$($PSStyle.Foreground.FromRGB(255,192,203))$($PSStyle.Blink)$($args[0])$($PSStyle.Reset)" }
[scriptblock]$WriteMintGreen = { Write-Output "$($PSStyle.Foreground.FromRGB(152,255,152))$($PSStyle.Blink)$($args[0])$($PSStyle.Reset)" }

# Create variables to store the initial certificates for both locations
$InitialLocal = Get-ChildItem Cert:\LocalMachine\* -Recurse
$InitialUser = Get-ChildItem Cert:\CurrentUser\* -Recurse

# Create a loop that runs indefinitely
while ($true) {
    # Create variables to store the current certificates for both locations
    $CurrentLocal = Get-ChildItem Cert:\LocalMachine\* -Recurse
    $CurrentUser = Get-ChildItem Cert:\CurrentUser\* -Recurse

    # Compare the variables and check if there is any difference in certificates for LocalMachine
    $DifferenceLocal = Compare-Object $InitialLocal $CurrentLocal

    # Compare the variables and check if there is any difference in certificates for CurrentUser
    $DifferenceUser = Compare-Object $InitialUser $CurrentUser

    # If there is any difference in certificates for LocalMachine, display it and update the initial variable
    if ($DifferenceLocal) {
        foreach ($Diff in $DifferenceLocal) {
            # Check if the change is an addition or a removal based on the side indicator
            if ($Diff.SideIndicator -eq '=>') {
                &$WritePink "Certificate Added to LocalMachine at $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss K')"
                $PSStyle.Formatting.FormatAccent = "$($PSStyle.Foreground.FromRGB(255,192,203))"
                $Diff.InputObject | Format-List -Property PSPath, EnhancedKeyUsageList, DnsNameList, SendAsTrustedIssuer, FriendlyName, HasPrivateKey, NotAfter, NotBefore, SerialNumber, Thumbprint, Issuer, Subject
            }
            elseif ($Diff.SideIndicator -eq '<=') {
                &$WriteMintGreen "Certificate Removed from LocalMachine at $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss K')"
                $PSStyle.Formatting.FormatAccent = "$($PSStyle.Foreground.FromRGB(152,255,152))"
                $Diff.InputObject | Format-List -Property PSPath, EnhancedKeyUsageList, DnsNameList, SendAsTrustedIssuer, FriendlyName, HasPrivateKey, NotAfter, NotBefore, SerialNumber, Thumbprint, Issuer, Subject
            }
        }
        $InitialLocal = $CurrentLocal
    }

    # If there is any difference in certificates for CurrentUser, display it and update the initial variable
    if ($DifferenceUser) {
        foreach ($Diff in $DifferenceUser) {
            # Check if the change is an addition or a removal based on the side indicator
            if ($Diff.SideIndicator -eq '=>') {
                &$WritePink "Certificate Added to CurrentUser at $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss K')"
                $PSStyle.Formatting.FormatAccent = "$($PSStyle.Foreground.FromRGB(255,192,203))"
                $Diff.InputObject | Format-List -Property PSPath, EnhancedKeyUsageList, DnsNameList, SendAsTrustedIssuer, FriendlyName, HasPrivateKey, NotAfter, NotBefore, SerialNumber, Thumbprint, Issuer, Subject
            }
            elseif ($Diff.SideIndicator -eq '<=') {
                &$WriteMintGreen "Certificate Removed from CurrentUser at $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss K')"
                $PSStyle.Formatting.FormatAccent = "$($PSStyle.Foreground.FromRGB(152,255,152))"
                $Diff.InputObject | Format-List -Property PSPath, EnhancedKeyUsageList, DnsNameList, SendAsTrustedIssuer, FriendlyName, HasPrivateKey, NotAfter, NotBefore, SerialNumber, Thumbprint, Issuer, Subject
            }
        }
        $InitialUser = $CurrentUser
    }

    # Wait for 3 seconds before repeating the loop
    Start-Sleep -Seconds 3
}

```

<br>

