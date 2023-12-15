Function Protect-WindowsSecurity {
    # Import functions
    . "$HardeningModulePath\Resources\Functions.ps1"

    # Apply the hardening measures from the local file
    & "$HardeningModulePath\Resources\Harden-Windows-Security.ps1"

    <#
.SYNOPSIS
    Applies the hardening measures
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security
.DESCRIPTION
    Applies the hardening measures
.COMPONENT
    PowerShell
.FUNCTIONALITY
    Applies the hardening measures
.INPUTS
    None
.OUTPUTS
    System.Void
#>
}
