function Compare-SecureString {
    <#
    .SYNOPSIS
        Safely compares two SecureString objects without decrypting them.
        Outputs $true if they are equal, or $false otherwise.
    .INPUTS
        System.Security.SecureString
    .OUTPUTS
        System.Boolean
    .PARAMETER SecureString1
        First secure string
    .PARAMETER SecureString2
        Second secure string to compare with the first secure string
    #>
    [CmdletBinding()]
    param(
        [System.Security.SecureString]$SecureString1,
        [System.Security.SecureString]$SecureString2
    )
    try {
        $Bstr1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString1)
        $Bstr2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString2)
        $Length1 = [Runtime.InteropServices.Marshal]::ReadInt32($Bstr1, -4)
        $Length2 = [Runtime.InteropServices.Marshal]::ReadInt32($Bstr2, -4)
        if ( $Length1 -ne $Length2 ) {
            return $false
        }
        for ( $I = 0; $I -lt $Length1; ++$I ) {
            $B1 = [Runtime.InteropServices.Marshal]::ReadByte($Bstr1, $I)
            $B2 = [Runtime.InteropServices.Marshal]::ReadByte($Bstr2, $I)
            if ( $B1 -ne $B2 ) {
                return $false
            }
        }
        return $true
    }
    finally {
        if ( $Bstr1 -ne [IntPtr]::Zero ) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr1)
        }
        if ( $Bstr2 -ne [IntPtr]::Zero ) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr2)
        }
    }
}

Export-ModuleMember -Function 'Compare-SecureString'
