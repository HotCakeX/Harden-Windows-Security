Function Measure-CIPolicyVersion {
    <#
    .SYNOPSIS
        Converts a 64-bit unsigned integer into version type, used for converting the numbers from CiTool.exe output to proper versions
    #>
    Param ([System.String]$Number)

    Try {
        # Convert the string to a 64-bit integer
        $Number = [System.UInt64]::Parse($Number)

        # Extract the version parts by splitting the 64-bit integer into four 16-bit segments and convert each segment to its respective part of the version number
        [System.UInt16]$Part1 = ($Number -band '0xFFFF000000000000') -shr '48' # mask isolates the highest 16 bits of a 64-bit number.
        [System.UInt16]$Part2 = ($Number -band '0x0000FFFF00000000') -shr '32' # mask isolates the next 16 bits.
        [System.UInt16]$Part3 = ($Number -band '0x00000000FFFF0000') -shr '16' # mask isolates the third set of 16 bits.
        [System.UInt16]$Part4 = $Number -band '0x000000000000FFFF' # mask isolates the lowest 16 bits.

        # Form the version string
        [System.Version]$version = "$Part1.$Part2.$Part3.$Part4"
        Return $version
    }
    catch {
        Return $Number
    }
}
Export-ModuleMember -Function 'Measure-CIPolicyVersion'
