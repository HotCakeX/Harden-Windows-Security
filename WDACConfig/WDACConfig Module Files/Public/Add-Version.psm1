Function Add-Version {
    <#
    .SYNOPSIS
        This can recursively increment an input version by one, and is aware of the max limit
    #>
    param (
        [System.Version]$Version
    )

    if ($Version.Revision -lt [System.Int32]::MaxValue) {
        $NewVersion = [System.Version]::new($Version.Major, $Version.Minor, $Version.Build, $Version.Revision + 1)
    }
    elseif ($Version.Build -lt [System.Int32]::MaxValue) {
        $NewVersion = [System.Version]::new($Version.Major, $Version.Minor, $Version.Build + 1, 0)
    }
    elseif ($Version.Minor -lt [System.Int32]::MaxValue) {
        $NewVersion = [System.Version]::new($Version.Major, $Version.Minor + 1, 0, 0)
    }
    elseif ($Version.Major -lt [System.Int32]::MaxValue) {
        $NewVersion = [System.Version]::new($Version.Major + 1, 0, 0, 0)
    }
    else {
        Throw 'Version has reached its maximum value.'
    }

    return $NewVersion
}
Export-ModuleMember -Function 'Add-Version'
