Function Show-DirectoryPathPicker {
    <#
    .SYNOPSIS
        Shows the folder picker GUI to the user for folder path selection
    #>
    [System.IO.DirectoryInfo[]]$ProgramsPaths = @()
    do {
        [System.Reflection.Assembly]::LoadWithPartialName('System.windows.forms') | Out-Null
        [System.Windows.Forms.FolderBrowserDialog]$OBJ = New-Object -TypeName System.Windows.Forms.FolderBrowserDialog
        $OBJ.InitialDirectory = "$env:SystemDrive"
        $OBJ.Description = 'To stop selecting directories, press ESC or select Cancel.'
        $OBJ.ShowHiddenFiles = $true
        [System.Windows.Forms.Form]$Spawn = New-Object -TypeName System.Windows.Forms.Form -Property @{TopMost = $true }
        [System.String]$Show = $OBJ.ShowDialog($Spawn)
        If ($Show -eq 'OK') { $ProgramsPaths += $OBJ.SelectedPath }
        else { break }
    }
    while ($true)
    Return $ProgramsPaths.Count -ne 0 ? $ProgramsPaths : $null
}
Export-ModuleMember -Function 'Show-DirectoryPathPicker'
