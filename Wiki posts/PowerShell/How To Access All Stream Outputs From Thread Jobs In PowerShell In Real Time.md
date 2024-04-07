# How To Access All Stream Outputs From Thread Jobs In PowerShell In Real Time

The following code snippet demonstrates how to access all stream outputs from thread jobs in PowerShell in real time. It uses the `Start-ThreadJob` cmdlet to start the thread jobs and the `Receive-Job` cmdlet to access the job output streams. The code snippet also demonstrates how to access the warning, debug, verbose, output, host, and information streams from the thread jobs.

It is properly commented to explain each part of the code.

```powershell
[System.String[]]$JobNames = 'cat', 'dog', 'Zebra', 'kangaroo'

# A hashtable to store the jobs
[System.Collections.Hashtable]$Jobs = @{}

# Start a job for each animal in the list
foreach ($JobName in $JobNames) {

    [System.Management.Automation.Job2]$CurrentJob = Start-ThreadJob -Name "Animals $JobName" -ScriptBlock {
        Param ($JobNameInput)
        #   $ErrorActionPreference = 'Stop'

        Write-Output -InputObject "Job started for $JobNameInput"

        # Simulate some real work
        Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 10)

        Throw 1 / 0

        Write-Error -Message "Error message for $JobNameInput"

        Write-Warning -Message "Warning message for $JobNameInput"
        Write-Debug -Message "Debug Message for $JobNameInput" -Debug
        Write-Verbose -Message "Verbose message for $JobNameInput" -Verbose
        Write-Output -InputObject "Output message for $JobNameInput"
        Write-Host -Object "Host message for $JobNameInput"
        Write-Information -MessageData "Information message for $JobNameInput"

    } -ArgumentList $JobName

    # Add the job to the hashtable with the job object as the key and its name as the value
    $Jobs[$CurrentJob] = $JobName
}

# Continuously check for job output
while ($Jobs.Count -ne 0) {

    # An array of the jobs to remove
    [System.Management.Automation.Job2[]]$JobsToRemove = @()

    foreach ($Job in $Jobs.Keys) {

        # Accessing individual output streams from the job that Receive-Job does not display
        # $Job.Warning - not required - Receive-Job shows it
        $Job.Debug
        $Job.Progress
        # $Job.Error - not required - Receive-Job shows it
        $Job.Information # Also displays the Write-Host message

        # Gets the success, error, warning and host stream from Write-Host
        Receive-Job -Job $Job

        if ($Job.State -eq 'Completed' -or $Job.State -eq 'Failed') {

            #  if ($Job.State -eq 'Failed') {
            #      Write-Output "Job $($Job.Id) failed with reason: $($Job.JobStateInfo.Reason)"
            #  }

            # Remove the job
            Remove-Job -Job $Job -Force

            # Add the job to the list of jobs to remove
            $JobsToRemove += $Job
        }
    }

    # Remove the jobs from the hashtable
    foreach ($Job in $JobsToRemove) {
        $Jobs.Remove($Job)
    }

    # Define the interval for checking the jobs
    Start-Sleep -Milliseconds 500
}

# Getting all of the jobs to make sure nothing is left
Get-Job
```

<br>

## Highly recommended to read the following related articles:

* [about_Output_Streams](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_output_streams)
* [Start-ThreadJob](https://learn.microsoft.com/en-us/powershell/module/threadjob/start-threadjob)

<br>
