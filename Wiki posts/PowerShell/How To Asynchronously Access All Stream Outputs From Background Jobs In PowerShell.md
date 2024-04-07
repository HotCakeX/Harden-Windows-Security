# How To Asynchronously Access All Stream Outputs From Background Jobs In PowerShell

In this article, we will learn how to asynchronously access all stream outputs from background jobs in PowerShell. We will use the `Start-Job` cmdlet to start a job for each animal in the list. We will then use the `Register-ObjectEvent` cmdlet to create an event subscriber for the job to automatically receive the job output for all streams and discard itself and the job. We will also use the `Unregister-Event` cmdlet to remove the event itself and the `Remove-Job` cmdlet to remove the event subscriber's job.

We will also properly communicate any terminating or non-terminating error that ocurred inside of each job to the console.

```powershell
[System.String[]]$JobNames = 'cat', 'dog', 'Zebra', 'kangaroo'

# Start a job for each animal in the list
foreach ($JobName in $JobNames) {

    $CurrentJob = Start-Job -Name "Animals $JobName" -ScriptBlock {
        Param ($JobNameInput)

        Start-Sleep -Seconds 2

        Write-Output -InputObject "Job started for $JobNameInput"

        # Simulate some real work
        Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 10)

        # Generate terminating error
        # Throw "Error message for $JobNameInput"

        # Generate Non-terminating error
        Write-Error -Message "Error message 1 for $JobNameInput"

        Write-Warning -Message "Warning message for $JobNameInput"
        Write-Debug -Message "Debug Message for $JobNameInput" -Debug
        Write-Verbose -Message "Verbose message for $JobNameInput" -Verbose
        Write-Error -Message "Error message 2 for $JobNameInput"
        Write-Output -InputObject "Output message for $JobNameInput"
        Write-Host -Object "Host message for $JobNameInput"
        Write-Information -MessageData "Information message for $JobNameInput"

    } -ArgumentList $JobName

    # Create an event subscriber for the job to automatically receive the job output for all streams and discard itself and the job
    Register-ObjectEvent -InputObject $CurrentJob -EventName StateChanged -Action {

        # Receive the Write-Output stream for success stream
        # Write-Host is needed to display the error message on the console
        # We need to use loop because all of the Write-Output messages are stored in the ChildJobs.Output property
        # And without a loop, they would all be written as a single string on in one line
        if ($null -ne $EventSubscriber.SourceObject.ChildJobs.Output) {
            $EventSubscriber.SourceObject.ChildJobs.Output | ForEach-Object -Process {
                Write-Host -Object $_
            }
        }

        # Check if a terminating error ocurred in the job
        if ($EventSubscriber.SourceObject.State -eq 'Failed') {
            Write-Host -Object "The Job $($EventSubscriber.SourceObject.Name) Failed" -ForegroundColor Red
        }

        # Receive the Terminating error stream - Write-Host is needed to display the error message on the console
        if ($null -ne $EventSubscriber.SourceObject.ChildJobs.JobStateInfo.Reason.Message) {
            $EventSubscriber.SourceObject.ChildJobs.JobStateInfo.Reason.Message | ForEach-Object -Process {
                Write-Host -Object $_ -ForegroundColor Red
            }
        }

        # Receive the Non-Terminating error stream - Write-Host is needed to display the error message on the console
        if ($null -ne $EventSubscriber.SourceObject.ChildJobs.Error) {
            $EventSubscriber.SourceObject.ChildJobs.Error | ForEach-Object -Process {
                Write-Host -Object $_ -ForegroundColor DarkRed
            }
        }

        # Receive the job output except for Wire-Output and error stream
        Receive-Job -Job $EventSubscriber.SourceObject

        # Unregister the event itself
        Unregister-Event -SourceIdentifier $EventSubscriber.SourceIdentifier -Force
        # Remove the event subscriber's job, it is the same as the event subscriber's SourceIdentifier
        Remove-Job -Name $EventSubscriber.SourceIdentifier -Force
        # Remove the input job initiated by Start-Job
        Remove-Job -Id $EventSubscriber.SourceObject.Id -Force

    } | Out-Null
}

# Get all of the jobs at the end to make sure there is no leftover
# Get-Job

# Make sure all of the event subscriptions have been properly removed at the end
# (Get-EventSubscriber).SourceIdentifier

# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_automatic_variables#eventsubscriber
# $EventSubscriber inside of the action block is the same as the following objects
# (Get-EventSubscriber)[0].SourceObject.ChildJobs.JobStateInfo.Reason.Message
# (Get-EventSubscriber).SourceObject.ChildJobs.output
```

<br>

## Note About Why We Needed To Access ChildJobs Property

when you use `Start-Job` to initiate a background job, it executes the provided script block in a separate, child job. This is because `Start-Job` is designed to run tasks asynchronously, allowing the main PowerShell session to continue without waiting for the task to complete.

The child job is essentially a separate PowerShell process that runs in the background. It's isolated from the parent job, which means it has its own scope and doesn't share variables or RunSpaces with the parent. This isolation ensures that the main session remains responsive and that the background task doesn't interfere with the ongoing tasks in the main session.

<br>
