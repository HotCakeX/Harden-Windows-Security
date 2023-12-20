Function Get-EventData {
    <#
    .SYNOPSIS
        A function that gets the live event data based on a template
    .PARAMETER Timeout
        The time to wait between each check for new events
    .PARAMETER EventViewerCustomViewXML
        The path to a custom view xml file from Event viewer
    .PARAMETER EventType
        The type of event to look for based on the custom views applied by the Harden Windows Security module
        At the moment it only supports Exploit protection events
    .INPUTS
        System.Int64
    .OUTPUTS
        System.Object[]
    .LINK
        https://github.com/HotCakeX/Harden-Windows-Security/wiki/Event-Viewer
    .EXAMPLE
        Get-EventData -EventType 'Exploit Protection' -EventViewerCustomViewXML 'C:\ProgramData\Microsoft\Event Viewer\Views\Hardening Script\Exploit Protection Events.xml'
    #>
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $false)]
        [System.Int64]$Timeout = 2,

        [parameter(Mandatory = $true)]
        [System.IO.FileInfo]$EventViewerCustomViewXML,

        [parameter(Mandatory = $false)]
        [ValidateSet('Exploit Protection')]
        [System.String]$EventType = 'Exploit Protection'
    )

    # Get the current time
    [System.DateTime]$LastEventTime = Get-Date

    # Load the XML content from the file
    $Xml = [System.Xml.XmlDocument](Get-Content -Path $EventViewerCustomViewXML)

    # Get the QueryList element using XPath
    [System.Xml.XmlLinkedNode]$QueryList = $Xml.SelectSingleNode('//QueryList')

    # Convert the QueryList element to a string
    [System.String]$QueryListString = $QueryList.OuterXml

    # Start an infinite loop
    while ($true) {

        # Get the events
        [System.Object[]]$Events = Get-WinEvent -FilterXml $QueryListString -Oldest | Sort-Object -Property TimeCreated -Descending

        # Check if there are any events
        if ($Events) {

            # Loop over the events
            foreach ($Event in $Events) {

                # Check if the event is newer than the last event
                if ($Event.TimeCreated -gt $LastEventTime) {

                    Write-Host "`n##################################################" -ForegroundColor Yellow

                    if ($EventType -eq 'Exploit Protection') {

                        # Get the time of the event
                        [System.DateTime]$Time = $Event.TimeCreated
                        Write-Host "Found new event at time $Time"
                        $LastEventTime = $Time

                        Write-Host "Message: $($Event.Message)`n" -ForegroundColor Cyan

                        # Convert the event to XML
                        $Xml = [System.Xml.XmlDocument]$Event.toxml()

                        # Loop over the data elements in the XML
                        $Xml.event.eventdata.data | ForEach-Object -Begin {
                            # Create an empty hash table
                            $DataHash = @{}
                        } -Process {
                            # Add a new entry to the hash table with the name and text value of the current data element
                            $DataHash[$_.name] = $_.'#text'
                        } -End {
                            # Convert the hash table to a custom object and output it
                            [pscustomobject]$DataHash
                        }
                    }
                    Write-Host '##################################################' -ForegroundColor Yellow
                }
            }
        }
        # Wait for the specified timeout
        Start-Sleep -Seconds $Timeout
    }
}
