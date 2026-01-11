# Create Policy From Event Logs

![AppControl Manager Application's Create Policy From Event Logs Page](https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/AppControl%20Manager%20page%20screenshots/Create%20policy%20from%20event%20logs.png)

This page in [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) allows you to create Application Control policies directly from local event logs or EVTX files. It focuses on processing Code Integrity and AppLocker event logs to help build tailored policies.

This page offers a data grid that has search functionality, sorting, removal of individual logs and copying entire rows or each cell to the clipboard.

### Supported Event Types

Only the following [event types](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations) are processed because they are the only ones that provide sufficient detail about applications allowed or blocked by Code Integrity or AppLocker to reliably generate supplemental policies.

- **Code Integrity**:

  - **Event ID `3076`:** This event is the main App Control block event for audit mode policies. It indicates that the file would have been blocked if the policy was enforced.

  - **Event ID `3077`:** This event is the main App Control block event for enforced policies. It indicates that the file didn't pass your policy and was blocked.

  - **Event ID `3089`:** This event contains signature information for files that were blocked or audit blocked by App Control. One of these events is created for each signature of a file.

- **AppLocker**:

  - **Event ID `8028`:** This event indicates that a script host, such as PowerShell, queried App Control about a file the script host was about to run. Since the policy was in audit mode, the script or MSI file should have run, but wouldn't have passed the App Control policy if it was enforced.

  - **Event ID `8029`:** This event is the enforcement mode equivalent of event 8028. Note: While this event says that a script was blocked, the script hosts control the actual script enforcement behavior.

  - **Event ID `8038`:** Signing information event correlated with either an 8028 or 8029 event. One 8038 event is generated for each signature of a script file. Contains the total number of signatures on a script file and an index as to which signature it is.

## Configuration Details

- **Scan Event Logs**: Click this button to initiate a scan of the system for relevant Code Integrity and AppLocker events and display them in the page.

- **Browse for EVTX**: Use this option to browse for Code Integrity and/or AppLocker exported EVTX log files. When EVTX log files are selected, pressing the **Scan Logs** button will scan those instead of the system logs.

- **Create Policy -> Add to policy**: Use this option to select an existing Application Control XML policy file. The events you choose will be added directly to this file, expanding its coverage.

- **Create Policy -> Base policy file**: This option allows you to specify a base XML policy file. The supplemental policy generated from the event logs will be linked to this base policy.

- **Create Policy -> Base GUID**: Enter the GUID of an existing base policy here. The supplemental policy created from the event logs will be associated with this specified GUID.

- **Policy Name**: Enter the name of the policy that will be created from the event logs.

- **Filters logs by date**: Use the calendar to filter the logs based on date they were generated.

- **Deploy policy after creation**: Use this toggle button to tell the application that you want to deploy the policy after creation.

- **Scan Level**: You can choose from different scan levels. [Refer to this page for all the information about them.](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Rule-Levels-Comparison-and-Guide)

- **Only Use Selected Items**: If this button is toggled, only the items in the List View that are highlighted will be added to the Supplemental policy. If this button is not toggled, then everything available in the List View will be added to the Supplemental policy.

- **Export to JSON File**: Use this button to export all of the processed event log entries to a JSON file.

- **Actions -> Deploy after Creation**: Toggle this button if you want to deploy the supplemental policy immediately after it is created.

- **Actions -> Clear Data**: Use this button to clear all of the data that have been processed and displayed.

- **Actions -> Clear System Logs**: Use this button to clear the entire Code Integrity or AppLocker event logs from the system. Keep in mind that this action is irreversible and there will be an additional prompt that needs confirmation before proceeding.
