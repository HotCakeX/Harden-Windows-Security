# Policy Editor

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/AppControl%20Manager%20page%20screenshots/Policy%20Editor.png" alt="AppControl Manager Application's Policy Editor Page">

</div>

<br>

<br>

Leverage the Policy Editor page to effortlessly refine your App Control policy files. With this tool, you can remove individual rules or clear all rules in one action, while accurately displaying the count of each rule type. Seamlessly search for the rule you wish to modify, and easily update policy details such as name, type, version, policy ID info, type ID, base policy ID, and HVCI option level.

Eliminate the need for error-prone, manual editing in a text editor. When you modify App Control policies with the Policy Editor, your policy remains fully compliant with the Code Integrity schema throughout the process.

This feature also deduplicates any redundant rules or signers within the policy file.

> [!TIP]\
> You can use this feature to convert CIP binary files, P7B files or BIN files back to XML too.

<br>

### Configuration Details

* **Browse for Policy**: Click this button to locate an App Control policy XML, CIP, BIN or P7B file. You can right-click or tap and hold on this button to preview the selected policy. You can also directly select a policy from the Policies Library on the Sidebar in order to be opened in the Policy Editor.

* **Load Policy**: Use this button to import the details of the chosen App Control policy into the user interface.

* **Save the Changes**: Click this button to commit any modifications back to the selected App Control policy. If the file you are working with is a `CIP` binary, BIN or P7B policy, then using this button will save it as XML file with the same name in the `AppControl Manager` directory in Program Files (if the app is running elevated), or it will save the XML in the same location as the CIP, BIN or P7B file (if the app is running with standard privilege).

* **Clear the Data**: Use this button to reset all data loaded in the interface as a consequence of loading the policy.

* **Text Selection**: Toggle this switch to enable or disable text selection within the List Views. When enabled, you can easily select and copy the text displayed in each cell.

* **Search the Data**: Enter a keyword in this text box to quickly locate the specific rule you wish to edit.

* **Diamond-shaped button**: Press this button to access additional information about the loaded policy, including the precise count of each rule type.

* **Policy Details Tab**: In this tab, review and update the policy’s details such as Name, Policy ID, Base Policy ID, Version, HVCI Level, Type, and Policy ID Info.

* **Signature-based Rules Tab**: This tab displays rules for the following levels: Publisher, PCA Certificate, Root Certificate, WHQL, WHQL Publisher, Leaf Certificate, Update Policy Signers, and Supplemental Policy Signers.

* **File-based Rules Tab**: Here, you will find rules for various types, including Allow and Deny rules (e.g., Hash, PackagedFamilyName, or File Name levels), File Rules, SignedVersion level, File Publisher level, and WHQL File Publisher level.

<br>

> [!TIP]\
> Please note that the IDs shown in the List Views do not correspond to the current IDs in the XML file. Instead, they represent the IDs that will be incorporated once you press the "Save the Changes" button.

<br>

> [!NOTE]\
> The Policy Editor organizes each rule for effortless adjustments. For instance, File Publisher or WHQL File Publisher rules are segmented into individual File Attributes. Removing all File Attributes at a specific level will automatically eliminate the associated Signer and any related elements, ensuring your App Control policy remains clean and precise. In essence, a WHQL File Publisher or File Publisher level without any File Attributes effectively reverts to a Publisher or WHQL Publisher.

<br>

## Custom Policy Settings

Use this section to view all of the Secure Settings in the selected policy or add new ones to it. You can also add new Secure Settings by picking one from the list of presets.

## Policy Details

Here you can modify the following details of the selected policy:

* **Policy Name**: the name of the selected App Control policy.

* **Policy ID**: the Policy ID of the selected App Control policy.

* **Base Policy ID**: the Base Policy ID of the selected App Control policy.

* **Policy Version**: the Version of the selected App Control policy.

* **Policy Type**: the Type of the selected App Control policy: `Base`, `Supplemental` or `AppIDTagging`.

* **Policy Info ID**: the Policy Info ID of the selected App Control policy.

* **HVCI Level**: the Hypervisor-Protected Code Integrity level of the selected App Control policy. The AppControl Manager always sets the value of this for the policies it creates to `Enabled - Strict` and it is recommended for it to stay that way for security reasons.

* **Policy Friendly Name**: the Friendly Name of the selected App Control policy.

### App ID Tags

In this section you can view all of the App ID Tags in the selected policy, remove them or add new ones by entering `Key` and `Value` and then pressing the **Add New Tag** button.

> [!IMPORTANT]\
> You need to use the `Save the Changes` button if you want the modifications you made to your policy in the Policy Editor to be saved back to the selected policy. If the selected policy originates from the Policies Library in the Sidebar, it will be saved back to the same entry in the Library.

<br>
