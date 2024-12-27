# Merge App Control Policies

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/AppControl%20Manager%20page%20screenshots/Merge%20App%20Control%20Policies.png" alt="AppControl Manager Application's Merge App Control Policies Page">

</div>

<br>

<br>

Use the Merge page in the [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) to combine multiple App Control policies into a single, unified policy. This is especially useful when you want to consolidate multiple policies into one. During the merge process, duplicate rules are automatically removed. You can even select the same policy as both the main source and the merge source to eliminate duplicate rules within a single policy.

Additionally, this feature generates astronomically unique IDs for each entry in the policy XML file, utilizing double GUID [version 7](https://www.rfc-editor.org/rfc/rfc9562.html#name-uuid-version-7) for maximum uniqueness. Keep in mind that the length of the IDs do not affect the generated CIP file's size.

<br>

## Configuration Details

* **Merge**: This button will begin the merge operation.

* **Deploy**: When this toggle button is toggled, the merge operation will deploy the main policy at the end.

* **Select Main Policy**: Use this section to select a single App Control XML file. This file will serve as the main policy to which other policies will be merged. If the deploy toggle is enabled, this same policy will be deployed to the system. All rule options, settings, and PolicyIDs in the main policy will remain unchanged.

* **Select other policies**: Use this section to browse for one or more App Control XML files. They will be merged with the main policy.

<br>
