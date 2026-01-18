# Merge App Control Policies

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/AppControl%20Manager%20page%20screenshots/Merge%20App%20Control%20Policies.png" alt="AppControl Manager Application's Merge App Control Policies Page">

</div>

<br>

<br>

Use the Merge page in the [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) to combine multiple App Control policies into a single, unified policy. This is especially useful when you want to consolidate multiple policies into one. During the merge process, duplicate rules are automatically removed. You can even select the same policy as both the main source and the merge source to eliminate duplicate rules within a single policy.

Additionally, this feature generates unique IDs for each entry in the policy, utilizing GUID [version 7](https://www.rfc-editor.org/rfc/rfc9562.html#name-uuid-version-7) for maximum uniqueness. Keep in mind that the length of the IDs do not affect the generated CIP file's size.

<br>

## Configuration Details

* **Merge**: This button will begin the merge operation.

* **Deploy**: When this toggle button is toggled, the merge operation will deploy the main policy at the end.

* **Select Main Policy**: Use this section to select a single App Control XML file. This file will serve as the main policy to which other policies will be merged. If the deploy toggle is enabled, this same policy will be deployed to the system. All rule options, settings, and PolicyIDs in the main policy will remain unchanged.

* **Select other policies**: Use this section to browse for one or more App Control XML files. They will be merged with the main policy.

<br>

---

## Advanced

This is a place where you can customize your App Control policies further, such as converting different policy types to App ID Tagging type or removing different signing scenarios from policies in a context-aware fashion that won't leave any associated orphan rules.

### Convert Policies to App ID Tagging

Here you can select App Control policies in order to convert them to App ID Tagging policy type. Any rule options in them that is not supported for an App ID Tagging policy will be removed, as well as the entire Kernel-mode Signing Scenario and its associated signers and rules.

A default `AppIDTag` element will also be added to the policy with `AppIDTaggingKey` as the key and `True` as the value of the tag.

### Signing Scenario Removal

Here you can select between User-mode and Kernel-mode Signing Scenarios to be removed from the App Control policies that you select. The removal is context-aware and any rules or signers associated with the selected signing scenario is also removed.

<br>
