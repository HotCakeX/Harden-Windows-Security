# Compare Policies

<div align="center">

<img src="https://github.com/HotCakeX/.github/blob/main/Pictures/PNG%20and%20JPG/AppControl%20Manager%20page%20screenshots/Compare%20Policies.png?raw=true" alt="Compare Policies page screenshot" />

</div>

<br>

Use [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) to compare two App Control policies side by side. This page builds an inventory of important policy elements, shows the number of items found in each policy, highlights count differences, lets you preview the exact items in each section, and exports the full comparison result to a JSON file.

This page is useful when you want to validate policy changes, compare a new policy against a known baseline, inspect what was added or removed, or review the structure of two policies before deployment.

## How It Works

1. Select the first App Control policy, either from a file or from the Sidebar's policies library.
2. Select the second App Control policy the same way.
3. Press **Compare** to build a policy inventory for both files.
4. Select any section in the **Policy inventory** pane to preview the items in that section.
5. Use the **First** and **Second** number chips on each inventory card to show or hide that policy's items in the preview.
6. Optionally sort the preview or export the results to JSON.

## Policy Inventory

After running a comparison, the left side of the page displays a **Policy inventory** list. Each inventory card represents a policy element group and includes:

* **Section name**: The policy element group being compared.
* **Description**: A short explanation of what the section contains.
* **Delta**: Shows whether both policies have the same number of items or whether one policy has more items than the other.
* **First count**: The number of items from the first policy in that section.
* **Second count**: The number of items from the second policy in that section.

Selecting a section automatically enables both policy chips for that section and loads its items into the preview pane.

### Compared Inventory Sections

The page compares the following policy element groups:

* **EKUs**: Unique EKU definitions available for signers.
* **All file rules**: All Allow, Deny, FileAttrib, and generic FileRule elements.
* **Allow rules**: Direct allow file rules in the FileRules section.
* **Deny rules**: Direct deny file rules in the FileRules section.
* **File attributes**: File publisher attributes referenced by signers.
* **Generic FileRule elements**: Schema FileRule elements with Match, Exclude, or Attribute type.
* **Signers**: Signer definitions in the Signers section.
* **CI signers**: Signers trusted for CI policy signing semantics.
* **Update policy signers**: Signers authorized to update the policy.
* **Supplemental policy signers**: Signers authorized for supplemental policies.
* **Signing scenarios**: Total signing scenarios in the policy.
* **User mode allowed signers**: Allowed signer references in signing scenario value `12`.
* **User mode denied signers**: Denied signer references in signing scenario value `12`.
* **User mode file rule refs**: File rule references in signing scenario value `12`.
* **Kernel mode allowed signers**: Allowed signer references in signing scenario value `131`.
* **Kernel mode denied signers**: Denied signer references in signing scenario value `131`.
* **Kernel mode file rule refs**: File rule references in signing scenario value `131`.
* **Settings**: All settings in the Settings section.
* **Macros**: Macro definitions used by file rules and settings.
* **App settings**: Application settings under AppSettings.
* **AppID tags**: AppID tags across signing scenarios.

## Preview Pane

The right side of the page displays a preview of the selected inventory section. Each preview item can show:

* **First policy label**: Indicates the item exists in the first policy.
* **Second policy label**: Indicates the item exists in the second policy.
* **Title**: A readable name for the item, such as a signer name, file rule name, setting name, or AppID tag.
* **Shared details**: Properties that exist in both policies and have the same values.
* **Different details**: Properties that exist in both policies but have different values.
* **Raw details**: Used when an item does not have shared or different property summaries available.

When an item exists in both policies, both policy labels are displayed. When it only exists in one policy, only that policy's label is displayed.

## Filtering the Preview by Policy

Each inventory card includes two number chips:

* **First**: Shows or hides items from the first policy for that section.
* **Second**: Shows or hides items from the second policy for that section.

This lets you quickly inspect:

* Items that are present in both policies.
* Items that only exist in the first policy.
* Items that only exist in the second policy.
* The full combined inventory for a section.

If both chips are disabled, the preview will show that no policy source is enabled for the selected section.

## Sorting the Preview

Use the preview sort drop down and the **Sort** button to change how preview items are ordered.

Available sort modes:

* **Both**: Items that exist in both policies are shown first, followed by items only in the first policy, then items only in the second policy.
* **First Policy**: Items unique to the first policy are prioritized first, followed by items also in the first policy, then the remaining items.
* **Second Policy**: Items unique to the second policy are prioritized first, followed by items also in the second policy, then the remaining items.

Within each sort group, items are sorted alphabetically by title.

## JSON Export

After running a comparison, you can use **Export to JSON** to save the full comparison result. The export includes:

* **SchemaVersion**: The export schema version.
* **ExportedAtUtc**: The UTC time when the export was created.
* **FirstPolicyName**: The identifier of the first selected policy.
* **SecondPolicyName**: The identifier of the second selected policy.
* **FirstPolicyPath**: The file path of the first selected policy (if available).
* **SecondPolicyPath**: The file path of the second selected policy (if available).
* **Inventory**: A summary of all compared sections, including counts and deltas.
* **Sections**: Detailed preview items for each compared section.

This makes the exported file suitable for reporting, auditing, troubleshooting, and reviewing policy changes.

## Validation and Empty States

* If you press **Compare** without selecting both policies, the page displays a warning asking you to select both policies.
* If you press **Export to JSON** before running a comparison, the page displays a warning asking you to run a comparison first.
