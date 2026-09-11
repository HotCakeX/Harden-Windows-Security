# Intune

<img src="https://raw.githubusercontent.com/HotCakeX/.github/38222c927722311f036585d2d2b2fbaa4aa84186/Pictures/Gifs/Intune%20Support%20Harden%20System%20Security.gif" alt="Microsoft Intune support in Harden System Security App" />

<br>

<br>

You can scale the security policies you trust locally to your entire fleet of Windows devices. The Harden System Security app introduces an Intune dashboard, allowing you to bridge the gap between local hardening and cloud management.

* Unified Policy Control: Instantly view your existing Device Configuration policies or push the hardened standards directly to the cloud.

* Complete Group Management: Effortlessly search, sort, add, remove, and export Entra groups without leaving the app.

* Streamlined Assignments: Deploy new policies and assign them to the right security groups in a single workflow.

## User Interface Guide

* **Microsoft Graph button**: This is the main entry point for interacting with your Microsoft tenant, whether it is to authenticate, add a new account, remove/sign out of an existing account or switch between different accounts.

* **Selected Groups**: This button shows the total count of the Entra groups you've selected. Pressing this button takes you to a dedicated page where you can list all available groups in your tenant and select which groups you want the policies you upload to be associated with.

* **Retrieve Intune Policies**: Use this button to retrieve all available device configurations from your tenant's Intune. You will see a detailed overview of all of them in the list view.

* **Policies List**: It lists security categories that the Harden System Security app offers. You can select the categories that you like and then use the `Deploy Selected Policies` button to deploy/upload them to your Intune.

* **Deploy Selected Policies**: Deploys the policies you select from the `Policies List` next to it.

## Deployed Policy Details

After retrieving the policies, you can click/tap on each of them to navigate to their details page. In this new page, you can:

* View all of the groups assigned to the policy and their types (inclusion or exclusion).

* Assign the `All Devices` or `All Users` virtual groups to the policy.

* Remove each assignment individually.

* Remove all assignments from the policy at once.

* View how many users are included in each assigned group.

* View how many devices are included in each assigned group which lets you view how many devices the policy applies to.
