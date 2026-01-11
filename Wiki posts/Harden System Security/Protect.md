# Protect

The Protect page in the [Harden System Security App](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden-System-Security) is a central hub for Applying, Verifying or Removing the security measures. It offers presets with optimal pre-selected categories and sub-categories to streamline the hardening process.

Each Security Measure category on this page has its own dedicated page where you can view and modify the specific settings related to that category in a more detailed manner. When you use the Apply, Verify or Remove buttons on this page, it is as if you are directly interacting with the button on that category's page.

## Device Usage Intents

Harden and secure your devices according to how you use them. Device Usage Intents work like the OS's Out-of-Box Experience (OOBE): during initial Windows setup you're asked how you'll use the device. Intents provide an easy, complementary way (in addition to the existing Presets) to configure your entire system. The currently available Device Usage Intents are:

- **Development:** Built for writing and testing software. Uses secure defaults while allowing common developer tools and local builds without unnecessary restrictions.

- **Gaming:** Tuned for performance and compatibility with games. Keeps essential protections while avoiding settings that can impact gameplay.

- **School:** Suitable for students, keeps compatibility with learning apps, avoids heavy enterprise controls.

- **Business:** Everyday corporate device with strong protections for work data and accounts. Balanced for productivity with sensible access, logging, and update behavior.

- **Specialized Access Workstation:** The Specialized security user demands a more controlled environment while still being able to do activities such as email and web browsing in a simple-to-use experience.

- **Privileged Access Workstation:** This is the highest security configuration designed for extremely sensitive roles that would have a significant or material impact on the organization if their account was compromised.

Each security measure in their own dedicated page is also annotated with device usage intent badges so you can easily tell which security measure belongs to which device usage intent.

> [!NOTE]
> When the Microsoft Security Baselines or Microsoft 365 Security Baselines are selected in the Protect page, either via Presets or Device Intents, they will be applied first among the selected categories. Similarly, if the Overrides for Microsoft Security Baselines category is among the selected categories, it will be applied last. Any other categories that are selected will be applied between these priority groups. This type of prioritization ensures complete and proper application of the security measures.

The preview **ListView** lets you remove individual security measures before pressing **Apply**, giving you finer control over what gets applied. Items can be deleted in two ways:

- Right-click (or Tap + Hold) a row and choose the delete option.

- Swipe left on touch devices — a smooth animation and deletion motion will remove the item from the ListView.

![HardenSystemSecurity_FIWig6IIer](https://github.com/user-attachments/assets/fae592a3-3473-4d92-b11f-911094f162c9)

## Backup and Restore System State

The Harden System Security app now provides comprehensive system report generation capabilities, allowing users to gain deeper insights into their system's security status and save the results to a file for further analysis. All of the security categories participate in this report, including Microsoft Security baselines and Microsoft 365 apps security baselines.

The name of the device, user account and time is also mentioned in the report header so you can easily identify when and where the report was generated.

The report provides a security score, the exact number of items in each category and the total number of compliant and non-compliant items.

After you generate a system report, whether it's a full system report that includes all categories or only contains 1 category, you can import and apply it to any system where Harden System Security app is installed.

### There are 2 modes of application: Partial and Full

- In partial mode, only items marked as `Applied` in the report will be applied to the system.

- In full mode, the system will be fully synchronized according to the report, that means any security measure marked as `Applied` will be applied onto the system and any security measure marked as `Not Applied` will be removed from the system.

Let's say you've configured a system to your liking and it's in a compliant golden state, you can back up the categories you want or the entire system state to a JSON file and import it on as many workstations as you want.

**The great thing about all of this? You can totally automate it, thanks to the new CLI support. [Documentation for CLI usage available here](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden-System-Security#commandline-interface-cli-support).**
