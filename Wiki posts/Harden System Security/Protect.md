# Protect

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/8de8501da8c40b634b193ceec6a42013d74836ec/Pictures/APNGs/Harden%20System%20Security/ProtectPage.apng" alt="Protect Page Demo of the Harden System Security App" />

</div>

<br>

The Protect page in the [Harden System Security App](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden-System-Security) is a central hub for Applying, Verifying or Removing the security measures. It offers presets with optimal pre-selected categories and sub-categories to streamline the hardening process.

Each Security Measure category on this page has its own dedicated page where you can view and modify the specific settings related to that category in a more detailed manner. When you use the Apply, Verify or Remove buttons on this page, it is as if you are directly interacting with the button on that category's page.

<br>

## Device Usage Intents

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/657a3c356665065f2a320fc88ca17a8d08345625/Pictures/Gifs/HardenSystemSecurity-DeviceIntentsDemo.gif" alt="Device Intents demo Harden System Security App"/>

</div>

<br>

Harden and secure your devices according to how you use them. Device Usage Intents work like the OS's Out-of-Box Experience (OOBE): during initial Windows setup you're asked how you'll use the device. Intents provide an easy, complementary way (in addition to the existing Presets) to configure your entire system. The currently available Device Usage Intents are:

* **Development:** Built for writing and testing software. Uses secure defaults while allowing common developer tools and local builds without unnecessary restrictions.

* **Gaming:** Tuned for performance and compatibility with games. Keeps essential protections while avoiding settings that can impact gameplay.

* **School:** Suitable for students, keeps compatibility with learning apps, avoids heavy enterprise controls.

* **Business:** Everyday corporate device with strong protections for work data and accounts. Balanced for productivity with sensible access, logging, and update behavior.

* **Specialized Access Workstation:** The Specialized security user demands a more controlled environment while still being able to do activities such as email and web browsing in a simple-to-use experience.

* **Privileged Access Workstation:** This is the highest security configuration designed for extremely sensitive roles that would have a significant or material impact on the organization if their account was compromised.

<br>

Each security measure in their own dedicated page is also annotated with device usage intent badges so you can easily tell which security measure belongs to which device usage intent.

<div align="center">

![HSS Small Intents Demo](https://github.com/user-attachments/assets/28d1363c-0911-47f8-bc28-516579eeec91)

</div>

<br>

> [!NOTE]\
> When the Microsoft Security Baselines or Microsoft 365 Security Baselines are selected in the Protect page, either via Presets or Device Intents, they will be applied first among the selected categories. Similarly, if the Overrides for Microsoft Security Baselines category is among the selected categories, it will be applied last. Any other categories that are selected will be applied between these priority groups. This type of prioritization ensures complete and proper application of the security measures.

<br>

The preview **ListView** lets you remove individual security measures before pressing **Apply**, giving you finer control over what gets applied. Items can be deleted in two ways:

   * Right-click (or Tap + Hold) a row and choose the delete option.

   * Swipe left on touch devices — a smooth animation and deletion motion will remove the item from the ListView.

<br>

![HardenSystemSecurity_FIWig6IIer](https://github.com/user-attachments/assets/fae592a3-3473-4d92-b11f-911094f162c9)

<br>
