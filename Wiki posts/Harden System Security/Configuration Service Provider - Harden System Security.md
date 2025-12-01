# Configuration Service Provider | Harden System Security

This page allows you to inspect and query Windows Configuration Service Provider (CSP) policies. It parses Policy DDF (Device Description Framework) files that are either sourced from local XML files you browse for or downloaded directly from Microsoft's server to generate a comprehensive catalog of available system settings. The Harden System Security app interacts with the local MDM (Mobile Device Management) client to query the live system state of these policies via their OMA-URIs, providing real-time visibility into current configurations, default values, and allowed operations (`Get`, `Add`, `Replace`, `Delete`).

## User Interface Guide

* **Browse**: Use this button to browse for DDF files that come in the form of XML files.

* **Retrieve Data**: Use this button to process and retrieve CSP data from the system. If you've already browsed for DDF files on your local system, they will be used, otherwise, the app will download the latest DDF files directly from [Microsoft's server](https://learn.microsoft.com/en-us/windows/client-management/mdm/configuration-service-provider-ddf).

* **Clear Data**: Use this button to clear all loaded CSP data from the app as well as any DDF files downloaded from Microsoft's server and cached.

* **Total**: Displays the total number of CSP settings loaded. You can also click/tap on it to switch between all CSP data and only those that are currently applied to the system.

* **Export To JSON**: Use this button to export all of the displayed results to a JSON file as a backup.
