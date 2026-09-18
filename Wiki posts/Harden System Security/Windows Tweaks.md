## Windows Tweaks

The **Windows Tweaks** page brings together privacy cleanup tools and system diagnostics in one place. Use the **Cleanup** section to review and remove selected traces of previous activity, or open **Diagnostics** to troubleshoot networking, manage storage-health updates, and inspect or control the Windows Recovery Environment.

> [!NOTE]
> The Diagnostics section requires the app to be running with administrator privileges.

> [!TIP]
> Many other new features and tweaks are on the way, so keep an eye on this page and future release notes for updates.

## Cleanup

The Cleanup section is designed around a review-first workflow. Select **Check** to find applicable data, open **Review detected data** to inspect what was found, and then select **Clear** or **Remove** when you are ready. Status messages report whether the operation completed successfully, found nothing to remove, or encountered items that could not be processed.

### NuGet Package Cache Cleaner

Free up disk space by finding older NuGet package versions that your development environment no longer needs. Close your .NET projects first, then review the detected folders before removing them.

The cleaner inspects the configured `NUGET_PACKAGES` directory, or the default per-user NuGet package cache when no custom location is configured. It recognizes package version folders, keeps the highest recognized version of each package, and lists older versions as removal candidates. The review also reports their combined size.

### PowerShell Command History Cleaner

Keep your command-line activity to yourself by reviewing and clearing commands you previously entered in PowerShell consoles and the Visual Studio Code terminal. This removes the saved command histories.

The check covers the standard PSReadLine history files for the PowerShell console host and the Visual Studio Code host. You can review the collected command text before clearing it.

### Run History Cleaner

Give the Windows Run dialog a fresh start by reviewing and clearing commands you previously entered. This prevents old commands from continuing to appear as suggestions when you use Run again.

### File Explorer Typed-Path History

Leave previously visited paths behind by reviewing and clearing entries from the File Explorer address bar. This removes saved path suggestions without deleting any files or folders.

### File Explorer Search-Box History

Start with a clean search slate by reviewing and clearing terms you previously entered in File Explorer. This removes saved search suggestions without affecting your files or Windows Search index. Search terms are decoded and displayed for review before removal.

### Recent Items Shortcuts

Clean up your Recent Items list and reduce traces of recently opened content by reviewing and removing its saved shortcuts. Your original files remain untouched.

This tool checks the current user's Recent Items folder for top-level shortcut files. It removes only those shortcuts, not the files or folders to which they point.

### Common Open/Save Dialog History

Stop Open and Save dialogs from retracing your steps by reviewing and clearing the file and folder locations they remember. This reduces previously visited locations shown by compatible apps without deleting your files.

The cleaner examines the history maintained by common Windows Open and Save dialogs, including remembered application and file-system locations.

### RecentDocs History

Clear the trail of document names remembered by File Explorer by reviewing and removing its RecentDocs history. This removes history records only and does not delete your documents.

The check searches both the main RecentDocs history and its category-specific items. It displays the document names that can be decoded safely, removes only those selected records, and updates the corresponding recent-use metadata.

### Jump List History

Reset your Jump Lists by reviewing and clearing the data that stores recently used and pinned items for supported apps. Use this when you want a cleaner Start menu and taskbar history.

The cleaner checks the current user's Automatic Destinations and Custom Destinations data folders. The review displays the exact Jump List data files that will be removed.

<br>

## Diagnostics

The Diagnostics section provides focused maintenance actions and system controls. Each operation displays progress and completion information in its associated status bar.

### Clear DNS Client Cache

Clears the DNS resolver cache so that name lookups are resolved again instead of being answered from cached records.

Use this after DNS records have changed, when a hostname continues to resolve to an outdated address, or while troubleshooting name-resolution problems. Clearing the cache does not change your configured DNS servers or network adapter settings.

### Reset IPv4 Addresses

Reset the IPv4 of every active DHCP-enabled network adapter by releasing and then renewing it. Network and VPN connectivity may be briefly interrupted.

The operation targets active, non-loopback IPv4 adapters that use DHCP and currently have a unicast address. Results identify the adapters that completed successfully and report release, renewal, or adapter-matching failures individually. Adapters using static IPv4 configuration are not changed.

### Reset System HTTP Proxy

Clears WinHTTP automatic proxy information, WPAD state, and cached proxy scripts for all networks.

Use this when system services or applications that rely on WinHTTP continue using stale automatic proxy information. This reset is aimed at WinHTTP automatic proxy discovery and caching.

### Disk Health Model Updates

Allows Windows to download updated machine learning model parameters used to predict storage disk failure. The toggle manages the machine-level policy for disk health model updates.

### Windows Recovery Environment

Enables or disables Windows Recovery Environment and displays its current configuration.

When you open Diagnostics, the page retrieves the current Windows RE configuration and synchronizes the toggle with the actual system state. The status area displays available details including:

- Windows RE image version
- Windows RE image location
- Boot Configuration Data identifier
- Scheduled recovery operation
- Automatic repair status
- Windows RE image hash

> [!WARNING]
> Windows Recovery Environment provides recovery and repair capabilities that can be important when Windows cannot start normally. Disable it only when you understand the effect on your recovery options.
