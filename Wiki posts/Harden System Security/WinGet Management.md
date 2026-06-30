# WinGet Management | Harden System Security

The **WinGet Management** page in the Harden System Security app is a full Windows Package Manager workspace. It makes everyday app management much easier and more convenient. You can search for apps, view and manage the apps already installed on your device, work with app bundles, and manage app sources, all from one dedicated place inside the app. The goal of this page is to give you a simpler and more organized way to handle app-related tasks without needing to jump between different tools, settings or command line.

It also brings a smoother and more polished experience overall, with clearer progress updates, better status messages, easier cancellation when something is taking too long, and more helpful feedback when an app action cannot be completed. App bundles make it faster to set up or remove groups of apps together, while the improved installed apps and search experience helps you find what you need more quickly.

You do not need to use search engine or websites anymore to find the apps you want to install. You can also find and install fonts on your system in this new page. Give it a try and if you have any feedback, please don't hesitate sharing it with me on [GitHub](https://github.com/HotCakeX/Harden-Windows-Security/discussions).

## What This Page Covers

The WinGet Management page is split into 4 functional views:

1. **Search Packages** - search configured WinGet catalogs and act on package results.
2. **Installed Programs** - load installed packages, identify updates, repair or uninstall apps, and export inventory.
3. **App Bundles** - install or uninstall curated groups of related applications from a visual bundle view.
4. **Sources** - add, refresh, remove, and inspect WinGet package catalogs. This section is available when the app is running elevated.

A settings pane is also available from the page toolbar. It shows the active WinGet engine version and lets you choose or reset the download directory used for package downloads, among other options.

## Search Packages View

The **Search Packages** view is for finding packages from the configured WinGet sources and performing package operations directly from the results list.

### Main Capabilities

- Search for packages by query text.
- Choose the search field:
  - Catalog default
  - Package ID
  - Name
  - Moniker
  - Tag
  - Command
- Choose the source to search.
- Choose the match mode:
  - Contains, case-insensitive
  - Equals, case-insensitive
  - Equals, case-sensitive
- Set the search result limit from 1 to 100.
- Cancel an active search.
- Clear the current results.
- Export search results to JSON.
- Select all or deselect all search results.
- Run bulk actions against selected search results.

Use this section when you know what you want to install, when you want to compare package metadata before installation, or when you need to download installers for later use.

### Result Cards

Each result appears as a package card with the package name, ID, description, version, installed version, update status, source, and expandable package details. The details area can include publisher, match information, installation status checks, installer elevation requirement, installer architecture, installer type, nested installer type, installer scope, installer locale, installed location, uninstall commands, package family names, product codes, tags, documentation URLs, icon URLs, license information, privacy URL, publisher URLs, package URL, purchase URL, release notes, and release notes URL.

A copy button is available on each detail item so long metadata values can be copied without selecting the text manually.

### Per-Package Actions

The package options menu provides direct actions for each search result:

- **Install**, **Update**, or **Reinstall**, depending on the package state.
- Install or update silently.
- Install or update interactively.
- Choose current-user scope or system scope where supported.
- Download the package installer to the configured download directory.
- Refresh the package status.
- Show installation notes when the package exposes them.
- Cancel the current package operation when cancellation is available.

System-scope actions are only enabled when Harden System Security is running elevated.

### Bulk Actions

The search results toolbar includes bulk actions for selected packages:

- Install or update selected packages.
- Install or update selected packages silently or interactively.
- Choose current-user or system scope for selected package actions where supported.
- Download selected packages.
- Refresh the status of selected packages.

This is useful for building a new system, preparing multiple application installers, or updating a set of tools without repeating the same action one package at a time.

## Installed Programs View

The **Installed Programs** view loads the local WinGet installed package catalog and presents installed applications in the same rich package-card layout used by search results.

### Main Capabilities

- Refresh the installed program inventory.
- Search the loaded installed programs list.
- Show only installed programs with available updates.
- Export the installed program inventory to JSON.
- Cancel an active installed-program query.
- Select all or deselect all installed programs.
- Run bulk actions against selected installed programs.

Use this section when you want an actionable software inventory, when you need to update installed applications, or when you want to remove or repair packages managed through WinGet.

### Per-Program Actions

Each installed program card includes a package options menu with actions such as:

- Update or reinstall the app.
- Download the package installer.
- Repair the app when a repairer is available.
- Uninstall the app.
- Use silent or interactive modes for install, update, reinstall, and uninstall operations.
- Choose current-user or system scope where supported.
- Refresh package status.
- Show installation notes when available.
- Cancel the current package operation when cancellation is available.

### Bulk Actions

For selected installed programs, the toolbar can:

- Update or reinstall selected apps.
- Download selected installers.
- Repair selected apps.
- Uninstall selected apps.
- Refresh selected package statuses.

The updates-only toggle is useful when you want to quickly focus on packages where maintenance is needed.

## App Bundles View

The **App Bundles** view provides curated groups of applications as visual bundle tiles. Selecting a bundle opens an animated overlay that shows the individual apps inside the bundle and provides bundle-level actions.

### Main Capabilities

- Browse available app bundles as visual tiles.
- Open a bundle to review the apps included in it.
- Install all apps in the selected bundle.
- Uninstall all apps in the selected bundle.
- Cancel a running bundle operation.
- Run actions against individual apps inside the selected bundle.

Use this section when you want to quickly deploy or remove a known set of related applications, such as a productivity set, developer tools set, gaming essentials set, or other curated software collection.

### Bundle-Level Actions

From the selected bundle overlay, you can:

- Install all bundle apps.
- Install all bundle apps silently or interactively.
- Choose current-user or system scope where supported.
- Uninstall all bundle apps.
- Uninstall all bundle apps silently or interactively.
- Cancel the active bundle operation.

### Per-App Bundle Actions

Each app inside the bundle has its own actions menu:

- Install or update the app.
- Uninstall the app.
- Choose silent or interactive mode.
- Choose current-user or system scope where supported.

This gives you both one-click bundle workflows and precise control over individual apps in the bundle.

## Sources View

The **Sources** view manages WinGet package catalogs. It is intended for source administration and is only enabled when the app is running elevated.

### Main Capabilities

- View configured WinGet sources.
- Add a new source by name, URI, type, and trust level.
- Refresh the source list.
- Update selected sources.
- Remove selected sources.
- Select all or deselect all sources.
- Cancel active source operations when cancellation is available.

Each source card displays the source name, type, argument or URI, origin, trust level, status, and source-level action buttons.

### Adding a Source

To add a source, provide:

- **Name** - the source name used by WinGet.
- **Argument** - the source URI or argument.
- **Type** - the catalog type. If no type is provided by the implementation, the default package catalog type is used.
- **Trust level** - the trust level used when registering the source.

After the source is added, refresh the source list to review the updated catalog configuration.

### Source Actions

For each configured source, you can:

- Update the source catalog.
- Remove the source.
- Cancel a running source operation.
- Review operation status text.

Bulk source actions are available for updating or removing multiple selected sources.

## Settings Pane

The settings pane is opened from the page toolbar and applies to the WinGet Management page as a whole.

### Main Capabilities

- View the WinGet engine version.
- Review the resolved download directory.
- Browse for a different package download directory.
- Reset the download directory back to the default.

Downloaded packages use this configured directory when the package download action is selected from search results or installed program cards.

## Operation Progress and Cancellation

WinGet Management is built around long-running operations that may involve network access, package catalogs, installers, uninstallers, repairers, or source refreshes. The page exposes operation status through progress rings, progress bars, status text, enabled or disabled action states, and cancel buttons where cancellation is supported.

## Exported JSON Workflows

The page supports JSON export for:

- Search results.
- Installed program inventory.

This is helpful when you want to save a package discovery session, keep an inventory snapshot, compare app state between systems, or share results for troubleshooting.

## Reliability and Safety Notes

- Package operations use the official Windows Package Manager APIs instead of shelling out to external commands.
- Package and source agreements are accepted through the Windows Package Manager API where required for catalog access or package actions.
- The app surfaces friendly error messages for common install failures.
- No-applicable-installer and no-applicable-repairer cases are handled explicitly so the user can distinguish unsupported package actions from generic failures.
- System-scope actions and source management require elevation where the UI exposes those capabilities.
- Long-running package, bundle, search, installed-program, and source operations can be canceled when cancellation is available.

## Typical Use Cases

WinGet Management is especially useful when you need to:

- Search packages from configured WinGet sources.
- Install, update, reinstall, download, repair, or uninstall apps from one interface.
- Bulk install or update selected applications.
- Export search results or installed-app inventory to JSON.
- Focus only on installed apps with available updates.
- Download installers into a configured folder.
- Manage WinGet package sources without using a command-line workflow.
- Deploy or remove curated app bundles.
- Review package metadata, installer details, URLs, uninstall commands, product codes, package family names, and installation notes before acting.

## Closing Notes

The WinGet Management page is designed to make Windows Package Manager operational inside Harden System Security: discover packages, inspect metadata, perform single or bulk actions, manage installed software, work with curated app bundles, administer sources, and keep visibility into progress, cancellation, and errors throughout the process.
