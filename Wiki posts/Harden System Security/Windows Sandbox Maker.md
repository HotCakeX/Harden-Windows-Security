# Sandbox Maker | Harden System Security

<div align="center"><img src="https://raw.githubusercontent.com/HotCakeX/.github/044eda32fad2c5707f2ba92297d074dd9a68196a/Pictures/PNG%20and%20JPG/Harden%20System%20Security%20page%20screenshots/Sandbox%20Maker.png" alt="Windows Sandbox Maker"></div>

<br>

The **Sandbox Maker** page in the [Harden System Security app](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden-System-Security) is a refined workspace for making, preserving, and launching Windows Sandbox environments. It brings identity, resource allocation, device-integration controls, time-zone tailoring, optional host-folder mapping, custom startup scripting, and saved-profile management into one coherent dashboard so you can prepare disposable environments with both precision and ease.

## What This Page Offers

The page is designed to support the full Sandbox lifecycle:

1. Define a named sandbox profile.
2. Choose a time zone for the guest environment.
3. Configure resource and redirection settings.
4. Optionally map a host folder and select its main executable.
5. Optionally provide custom PowerShell code to run when the sandbox starts.
6. Save the profile for future use.
7. Launch the sandbox immediately or start any previously saved profile later.

Each saved profile produces its own `.wsb` configuration file, while the saved definitions are preserved separately so they can be reloaded into the page whenever the app is opened again.

## Sandbox Identity

The opening section of the page establishes the sandbox's identity.

- **Sandbox Name** lets you assign a human-readable name to the profile.
- **Sandbox File Path** shows the precise `.wsb` path that will be used for that profile.

The chosen name is not merely decorative. It determines the saved profile identity and the generated `.wsb` file name, allowing multiple sandbox configurations to coexist elegantly rather than overwriting one another.

## Time Zone Selection

The **Time Zone** section lets you choose whether the sandbox should inherit the host time zone or switch to another supported region.

- The first option preserves the **sandbox default time zone**, which mirrors the host.
- Additional entries are arranged by UTC offset, from the most negative offset through UTC and onward to the most positive range.
- Each option presents both a region description and a concise offset label so selection remains intelligible at a glance.

When a non-default time zone is selected, the sandbox applies it automatically during startup to improve your anonymity in the guest OS.

## Sandbox Profile Controls

The **Sandbox Profile** area is the operational heart of the page. It combines memory selection with a modern grid of interactive option cards.

### Memory

- **Custom RAM (MB)** lets you specify how much memory the sandbox should receive.
- The app begins with a **4 GB default** and validates the final value so it remains within an acceptable range for the host system. The minimum is 2GB.

### Profile Option Cards

Each option is presented as a dedicated card with a short description, making the purpose of every control immediately legible.

Available options include:

- **Disable internet access** - disables sandbox networking to reduce exposure.
- **Enable vGPU** - allows GPU sharing; if disabled, software rendering is used instead.
- **Enable clipboard redirection** - shares clipboard content between host and sandbox.
- **Enable audio input** - exposes host microphone input to the sandbox.
- **Enable video input** - exposes host camera input to the sandbox.
- **Enable printer redirection** - makes host printers visible inside the sandbox.
- **Enable protected client mode** - runs the session with increased security by using AppContainer-backed isolation on the RDP session.

## Optional Mapped Program

The **Optional Mapped Program** section allows you to enrich the sandbox with a host folder and a chosen executable from within that folder.

### Host Folder Mapping

- Use **Browse** to select the folder on the host.
- Use **Clear** to remove the current selection.
- The selected host folder is mapped into the sandbox directly under `C:\` using the same folder name.

### Executable Selection

Once a folder is chosen, the page enumerates executable files within it and allows you to select the main executable from a drop-down list.

### Read-Only and Startup Behavior

Two additional toggles govern how the mapped program behaves:

- **Map the selected host folder as read-only** - prevents writes from within the sandbox.
- **Run the selected program automatically when the sandbox starts** - launches the selected executable during sandbox logon.

Even when automatic launch is not enabled, the page still prepares a desktop shortcut for the selected executable inside the sandbox, giving you a convenient entry point once the environment has started.

## Custom PowerShell Startup Code

The **Custom PowerShell startup code** section lets you attach your own PowerShell instructions to the sandbox startup process. This is useful for preparing the guest environment, creating files or folders, applying temporary settings, launching auxiliary tools, or performing any other initialization task that should happen automatically when the sandbox starts.

This feature is independent from the optional mapped program. You can use custom PowerShell startup code whether or not a mapped program is configured, and whether or not that mapped program is set to launch automatically.

### Startup Script Control

The section provides a dedicated toggle to enable or disable custom PowerShell execution at sandbox startup.

When enabled, you can enter multiline PowerShell code directly into the editor. The supplied code is incorporated into the sandbox logon command and runs inside the sandbox environment during startup.

### Execution Order

When a mapped program is configured and set to launch automatically, the page lets you choose where the custom PowerShell code should run in relation to that mapped program launch:

- **Before mapped program launch** - prepares the sandbox first, then starts the selected mapped program.
- **After mapped program launch** - starts the selected mapped program first, then runs the custom PowerShell code.

If no mapped program is configured, or if the mapped program is not set to launch automatically, the custom PowerShell code still runs during sandbox startup. In that case, the selected ordering simply defines its position relative to the built-in startup preparation steps.

### Preservation in Saved Profiles

Custom PowerShell startup code is saved with the sandbox profile. To preserve the script completely, the app stores the custom PowerShell code in the JSON definitions file as Base64 encoded UTF-8 text. This ensures that spacing, quotation marks, double quotation marks, line breaks, and unusual characters remain intact when the profile is saved and loaded again.

## Save and Start Workflow

The command bar above the saved profiles area offers two principal actions:

- **Save** - writes the current profile to disk and updates the saved-profile list without launching the sandbox.
- **Start** - saves the current profile and then launches it immediately.

## Saved Sandboxes

The **Saved Sandboxes** section presents the profiles already preserved by the app.

Each saved item displays:

- **Sandbox name**
- **RAM**
- **Mapped program**
- **Custom PowerShell**
- **Date**
- **Timezone**

If the mapped program is configured to run automatically at startup, that detail is reflected directly in the saved item summary. If custom PowerShell startup code is configured, the summary also indicates its selected execution position.

### Per-Profile Actions

Every saved sandbox offers a compact action row:

- **Load** - restores the profile into the editor so you can revise it.
- **Start** - launches the saved profile immediately.
- **Open Location** - opens the generated `.wsb` file location in File Explorer.
- **Delete** - removes the saved profile and deletes its generated `.wsb` file when present.

### Delete All

The section header also exposes a **Delete All** command, allowing you to remove every saved sandbox profile in one deliberate action.

## Persistence and Generated Files

Windows Sandbox Maker preserves its state with two complementary artifacts:

1. A JSON definitions file that stores the saved profile metadata.
2. Individual `.wsb` files generated per saved sandbox profile.

These files are stored within the app's local cache area under the Sandbox Maker storage folder. This gives the feature durable persistence while keeping the generated artifacts neatly contained within the app's own storage boundary. These data are deleted when the Harden System Security app is uninstalled from the system. You can manually copy the data in order to restore them later on the same system or another one.

The JSON definitions file stores profile settings such as identity, memory, device redirection choices, time-zone selection, mapped program details, and custom PowerShell startup configuration. Custom PowerShell code is stored as Base64 encoded UTF-8 text so the original script content remains pristine across save and load cycles.

## Practical Workflow

A typical workflow on this page is pleasantly straightforward:

1. Enter a sandbox name.
2. Choose a time zone or keep the host default.
3. Adjust memory and profile cards.
4. Optionally map a host folder and select its main executable.
5. Decide whether the folder should be read-only.
6. Decide whether the mapped program should launch on startup.
7. Optionally enable custom PowerShell startup code.
8. Choose whether custom PowerShell code should run before or after the mapped program launch.
9. Save the profile, or start it at once.
10. Revisit the saved profile later to load, amend, relaunch, or remove it.

This arrangement makes the page suitable both for ephemeral experimentation and for maintaining a carefully curated library of reusable sandbox profiles.

## Closing Notes

Windows Sandbox Maker transforms Windows Sandbox configuration from a raw file-editing exercise into a composed and intelligible experience. Instead of authoring `.wsb` documents by hand, you can shape disposable environments through a deliberate visual workflow, enrich them with mapped program support and custom startup automation, preserve them as named profiles, and return to them whenever a familiar scenario is needed again.
