# Download Manager | Harden System Security

<br>

The **Download Manager** is a dedicated feature in [the Harden System Security app](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden-System-Security) under the Extras section. It can accelerate your download speeds and offers many features and capabilities that go beyond the built-in browser download experiences, making it a resilient download manager suitable for any use cases.

## Adding Downloads

You can add downloads in multiple ways:

* **Add Links button:** Opens a dialog where you can paste one or more direct HTTP/HTTPS links.
* **Clipboard-aware input:** If your clipboard already contains links, the dialog preloads them automatically.
* **Keyboard shortcut:** Press `Ctrl + V` on the page to immediately queue valid links from the clipboard.
* **Drag and drop:** You can also drag and drop links from a browser or text file directly into the app. (Only works when running unelevated.)

The app detects all valid links in the pasted text and queues them together.

<br>

## Queue and Bulk Actions

The top command bar provides quick access to the main queue operations:

* **Search:** Instantly filters the current list.
* **Add Links:** Queues one or more new downloads.
* **Settings:** Opens the dedicated Download Manager settings page.
* **Speed Preset selector:** Quickly switches between **Slow**, **Medium**, and **Full** download-rate presets.
* **Selection actions:** When you select one or more items, bulk **Pause**, **Resume**, **Delete file**, and **Remove from list** actions become available automatically.

The list also supports drag-and-drop. If a selected item already has either its completed file or a partial file on disk, you can drag it out of the app to another destination in order to play or run it.

<br>

## Per-Item Actions

Every download item has quick actions and a flyout menu for common operations:

* Open the containing folder
* Pause or resume the transfer
* Open the downloaded file
* Delete the downloaded file
* Copy the original download link
* Change the download link
* Calculate file hashes
* Remove the item from the list without deleting the file

### Replacing an Expired Link

If a signed or time-limited link expires, the item flyout can be used to replace it with a new link.

The replacement link is validated before it is accepted:

* It must be a valid HTTP/HTTPS URL.
* It must resolve to the same file name.
* If size metadata is available for the existing item, the replacement must also match the same file size.

> [!TIP]\
> This helps you keep the same item in the list and continue the download without losing any progress, even if the original link becomes invalid.

### File Hashes

For files that already exist on disk, the item flyout can display hashes in a dialog. The current implementation supports:

* SHA-2 256
* SHA-2 512
* SHA3 256
* SHA3 384
* SHA3 512

> [!TIP]\
> This can come in handy for verifying the integrity of downloaded files, especially when the source provides expected hash values for comparison.

<br>

## Reliability and Resume Behavior

The Download Manager is built to be resilient rather than assuming every server behaves perfectly.

It includes:

* **Checkpoint-based resume support** so interrupted downloads can continue later
* **Parallel downloading** when the source supports byte ranges
* **Automatic retry/backoff handling** for transient request and stream failures
* **Conflict handling** when the target file name already exists
* **Metadata-based file-name resolution** using server response headers and other fallbacks when the raw URL is not the real file name

> [!IMPORTANT]\
> For downloaded executable and script-like file types, the app also applies Mark-of-the-Web tagging so Windows can preserve the proper internet-origin security context.

<br>

## Settings Page

The Download Manager has its own settings page where you can control how transfers behave.

### Storage

* Change the default save location for downloaded files
* Restore the default Downloads folder
* Open the Download Manager's storage location used for its internal state data

### Transfers

* Set the maximum number of simultaneous downloads
* Set the number of parallel connections per download (does not apply to downloads that are already in progress)
* Choose an action to run after all downloads finish
  * None
  * Shutdown
  * Sleep
  * Hibernate
* Choose how file-name conflicts are handled
  * Ask
  * Overwrite
  * Add duplicate
* Enable or disable **automatic removal of completed downloads from the list**

When the automatic removal option is turned on, completed items are removed from the list and their stored checkpoints/history state is cleaned up automatically, while the finished files remain in the selected download folder.

### Speed Presets

The three preset modes can be configured from the settings page:

* **Slow**
* **Medium**
* **Full**

The Full preset can also be set to unlimited mode.

<br>

## Preview Experience

The preview area is designed to provide useful visual information about the download items:

* Images and supported visual files can show thumbnails.
* Videos can show a static preview and when you hover over them, a short preview clip is played.
* Placeholder text is shown when a preview is not available yet

<br>

## Typical Use Cases

The Download Manager is especially useful when you need one or more of the following:

* Downloading multiple links in one session
* Resuming interrupted large-file transfers
* Handling short-lived links that may need to be refreshed later
* Controlling bandwidth with presets
* Verifying downloaded files with built-in hash dialogs

It is meant to provide a practical, reliable, and security-conscious download workflow directly inside Harden System Security without relying on a separate external download tool.
