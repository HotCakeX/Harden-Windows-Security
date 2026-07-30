# EXIF Manager | Harden System Security

<div align="center">

<img src="https://github.com/HotCakeX/.github/blob/aaf415fd0b8a2d84597377859e50b1f9bc8d93bc/Pictures/Gifs/HardenSystemSecurity_EXIFManager.gif?raw=true" alt="EXIF Manager | Harden System Security">

</div>

<br>

The **EXIF Manager** is a privacy-focused feature integrated into [the Harden System Security app](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden-System-Security) under the Extras section. It allows you to deeply inspect, copy, and securely strip hidden metadata (EXIF, XMP, Comments, etc.) from your photos. It operates directly on the file's data chunks at the lowest level, strictly adhering to the official specs of each data model and photo format, ensuring that your privacy is protected without re-encoding the image or losing any visual quality.

## How It Works

Digital photos often contain hidden information, such as the camera model, software used to modify them, exact GPS location, and timestamps. The EXIF Manager parses the internal structure of the image file, categorizing every piece of metadata. When you choose to remove metadata, the app safely strips out privacy-leaking and unnecessary data segments while carefully preserving chunks that are required for 100% visual integrity (such as ICC Color Profiles, physical dimensions, and minimal EXIF headers required to maintain the correct image Orientation).

**Supported Image Formats:** `.jpg`, `.jpeg`, `.png`. 

*More will be added in the future.*

## Selecting an Image

To analyze a photo, you need to load it into the EXIF Manager interface.

* **Browse Button:** Click the Browse button in the toolbar to open a file picker and select your image.
* **Drag & Drop:** You can easily drag and drop a JPG/JPEG or PNG file directly into the app's main window to instantly load it. *(Note: Drag & Drop is natively disabled by Windows when the app is running as Administrator).*
* **View Selected File:** Click the arrow next to the Browse button to view the exact path of the currently loaded image or to clear the selection.

## Viewing and Managing Metadata

Once an image is loaded, a preview thumbnail appears on the right, and the parsed metadata is displayed in a dynamic, categorized list on the left.

* **Categorized View:** Metadata is neatly organized into categories such as *File Information*, *EXIF Metadata*, *XMP Metadata*, *Photoshop IRB*, and more.
* **Tag Counts:** Each category header displays a badge indicating the exact number of metadata tags found within that specific section.
* **Expand / Collapse:** You can manually expand or collapse individual categories, or use the **Expand All** / **Collapse All** options located in the Actions drop-down menu to view everything at once.

### Copying Metadata

If you need to save or share the metadata for analysis:

* Open the **Actions** drop-down menu and click **Copy All**, or simply press `Ctrl + C` on your keyboard.
* This will copy a beautifully formatted, plain-text summary of all parsed categories and their associated tags directly to your clipboard.

## Removing Metadata

The EXIF Manager provides fine-grained control over what data gets removed.

**Note:** *Removing metadata will permanently overwrite the original file and cannot be undone.*

### 1. Remove Specific Categories

If you only want to strip certain types of data (e.g., removing *XMP Metadata* but keeping *EXIF Metadata*), you can do so easily:

* Look for the **Remove** button (with a red trash icon) on the right side of a category's header.
* Clicking this button will instantly strip only that specific category of metadata from the file.
* *Note: Categories crucial for visual fidelity (like File Information or Image Headers) will not have a Remove button, as they are not safe to remove.*

### 2. Remove All Metadata

To thoroughly sanitize the photo and remove all safe-to-remove metadata in one step:

* Open the **Actions** drop-down menu and select **Remove All Metadata**, or simply press the `Delete` key on your keyboard.
* A confirmation dialog will appear. Once confirmed, the app will scrub the file, reconstruct the necessary visual headers, and reload the sanitized file to show you the remaining, safe baseline data.

## Bulk Metadata Removal

Bulk metadata removal lets you sanitize all supported images in one or more folders, including their subfolders, without loading each image individually.

**Note:** *Bulk removal permanently overwrites every processed original file and cannot be undone.*

### Selecting Folders

* Click **Browse for folders** in the toolbar and select one or more folders.
* Open the button's flyout to review the selected folders.
* Select **Clear** in the flyout if you want to remove all folders from the current selection and start over.

### Running the Bulk Operation

1. Select at least one folder.
2. Click **Start**.
3. Review the confirmation dialog, which explains that supported images in the selected folders and their subfolders will be permanently modified.
4. Select **Start Removal** to continue, or **Cancel** to leave the files unchanged.

The operation searches recursively for `.jpg`, `.jpeg`, and `.png` files. Each image is analyzed using the same rules as the single-image workflow, and every category marked safe to remove is scrubbed. Data required for visual fidelity remains preserved.

During processing, the information bar reports progress periodically. When the operation finishes, it displays a summary containing:

* The total number of supported files found.
* The number of files cleaned.
* The number of files that had nothing safe to remove.
* The number of files that failed.
* The total number of bytes reclaimed.

If no supported images are found, the app displays a warning and does not offer a report.

### Saving the JSON Report

After a completed bulk operation that found supported images, the app offers to save a detailed JSON report. Saving the report is optional.

The report includes operation-level information such as:

* The report format and generation time.
* The operation start time and duration in milliseconds.
* The selected folders and supported file extensions.
* Totals for files found, cleaned, unchanged, and failed.
* Total file sizes before and after processing.
* Total bytes reclaimed.

It also includes one result entry per discovered image with:

* Full file path, file name, and directory.
* Processing status: `Cleaned`, `NothingToRemove`, or `Failed`.
* Names and count of metadata categories selected for removal.
* File size before and after processing.
* Size difference in bytes.
* An error message when processing failed.

The default report file name is `EXIFBulkRemovalReport.json`. If the chosen name does not end in `.json`, the app adds the extension automatically.
