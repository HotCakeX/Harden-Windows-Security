# Duplicate Photos Finder | Harden System Security

<div align="center">

<img src="https://github.com/HotCakeX/.github/blob/268c636ff136c5c454390ee7522be41827e84440/Pictures/Gifs/HardenSystemSecurity_DuplicatePhotosFinder.gif?raw=true" alt="Duplicate Photos Finder | Harden System Security">

</div>

<br>

The **Duplicate Photos Finder** is an optimized tool integrated into the Harden System Security app, designed to help you reclaim disk space by finding and removing redundant images. It uses an advanced perceptual hashing algorithm to identify visually similar or exact duplicate photos, even if they have different file names, formats, or slight variations in resolution.

## How It Works

Under the hood, the Duplicate Photos Finder uses **dHash (Difference Hash)**. This perceptual hashing technique converts images to grayscale, resizes them, and compares adjacent pixels to generate a unique signature (hash) for each image. By comparing these hashes, the app can find identical or highly similar images quickly and accurately.

The scan is fully multithreaded and parallelized, utilizing all available CPU cores to process thousands of images in seconds.

**Supported Image Formats:** `.jpg`, `.jpeg`, `.png`, `.bmp`, `.gif`, `.tiff`, `.ico`, `.jxr`, `.webp`.

<br>

## Selecting Files and Folders

To begin a scan, you need to provide the app with the locations you want to search.

* **Select Files and Folders:** Use the dedicated buttons in the toolbar to browse and add specific files or entire directories to the scan list. You can view or clear your selections at any time using the flyout menus.

* **Drag & Drop:** You can also simply drag and drop files and folders directly into the app's interface (Note: Drag & Drop is natively disabled by Windows when the app is running as Administrator).

<br>

## Customizing the Scan

Before starting the scan, you can fine-tune how the app detects and sorts duplicates.

### Similarity Threshold

You can adjust the **Similarity Threshold** slider between 50% and 100%.

* **100%** means strict matching (exact duplicates).
* Lowering the percentage allows the app to find images that are visually similar but might have been resized, slightly cropped, or filters applied to them. Keep in mind that lower values might include false positives (non-duplicates).

### Keep Original Strategy

When a group of duplicate photos is found, the app needs to decide which one is considered the "Original" (the one to keep) and which ones are "Duplicates" (the ones to delete). You can choose from four strategies:

1. **Biggest Resolution** (Default)
2. **Smallest Resolution**
3. **Biggest File Size**
4. **Smallest File Size**

> [!NOTE]
> In the event of a tie between two formats (e.g., a PNG and a JPG with the exact same resolution and size), the app is programmed to automatically prefer keeping the lossless PNG format over the JPG/JPEG format. This logic only comes into play when the formats are either PNG or JPG/JPEG.

<br>

## Reviewing Results

Once the scan is complete, the results are displayed in a clean, side-by-side grouped layout.

* **Left Column (Original):** The file selected to be kept based on your chosen strategy. It is marked in green.
* **Right Column (Duplicates):** The list of redundant files that match the original. They are marked in red and intended for deletion.

Each item displays a thumbnail preview along with its file name, resolution, file size, and exact path.

### Image Preview, Pan, and Zoom

Clicking on any image thumbnail opens a full-size, interactive preview dialog:

* **Pan & Zoom:** You can click and drag to pan around the image.
* **Zoom Controls:** Use the Zoom In/Out buttons on the toolbar, or toggle the **Mouse Wheel Zoom** to zoom in and out using your scroll wheel.
* **Open File Location:** Easily open Windows File Explorer with the specific image highlighted.

<br>

## Deletion and Data Management

You have full control over how you want to clean up the duplicates.

* **Delete Individual Duplicates:** Click the "Delete" button under any specific duplicate image to remove it.
* **Delete All Duplicates in Group:** A single button under the Original image allows you to delete all associated duplicates at once.
* **Auto Delete All Duplicates:** Found under the "Actions" menu, this will automatically iterate through all found groups and delete every duplicate file, leaving only the originals.
* **Delete Original File:** If you decide you don't want the original file either, you can right-click (or use the context menu) on the Original image's thumbnail to delete it. This will remove the original file from your disk and dismiss the group from the results, but it will safely leave the duplicates untouched in case you want to manage them differently.

### Undo Last Deletion

Made a mistake? The app features an **Undo** capability. When you delete individual duplicates or a single group of duplicates, the app temporarily holds the deleted file bytes securely in RAM.

* You can click **Undo Last Deletion** in the Actions menu or simply press `Ctrl + Z` on your keyboard to instantly restore the deleted files back to your hard drive and the app's UI.
* *Note: The Undo feature does not apply to the "Auto Delete All Duplicates" mass action due to possible memory constraints.*

### Search and Statistics

* **Search:** Use the search bar to filter the grouped results by file name. The list updates instantly.
* **Statistics:** Click the Statistics button to see the total number of files processed during the scan and the exact number of duplicates found.
* **Clear Data:** Resets the app's state, clearing all loaded images, undo history, and scan results so you can start a fresh session.
