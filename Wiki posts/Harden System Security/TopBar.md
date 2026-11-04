## TopBar in the Harden System Security App

<div align="center">

<a href="https://youtu.be/jMl0Uzt4_1k?si=Q8pjbfawJYZvDSt2">
<img width="800" src="https://github.com/HotCakeX/.github/blob/main/Pictures/PNG%20and%20JPG/TopBar%20Video%20Thumbnail%20HSS%20with%20YT%20Logo.png?raw=true" alt="TopBar video thumbnail"/>
</a>

</div>

<br>

<div align="center">

<img alt="TopBarDemoHSS" src="https://github.com/user-attachments/assets/df25bf1f-6cce-4f33-9961-feeec5e72ab1" />

</div>

<br>

The **TopBar** is a small, elegant companion bar that lives at the very top‑center edge of your screen. Most of the time it stays tucked away as a tidy little "notch," quietly out of your way. When you move your pointer to it (or tap it), it smoothly expands into a compact panel packed with handy tools, and it slides back into its notch the moment you're done. It's designed to always be within easy reach without ever getting in the way of your work.

## How To Start

* By clicking/tapping on its access point button on [the Home page](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Home-Page).

* By right-clicking on the Harden System Security app's pinned icon on Start menu or Taskbar and selecting "Windows Top Bar"

* Via Command Line: `hss.exe --windows-top-bar`

<br>

<div align="center">

https://github.com/user-attachments/assets/a7c1e10a-0d33-4c52-8120-4cfd34e52780

</div>

<br>

## The Notch and How It Opens

While collapsed, the TopBar appears as a slim pill at the top of your display. It shows the name (and a small icon) of whichever tool it's currently set to, so you always know what it holds at a glance. Depending on the tool you've chosen, the notch can also show a live preview right there without opening.

- **Open on hover or on click.** By default, the bar opens the moment your pointer reaches it. If you prefer, you can switch it to only open when you actually click or tap the notch, so it never expands just because your pointer passed over it.

- **Touch friendly.** If you tap it with your finger, the bar opens and stays open until you tap somewhere else, so it won't collapse the instant you lift your finger.

- **Shy Bar mode.** If you want the TopBar completely out of sight when you are not using it, enable **Shy Bar mode** from the settings menu. The notch disappears and the bar remains hidden until you move your pointer back and forth three times along the screen edge where the TopBar is docked. The gesture works directly on the screen edge as well as slightly inside it. Requiring three completed changes of direction helps prevent accidental reveals. While Shy Bar mode is enabled, the notch style, open-on-hover, and pin-open options are unavailable because there is no visible notch to hover over, click, or keep open.
   * Note that if the current program window that you are using is elevated, the reveal gesture will not be detected until you change the focus to an unelevated window or simply clicking somewhere on taskbar first and then perform the gesture.

<div align="center">

<img alt="TopBar Shy Bar Mode" src="https://github.com/user-attachments/assets/cc799c73-79cf-45f9-8c8c-4d6ad0e72341" />

</div>

<br>

- **Two notch shapes.** When Shy Bar mode is off, you can choose between the standard notch (which shows an icon, the tool name, and a little chevron) or a slimmer, lower‑profile notch that takes up even less of your screen.

## The Views

The TopBar can display one tool at a time, and you switch between them from a small menu inside the expanded bar. You can also **use your mouse wheel or scroll on a trackpad** while your pointer is over the view switcher button or an empty part of the bar to move through the views. Scroll down to go forward and up to go back; the selection wraps around when you reach either end. Scrolling over tiles and other controls keeps their usual behavior. Whichever view you pick, the bar automatically resizes itself to fit that view's content. Below is an overview of the available views:

### Apps

A quick‑launch strip of your favorite programs. Each app appears as a tile with its own icon and name; click one to open it. You can add your own apps, remove ones you don't want, and the bar comes preloaded with common shortcuts like Settings, File Explorer, Notepad, Calculator, and Task Manager. If you're running the app normally (not as an administrator), you can even **drag one or more programs' file(s) straight onto the bar** to pin them.

### Folders

A strip of pinned folders for one‑click access to the places you use most. It starts with Downloads, Documents, and Desktop. You can:

- **Add or remove** folders freely, and drag folders onto the bar to pin them.

- **Give each folder a custom color** so your favorites are easy to spot.

- **Search inside a folder** right from the bar. Type part of a file name and matching files appear instantly; click one to open it, or even drag a result out to another app.

<div align="center">

<img alt="image" src="https://github.com/user-attachments/assets/1af5c453-00db-4a3c-a237-a2a3cf29fa09" />

</div>

<br>

### Search

The **Search** view provides instant, system-wide file and folder search directly from the TopBar. Start typing part of a file or folder name and matching items from the indexed drives appear in real time, without waiting for Windows Search to scan each location.

<div align="center">

<img alt="image" src="https://github.com/user-attachments/assets/55de4ee0-7b5c-4596-8f9f-40ef9e6b1b5a" />

</div>

Global Search is designed for fast searches across every local **NTFS** and **ReFS** drives.

- **Search as you type.** Results update in real time as the search text changes.

- **Search by name.** Search looks at the names of files and folders, not their full paths. For example, typing `vacation` finds a folder named `Vacation` and a file named `Vacation.jpg`, but not `beach.jpg` that is saved inside that folder. If there are more matches than your **Max results** number, type more of the name to narrow them down.

- **Search with wildcards.** Use `*` in the search text to match any number of characters, with up to 2 of them in one search. A search with a wildcard matches the whole name instead of any part of it, and capital and small letters are treated the same. For example, `HardenSystem*.exe` and `Ha*ystem*ity.exe` both find `HardenSystemSecurity.exe`, `*.pdf` finds every name that ends with `.pdf`, and `report*` finds every name that starts with `report`. A search without a wildcard keeps finding every name that contains the text, at the same speed as before.

- **Choose how many results to show.** The **Max results** box at the top left of the Search view sets the most results shown for each search. It starts at 100 and accepts any number from 1 to 10,000. Type a number and press Enter, or click the box and use the up and down arrows that appear, which change it by 100 at a time. Higher numbers can take a little longer to show because the size and date of every result are read from the drive, so a smaller number keeps Search at its fastest. Your choice is remembered.

- **Choose files, folders, or both.** The small buttons on the top row of the Search view, next to the indexed items count, let you pick what to find. **All** shows both files and folders and is selected by default, **Files** shows only files, and **Folders** shows only folders.

- **Filter by file type.** Select **Pictures**, **Videos**, **Audio**, **Documents**, or **Archives** to only show those kinds of files. You can select more than one, for example Pictures and Videos together to find both your photos and your clips. When none of them is selected, every type of file is included. Hover over a button to see examples of the file types it covers. File types only apply to files, so they are turned off while **Folders** is selected, and folders are not shown while a file type is selected.

- **Show large thumbnails.** The picture button at the end of the same row switches the results to taller rows with large thumbnails, so you can preview your photos and videos and recognize them at a glance. Pictures and videos keep their original shape, and other files and folders show a preview when Windows has one, or a large icon otherwise. Select the button again to go back to the compact list. Only the look of the results changes, so the same results stay on screen without searching again. Your choice is remembered.

- **Open results immediately.** Double click or tap a result to launch the file with its associated app.

- **Use native file actions.** Right-click or tap and hold on a result to access rich Windows file operations and other actions relevant to that item.

- **On-demand background indexing.** A dedicated LocalSystem service builds and maintains the search indexes using the fastest available file-system mechanisms. The Top Bar starts it when you start typing in the search box or load drive statistics, and indexing begins at that point (this is the default behavior). If you enable the **Index at Windows startup** option, a startup task starts the service when you sign in to Windows, so the index is ready when you need it. You can also turn that startup task on or off from the Startup apps page in the Settings app.

- **Saved index for fast starts.** When the service turns itself off, or when Windows shuts down, it saves the index in the app's machine folder on your OS drive. The next time it starts, it loads the saved index in a few seconds and only applies the changes made to your drives since then, instead of reading every file again. Right before each search, it also applies the latest changes, so new, renamed, and deleted items are always found correctly, and nothing runs in the background between searches. Search reads the index straight from the saved files, so the memory the service needs stays small no matter how many files your drives hold. Windows keeps recently read parts of the files in its cache and frees them whenever other apps need the memory. Only the service, which runs as SYSTEM, can change the saved index, administrators can read it, and Windows removes it when you uninstall the app.

- **Rebuilt only when needed.** The saved index is built again from scratch only when it cannot be trusted, for example when the service was stopped unexpectedly before it could save, when a drive was formatted or replaced, or when so many changes were made while the service was off that the drive's change journal no longer holds all of them.

- **Drives you connect later.** By default, a drive connected while the service is already running, such as an external SSD, is added to the index the next time the service starts, when you select **Detect and index drives** or when you load statistics for it in **Drive Statistics**. Turn on **Index drives when they are connected** to have the service add every drive as soon as it is connected to your system.

- **Safe removal of drives.** When you safely remove or eject an indexed drive, the service saves its index and releases the drive right away, so Windows never reports the drive as in use because of Global Search. If the removal does not happen, for example because another app is still using the drive, the drive is added back to the index.

- **Resource-conscious service lifetime.** The service turns itself off after 6 hours without use, counted from when it starts, when it finishes building the initial index, or when it answers the last request. The Top Bar starts it again automatically the next time it is needed.

> [!NOTE]\
> The first search after the service turned itself off takes a moment longer because the service must start and load the saved index. Only the very first search, or one after the saved index had to be built again, takes longer because every file on the indexed drives must be read.

> [!TIP]\
> The indexed database is a very compact database that the Global Search uses for its search functionality. It can only be [accessed](https://github.com/microsoft/WindowsAppSDK/blob/main/specs/applicationdata/ApplicationData.md#34-per-machine-data-store) by the `Trusted Installer` or the `SYSTEM` accounts.

#### Global Search Settings

The **Global Search Settings** button, next to the **Drive Statistics** button in the Search view, opens a panel to manage the saved index of Global Search.

- **Calculate size.** Shows the total size of the saved index on your OS drive. Select it again at any time to see the current size.

- **Delete unused indexes.** The saved index of a drive that is not connected is kept for 10 days, so the drive is found again quickly when you reconnect it, and is then deleted automatically. Select this button to delete such saved indexes right away instead of waiting. The indexes of the drives that are in the index now are kept, and the new size is shown when it finishes.

- **Index drives when they are connected.** When this is on, the service adds every drive you connect while it is running to the index right away, and also adds the drives that were connected while the option was off. It is off by default, and your choice is remembered and applied every time the Top Bar connects to the service.

- **Detect and index drives.** Looks for connected drives that are not in the index yet and adds them, then shows how many drives were added and how many are indexed in total. Use it when a drive could not be indexed when you connected it, such as a BitLocker encrypted drive that you unlocked afterwards.

#### Drive Statistics

<div align="center">

<img alt="image" src="https://github.com/user-attachments/assets/390ee505-355f-4de3-90e5-f99436e28fa3" />

<br>

<img width="227" height="347" alt="image" src="https://github.com/user-attachments/assets/2f643756-abb5-4b71-9f04-247acaeb4d3a" />

</div>

The Search view also includes **Drive Statistics**, which provides a quick snapshot of the types of files stored on a selected drive.

- Choose an available drive and select **Load statistics** to calculate the snapshot.

- If the drive isn't in the search index yet, for example because you connected it after the search service started, it is indexed first, so that load takes longer. The drive then stays in the index, so its files show up in your searches too.

- View the results in a color-coded chart and legend, with both the file count and percentage shown for each category.

- Hover over a chart segment for its detailed count and percentage.

- See counts for **Pictures**, **Audio**, **Video**, **DLL files**, **EXE files**, **Documents**, **Archives**, **Source and data files**, files with **no extension**, and **Other** file types.

### Websites

A quick-launch strip of your favorite websites. Each site appears as a tile with its name and icon; click one to open it in your default browser. You can:

- **Pin a website** by entering its address, with an optional name. The bar comes preloaded with a few familiar sites. The icons of the pinned websites are only fetched during the first load of this view when you launch the TopBar.

- **Drag a link or browser tab/window onto the bar** to pin it. If you're running the app normally (not as an administrator), you can drag a browser window or tab onto the Websites view to add its current page. It currently only works for Microsoft Edge and Google Chrome.

- **Remove a website** or clear the whole list from a tile's right-click menu.

- **Edit an existing website** by right-clicking or tap + holding on it and selecting the Edit option.

### Performance

A compact, live dashboard of how your computer is doing, refreshed every second while you're viewing it. It shows the same rich metrics as the Home page's Live System Intelligence, laid out over two neat rows:

- **CPU Usage** and **CPU Temperature**

- **Memory** usage (hover it to see the exact amount used out of your total)

- **Storage Temperature** and **Disk Activity** (read and write speeds)

- **Network** activity (download and upload)

- **Total System Power** and **Battery Discharge** (on supported hardware)

- **App Memory** used by Harden System Security itself

When this view is selected, the standard notch can even show a tiny live readout of the app you're currently using (its name, CPU, and memory) without opening the bar. For example, if you are watching a video on Edge or coding in Visual Studio, you see the active CPU/RAM usage of them. It is highly optimized and uses very low system resources.

<div align="center">

<img alt="Performance Notch" src="https://github.com/user-attachments/assets/886e67b6-390e-4660-a1ac-86b2335bff3e" />

</div>

<br>

### Clocks

A row of world clocks so you can keep an eye on the time in different places at once. Each clock shows a name you choose, the current time, and the date. You can:

- **Add clocks** for any time zone (up to seven of them) and **remove** ones you no longer need.

- **Pin up to two clocks to the notch**, so their times are visible even while the bar is collapsed.

It comes preloaded with a handful of clocks, including your local time and UTC.

### Network Quality

A live connection‑quality tester. Enter a website or IP address (a few popular ones are ready to pick from) and press Start. The bar continuously measures your connection and shows:

- **Current, average, lowest, and highest** response times

- **Jitter** (how much your response time bounces around)

- **Packet loss** (how many replies didn't come back)

- A **live bar graph** of recent results, with green bars for successful replies and red bars for lost ones.

It's a quick, friendly way to see whether your internet is stable and responsive.

### Acoustic Sentry

<div align="center">

<img alt="TopBar Sentry" src="https://github.com/user-attachments/assets/410519d2-4a33-452d-8341-ab2cd2beb5e8" />

</div>

It is an environment audio watchdog security capability. Arm it, and it quietly listens to your surroundings; the moment the ambient sound level crosses a threshold you define, or someone says a phrase you choose, it captures high‑fidelity audio to disk, then waits out a cooldown before it's allowed to trigger again. It keeps working whether the workstation is locked or not. Use it to detect unusual or suspicious sounds in your environment when you are away from your device.

> [!TIP]\
> Example Scenario: You are away from your home and the Acoustic Sentry is armed on the device at your home. If a loud noise occurs, such as a window breaking, or door unlocking while you are away, the Sentry will automatically capture the audio and save it to the designated folder. You can also have it listen for a spoken phrase instead, such as "help me", so it only records when someone says those words. You define how long it should record for each incident and control all aspects of it. **Set the save location to OneDrive and then listen to the recordings from anywhere in the world.** Your own private secure monitoring solution.

#### Highlights

* **Two trigger modes**: Choose what starts a recording from the **MODE** box. Only the settings of the selected mode are shown. The mode, the phrase, and the encryption choice can only be changed while the Sentry is disarmed; the trigger level, capture duration, gap, cycle limit, and folder apply right away, even while it is armed.
   * **Decibel level**: Set a custom trigger level (in dBFS). When the ambient level reaches or exceeds it, recording begins automatically.
   * **Spoken phrase**: Type a word or a few words. When someone says them, recording begins automatically, while other sounds, however loud, are ignored. See **Spoken phrase mode** below.

* **Arm / Disarm**: A single toggle opens or releases the microphone. The mic is only ever held open while a session is armed, nothing is captured or monitored when idle.

* **Manual stop**: End the in‑flight capture at any time without waiting for its duration to elapse.

* **Custom capture duration**: Choose how many seconds each capture lasts once triggered.

* **Cooldown / cadence control**: A configurable gap (timeout) governs how often a capture can repeat, so a continuously loud room doesn't record endlessly.

* **Cycle limit**: Cap how many captures a session performs before it disarms itself, or set it to unlimited.

* **Custom output folder**: Save captures anywhere you like, with Browse / Open / Reset controls. Defaults to a named folder in your user profile: %UserProfile%\Harden System Security Sentry.

* **Works while locked**: Capture is bound to the process rather than the desktop, so it continues across lock/unlock.

* **Highest audio quality**: Recordings are written as lossless WAV PCM at the microphone's native sample rate and channel count (24‑bit), no resampling, no fidelity loss.

* **Live level graph**: In decibel level mode, a lightweight, scrolling meter shows the ambient level in real time and turns red the instant it crosses your trigger, so you can read the threshold straight off the graph. While the bar is collapsed, the standard notch shows the live dBFS reading in place of the view name. The meter only runs while the Sentry is armed and its view is expanded or shown on the standard notch; it costs nothing otherwise.

* **Recordings Encryption**: For privacy and security, you can optionally choose to encrypt any existing recordings and also automatically encrypt any future recordings on disk with user or machine context.
   * User Context will only allow your own user account to decrypt them.
   * Machine context will only allow your device to encrypt them and they cannot be read or played on any other device.

* Very efficient and low system resource usage.

#### Spoken phrase mode


<div align="center">
<a href="https://youtu.be/JLRsJfzyBR0">
<img width="800" src="https://github.com/HotCakeX/.github/blob/main/Pictures/PNG%20and%20JPG/Audio%20Sentry%20Phrase%20Mode%20banner.png?raw=true" alt="Audio Sentry" />
</a>
</div>

<br>

* **Private, on‑device recognition**: Your phrase is recognized right on your device by the speech recognition built into Windows, in your system speech language, without any online service. Make sure a speech language is installed in the Settings app under **Time & language** > **Speech**.

* **Choosing a phrase**: Type one or more words in your system speech language, up to 160 characters, in the **Spoken Phrase** box. Two or three distinct words work best and every word of a long phrase must be heard correctly.

* **Said within other speech**: The phrase can be said on its own or in the middle of a sentence, but its words must be said in order and in one go.

* **Only the words count**: Capitalization and punctuation don't matter, so "Help me!" and "help me" are the same phrase.

* **See what it hears**: The words of your phrase light up green as they are heard, with a quick left‑to‑right flash, so you can test your phrase before you leave. If only part of the phrase is heard, those words light up too. The words stay lit while a recording is in progress and clear about 3 seconds after the last speech it heard.

* **Phrase on the notch**: While the Sentry is armed in this mode and is the selected view, the standard notch shows your phrase in place of the view name, and its words light up the same way.

* **Listening and recording take turns**: Listening pauses while a recording is in progress and starts again when the cooldown ends.

* **Recovers on its own**: If the speech session stops by itself, for example when the microphone is briefly unavailable, the Sentry restarts it automatically and shows **Speech not ready** in the meantime. If it keeps stopping right after it starts, the Sentry disarms itself and tells you why.

> [!NOTE]\
> The speech recognition engine in Windows has a known issue where if you play an audio or video such as a YouTube video in the browser, while the Audio Sentry is armed, it might not be able to recognize the words spoken in the microphone, even if the audio of the video playback comes from the headphones or the video/audio being played is muted.

#### Clear, actionable error reporting

When a session can't be armed, or has to stop, the status area tells you exactly why:

* Microphone muted, detected up front; the Sentry refuses to arm on a device that can't hear anything, instead of silently recording nothing.

* Access turned off, surfaces a one‑click "Open mic settings" shortcut to the Windows microphone privacy page.

* No microphone found / unsupported format, explained plainly.

* An empty spoken phrase, or one without any words.

* Speech recognition that can't start, with a reminder to install a speech language and allow microphone access.

* A microphone or speech engine that doesn't respond within 15 seconds.

* A failed capture, or spoken phrase listening that keeps stopping on its own; the Sentry disarms itself and shows what happened.

### Clipboard

<div align="center">

<img src="https://github.com/HotCakeX/.github/blob/main/Pictures/Gifs/TopBar%20Clipboard%20Demo.gif?raw=true" alt="ClipBoard" />

</div>

<br>

The **Clipboard** view keeps a private, encrypted history of what you copy. Your copies are sorted into **buckets**, and buckets are grouped into **collections**, so you can keep things such as work, personal, and project copies apart. You can name, rearrange, merge, search, and paste from them at any time. Clipboard history is off by default. Once you turn it on, every copy you make is saved, even while the bar is collapsed or showing another view, as long as the TopBar is running.

- **The Clipboard buttons.** While the Clipboard view is shown, four small round buttons appear next to the **Close** and **Settings** buttons. Hover over a button to see what it does.
   * **Clipboard history** turns clipboard history on or off, and your choice is remembered. While it is off, the TopBar doesn't look at your clipboard at all, and a pulsing ring highlights this button so it's easy to find the first time you open the view. Turning it off doesn't delete anything you already saved; use **Clear all** for that.
   * **Export or import** saves your whole clipboard history to a zip file, or brings it back from one, for example when you reinstall Windows. See **Take your history with you** below.
   * **Link previews** shows web addresses that you copy on their own as preview cards. It is off by default. See **Link cards** below.
   * **Clear all** permanently deletes every collection, every bucket, and all saved clipboard data. Clipboard history stays on or off as it was. Nothing is deleted right away: a confirmation opens next to the button and stays open until you choose. Select **Delete everything** to go ahead, or close it with its **X** button to keep everything.

- **Collections.** The row at the top of the view shows your collections, two at a time. Scroll it sideways to see the rest. Each collection shows its name and a small number that tells you how many buckets it holds. The **Default** collection, with the history icon, is always there and can't be renamed or deleted.
   * **Create a collection** with the **+** button next to the row. Type a name of up to 16 characters and press Enter or select **Create**. If you leave the name empty, the collection gets a numbered name. You can create up to 10 collections in addition to **Default**.
   * **Switch collections** by clicking or tapping one. Its buckets are shown, and from then on, everything you copy is saved only in that collection. Each collection remembers its own selected bucket, and when you switch to a collection that has a bucket selected, that bucket is placed on the clipboard right away.
   * **Rename or delete a collection** by right-clicking it, or tapping and holding it, and selecting **Rename** or **Delete**. **Rename** opens the name box with the current name already typed in, so you can change it and press Enter or select **Rename**. **Delete** deletes all of the collection's buckets with it.

- **Buckets.** The buckets of the selected collection are shown as cards in a row that you can scroll sideways. Each card shows the bucket's name, how many clips it holds, and a preview of its 4 newest items: pictures and files are shown as thumbnails, text as a short snippet, colors as color swatches, and links as preview cards when **Link previews** is on. Hover over a preview to see more of its text or the name of its file. Each collection can hold up to 1,000 buckets, and only the ones that hold something are shown.

- **A new bucket for every copy.** While the **NEW BUCKET** card at the end of the row is selected, which is the default, every new copy goes into a bucket of its own in the selected collection. If that collection already has 1,000 buckets, new copies are added to its existing buckets one after another instead.

- **Pick a bucket to paste from and copy into.** Click or tap a bucket to select it. Its content is placed on the Windows clipboard right away, so pressing Ctrl+V in any app pastes it, and your next copies are added to that bucket instead of going into new ones. Select **NEW BUCKET** again to go back to one bucket per copy.
   * **What you see selected is what you paste.** You never have to click the selected bucket again to paste it. The selected bucket of the collection you are looking at is placed on the clipboard again by itself when you switch collections, when a search switches to another collection, when you delete the collection you are looking at, when you import, when the TopBar starts or you turn clipboard history on, and when items are moved into, moved out of, or deleted from that bucket. While **NEW BUCKET** is selected, the TopBar leaves your clipboard as it is.
   * Something you copy that isn't saved, such as a password, stays on the clipboard until one of those things happens. Click or tap the selected bucket to place it on the clipboard again at any time.
   * If the bucket holds files, all of its files that still exist are placed on the clipboard together, so a single paste in File Explorer copies all of them.
   * Otherwise, the newest item in the bucket is placed on the clipboard.
   * If another app is using the clipboard at that moment, the TopBar keeps trying for a few seconds. If the clipboard is still busy after that, the status line tells you, and you can click the bucket again.
   * If none of the bucket's files exist anymore and it has nothing else to paste, the clipboard is emptied, so an older copy is never pasted by mistake, and the status line tells you.

- **Name your buckets.** Click or tap a bucket's name and type a new one, up to 18 characters, then press Enter or click anywhere else. Clear the name to go back to the default numbered name. Buckets are numbered by their place in the row, so the numbers update when you move or delete a bucket.

- **See everything in a bucket.** Select **Open details**, or double click or tap the bucket, to open a small window that lists every item in the bucket with a thumbnail and its name or text. For a file, it also shows where the file is and how big it is. For anything else, it shows what kind of content was saved and when you copied it. Select the delete button next to an item to remove only that item.

- **Delete a bucket.** The **Delete bucket** button removes the bucket and everything in it.

- **Move and merge buckets.** Drag a bucket onto the left or right edge of another bucket to move it before or after that bucket, or drop it on the middle of another bucket to merge the two. A label next to the pointer tells you which one will happen before you let go. The bucket you drop on keeps its name, its items are sorted from newest to oldest, and a file that was in both buckets is kept only once.

- **Move a single item to another bucket.** Open the details window of a bucket, then drag an item from the window and drop it on another bucket in the bar. The item moves into that bucket and takes its place among the other items by the time it was copied. A bucket that is left empty after its last item is moved away is removed, and its details window closes.

- **Split an item into a bucket of its own.** If two items ended up in the same bucket by accident, drag one of them from the details window and drop it on the **NEW BUCKET** card. The item moves into a new bucket at the end of the row of the collection you are looking at. This isn't possible while that collection already has 1,000 buckets.

- **Drag into other apps.** Drag a whole bucket out of the bar, or a single item out of the details window, and drop it into another app, such as File Explorer, an email, or a chat. A bucket offers its files along with its newest text or picture, a single item offers only itself, and the app takes whatever it supports. Files are always copied, never moved from where they are.

- **Search.** Select the search button at the top left of the view, and a search box slides open next to it. As you type, the TopBar looks through the bucket names, the copied text and links, the titles and descriptions of link cards, and the locations of copied files in every collection. It switches to the collection that holds the first match, scrolls to that bucket, and highlights it. The line next to the search box tells you which collection and bucket matched.
   * Press **Enter** to jump to the next match, even when it's in another collection.
   * Press **Esc**, or select the search button again, to close the search box and remove the highlight.
   * The collection where a match was found becomes the selected collection, so your next copies are saved there.

- **Colors.** When you copy just a color code, such as `#0078D4`, `#FFF`, `rgb(0, 120, 212)`, `hsl(206 100% 42%)`, or `hwb(206 0% 17%)`, the preview shows the color itself with its code written on top, instead of plain text. A color code without the leading `#` is recognized when it is exactly 6 characters long and mixes numbers and letters, such as `0078D4`, so ordinary words and numbers are never mistaken for colors. Pasting it gives you back the code exactly as you copied it.

- **Link cards.** While **Link previews** is on, a web address that you copy on its own is shown as a preview card, the same kind of card that sites such as X (Twitter) and Facebook or chat apps show when you paste a link there. The card shows the page's preview picture, such as the banner of a GitHub repository or the thumbnail of a YouTube video, along with the page's title, and the details window also shows its short description. If the address leads straight to a picture, the picture itself is shown.
   * Only a single web address copied with nothing else gets a card. Text that contains links, or several links copied together, is saved and shown as ordinary text.
   * To make a card, the TopBar visits the address once, right after you copy it, just like a social site does when you paste a link there. It reads only the preview information that the page provides for this purpose. Website icons aren't used.
   * Only addresses on the public internet are visited. Links to your own computer or to devices on your local network, such as your router's settings page, are never visited.
   * Cards are always fetched directly and never through a proxy. On a network that only allows internet access through a proxy, links are shown as text.
   * Cards are only made for links copied while **Link previews** is on. Turning it off hides the cards that were already made, and turning it on again shows them again.
   * A page that can't be reached, or doesn't answer within 15 seconds, gets no card, and the link is shown as text.
   * Pasting a link that has a card still pastes the link exactly as you copied it.

- **Passwords and other private content are skipped.** Many apps, such as password managers, mark what you copy from them as private. The TopBar never saves such content, honoring the same signals that keep it out of Windows' own clipboard history (Windows key + V).

- **It doesn't save its own pastes.** What the TopBar places on the clipboard when you select a bucket isn't saved again as a new item. It's also kept out of Windows' own clipboard history and isn't synced to your other devices.

- **Copying the same thing twice in a row saves it once.** If what you copy is exactly the same as your previous copy, and that copy is still the newest item in its bucket, it isn't saved again. Some apps, such as Sticky Notes, report a single copy to Windows twice, and this makes sure it's saved only once.

#### What Is Saved for Each Kind of Copy

Text and pictures only exist on the clipboard, so the TopBar saves them in full. Files already exist on your drives, so the TopBar only remembers where they are and never makes a copy of them.

- **Plain text.** The text is saved in full. The bucket card shows its beginning, and pasting it later gives you back exactly what you copied.

- **Formatted text.** When you copy from a web page, an email, or a document in an app such as Word, the app also provides a formatted version with things like bold text, colors, links, and tables. The TopBar saves those formatted versions (HTML and Rich Text) together with the plain text, so pasting into an app that supports formatting brings the formatting back too.

- **Links.** A link is saved as text, which is the web address itself. If the browser or app also provided a formatted version, for example the page title as a clickable link, that is saved too. When you paste it later, apps that only accept plain text, such as Notepad, get the web address, while apps such as Word or Outlook get the formatted link, just like the original copy. When **Link previews** is on and you copy a single web address, the title, description, and preview picture of its card are saved with it too.

- **Colors.** A copied color code is saved as text, exactly as you copied it. The color swatch is made from the text whenever it's shown, so nothing extra is saved.

- **Pictures copied from a web page.** When you use **Copy image** in a browser, the browser usually places the picture itself on the clipboard, often along with a bit of web code that points to where the image came from. The TopBar saves the picture in full along with that web code, so the picture stays available even after you close the page or the image is removed from the website. The bucket card shows the picture itself.

- **Screenshots and other pictures without a file.** A screenshot taken with the Snipping Tool or the Print Screen key, or a picture copied in an app such as Paint, is placed on the clipboard as a picture with no file behind it. The TopBar saves the picture in full, so you can paste it later even if you never saved it as a file.

- **Image files and other files.** When you copy files in File Explorer, the TopBar doesn't copy the files themselves. It only saves each file's name, location (its full path, such as `C:\Users\You\Pictures\photo.jpg`), type, and size. The files stay where they are, and:
   * The thumbnails on the bucket card and in the details window are made by Windows from the original files whenever they're needed, so they're never stored.
   * When you paste them later, the files are taken from their original locations at that moment, so you get their latest version.
   * If a file is moved, renamed, or deleted, or its drive is disconnected, the TopBar can no longer show its thumbnail or paste it. The item stays in the bucket until you delete it, and pasting the bucket skips that file.

- **Several files at once.** Each file becomes its own item in the same bucket, so you can see, drag, and delete each one separately in the details window. If you copy a file that is already in the bucket, only the newest copy of it is kept.

- **Files inside a zip archive.** Files that you copy straight out of a zip archive opened in File Explorer, without extracting it first, don't exist as ordinary files on your drive yet, so the TopBar has no location to remember and doesn't save them. Extract the archive first, then copy the files.

- **Folders.** Folders aren't saved. If you copy folders together with files, only the files are saved.

- **Mixed content.** Some apps place several kinds of content on the clipboard at once, such as text together with a picture. The TopBar saves all of them as one item, so the app you paste into can use the kind it understands.

> [!NOTE]\
> Each copied picture can be up to 64 MB in size. If you copy a bigger one, nothing from that copy is saved, and the status line at the top of the view tells you the item could not be saved.

#### Where Your Clipboard History Is Stored

- **One private folder.** Everything the Clipboard view saves is kept in a folder in the app's private data folder on your OS drive: `%LocalAppData%\Packages\VioletHansen.HardenSystemSecurity_ea7andspwdn10\LocalCache\TopBarClipboard`
   * `Index.dat` holds the list of your collections, buckets, and items, with the text of each item.
   * Every picture, every formatted version of a copy, and every link card picture is kept in an encrypted file of its own, named with a random code. These files are only opened when a picture is shown or a copy is pasted, so even a full history of 10 collections with 1,000 buckets each opens quickly.

- **See how much space it takes.** While the Clipboard view is selected, the standard notch shows how much space this folder takes on your drive next to the view name, for example **Clipboard 2.4 MB**. It counts every file in the folder and updates on its own whenever anything is saved, changed, moved, or deleted, including when you use **Clear all**. The slim notch doesn't show it, to stay as small as possible.

- **Only you can read it.** Every file in this folder is encrypted with the data protection built into Windows and tied to your own Windows user account. Only your user account can decrypt them, so other accounts on the same computer can't read them even if they can open the files. Each time something changes, the list is encrypted and saved again, and the files of deleted items are deleted.

- **Pasting never leaves an unencrypted copy.** When you paste or drag a saved picture, it is decrypted in memory and handed straight to the app you paste into. No unencrypted copy is written to your drive.

- **What's inside it:**
   * The full text you copied, including links and color codes, and its formatted versions (HTML and Rich Text).
   * The full picture data of the pictures and screenshots you copied.
   * For files, only their name, location, type, and size.
   * The date and time you copied each item.
   * For link cards, the page's title, short description, and preview picture.
   * Your collection names, your bucket names, the order of your buckets, which bucket or **NEW BUCKET** card is selected in each collection, and which collection is selected.

- **What's never inside it:** the contents of your files, thumbnails, folders, website icons, and anything the app you copied from marked as private.

- **Ready for future updates.** The saved files carry a version number, so future versions of the app that save more information about each item can still read the history you already have. Updating the app won't make you lose your clipboard history.

- **Not backed up, removed on uninstall.** Windows doesn't include this folder in app data backups, and removes it when you uninstall the app. Use **Export** to keep a copy of it.

- **Take your history with you.** Before you reinstall Windows or move to another computer, select the **Export or import** button, select **Export**, and choose where to save the zip file. After you install the app again, turn on clipboard history, select the same button, select **Import**, and pick that zip file.
   * The zip file holds every collection, bucket, and item, with their names and order, the full pictures, the formatted versions of your copies, and the link card pictures.
   * The zip file is **not encrypted**, so anyone who gets it can read everything you copied. Keep it somewhere safe, and delete it once you have imported it.
   * Import replaces your whole current clipboard history with the history in the zip file. The imported history is encrypted for your Windows user account again, just like before.
   * Copied files are saved by their location only, so the files themselves aren't in the zip file. Put them back in the same locations if you want to paste them from your buckets.
   * Clipboard history must be on to export or import.

<div align="center">

<img alt="image" src="https://github.com/user-attachments/assets/e30de57b-4f90-485b-a900-bb4ea8cbcd67" />

</div>

<br>

> [!TIP]\
> Turn on **Start with Windows** in the settings menu so the TopBar is running and saving your copies from the moment you sign in. Copies made while the TopBar is closed aren't saved.

## The Companion

<div align="center">

<img alt="TopBarNextVer" src="https://github.com/user-attachments/assets/c0f23c7b-0446-42a2-9e41-661be6fef334" />

</div>

<br>

Beside the active view you can display a small, charming animated **companion**, a bit of personality for your bar. You can choose from several delightful characters:

- **PrisMatrix** (a rotating geometric prism, and the default)

- **NullCat** (a cat typing on a laptop)

- **Bunny**

- **Squirrel**

- **PopForge** (a playful toaster)

Or you can turn the companion off entirely if you want. Each companion only uses resources while it's actually on screen.

## Settings and Handy Options

A settings menu in the expanded bar lets you tailor how the TopBar behaves:

- **Notch style.** Switch between the standard and the slim notch when Shy Bar mode is off.

- **Open on hover.** Choose whether the bar opens automatically on hover, or only when clicked/tapped.

- **Shy Bar mode.** Hide the TopBar completely, including its notch, and reveal it by moving your pointer back and forth three times along its screen edge. This deliberate gesture helps prevent the bar from appearing accidentally. Turning the mode off restores the normal collapsed notch.

- **Always on top.** Keep the bar above every other window so it's always visible.

- **Pin open.** Keep the bar expanded so it doesn't retract while you work with it. This option is unavailable while Shy Bar mode is enabled.

- **Companion.** Pick your animated companion (or none).

- **Start with Windows.** Have the TopBar appear automatically when you sign in. If you've turned this off elsewhere in Windows (such as in Task Manager), the app respects that and lets you know.

There are also quick buttons to **add** a new item to the current view, and to **close** the bar entirely.

## Thoughtful Details

- **It stays out of the way.** The bar hugs the top edge of your screen with softly rounded lower corners and gentle "flared" upper edges, so it looks like it grows naturally out of the top of your display. It doesn't appear in the taskbar or the task switcher.

- **It's light on your system.** The live tools only do their work while you're actually looking at them and the bar is open. A collapsed bar costs practically nothing.

- **Your choices are remembered.** Your pinned apps, folders, websites, clocks, companion choice, notch style, Shy Bar mode choice, Search **Max results** number and large thumbnails choice, the Clipboard history and Link previews switches, and all your Sentry preferences are saved automatically, so the bar looks and behaves exactly the same the next time you open it.

- **One bar at a time.** Even if you have more than one copy of the app running, only a single TopBar is shown, so it never clutters your screen.

- **It matches your theme.** The bar follows your app's light or dark theme, including when Windows switches themes automatically.

### In Short

The TopBar is a compact, always‑at‑hand command center that tucks neatly into the top of your screen. Whether you're launching apps, jumping to folders, searching among every file in your system, reviewing drive statistics, opening websites, watching your system's performance, keeping time across the world, checking your connection quality, letting the Acoustic Sentry listen for you, or keeping an encrypted history of everything you copy, it's all a quick glance (and a gentle hover) away, wrapped up with a bit of animated charm.
