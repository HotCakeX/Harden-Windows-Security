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

- **Two notch shapes.** You can choose between the standard notch (which shows an icon, the tool name, and a little chevron) or a slimmer, lower‑profile notch that takes up even less of your screen.

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

- **Notch style.** Switch between the standard and the slim notch.

- **Open on hover.** Choose whether the bar opens automatically on hover, or only when clicked/tapped.

- **Always on top.** Keep the bar above every other window so it's always visible.

- **Pin open.** Keep the bar expanded so it doesn't retract while you work with it.

- **Companion.** Pick your animated companion (or none).

- **Start with Windows.** Have the TopBar appear automatically when you sign in. If you've turned this off elsewhere in Windows (such as in Task Manager), the app respects that and lets you know.

There are also quick buttons to **add** a new item to the current view, and to **close** the bar entirely.

## Thoughtful Details

- **It stays out of the way.** The bar hugs the top edge of your screen with softly rounded lower corners and gentle "flared" upper edges, so it looks like it grows naturally out of the top of your display. It doesn't appear in the taskbar or the task switcher.

- **It's light on your system.** The live tools only do their work while you're actually looking at them and the bar is open. A collapsed bar costs practically nothing.

- **Your choices are remembered.** Your pinned apps, folders, websites, clocks, companion choice, notch style, Search **Max results** number and large thumbnails choice, and all your Sentry preferences are saved automatically, so the bar looks and behaves exactly the same the next time you open it.

- **One bar at a time.** Even if you have more than one copy of the app running, only a single TopBar is shown, so it never clutters your screen.

- **It matches your theme.** The bar follows your app's light or dark theme, including when Windows switches themes automatically.

### In Short

The TopBar is a compact, always‑at‑hand command center that tucks neatly into the top of your screen. Whether you're launching apps, jumping to folders, searching among every file in your system, reviewing drive statistics, opening websites, watching your system's performance, keeping time across the world, checking your connection quality, or letting the Acoustic Sentry listen for you, it's all a quick glance (and a gentle hover) away, wrapped up with a bit of animated charm.
