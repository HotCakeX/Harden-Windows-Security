## TopBar in the Harden System Security App

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

The TopBar can display one tool at a time, and you switch between them from a small menu inside the expanded bar. Whichever view you pick, the bar automatically resizes itself to fit that view's content. Below is an overview of the available views:

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

It is a decibel‑triggered environment audio watchdog security capability. Arm it, and it quietly listens to the ambient sound level; the moment the environment crosses a threshold you define, it captures high‑fidelity audio to disk, then waits out a cooldown before it's allowed to trigger again. It keeps working whether the workstation is locked or not. Use it to detect unusual or suspicious sounds in your environment when you are away from your device.

> [!TIP]\
> Example Scenario: You are away from your home and the Acoustic Sentry is armed on the device at your home. If a loud noise occurs, such as a window breaking, or door unlocking while you are away, the Sentry will automatically capture the audio and save it to the designated folder. You define how long it should record for each incident and control all aspects of it. **Set the save location to OneDrive and then listen to the recordings from anywhere in the world.** Your own private secure monitoring solution.

#### Highlights

* **Decibel‑triggered capture**: Set a custom trigger level (in dBFS). When the ambient level reaches or exceeds it, recording begins automatically.

* **Arm / Disarm**: A single toggle opens or releases the microphone. The mic is only ever held open while a session is armed, nothing is captured or monitored when idle.

* **Manual stop**: End the in‑flight capture at any time without waiting for its duration to elapse.

* **Custom capture duration**: Choose how many seconds each capture lasts once triggered.

* **Cooldown / cadence control**: A configurable gap (timeout) governs how often a capture can repeat, so a continuously loud room doesn't record endlessly.

* **Cycle limit**: Cap how many captures a session performs before it disarms itself, or set it to unlimited.

* **Custom output folder**: Save captures anywhere you like, with Browse / Open / Reset controls. Defaults to a named folder in your user profile: %UserProfile%\Harden System Security Sentry.

* **Works while locked**: Capture is bound to the process rather than the desktop, so it continues across lock/unlock.

* **Highest audio quality**: Recordings are written as lossless WAV PCM at the microphone's native sample rate and channel count (24‑bit), no resampling, no fidelity loss.

* **Live level graph**: A lightweight, scrolling meter shows the ambient level in real time and turns red the instant it crosses your trigger, so you can read the threshold straight off the graph. The meter only runs while the Sentry view is expanded and armed; it costs nothing otherwise.

* Very efficient and low system resource usage.

#### Clear, actionable error reporting

When a session can't be armed, the status area tells you exactly why:

* Microphone muted, detected up front; the Sentry refuses to arm on a device that can't hear anything, instead of silently recording nothing.

* Access turned off, surfaces a one‑click "Open mic settings" shortcut to the Windows microphone privacy page.

* No microphone found / unsupported format, explained plainly.

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

- **Your choices are remembered.** Your pinned apps, folders, clocks, companion choice, notch style, and all your Sentry preferences are saved automatically, so the bar looks and behaves exactly the same the next time you open it.

- **One bar at a time.** Even if you have more than one copy of the app running, only a single TopBar is shown, so it never clutters your screen.

- **It matches your theme.** The bar follows your app's light or dark theme, including when Windows switches themes automatically.

### In Short

The TopBar is a compact, always‑at‑hand command center that tucks neatly into the top of your screen. Whether you're launching apps, jumping to folders, watching your system's performance, keeping time across the world, checking your connection quality, or letting the Acoustic Sentry listen for you, it's all a quick glance (and a gentle hover) away, wrapped up with a bit of animated charm.
