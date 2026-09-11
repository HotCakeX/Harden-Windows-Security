# Home Page

The **Home page** is the landing/overview surface of the app. It presents a live, at‑a‑glance dashboard of the machine's identity, hardware, operating system, security posture, and real‑time telemetry.

> [!NOTE]\
> The page has two entry points into richer experiences for [the Harden System Security app](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden-System-Security) only.
> 
> - An entry to the [**Windows TopBar**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/TopBar).
> - An entry to the **Live System Intelligence** window (documented in full at the end).

## What the Home Page Shows You

The Home page is your system's dashboard. The moment you open it, it fills in with details about your computer and keeps the live values fresh while you're looking at them. Everything is organized into tidy cards so you can scan the whole picture quickly, and some cards can be clicked to reveal a deeper view.

The page is split into two areas:

- **System Overview**: Your computer's identity, hardware, operating system, activation, network, and live performance readings.

- **Online Microsoft Defender Status**: The latest antivirus engine and definition information published by Microsoft.

Cards that you can click show a small arrow in their corner. Clicking them opens a window with much more detail about that topic. Cards without the arrow are simply live readouts.

## System Overview

### Identity and Session

- **System Time**: The current time on your computer, shown in your preferred 12‑hour or 24‑hour format, along with your time zone's offset from UTC.

- **User**: The account you're signed in as, and whether the app is currently running with administrator privileges or as a standard (unelevated) session.

- **Computer Name**: Your PC's name. Click this card to rename your computer. Renaming requires administrator privileges, and the app confirms whether the change succeeded.

- **System Model**: The manufacturer and model of your computer.

### Operating System and Activation

- **Operating System**: Your Windows edition, version, and build number.

- **Windows Activation**: A quick summary of whether Windows is genuine and how it was licensed. Click the card to see the full activation and licensing breakdown, including license status, product key channel, digital license details, subscription information, and more.

- **Uptime**: How long your computer has been running since it was last started. Click to see additional shutdown and startup details.

- **Last Boot Time**: How long the firmware startup (the phase before Windows loads) took, shown in seconds.

### Memory and Storage

- **System RAM**: The total amount of memory installed, along with its type and speed (for example, DDR5 5600 MT/s).

- **App RAM Usage**: How much memory the app itself is using right now, along with a small live graph showing the last 60 seconds.

- **Storage Size and Temperature**: The combined capacity of your fixed drives and the current temperature of each drive, with a live graph tracking the hottest drive over the last 60 seconds.

- **USB Device History**: A count of every USB storage device that has ever been connected to this computer. Click to see the full list with each device's name and identifier.

### Network

- **Internet Speed**: Your live download and upload speeds, plus the running totals of data received and sent.

- **IP Address**: Your public IP address. For privacy, it isn't looked up automatically, click the card to retrieve it, and click again to refresh it. It uses secure anonymous Cloudflare and AWS servers.

- **Open Network Ports**: How many network ports are currently listening for connections, split into TCP and UDP. Click to see the details of those open ports.

### Processor and Graphics

- **CPU**: Your processor's name, core and thread counts, architecture, base speed, cache size, and socket count.

- **GPU**: The name of your graphics hardware. Click to see full details such as manufacturer, driver version and date, and device identifiers.

- **CPU Temperature**: The current temperature of your processor, with a live graph covering the last 60 seconds.

### Power and Hardware Identity

- **Power Plan**: The name of the power plan Windows is currently using.

- **System Serial Number**: Your computer's serial number.

- **System UUID**: The unique hardware identifier assigned to your computer.

- **Baseboard Serial Number**: The serial number of your motherboard.

- **Chassis Serial / Asset Tag**: The serial number of your computer's chassis and, if one is assigned, its asset tag.

## Online Microsoft Defender Status

This section shows the newest Microsoft Defender information published online by Microsoft. These are the latest available values, which is handy for checking whether newer protection is out there compared with what your machine already has:

- **Engine Version**: The latest antimalware engine version.

- **Signature Version**: The latest antivirus definition version.

- **Platform Version**: The latest Defender platform version.

- **Signature Update Date**: When those latest definitions were published (in UTC).

If your computer is offline or the information can't be retrieved, these cards simply show "Unavailable."

## Keeping Things Light

The Home page is designed to be gentle on your system. Its live readings and subtle background animation are only active while you're actually viewing the page. As soon as you move to another part of the app, everything on the page winds down so it **isn't** quietly using resources in the background.

## Live System Intelligence

<br>

<div align="center">

<a href="https://www.youtube.com/watch?v=-NH51-L80Tc">
<img src="https://raw.githubusercontent.com/HotCakeX/.github/422e1331fb6e7c5fe2fe8317fb17056fd12ee2a1/Pictures/PNG%20and%20JPG/Live%20System%20Intelligence%20Video%20Thumbnail.png" alt="Harden System Security's Live System Intelligence dashboard demo" />

</a>

</div>

> It's a YouTube video. Click to play it.

<br>

At the top of the System Overview area, next to the section title, is a button that opens the **Live System Intelligence** window; a full, immersive, real‑time view of how your computer is performing.

Like the Home page itself, this window is careful with resources: it does nothing in the background when it's closed. If you leave it open and move to another part of the app, its graphs keep updating; once you close it, everything stops.

### Live Performance Graphs

The window presents a wall of live graphs, each updating every couple of seconds. Every graph is interactive, hover or tap along the line to see the exact value at that moment in time. The built‑in graphs cover:

- **App RAM**: Memory used by the app.

- **System Memory Utilization**: How much of your total RAM is in use, as a percentage.

- **Storage Temperature**: The temperature of your hottest drive.

- **CPU Temperature**: Your processor's temperature.

- **CPU Usage**: How hard your processor is working, as a percentage.

- **Disk Activity**: Read and write speeds of your storage.

- **Network Usage**: Your combined upload and download activity.

- **Total System Power**: The overall power draw of your system, in watts (on supported hardware).

- **Battery Discharge**: How quickly your battery is discharging, in watts (on supported hardware).

- **GPU Usage**: In addition, a separate live graph appears automatically for **each graphics card** in your system, showing how busy it is.

### Popping Out a Graph

Every graph's title can be clicked to "pop it out" into its own floating, always‑on‑top window that you can resize and place anywhere on screen. Close the pop‑out and the graph slides right back into the dashboard. You can even launch a specific graph straight from the app's taskbar shortcuts.

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/Widgets/Desktop%20Widgets%202.png" alt="Harden System Security Windows Desktop Widget Screenshot"/>

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/Widgets/Desktop%20Widgets%201.png" alt="Harden System Security Windows Desktop Widget Screenshot"/>

<br>

</div>

### Personalizing the View

A control strip at the top lets you tailor the experience:

- **Background**: Choose between an animated **Tesseract** backdrop or a **Black Hole** effect, or turn the background off entirely.

- **Background style and opacity**: Pick a color theme for the Tesseract and dial the background's intensity up or down.

- **Chart animations**: Turn the smooth graph animations on or off.

- **Graph size**: Switch between Small, Medium, and Big layouts to fit more graphs on screen or make each one larger.

A glowing "Live System Intelligence" title badge and a playful heart button add a bit of personality to the window.

### Extra Diagnostics

Below the graphs, a row of tabs opens a set of deeper, hands‑on diagnostic tools:

- **Network Openness**: Runs a quick check of how reachable a curated list of popular websites and services is from your current network, grouped into categories such as social media, messaging, news, search, developer tools, and privacy tools. It gives you an overall openness score along with a per‑category breakdown and a detailed log, a great way to understand how open or restricted your internet connection is.

- **Wi‑Fi Profiles**: Lists the saved Wi‑Fi networks on your computer and shows details for each one, such as its security type, encryption, and connection settings.

- **Physical Orientation**: A live 3‑D view of how your device is physically tilted and moving, using your device's motion sensors (pitch, roll, yaw, and movement state), on hardware that has them.

- **Compass**: A live compass showing your heading, direction, and accuracy, on devices with a magnetometer.

- **Light Sensor**: A live ambient‑light meter showing the brightness around you in lux, a plain‑language rating, and helpful notes, on devices with a light sensor.

To stay efficient, only the diagnostic tab you're currently viewing does any live updating.

### In Short

The Home page gives you a clear, all‑in‑one snapshot of your computer, who and what it is and how it's doing. And when you want to go deeper, the Live System Intelligence window turns that snapshot into a living, real‑time cockpit complete with pop‑out graphs, per‑GPU tracking, power and battery insights, and a handy set of network and sensor diagnostics.
