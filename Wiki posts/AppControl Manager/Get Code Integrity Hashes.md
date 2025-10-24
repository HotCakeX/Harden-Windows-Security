# Get Code Integrity Hashes

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/AppControl%20Manager%20page%20screenshots/Get%20Code%20Integrity%20Hashes.png" alt="AppControl Manager Application's Get Code Integrity Hashes Page">

</div>

<br>

<br>

Use this [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) page to calculate Code Integrity hashes of the files. Code Integrity hashes are those that the Code Integrity in Windows primarily uses: SHA1 and SHA2-256 1st page hashes, SHA1 and SHA2-256 Authenticode hashes.

Use the browse button to select a file and the hashes will be immediately calculated and displayed on the page.

> [!NOTE]\
> If the selected file is non-conformant, the app will calculate the flat hashes of the file and present them as Authenticode hashes. When that happens, the page hashes will be displayed as `N/A`. This is compliant with how the App Control engine in Windows works.

<br>

This page also calculates the new [secure](https://csrc.nist.gov/pubs/fips/202/final) SHA3-384 and SHA3-512 flat file hashes.

<br>

