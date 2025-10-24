# Simulation

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/AppControl%20Manager%20page%20screenshots/Simulation.png" alt="AppControl Manager Application's Simulation Page">

</div>

<br>

<br>

The Simulation page in [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) allows you to simulate an App Control for Business policy deployment. Simply select folders or files and a policy XML file, it will show you whether the selected files would be allowed or blocked by your App Control policy if it was actually deployed on a system and those files were running.

There will be very detailed results of each file that participates in the Simulation process. You can use sorting and search features to categorize and find the files quickly.

<br>

## Some Use Cases

* Have an App Control policy and you want to test whether all of the files of a program will be allowed by the policy without running the program first? Use this App Control simulation to find out.

* Employ this simulation method to discover files that are not explicitly specified in the App Control policy but are still authorized to run by it due to implicit authorization.

* Identify files that have hash mismatch and will not be permitted by App Control engine using signature. These files are typically found in [*questionable* software](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Notes#allowing-questionable-software-in-a-wdac-policy) because they are tampered with.

* And many more use cases...

<br>

## Configuration Details

* **Select XML File**: Use this button to browse for the App Control XML policy file that will be used for the simulation.

* **Select Files**: Use this button to browse for file(s) to be tested against the selected policy.

* **Select Folders**: Use this button to browse for folder(s) the files of which will be tested against the selected policy.

* **Scalability**: Use the gauge to select the number of threads to be used for the simulation. The more threads you use, the faster the simulation will be completed and the more CPU/Disk resources will be consumed.

* **Cat Root Paths**: Browse for one or more folders that contain `.cat` security catalogs. Security catalogs are signed objects that include the hashes of other files. Code Integrity in Windows uses these files to determine the signing status of unsigned files. The security catalogs in the folders you specify will be used to determine the signing status of the files you are testing.

> [!TIP]\
> Files do not need to contain a digital signature in order to be considered as signed in the OS. If a file's hash is included in one of the installed security catalogs on the system, its signing status will be acquired from the security catalog, and it will be considered a signed file.

* **No Cat Root Scanning**: It's a toggle button. You can use it to turn off the scanning of security catalogs that are installed on the system by default. If it is turned off, the results of the simulation might not be accurate if the signing status of some of the files depend on security catalogs to be determined.

* **Save Output to CSV**: Use this toggle button to save the output of the App Control Simulation to a CSV file at the end.

* **Clear Data**: Use this button to clear the Simulation results data displayed on the page.

<br>
