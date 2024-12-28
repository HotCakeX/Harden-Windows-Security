# Create Supplemental App Control Policy

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/AppControl%20Manager%20page%20screenshots/Create%20Supplemental%20Policy.png" alt="AppControl Manager Application's Create Supplemental App Control Policy Page">

</div>

<br>

<br>

Use [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) to create Supplemental App Control policies for your base policies. Use Supplemental policies to expand the scope of your base policies by allowing more files or applications.

<br>

## Create a Supplemental Policy by Files or Folders Scan

With AppControl Manager, you can easily create a supplemental policy by scanning files or folders. If an application or file is being blocked by Application Control, use this feature to scan its files or installation directory. This process enables you to generate a supplemental policy that ensures the application or file can run seamlessly on your system.

### Configuration Details

* **Browse For Files**: Use this button to browse for files on the system. Multiple files can be added at once.

* **Browse for Folders**: Use this button to browse for folders on the system. Multiple folders can be added at once.

* **Policy Name**: Enter a name for the Supplemental policy. You will be able to use this name to detect it after deployment in the **System Information** section of the AppControl Manager.

* **Base Policy File**: Browse for the path to the base policy XML file that this Supplemental policy will be expanding.

* **Scalability**: Use this gauge to set the number of concurrent threads for the scan. By default, 2 threads are used. Increasing this number will speed up the scan but will also consume more system resources.

* **Select Scan Level**: You can choose from different scan levels. [Refer to this page for all the information about them.](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Rule-Levels-Comparison-and-Guide)

> [!TIP]\
> Use the ***View Detected File Details*** section to view highly detailed results of the files and folder scans.

<br>

## Create a Supplemental Policy from Certificate Files

If you have certificate `.cer` files, you can use this feature to scan them and create a Supplemental App Control policy based on them. Once deployed, it will allow any file signed by those certificates to run on the system.

### Configuration Details

* **Browse For Certificates**: Use this button to browse for certificate `.cer` files on the system. Multiple files can be added at once.

* **Policy Name**: Enter a name for the Supplemental policy. You will be able to use this name to detect it after deployment in the **System Information** section of the AppControl Manager.

* **Base Policy File**: Browse for the path to the base policy XML file that this Supplemental policy will be expanding.

* **Signing Scenario**: Choose between User Mode or Kernel Mode signing scenarios. If you choose User Mode, the supplemental policy will only allow User Mode files signed by that certificate to run and Kernel mode files such as drivers will remain blocked.

<br>
