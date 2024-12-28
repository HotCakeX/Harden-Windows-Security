# Deploy App Control Policy

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/AppControl%20Manager%20page%20screenshots/Deploy%20App%20Control%20Policies.png" alt="AppControl Manager Application's Deploy App Control Policy Page">

</div>

<br>

<br>

Use this [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) page to select XML policy files or `.cip` binary files to deploy on the system.

<br>

## Configuration Details for Unsigned Deployment

* **Select XML Policy File(s)**: Use this button to browse for App Control XML policy files.

* **Select CIP Binary File(s)**: Use this button to browse for App Control CIP binary files.

* **Deploy**: Use this button to deploy all of the XML and CIP files you selected on the system.

<br>

## Configuration Details for Signed Deployment

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/AppControl%20Manager%20page%20screenshots/Deploy%20Signed%20App%20Control%20Policies%20Dialog.png" alt="AppControl Manager Application's Content Dialog for Policy Signing details">

</div>

<br>

<br>

When signing and deploying App Control Policies, a dialog will be displayed asking for additional information required for signing the policy.

* **Certificate File**: Provide the path to the certificate `.cer` file. It must be a code signing certificate that is either issued by a public certificate authority (CA) or a self-signed certificate. You can generate a self-signed certificate suitable for App Control policy signing in [the certificate building page](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Build-New-Certificate) of the AppControl Manager. The certificate's details will be added to the XML policy as signers. The certificate must exist in the Personal store of the Current User certificate stores with private key.

* **Certificate Common Name**: The Common Name (CN) of the same certificate file you select.

* **SignTool Path**: The path to the `SignTool.exe`. If you don't have it, you can toggle the **Auto Acquire** switch. Auto Acquire will try to first find it on the system by checking for installed Windows SDK, if it cannot find it, it will download it from the official Microsoft server.

Once you've provided all 3 items, press the **Verify** button. It will verify your inputs and then the **Submit** button will be enabled, allowing you to proceed with policy signing and deployment.

All of the information you submit will be saved in app settings so that the next time they will be automatically populated for you.

<br>
