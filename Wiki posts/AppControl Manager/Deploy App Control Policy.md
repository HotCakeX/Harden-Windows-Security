# Deploy App Control Policy

![AppControl Manager Application's Deploy App Control Policy Page](https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/AppControl%20Manager%20page%20screenshots/Deploy%20App%20Control%20Policies.png)

Use this [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) page to select XML policy files or `.cip` binary files to deploy on the local/cloud systems or convert XML files to CIP files for manual deployment.

- [![AppControl Manager Menu Item](https://raw.githubusercontent.com/HotCakeX/.github/7ac3898730bc82a790f56a61e301b6663dfc9d5a/Pictures/Gifs/AppControl%20Manager%20Menu/Microsoft%20Graph.gif)](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Microsoft-Graph) [**Microsoft Graph Button**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Microsoft-Graph).

> [!IMPORTANT] > **Intune Cloud Deployment**
>
> Please [**refer to this page**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/How-To-Upload-App-Control-Policies-To-Intune-Using-AppControl-Manager) for details on how to upload App Control Policies to Intune using AppControl Manager.

## Configuration Details for Unsigned XML Policy Files Deployment

- **Browse**: Use this button to browse for App Control XML policy files that you want to deploy as unsigned policies.

- **Deploy**: Use this button to deploy all of the XML files you selected on the local or cloud system.

## Configuration Details for Signed XML Policy Files Deployment

![AppControl Manager Application's Content Dialog for Policy Signing details](https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/AppControl%20Manager%20page%20screenshots/Deploy%20Signed%20App%20Control%20Policies%20Dialog.png)

- **Browse**: Use this button to browse for App Control XML policy files that you want to Sign and deploy.

- **Deploy**: Use this button to deploy all of the XML files you selected on the local or cloud system.

- **Sign Only - No Deployment**: If you only want to sign the policy without deploying it, you can use this button. It will generate the signed CIP file for you that you can use to manually deploy somewhere else.

When signing and deploying App Control Policies, a dialog will be displayed asking for additional information required for signing the policy.

- **Certificate File**: Provide the path to the certificate `.cer` file. It must be a code signing certificate that is either issued by a public certificate authority (CA) or a self-signed certificate. You can generate a self-signed certificate suitable for App Control policy signing in [the certificate building page](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Build-New-Certificate) of the AppControl Manager. The certificate's details will be added to the XML policy as signers. The certificate must exist in the Personal store of the Current User certificate stores with private key.

- **Certificate Common Name**: The Common Name (CN) of the same certificate file you select.

Once you've provided both items, press the **Verify** button. It will verify your inputs and then the **Submit** button will be enabled, allowing you to proceed with policy signing and deployment.

All of the information you submit will be saved in app settings so that the next time they will be automatically populated for you.

## Configuration Details for CIP Binary Files Deployment

This section can deploy `.CIP` binary files on the local or cloud system, whether they are signed or unsigned.

- **Browse**: Use this button to browse for App Control `CIP` binary files that you want to deploy.

- **Deploy**: Use this button to deploy all of the CIP files you selected on the local or cloud system.

## Configuration Details for Converting XML to CIP Files

Use this section to convert all of your XML files to CIP binaries files in bulk.

- **Browse**: Use this button to browse for App Control XML policy files that you want to convert to `CIP` binary files.

- **Convert**: Use this button to convert all of the selected XML policy files to `CIP` binary files with the same file names.
