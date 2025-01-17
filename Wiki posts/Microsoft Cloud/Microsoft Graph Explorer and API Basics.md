# Microsoft Graph Explorer and API Basics

Use the [aka.ms/ge](https://aka.ms/ge) link to access the Microsoft Graph Explorer. You will need to sign into your tenant to access the Microsoft Graph Explorer and provide the necessary permissions to access the data you want to work with.

<br>

## How To Get The Tenant ID Using Microsoft Graph Explorer

Send a `GET` request to the following endpoint:

```
https://graph.microsoft.com/beta/organization
```

<br>

## How To List All Intune Device Configuration Policies Using Microsoft Graph Explorer

Send a `GET` request to the following endpoint:

```
https://graph.microsoft.com/beta/deviceManagement/configurationPolicies
```

<br>

## How To Get A Specific Intune Device Configuration Policy Using Microsoft Graph Explorer

Send a `GET` request to the following endpoint (replace `PolicyID` with the ID of the policy you want to get):

```
https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/{PolicyID}
```

Example:

```
https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/0f6899f8-f2af-49b9-90c7-dd9ab7315fea
```

<br>

## How To Upload Intune Device Configuration Policies Using Microsoft Graph Explorer

Send a `POST` request to the following endpoint:

```
https://graph.microsoft.com/beta/deviceManagement/configurationPolicies
```

And in the request body, include the JSON payload for the device configuration policy you want to upload. [You can find them in here.](https://github.com/HotCakeX/Harden-Windows-Security/tree/main/Intune%20Files/Hardening%20Policies)

<br>

## How To List Intune Device Compliance Policies Using Microsoft Graph Explorer

Send a `GET` request to the following endpoint:

```
https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies
```

<br>

## How To Upload Intune Device Compliance Policies Using Microsoft Graph Explorer

Send a `POST` request to the following endpoint:

```
https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies
```

And in the request body, include the JSON payload for the device compliance policy you want to upload. [You can find them in here.](https://github.com/HotCakeX/Harden-Windows-Security/tree/main/Intune%20Files/Compliance)

<br>

## How To Upload An App Control Policy Through Intune custom OMA-URI Using Microsoft Graph Explorer

Send a `POST` request to the following endpoint:

```
https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations
```

And in the request body, include the following JSON payload

```JSON
{
  "@odata.type": "#microsoft.graph.windows10CustomConfiguration",
  "displayName": "Custom OMA-URI Policy",
  "description": "Custom policy for Application Control",
  "omaSettings": [
    {
      "@odata.type": "microsoft.graph.omaSettingBase64",
      "displayName": "Application Control Policy",
      "description": "Configure application control policy using OMA-URI.",
      "omaUri": "./Vendor/MSFT/ApplicationControl/Policies/d41d8cd9-8f00-b204-e980-0998ecf8427e/Policy",
      "fileName": "Policy.bin",
      "value": "PD94bWwgdmVyc2lvbj0iMS4wIj8+CjxQb2xpY3k+CiAgPENvbnRlbnQ+QXBwbGljYXRpb24gY29udHJvbCBwb2xpY3k8L0NvbnRlbnQ+CjwvUG9saWN5Pg=="
    }
  ],
  "platforms": [
    "windows10AndLater"
  ]
}
```

The `Value` must be the Base64 representation of your `.CIP` file.

<br>
