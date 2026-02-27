# Microsoft Graph

The AppControl Manager offers integration with Microsoft Graph to allow you to manage your Microsoft 365 tenants. This integration allows you to perform various operations such as logging into multiple different tenants and user accounts, and choosing which one to use for each operation.

<br>

## Sign In

### Sign In button <img src="https://raw.githubusercontent.com/HotCakeX/.github/7ac3898730bc82a790f56a61e301b6663dfc9d5a/Pictures/Gifs/AppControl%20Manager%20Menu/Microsoft%20Graph%20-%20Sign%20in.gif" alt="Sign In" width="30" />

Use this button to sign in to your Microsoft 365 account. You will be prompted to enter your credentials, and once signed in, you will be able to access the features of the AppControl Manager that require Microsoft Graph access.

### Cancel Sign In <img src="https://raw.githubusercontent.com/HotCakeX/.github/7ac3898730bc82a790f56a61e301b6663dfc9d5a/Pictures/Gifs/AppControl%20Manager%20Menu/Microsoft%20Graph%20-%20Cancel%20Sign%20in.gif" alt="Cancel Sign In" width="30" />

Use this button to cancel the sign-in process. This only works if you've already pressed the Sign In button to initiate the sign in process.

### Sign In Method

* WebAccountManager: This will launch a native Windows sign-in dialog, allowing you to select any existing accounts or sign into new accounts.

* WebBrowser: This will launch a web browser window for you to sign in. After signing in the browser, the application will receive the authentication token automatically.

### Authentication Context

Here you can select the authentication context for the sign-in process. They are groups of permissions that the application will request from Microsoft Graph in order to perform certain operations.

Available authentication contexts:
* **Intune**: Requests permissions required to create, read, update, and delete device configuration policies, groups, and scripts (`Group.ReadWrite.All`, `DeviceManagementConfiguration.ReadWrite.All`, `DeviceManagementScripts.ReadWrite.All`).
* **MDEAdvancedHunting**: Requests permissions required to retrieve Microsoft Defender for Endpoint Advanced Hunting queries (`ThreatHunting.Read.All`).

### Azure Cloud Environment

Here you can select the target Azure Cloud environment for your authentication session.

* **Public**: The standard Microsoft Azure public cloud environment.
* **US Government (GCC High)**: The US government cloud environment.

<br>

## Signed In Accounts

### Remove <img src="https://raw.githubusercontent.com/HotCakeX/.github/7ac3898730bc82a790f56a61e301b6663dfc9d5a/Pictures/Gifs/AppControl%20Manager%20Menu/Microsoft%20Graph%20-%20Log%20Out.gif" alt="Remove" width="30" />

After selecting an account from the list, you can remove it by clicking this button. This will log you out of the selected account and remove it from the list of signed-in accounts. It will also completely remove its authentication token from the application's memory.

### Set Active Account <img src="https://raw.githubusercontent.com/HotCakeX/.github/7ac3898730bc82a790f56a61e301b6663dfc9d5a/Pictures/Gifs/AppControl%20Manager%20Menu/Microsoft%20Graph%20-%20Set%20Active%20Account.gif" alt="Set Active Account" width="30" />

After selecting an account from the list, you can set it as the active account by clicking this button. This will make the selected account the default account for all operations that require Microsoft Graph access in the page you are currently on.

The Signed In Accounts list displays the following details for each authenticated session to help you manage multiple logins:
* Username
* Tenant ID
* Account Identifier
* Permissions
* Environment

<br>

## Active Account

This section shows you the details of the currently active account that will be used for all operations that require Microsoft Graph access in the page you are currently on.

The displayed details for the active account include:
* **Username**: The user principal name or email address of the authenticated account.
* **Tenant ID**: The unique ID of the Microsoft Entra ID tenant.
* **Account Identifier**: The unique home account identifier.
* **Permissions**: The list of Graph API scopes granted during the sign-in process.
* **Environment**: The Azure Cloud environment (Public or US Government) the account is authenticated against.

<br>

## Local Token Caching

Use the `Cache Tokens Locally` checkbox before signing into your tenant in order to enable local caching of the authentication tokens for that specific tenant. If before signing in, the checkbox is not selected, the authentication tokens will only be stored in the app's memory and will be lost once the application is closed.

Token caching helps you save time by not having to sign in every time you close and reopen the application, by encrypting and storing the authentication tokens securely on your local device. The exact location is in the App's own cache directory which is cleaned up automatically by the system when app itself is uninstalled.

You can use the `Clear Local Cache` button to manually clear all locally cached tokens. This will log you out of all accounts that were signed in with the `Cache Tokens Locally` option enabled, and remove their authentication tokens from the application's memory and local storage.

The encryption of the local cache is done via [DPAPI](https://learn.microsoft.com/dotnet/standard/security/how-to-use-data-protection) and current user's context. That means if the tokens are ever moved to another system then they won't be readable. They cannot be read by another user account on the same device either.
