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

<br>

## Signed In Accounts

### Remove <img src="https://raw.githubusercontent.com/HotCakeX/.github/7ac3898730bc82a790f56a61e301b6663dfc9d5a/Pictures/Gifs/AppControl%20Manager%20Menu/Microsoft%20Graph%20-%20Log%20Out.gif" alt="Remove" width="30" />

After selecting an account from the list, you can remove it by clicking this button. This will log you out of the selected account and remove it from the list of signed-in accounts. It will also completely remove its authentication token from the application's memory.

### Set Active Account <img src="https://raw.githubusercontent.com/HotCakeX/.github/7ac3898730bc82a790f56a61e301b6663dfc9d5a/Pictures/Gifs/AppControl%20Manager%20Menu/Microsoft%20Graph%20-%20Set%20Active%20Account.gif" alt="Set Active Account" width="30" />

After selecting an account from the list, you can set it as the active account by clicking this button. This will make the selected account the default account for all operations that require Microsoft Graph access in the page you are currently on.

<br>

## Active Account

This section shows you the details of the currently active account that will be used for all operations that require Microsoft Graph access in the page you are currently on.

<br>
