# Microsoft Graph

The AppControl Manager offers integration with Microsoft Graph to allow you to manage your Microsoft 365 tenants. This integration allows you to perform various operations such as logging into multiple different tenants and user accounts, and choosing which one to use for each operation.

## Sign In

### Sign In button

Use this button to sign in to your Microsoft 365 account. You will be prompted to enter your credentials, and once signed in, you will be able to access the features of the AppControl Manager that require Microsoft Graph access.

### Cancel Sign In

Use this button to cancel the sign-in process. This only works if you've already pressed the Sign In button to initiate the sign in process.

### Sign In Method

- WebAccountManager: This will launch a native Windows sign-in dialog, allowing you to select any existing accounts or sign into new accounts.

- WebBrowser: This will launch a web browser window for you to sign in. After signing in the browser, the application will receive the authentication token automatically.

### Authentication Context

Here you can select the authentication context for the sign-in process. They are groups of permissions that the application will request from Microsoft Graph in order to perform certain operations.

## Signed In Accounts

### Remove

After selecting an account from the list, you can remove it by clicking this button. This will log you out of the selected account and remove it from the list of signed-in accounts. It will also completely remove its authentication token from the application's memory.

### Set Active Account

After selecting an account from the list, you can set it as the active account by clicking this button. This will make the selected account the default account for all operations that require Microsoft Graph access in the page you are currently on.

## Active Account

This section shows you the details of the currently active account that will be used for all operations that require Microsoft Graph access in the page you are currently on.
