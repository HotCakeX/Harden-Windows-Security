// MIT License
//
// Copyright (c) 2023-Present - Violet Hansen - (aka HotCakeX on GitHub) - Email Address: spynetgirl@outlook.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// See here for more information: https://github.com/HotCakeX/Harden-Windows-Security/blob/main/LICENSE
//

using System.Collections.Generic;
using System.Collections.Specialized;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using Microsoft.UI.Xaml;

namespace CommonCore.MicrosoftGraph;

/// <summary>
/// Encapsulates the logic shared among the pages and ViewModels that implement Microsoft Graph functionality
/// </summary>
internal sealed partial class AuthenticationCompanion : ViewModelBase, IDisposable
{
	private readonly Action<bool> _UpdateButtons;
	private readonly InfoBarSettings _InfoBar;
	private readonly AuthenticationContext _AuthContext;

	/// <summary>
	/// Collection bound to the ListViews that display the authenticated accounts in every page
	/// </summary>
	internal static readonly ThreadSafeObservableCollection<AuthenticatedAccounts> AuthenticatedAccounts = [];

	/// <summary>
	/// Collection of the tenants saved by the user that can be targeted for sign-in or tenant switching.
	/// Shared among every page so all of them display the same saved tenants.
	/// </summary>
	internal static readonly ThreadSafeObservableCollection<SavedTenant> SavedTenants = [];

	/// <summary>
	/// The constructor needs methods to run when the Active Account is updated
	/// </summary>
	internal AuthenticationCompanion(Action<bool> updateButtons, InfoBarSettings infoBar, AuthenticationContext authContext)
	{
		_UpdateButtons = updateButtons;
		_InfoBar = infoBar;
		_AuthContext = authContext;

		// Initializing the field using the provided authContext
		AuthenticationContextComboBoxSelectedItem = _AuthContext;

		AuthenticatedAccounts.CollectionChanged += AuthenticatedAccounts_CollectionChanged;
		SavedTenants.CollectionChanged += SavedTenants_CollectionChanged;

		// Detect and set the Shimmer/ListView visibility when the class is instantiated in each ViewModel/Page
		ShimmerListViewVisibilityConfig();
		SavedTenantsVisibilityConfig();
		UpdateAuthenticatedAccountCardStates();
	}

	/// <summary>
	/// Auto-selects the CurrentActiveAccount if there is exactly 1 authenticated account that matches the requested AuthContext.
	/// </summary>
	internal void AutoSelectAccountIfApplicable()
	{
		if (CurrentActiveAccount is null)
		{
			List<AuthenticatedAccounts> matchingAccounts = [];
			foreach (AuthenticatedAccounts account in AuthenticatedAccounts)
			{
				if (account.AuthContext == _AuthContext)
				{
					matchingAccounts.Add(account);
				}
			}

			if (matchingAccounts.Count == 1)
			{
				CurrentActiveAccount = matchingAccounts[0];
			}
		}
	}

	/// <summary>
	/// Restores the previously cached accounts utilizing silent sign in. Recommended to be called on initialization or View loaded.
	/// </summary>
	internal async Task InitializeAccountsAsync()
	{
		ManageButtonsStates(false);
		try
		{
			await Main.RestoreSavedTenantsAsync();
			await Main.RestoreCachedAccountsAsync();
			UpdateAuthenticatedAccountCardStates();
			AutoSelectAccountIfApplicable();
		}
		finally
		{
			ManageButtonsStates(true);
		}
	}

	/// <summary>
	/// To subscribe to the Saved Accounts Observable Collection's events to update the local instances automatically
	/// </summary>
	private void AuthenticatedAccounts_CollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
	{
		// Determine the Shimmer/ListView visibility on every collection change event that is fired
		ShimmerListViewVisibilityConfig();

		if (e.Action is NotifyCollectionChangedAction.Remove or
			NotifyCollectionChangedAction.Reset or
			NotifyCollectionChangedAction.Replace)
		{
			// For Remove or Replace actions, check the items that were removed
			if (e.OldItems != null)
			{
				foreach (AuthenticatedAccounts removed in e.OldItems)
				{
					if (CurrentActiveAccount == removed)
					{
						CurrentActiveAccount = null;
					}
				}
			}

			// If the collection was cleared, both properties should be null.
			if (e.Action == NotifyCollectionChangedAction.Reset)
			{
				CurrentActiveAccount = null;
			}
		}
		UpdateAuthenticatedAccountCardStates();
	}

	/// <summary>
	/// Keeps active badges synchronized for the accounts displayed by this companion.
	/// </summary>
	private void UpdateAuthenticatedAccountCardStates()
	{
		foreach (AuthenticatedAccounts account in AuthenticatedAccounts)
		{
			account.SetActiveState(CurrentActiveAccount is not null && account.Equals(CurrentActiveAccount));
		}
	}

	/// <summary>
	/// To determine the visibility of the Shimmer/ListView based on the availability of elements in the AuthenticatedAccounts ObservableCollection
	/// </summary>
	private void ShimmerListViewVisibilityConfig()
	{
		if (AuthenticatedAccounts.Count > 0)
		{
			// Action when there is at least one element.
			AuthenticatedAccountsShimmerVisibility = Visibility.Collapsed;
			AuthenticatedAccountsListViewVisibility = Visibility.Visible;
		}
		else
		{
			// Action when the collection is empty.
			AuthenticatedAccountsShimmerVisibility = Visibility.Visible;
			AuthenticatedAccountsListViewVisibility = Visibility.Collapsed;
		}
	}

	/// <summary>
	/// Visibility of the ListView that contains the list of the Authenticated Accounts
	/// </summary>
	internal Visibility AuthenticatedAccountsListViewVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	/// <summary>
	/// Visibility of the Shimmer for the ListView that contains the list of the Authenticated Accounts
	/// </summary>
	internal Visibility AuthenticatedAccountsShimmerVisibility { get; set => SP(ref field, value); } = Visibility.Visible;

	/// <summary>
	/// Visibility of the active account details area.
	/// </summary>
	internal Visibility ActiveAccountDetailsVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	/// <summary>
	/// Visibility of the placeholder shown when no account is active.
	/// </summary>
	internal Visibility ActiveAccountPlaceholderVisibility { get; set => SP(ref field, value); } = Visibility.Visible;

	internal AuthenticatedAccounts? CurrentActiveAccount
	{
		get; set
		{
			if (SP(ref field, value))
			{
				// When the current account changes, update the dependent properties.
				UpdateAccountDetails();
				UpdateAuthenticatedAccountCardStates();

				_UpdateButtons(value is not null);
			}
		}
	}

	/// <summary>
	/// Helper method to update computed properties when CurrentActiveAccount changes.
	/// </summary>
	private void UpdateAccountDetails()
	{
		if (CurrentActiveAccount is not null)
		{
			CurrentActiveAccountUsername = CurrentActiveAccount.Username;
			CurrentActiveAccountTenantID = CurrentActiveAccount.TenantID;
			CurrentActiveAccountAccountIdentifier = CurrentActiveAccount.AccountIdentifier;
			CurrentActiveAccountPermissions = CurrentActiveAccount.Permissions;
			CurrentActiveAccountEnvironment = CurrentActiveAccount.Environment.ToString();
			ActiveAccountDetailsVisibility = Visibility.Visible;
			ActiveAccountPlaceholderVisibility = Visibility.Collapsed;
		}
		else
		{
			// When CurrentActiveAccount is null, set the properties to null
			CurrentActiveAccountUsername = null;
			CurrentActiveAccountTenantID = null;
			CurrentActiveAccountAccountIdentifier = null;
			CurrentActiveAccountPermissions = null;
			CurrentActiveAccountEnvironment = null;
			ActiveAccountDetailsVisibility = Visibility.Collapsed;
			ActiveAccountPlaceholderVisibility = Visibility.Visible;
		}
	}

	/// <summary>
	/// Computed property for Username.
	/// </summary>
	internal string? CurrentActiveAccountUsername { get; set => SP(ref field, value); }

	/// <summary>
	/// Computed property for TenantID.
	/// </summary>
	internal string? CurrentActiveAccountTenantID { get; set => SP(ref field, value); }

	/// <summary>
	/// Computed property for Account Identifier.
	/// </summary>
	internal string? CurrentActiveAccountAccountIdentifier { get; set => SP(ref field, value); }

	/// <summary>
	/// Computed property for Permissions.
	/// </summary>
	internal string? CurrentActiveAccountPermissions { get; set => SP(ref field, value); }

	/// <summary>
	/// Computed property for Environment.
	/// </summary>
	internal string? CurrentActiveAccountEnvironment { get; set => SP(ref field, value); }

	internal bool SignInButtonState { get; set => SP(ref field, value); } = true;

	internal bool SignOutButtonState { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// To save the cancellation token source for sign in operation
	/// </summary>
	private CancellationTokenSource? cancellationTokenSource;

	/// <summary>
	/// Event handler for the Cancel Sign In button
	/// </summary>
	internal void MSGraphCancelSignInButton_Click()
	{
		try
		{
			ManageButtonsStates(false);

			CancelAndDisposeCts();

			_InfoBar.WriteInfo(Atlas.GetStr("SignInProcessCancelledMessage"));
		}
		finally
		{
			_InfoBar.IsClosable = true;
			ManageButtonsStates(true);
		}
	}

	/// <summary>
	/// Sets the provided account as the active account to use.
	/// </summary>
	internal void SetActiveAccount(AuthenticatedAccounts? account)
	{
		CurrentActiveAccount = account;
		if (CurrentActiveAccount is not null)
		{
			_InfoBar.WriteSuccess(string.Format(
				Atlas.GetStr("SuccessfullySetActiveAccountMessage"),
				CurrentActiveAccount.Username));
		}
	}

	/// <summary>
	/// Logs out of the provided account.
	/// </summary>
	internal async Task LogOutOfAccountAsync(AuthenticatedAccounts? account)
	{
		try
		{
			ManageButtonsStates(false);
			if (account is not null)
			{
				await Main.SignOut(account);
				_InfoBar.WriteInfo(Atlas.GetStr("SuccessfullyLoggedOutSelectedAccountMessage"));
			}
		}
		finally
		{
			_InfoBar.IsClosable = true;
			ManageButtonsStates(true);
		}
	}

	/// <summary>
	/// Enable or Disable button states
	/// </summary>
	/// <param name="on">True will enable and False will disable UI buttons when an operation is ongoing</param>
	private void ManageButtonsStates(bool on)
	{
		SignInButtonState = on;
		SignOutButtonState = on;
	}

	/// <summary>
	/// Helper method to cancel and dispose the cancellation token source
	/// </summary>
	private void CancelAndDisposeCts()
	{
		if (cancellationTokenSource is not null)
		{
			try
			{
				cancellationTokenSource.Cancel();
				cancellationTokenSource.Dispose();
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}
			cancellationTokenSource = null;
		}
	}

	/// <summary>
	/// All Sign-in methods supported by the app. Used for ComboBox source too.
	/// </summary>
	internal static readonly List<AuthenticationContextComboBox> SignInMethodsComboBoxSource =
	[
		new AuthenticationContextComboBox(
			name: "Web Account Manager (WAM)",
			authContext: SignInMethods.WebAccountManager,
			image: "ms-appx:///Assets/External/WAM.png"),

		new AuthenticationContextComboBox(
			name: "Web Browser",
			authContext: SignInMethods.WebBrowser,
			image: "ms-appx:///Assets/External/Browser.png")
	];

	/// <summary>
	/// Bound to the ComboBox's SelectedItem property with the default value.
	/// </summary>
	internal AuthenticationContextComboBox SignInMethodsComboBoxSelectedItem { get; set => SP(ref field, value); } = SignInMethodsComboBoxSource[1];

	/// <summary>
	/// Authentication context ComboBox source
	/// </summary>
#if HARDEN_SYSTEM_SECURITY
	internal readonly Array AuthenticationContextComboBoxSource = new AuthenticationContext[] { AuthenticationContext.Intune };
#else
	internal readonly Array AuthenticationContextComboBoxSource = Enum.GetValues<AuthenticationContext>();
#endif

	/// <summary>
	/// Bound to the ComboBox's SelectedItem property.
	/// Default value is supplied via the class constructor.
	/// </summary>
	internal AuthenticationContext AuthenticationContextComboBoxSelectedItem { get; set => SP(ref field, value); }

	/// <summary>
	/// Azure Cloud environment source items.
	/// </summary>
	internal static readonly List<AzureCloudEnvironmentComboBoxItem> AzureCloudEnvironmentComboBoxSource =
	[
		new AzureCloudEnvironmentComboBoxItem("Public", AzureCloudInstance.AzurePublic),
		new AzureCloudEnvironmentComboBoxItem("US Government (GCC High)", AzureCloudInstance.AzureUsGovernment)
	];

	internal AzureCloudEnvironmentComboBoxItem AzureCloudEnvironmentComboBoxSelectedItem { get; set => SP(ref field, value); } = AzureCloudEnvironmentComboBoxSource[0];

	/// <summary>
	/// Signs into the Microsoft tenant.
	/// If a target tenant is selected, the sign-in is performed against that tenant instead of the home tenant of the account.
	/// </summary>
	internal async void SignIn() => await RunCancellableOperationAsync(
		Atlas.GetStr("SigningIntoMSGraphMessage"),
		Atlas.GetStr("ErrorSigningIntoMSGraphMessage"),
		async (CancellationToken token) =>
		{
			CurrentActiveAccount = await Main.SignIn(
				AuthenticationContextComboBoxSelectedItem,
				SignInMethodsComboBoxSelectedItem.AuthContext,
				AzureCloudEnvironmentComboBoxSelectedItem.Environment,
				TargetTenantComboBoxSelectedItem,
				token);

			_InfoBar.WriteSuccess(Atlas.GetStr("SuccessfullySignedIntoMSGraphMessage"));
		});

	/// <summary>
	/// Runs an operation that can be cancelled with the Cancel button of the sign in section.
	/// Handles the cancellation token source, the UI elements states and the errors in a uniform way.
	/// </summary>
	/// <param name="startMessage">The message to display when the operation starts.</param>
	/// <param name="errorMessage">The message to display when the operation fails.</param>
	/// <param name="operation">The operation to run, receives the cancellation token.</param>
	private async Task RunCancellableOperationAsync(string startMessage, string? errorMessage, Func<CancellationToken, Task> operation)
	{
		CancelAndDisposeCts(); // Make sure any previous token is cancelled and disposed of before storing a new one.

		// create and store the CTS
		cancellationTokenSource = new CancellationTokenSource();

		try
		{
			SignInButtonState = false;

			_InfoBar.WriteInfo(startMessage);

			await operation(cancellationTokenSource.Token);
		}
		catch (OperationCanceledException)
		{
			_InfoBar.WriteWarning(Atlas.GetStr("SignInProcessCancelledByUserMessage"));
		}
		// Specifically for WAM
		catch (MsalClientException ex) when (string.Equals(ex.ErrorCode, "authentication_canceled", StringComparison.OrdinalIgnoreCase))
		{
			_InfoBar.WriteWarning(Atlas.GetStr("SignInProcessCancelledByUserMessage"));
		}
		catch (Exception ex)
		{
			_InfoBar.WriteError(ex, errorMessage);
		}
		finally
		{
			CancelAndDisposeCts();

			_InfoBar.IsClosable = true;
			SignInButtonState = true;
		}
	}

	/// <summary>
	/// Returns the display friendly name of a cloud environment.
	/// </summary>
	internal static string GetCloudEnvironmentName(AzureCloudInstance environment)
	{
		foreach (AzureCloudEnvironmentComboBoxItem item in AzureCloudEnvironmentComboBoxSource)
		{
			if (item.Environment == environment)
			{
				return item.Name;
			}
		}

		return environment.ToString();
	}

	/// <summary>
	/// The tenant to target during sign in. Null means the home tenant of the account, which is the default behavior.
	/// Bound to the Target Tenant ComboBox's SelectedItem property.
	/// </summary>
	internal SavedTenant? TargetTenantComboBoxSelectedItem { get; set => SP(ref field, value); }

	/// <summary>
	/// Resets the target tenant so the sign in uses the home tenant of the account.
	/// </summary>
	internal void ClearTargetTenant() => TargetTenantComboBoxSelectedItem = null;

	/// <summary>
	/// Tenant ID or verified domain name entered by the user to add a new tenant.
	/// </summary>
	internal string? TenantInputText { get; set => SP(ref field, value); }

	/// <summary>
	/// Optional friendly name entered by the user for the new tenant.
	/// </summary>
	internal string? TenantFriendlyNameText { get; set => SP(ref field, value); }

	/// <summary>
	/// Visibility of the ListView that displays the saved tenants.
	/// </summary>
	internal Visibility SavedTenantsListViewVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	/// <summary>
	/// Visibility of the placeholder displayed when there are no saved tenants.
	/// </summary>
	internal Visibility NoSavedTenantsVisibility { get; set => SP(ref field, value); } = Visibility.Visible;

	/// <summary>
	/// Keeps the saved tenants related UI in sync with the saved tenants collection.
	/// </summary>
	private void SavedTenants_CollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
	{
		SavedTenantsVisibilityConfig();

		// If the selected target tenant was removed, revert to the home tenant
		if (TargetTenantComboBoxSelectedItem is not null && !SavedTenants.Contains(TargetTenantComboBoxSelectedItem))
		{
			TargetTenantComboBoxSelectedItem = null;
		}
	}

	/// <summary>
	/// Determines the visibility of the saved tenants ListView and its placeholder.
	/// </summary>
	private void SavedTenantsVisibilityConfig()
	{
		bool hasTenants = SavedTenants.Count > 0;
		SavedTenantsListViewVisibility = hasTenants ? Visibility.Visible : Visibility.Collapsed;
		NoSavedTenantsVisibility = hasTenants ? Visibility.Collapsed : Visibility.Visible;
	}

	/// <summary>
	/// Resolves the tenant entered by the user and adds it to the saved tenants.
	/// </summary>
	internal async void AddTenantButton_Click()
	{
		string? input = TenantInputText?.Trim();

		if (string.IsNullOrEmpty(input))
		{
			_InfoBar.WriteWarning(string.Format(Atlas.GetStr("InvalidTenantIdentifierMessage"), string.Empty));
			return;
		}

		AzureCloudInstance environment = AzureCloudEnvironmentComboBoxSelectedItem.Environment;

		await RunCancellableOperationAsync(
			Atlas.GetStr("ResolvingTenantMessage"),
			null,
			async (CancellationToken token) =>
			{
				string tenantID = await Main.ResolveTenantIDAsync(input, environment, token);

				// Use the friendly name if provided, otherwise the domain name, or the tenant ID if a GUID was entered
				string? friendlyName = TenantFriendlyNameText?.Trim();
				string displayName = !string.IsNullOrEmpty(friendlyName)
					? friendlyName
					: Guid.TryParse(input, out _) ? tenantID : input;

				SavedTenant tenant = new(tenantID, displayName, environment);

				int added = await Main.AddSavedTenantsAsync([tenant]);

				if (added > 0)
				{
					TenantInputText = null;
					TenantFriendlyNameText = null;

					_InfoBar.WriteSuccess(string.Format(Atlas.GetStr("TenantAddedSuccessfullyMessage"), displayName, tenantID));
				}
				else
				{
					_InfoBar.WriteWarning(string.Format(Atlas.GetStr("TenantAlreadySavedMessage"), tenantID));
				}
			});
	}

	/// <summary>
	/// Imports the GDAP customer tenants of the partner tenant of the active account into the saved tenants.
	/// </summary>
	internal async void ImportGdapCustomersButton_Click()
	{
		AuthenticatedAccounts? account = CurrentActiveAccount;

		if (account is null)
		{
			_InfoBar.WriteWarning(Atlas.GetStr("NoActiveAccountForTenantOperationMessage"));
			return;
		}

		await RunCancellableOperationAsync(
			Atlas.GetStr("ImportingGdapCustomersMessage"),
			null,
			async (CancellationToken token) =>
			{
				List<SavedTenant> customers = await Main.GetGdapCustomerTenantsAsync(account, token);

				int added = await Main.AddSavedTenantsAsync(customers);

				_InfoBar.WriteSuccess(string.Format(Atlas.GetStr("ImportedGdapCustomersMessage"), customers.Count, added));
			});
	}

	/// <summary>
	/// Switches the active account to the provided tenant and sets the resulting session as the active account.
	/// </summary>
	internal async Task SwitchToTenantAsync(SavedTenant? tenant)
	{
		if (tenant is null)
		{
			return;
		}

		AuthenticatedAccounts? account = CurrentActiveAccount;

		if (account is null)
		{
			_InfoBar.WriteWarning(Atlas.GetStr("NoActiveAccountForTenantOperationMessage"));
			return;
		}

		await RunCancellableOperationAsync(
			string.Format(Atlas.GetStr("SwitchingTenantMessage"), account.Username, tenant.DisplayName),
			null,
			async (CancellationToken token) =>
			{
				CurrentActiveAccount = await Main.SwitchTenantAsync(account, tenant, token);

				_InfoBar.WriteSuccess(string.Format(Atlas.GetStr("SwitchedTenantSuccessfullyMessage"), account.Username, tenant.DisplayName));
			});
	}

	/// <summary>
	/// Removes the provided tenant from the saved tenants.
	/// </summary>
	internal async Task RemoveSavedTenantAsync(SavedTenant? tenant)
	{
		if (tenant is null)
		{
			return;
		}

		try
		{
			ManageButtonsStates(false);

			await Main.RemoveSavedTenantAsync(tenant);

			_InfoBar.WriteInfo(string.Format(Atlas.GetStr("SavedTenantRemovedMessage"), tenant.DisplayName));
		}
		catch (Exception ex)
		{
			_InfoBar.WriteError(ex);
		}
		finally
		{
			_InfoBar.IsClosable = true;
			ManageButtonsStates(true);
		}
	}

	public void Dispose()
	{
		// Unsubscribe from the event to avoid leaks.
		AuthenticatedAccounts.CollectionChanged -= AuthenticatedAccounts_CollectionChanged;
		SavedTenants.CollectionChanged -= SavedTenants_CollectionChanged;
		CancelAndDisposeCts();
	}

	/// <summary>
	/// Deletes local tokens stored on the disk
	/// </summary>
	internal async void ClearLocalCacheButton_Click()
	{
		try
		{
			ManageButtonsStates(false);

			await Main.ClearLocalCacheAsync();

			AuthenticatedAccounts.Clear();
			CurrentActiveAccount = null;

			_InfoBar.WriteSuccess("Local token cache cleared successfully.");
		}
		catch (Exception ex)
		{
			_InfoBar.WriteError(ex);
		}
		finally
		{
			_InfoBar.IsClosable = true;
			ManageButtonsStates(true);
		}
	}
}
