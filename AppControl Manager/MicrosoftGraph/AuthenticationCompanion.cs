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
using AppControlManager.ViewModels;
using Microsoft.Identity.Client;
using Microsoft.UI.Xaml;

namespace AppControlManager.MicrosoftGraph;

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
	/// The constructor needs methods to run when the Active Account is updated
	/// </summary>
	/// <param name="updateButtons"></param>
	/// <param name="infoBar"></param>
	/// <param name="authContext"></param>
	internal AuthenticationCompanion(Action<bool> updateButtons, InfoBarSettings infoBar, AuthenticationContext authContext)
	{
		_UpdateButtons = updateButtons;
		_InfoBar = infoBar;
		_AuthContext = authContext;

		// Initializing the field using the provided authContext
		AuthenticationContextComboBoxSelectedItem = _AuthContext;

		AuthenticatedAccounts.CollectionChanged += AuthenticatedAccounts_CollectionChanged;

		// Detect and set the Shimmer/ListView visibility when the class is instantiated in each ViewModel/Page
		ShimmerListViewVisibilityConfig();
	}

	/// <summary>
	/// To subscribe to the Saved Accounts Observable Collection's events to update the local instances automatically
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void AuthenticatedAccounts_CollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
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
					if (ListViewSelectedAccount == removed)
					{
						ListViewSelectedAccount = null;
					}
				}
			}

			// If the collection was cleared, both properties should be null.
			if (e.Action == NotifyCollectionChangedAction.Reset)
			{
				CurrentActiveAccount = null;
				ListViewSelectedAccount = null;
			}
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

	internal AuthenticatedAccounts? ListViewSelectedAccount { get; set => SP(ref field, value); }

	internal AuthenticatedAccounts? CurrentActiveAccount
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				// When the current account changes, update the 4 dependent properties.
				UpdateAccountDetails();

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
		}
		else
		{
			// When CurrentActiveAccount is null, set the properties to null
			CurrentActiveAccountUsername = null;
			CurrentActiveAccountTenantID = null;
			CurrentActiveAccountAccountIdentifier = null;
			CurrentActiveAccountPermissions = null;
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

	internal bool SignInButtonState { get; set => SP(ref field, value); } = true;

	internal bool SignOutButtonState { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// To save the cancellation token source for sign in operation
	/// </summary>
	internal CancellationTokenSource? cancellationTokenSource;

	/// <summary>
	/// Event handler for the Cancel Sign In button
	/// </summary>
	internal void MSGraphCancelSignInButton_Click()
	{
		try
		{
			ManageButtonsStates(false);

			CancelAndDisposeCts();

			_InfoBar.WriteInfo(GlobalVars.GetStr("SignInProcessCancelledMessage"));
		}
		finally
		{
			_InfoBar.IsClosable = true;
			ManageButtonsStates(true);
		}
	}

	/// <summary>
	/// Logs out of the currently selected account.
	/// </summary>
	internal async void LogOutOfSelectedAccount()
	{
		try
		{
			ManageButtonsStates(false);

			if (ListViewSelectedAccount is not null)
			{
				await Main.SignOut(ListViewSelectedAccount);

				_InfoBar.WriteInfo(GlobalVars.GetStr("SuccessfullyLoggedOutSelectedAccountMessage"));
			}
		}
		finally
		{
			_InfoBar.IsClosable = true;
			ManageButtonsStates(true);
		}
	}

	/// <summary>
	/// Set the selected item in the ListView as active account to use
	/// </summary>
	internal void SetActiveFromListView()
	{
		// Replace the current active account with the one from ListView
		CurrentActiveAccount = ListViewSelectedAccount;

		if (CurrentActiveAccount is not null)
		{
			_InfoBar.WriteSuccess(string.Format(
				GlobalVars.GetStr("SuccessfullySetActiveAccountMessage"),
				CurrentActiveAccount.Username));
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
			cancellationTokenSource.Cancel();
			cancellationTokenSource.Dispose();
			cancellationTokenSource = null;
		}
	}

	/// <summary>
	/// All Sign-in methods supported by the app.
	/// </summary>
	private static readonly List<AuthenticationContextComboBox> _SignInMethodsComboBoxSource =
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
	/// Sign In methods ComboBox source.
	/// </summary>
	internal List<AuthenticationContextComboBox> SignInMethodsComboBoxSource => _SignInMethodsComboBoxSource;

	/// <summary>
	/// Bound to the ComboBox's SelectedItem property with the default value.
	/// </summary>
	internal AuthenticationContextComboBox SignInMethodsComboBoxSelectedItem { get; set => SP(ref field, value); } = _SignInMethodsComboBoxSource[1];

	/// <summary>
	/// Authentication context ComboBox source
	/// </summary>
	internal readonly Array AuthenticationContextComboBoxSource = Enum.GetValues<AuthenticationContext>();

	/// <summary>
	/// Bound to the ComboBox's SelectedItem property.
	/// Default value is supplied via the class constructor.
	/// </summary>
	internal AuthenticationContext AuthenticationContextComboBoxSelectedItem { get; set => SP(ref field, value); }

	/// <summary>
	/// Signs into the Microsoft tenant
	/// </summary>
	internal async void SignIn()
	{
		// create and store the CTS
		cancellationTokenSource = new CancellationTokenSource();

		try
		{
			SignInButtonState = false;

			_InfoBar.WriteInfo(GlobalVars.GetStr("SigningIntoMSGraphMessage"));

			(bool, AuthenticatedAccounts?) signInResult = await Main.SignIn(
				AuthenticationContextComboBoxSelectedItem,
				SignInMethodsComboBoxSelectedItem.AuthContext,
				cancellationTokenSource.Token);

			if (signInResult.Item1)
			{
				CurrentActiveAccount = signInResult.Item2;

				_InfoBar.WriteSuccess(GlobalVars.GetStr("SuccessfullySignedIntoMSGraphMessage"));
			}
		}
		catch (OperationCanceledException)
		{
			_InfoBar.WriteWarning(GlobalVars.GetStr("SignInProcessCancelledByUserMessage"));
		}
		// Specifically for WAM
		catch (MsalClientException ex) when (ex.ErrorCode == "authentication_canceled")
		{
			_InfoBar.WriteWarning(GlobalVars.GetStr("SignInProcessCancelledByUserMessage"));
		}
		catch (Exception ex)
		{
			_InfoBar.WriteError(ex, GlobalVars.GetStr("ErrorSigningIntoMSGraphMessage"));
		}
		finally
		{
			CancelAndDisposeCts();

			_InfoBar.IsClosable = true;
			SignInButtonState = true;
		}
	}

	public void Dispose()
	{
		try
		{
			// Unsubscribe from the event to avoid leaks.
			AuthenticatedAccounts.CollectionChanged -= AuthenticatedAccounts_CollectionChanged;
		}
		catch { }

		CancelAndDisposeCts();
	}
}
