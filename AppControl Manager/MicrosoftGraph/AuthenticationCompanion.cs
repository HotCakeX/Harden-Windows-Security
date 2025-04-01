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

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Threading;
using AppControlManager.Others;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.MicrosoftGraph;

/// <summary>
/// Encapsulates the logic shared among the pages and ViewModels that implement Microsoft Graph functionality
/// </summary>
internal sealed partial class AuthenticationCompanion : INotifyPropertyChanged
{
	private readonly Action<bool> _UpdateButtons;
	private readonly InfoBarSettings _InfoBar;
	private readonly AuthenticationContext _AuthContext;

	private ViewModel ViewModelMSGraph { get; } = App.AppHost.Services.GetRequiredService<ViewModel>();

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
		_AuthenticationContextComboBoxSelectedItem = _AuthContext;

		// Detect and set the Shimmer/ListView visibility when the class is instantiated in each ViewModel/Page
		ShimmerListViewVisibilityConfig();
	}

	public event PropertyChangedEventHandler? PropertyChanged;

	/// <summary>
	/// To subscribe to the Saved Accounts Observable Collection's events to update the local instances automatically
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void AuthenticatedAccounts_CollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
	{
		// Determine the Shimmer/ListView visibility on every collection change event that is fired
		ShimmerListViewVisibilityConfig();

		if (e.Action == NotifyCollectionChangedAction.Remove ||
			e.Action == NotifyCollectionChangedAction.Reset ||
			e.Action == NotifyCollectionChangedAction.Replace)
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
		if (ViewModelMSGraph.AuthenticatedAccounts.Count > 0)
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
	private Visibility _AuthenticatedAccountsListViewVisibility = Visibility.Collapsed;
	internal Visibility AuthenticatedAccountsListViewVisibility
	{
		get => _AuthenticatedAccountsListViewVisibility;
		set => SetProperty(_AuthenticatedAccountsListViewVisibility, value, newValue => _AuthenticatedAccountsListViewVisibility = newValue);
	}

	/// <summary>
	/// Visibility of the Shimmer for the ListView that contains the list of the Authenticated Accounts 
	/// </summary>
	private Visibility _AuthenticatedAccountsShimmerVisibility = Visibility.Visible;
	internal Visibility AuthenticatedAccountsShimmerVisibility
	{
		get => _AuthenticatedAccountsShimmerVisibility;
		set => SetProperty(_AuthenticatedAccountsShimmerVisibility, value, newValue => _AuthenticatedAccountsShimmerVisibility = newValue);
	}


	private AuthenticatedAccounts? _ListViewSelectedAccount;
	internal AuthenticatedAccounts? ListViewSelectedAccount
	{
		get => _ListViewSelectedAccount;
		set => SetProperty(_ListViewSelectedAccount, value, newValue => _ListViewSelectedAccount = newValue);
	}


	private AuthenticatedAccounts? _currentActiveAccount;
	internal AuthenticatedAccounts? CurrentActiveAccount
	{
		get => _currentActiveAccount;
		set
		{
			if (SetProperty(_currentActiveAccount, value, newValue => _currentActiveAccount = newValue))
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
	private string? _currentActiveAccountUsername;
	internal string? CurrentActiveAccountUsername
	{
		get => _currentActiveAccountUsername;
		set => SetProperty(_currentActiveAccountUsername, value, newValue => _currentActiveAccountUsername = newValue);
	}

	/// <summary>
	/// Computed property for TenantID.
	/// </summary>
	private string? _currentActiveAccountTenantID;
	internal string? CurrentActiveAccountTenantID
	{
		get => _currentActiveAccountTenantID;
		set => SetProperty(_currentActiveAccountTenantID, value, newValue => _currentActiveAccountTenantID = newValue);
	}

	/// <summary>
	/// Computed property for Account Identifier.
	/// </summary>
	private string? _currentActiveAccountAccountIdentifier;
	internal string? CurrentActiveAccountAccountIdentifier
	{
		get => _currentActiveAccountAccountIdentifier;
		set => SetProperty(_currentActiveAccountAccountIdentifier, value, newValue => _currentActiveAccountAccountIdentifier = newValue);
	}

	/// <summary>
	/// Computed property for Permissions.
	/// </summary>
	private string? _currentActiveAccountPermissions;
	internal string? CurrentActiveAccountPermissions
	{
		get => _currentActiveAccountPermissions;
		set => SetProperty(_currentActiveAccountPermissions, value, newValue => _currentActiveAccountPermissions = newValue);
	}

	private bool _SignInButtonState = true;
	internal bool SignInButtonState
	{
		get => _SignInButtonState;
		set => SetProperty(_SignInButtonState, value, newValue => _SignInButtonState = newValue);
	}

	private bool _SignOutButtonState = true;
	internal bool SignOutButtonState
	{
		get => _SignOutButtonState;
		set => SetProperty(_SignOutButtonState, value, newValue => _SignOutButtonState = newValue);
	}


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

			if (cancellationTokenSource is not null)
			{
				cancellationTokenSource.Cancel();
				cancellationTokenSource.Dispose();
				cancellationTokenSource = null;

				_InfoBar.Visibility = Visibility.Visible;
				_InfoBar.IsOpen = true;
				_InfoBar.Message = "Sign in process was cancelled";
				_InfoBar.Severity = InfoBarSeverity.Informational;
				_InfoBar.IsClosable = true;
			}
		}
		finally
		{
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

				_InfoBar.Visibility = Visibility.Visible;
				_InfoBar.IsOpen = true;
				_InfoBar.Message = "Successfully logged out of the selected account.";
				_InfoBar.Severity = InfoBarSeverity.Informational;
				_InfoBar.IsClosable = true;
			}
		}

		finally
		{
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
			_InfoBar.Visibility = Visibility.Visible;
			_InfoBar.IsOpen = true;
			_InfoBar.Message = $"Successfully set the account with the username ({CurrentActiveAccount?.Username}) as the Active Account for the current page.";
			_InfoBar.Severity = InfoBarSeverity.Success;
			_InfoBar.IsClosable = true;
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
	/// Sign In methods ComboBox source
	/// </summary>
	internal readonly Array SignInMethodsComboBoxSource = Enum.GetValues<SignInMethods>();

	/// <summary>
	/// Bound to the ComboBox's SelectedItem property with the default value
	/// </summary>
	private SignInMethods _SignInMethodsComboBoxSelectedItem = SignInMethods.WebAccountManager;
	internal SignInMethods SignInMethodsComboBoxSelectedItem
	{
		get => _SignInMethodsComboBoxSelectedItem;
		set => SetProperty(_SignInMethodsComboBoxSelectedItem, value, newValue => _SignInMethodsComboBoxSelectedItem = newValue);
	}


	/// <summary>
	/// Authentication context ComboBox source
	/// </summary>
	internal readonly Array AuthenticationContextComboBoxSource = Enum.GetValues<AuthenticationContext>();


	/// <summary>
	/// Bound to the ComboBox's SelectedItem property.
	/// Default value is supplied via the class constructor.
	/// </summary>
	private AuthenticationContext _AuthenticationContextComboBoxSelectedItem;
	internal AuthenticationContext AuthenticationContextComboBoxSelectedItem
	{
		get => _AuthenticationContextComboBoxSelectedItem;
		set => SetProperty(_AuthenticationContextComboBoxSelectedItem, value, newValue => _AuthenticationContextComboBoxSelectedItem = newValue);
	}


	/// <summary>
	/// Signs into the Microsoft tenant
	/// </summary>
	internal async void SignIn()
	{
		try
		{
			SignInButtonState = false;

			_InfoBar.Visibility = Visibility.Visible;
			_InfoBar.IsOpen = true;
			_InfoBar.Message = "Signing into MSGraph";
			_InfoBar.Severity = InfoBarSeverity.Informational;
			_InfoBar.IsClosable = false;

			(bool, CancellationTokenSource?, AuthenticatedAccounts?) signInResult = await Main.SignIn(AuthenticationContextComboBoxSelectedItem, SignInMethodsComboBoxSelectedItem);

			if (signInResult.Item1)
			{
				cancellationTokenSource = signInResult.Item2;
				CurrentActiveAccount = signInResult.Item3;

				_InfoBar.Message = "Successfully signed into MSGraph";
				_InfoBar.Severity = InfoBarSeverity.Success;
			}
		}
		catch (OperationCanceledException)
		{
			Logger.Write("Sign in to MSGraph was cancelled by the user");


			_InfoBar.Message = "Sign in to MSGraph was cancelled by the user";
			_InfoBar.Severity = InfoBarSeverity.Warning;
		}

		catch (Exception ex)
		{
			_InfoBar.Message = $"There was an error signing into MSGraph: {ex.Message}";
			_InfoBar.Severity = InfoBarSeverity.Error;

			throw;
		}
		finally
		{
			_InfoBar.IsClosable = true;

			SignInButtonState = true;
		}
	}

	/// <summary>
	/// Sets the property and raises the PropertyChanged event if the value has changed.
	/// This also prevents infinite loops where a property raises OnPropertyChanged which could trigger an update in the UI, and the UI might call set again, leading to an infinite loop.
	/// </summary>
	/// <typeparam name="T"></typeparam>
	/// <param name="currentValue"></param>
	/// <param name="newValue"></param>
	/// <param name="setter"></param>
	/// <param name="propertyName"></param>
	/// <returns></returns>
	private bool SetProperty<T>(T currentValue, T newValue, Action<T> setter, [CallerMemberName] string? propertyName = null)
	{
		if (EqualityComparer<T>.Default.Equals(currentValue, newValue))
			return false;
		setter(newValue);
		OnPropertyChanged(propertyName);
		return true;
	}


	private void OnPropertyChanged(string? propertyName)
	{
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
	}
}
