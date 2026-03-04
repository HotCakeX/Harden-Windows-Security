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

using System.Threading;
using System.Threading.Tasks;
using CommonCore.MicrosoftGraph;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.CustomUIElements;

internal sealed partial class GraphAuthPanel : UserControl
{
	private CommonCore.AppSettings.Main AppSettings => GlobalVars.Settings;

	public IGraphAuthHost Host
	{
		get => (IGraphAuthHost)GetValue(HostProperty); set => SetValue(HostProperty, value);
	}

	internal static readonly DependencyProperty HostProperty =
		DependencyProperty.Register(
			nameof(Host),
			typeof(IGraphAuthHost),
			typeof(GraphAuthPanel),
			new PropertyMetadata(null, OnHostChanged));

	internal ThreadSafeObservableCollection<AuthenticatedAccounts> AuthenticatedAccounts => AuthenticationCompanion.AuthenticatedAccounts;

	// Static flag to ensure we only read the cache from disk once per application lifecycle
	private static bool _accountsRestored;

	// Lock to prevent multiple threads/views from triggering initialization concurrently
	private static readonly SemaphoreSlim _restoreLock = new(1, 1);

	internal GraphAuthPanel() => InitializeComponent();

	private async void GraphAuthPanel_Loaded() => await RestoreAccountsAsync();

	private static async void OnHostChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is GraphAuthPanel panel)
		{
			await panel.RestoreAccountsAsync();
		}
	}

	/// <summary>
	/// Restores the cached accounts into the UI. Only runs once per session.
	/// Also handles automatic account selection if available.
	/// </summary>
	private async Task RestoreAccountsAsync()
	{
		// Wait until the Host and AuthCompanionCLS are fully initialized
		if (Host?.AuthCompanionCLS is not null)
		{
			if (!_accountsRestored)
			{
				await _restoreLock.WaitAsync();
				try
				{
					if (!_accountsRestored)
					{
						_accountsRestored = true; // Mark as true so we don't spam the disk on re-navigations
						await Host.AuthCompanionCLS.InitializeAccountsAsync();

						// InitializeAccountsAsync handles the AutoSelectAccountIfApplicable internally,
						// so we return early here to prevent a redundant call.
						return;
					}
				}
				finally
				{
					_ = _restoreLock.Release();
				}
			}

			Host.AuthCompanionCLS.AutoSelectAccountIfApplicable();
		}
	}

}
