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
using System.Net.Http;
using System.Threading.Tasks;
using AppControlManager.ViewModels;
using Windows.Services.Store;

namespace AppControlManager.Others;

/// <summary>
/// AppUpdate class is responsible for checking for application updates.
/// </summary>
internal static class AppUpdate
{
	/// <summary>
	/// Event triggered when an update is available.
	/// Includes details about the availability status and the version.
	/// </summary>
	internal static event EventHandler<UpdateAvailableEventArgs>? UpdateAvailable;

	private static UpdateVM UpdateVM { get; } = ViewModelProvider.UpdateVM;

	internal static StoreContext? _StoreContext;

	/// <summary>
	/// Downloads the version file from GitHub,
	/// Checks the online version against the current app version,
	/// and raises the UpdateAvailable event if an update is found.
	/// </summary>
	internal static UpdateCheckResponse CheckGitHub()
	{
		using HttpClient client = new SecHttpClient();

		string versionsResponse = client.GetStringAsync(GlobalVars.AppVersionLinkURL).GetAwaiter().GetResult();

		Version onlineAvailableVersion = new(versionsResponse);
		bool isUpdateAvailable = onlineAvailableVersion > App.currentAppVersion;

		// Raise the UpdateAvailable event if there are subscribers
		UpdateAvailable?.Invoke(
			null,
			new UpdateAvailableEventArgs(isUpdateAvailable, onlineAvailableVersion)
		);

		// If a new version is available
		if (isUpdateAvailable)
		{
			// Set the text for the button in the update page
			UpdateVM.UpdateButtonContent = string.Format(
				GlobalVars.Rizz.GetString("InstallVersionMessage"),
				onlineAvailableVersion);
		}
		else
		{
			Logger.Write(GlobalVars.Rizz.GetString("TheAppIsUpToDate"));
		}

		return new UpdateCheckResponse(
			isUpdateAvailable,
			onlineAvailableVersion
		);
	}

	/// <summary>
	/// Checks for update based on the Store Context.
	/// </summary>
	/// <returns></returns>
	internal async static Task<UpdateCheckResponse> CheckStore()
	{
		_StoreContext = StoreContext.GetDefault();

		// Initialize the dialog using wrapper function for IInitializeWithWindow
		WinRT.Interop.InitializeWithWindow.Initialize(_StoreContext, GlobalVars.hWnd);

		// Find any available updates to the currently running package
		IReadOnlyList<StorePackageUpdate> updates = await _StoreContext.GetAppAndOptionalStorePackageUpdatesAsync();

		bool isUpdateAvailable = false;
		Version latestVersion = new(0, 0, 0, 0);

		if (updates.Count is 0)
		{
			Logger.Write(GlobalVars.Rizz.GetString("TheAppIsUpToDate"));
		}
		else
		{
			isUpdateAvailable = true;

			// Raise the UpdateAvailable event if there are subscribers
			UpdateAvailable?.Invoke(
				null,
				new UpdateAvailableEventArgs(isUpdateAvailable, latestVersion)
			);

			// Set the text for the button in the update page
			UpdateVM.UpdateButtonContent = GlobalVars.Rizz.GetString("InstallLatestVer");
		}

		return new UpdateCheckResponse(
			isUpdateAvailable,
			latestVersion
		);
	}

	/// <summary>
	/// Runs at startup to perform update check.
	/// </summary>
	internal static void CheckAtStartup()
	{
		_ = Task.Run(async () =>
		{
			try
			{
				if (App.Settings.AutoCheckForUpdateAtStartup)
				{
					if (App.PackageSource is 0)
					{
						_ = CheckGitHub();
					}
					else
					{
						_ = await CheckStore();
					}
				}
			}
			catch (Exception ex)
			{
				Logger.Write(ErrorWriter.FormatException(ex));
			}
		});
	}

}
