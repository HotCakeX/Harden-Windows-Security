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
using System.Net.Http;
using Microsoft.Extensions.DependencyInjection;

namespace AppControlManager.Others;

/// <summary>
/// AppUpdate class is responsible for checking for application updates.
/// This class is implemented as a Singleton to ensure only one instance is created and used throughout the app.
/// Providing a single access point for update-related operations.
/// </summary>
internal static class AppUpdate
{
	/// <summary>
	/// Event triggered when an update is available.
	/// Includes details about the availability status and the version.
	/// </summary>
	internal static event EventHandler<UpdateAvailableEventArgs>? UpdateAvailable;

	private static ViewModels.UpdateVM UpdateVM { get; } = App.AppHost.Services.GetRequiredService<ViewModels.UpdateVM>();

	/// <summary>
	/// Downloads the version file from GitHub,
	/// Checks the online version against the current app version,
	/// and raises the UpdateAvailable event if an update is found.
	/// </summary>
	internal static UpdateCheckResponse Check()
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
			UpdateVM.UpdateButtonContent = $"Install version {onlineAvailableVersion}";
		}
		else
		{
			Logger.Write("No new version of the AppControl Manager is available.");
		}

		return new UpdateCheckResponse(
			isUpdateAvailable,
			onlineAvailableVersion
		);
	}
}
