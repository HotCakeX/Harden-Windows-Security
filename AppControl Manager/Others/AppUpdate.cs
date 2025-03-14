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

namespace AppControlManager.Others;

/// <summary>
/// AppUpdate class is responsible for checking for application updates.
/// This class is implemented as a Singleton to ensure only one instance is created and used throughout the app.
/// Providing a single access point for update-related operations.
/// </summary>
internal sealed class AppUpdate
{
	// Singleton instance of AppUpdate, created lazily to optimize memory usage and control instantiation.
	private static readonly Lazy<AppUpdate> _instance = new(() => new AppUpdate());

	// property to access the single AppUpdate instance, enforcing Singleton pattern.
	// The Instance property returns the one and only instance of this class.
	internal static AppUpdate Instance => _instance.Value;

	/// <summary>
	/// Event triggered when an update is available.
	/// Includes details about the availability status and the version.
	/// </summary>
	internal event EventHandler<UpdateAvailableEventArgs>? UpdateAvailable;

	// Private constructor prevents instantiation from outside, ensuring only one instance.
	private AppUpdate() { }

	/// <summary>
	/// Downloads the version file from GitHub,
	/// Checks the online version against the current app version,
	/// and raises the UpdateAvailable event if an update is found.
	/// </summary>
	internal UpdateCheckResponse Check()
	{
		using HttpClient client = new SecHttpClient();

		string versionsResponse = client.GetStringAsync(GlobalVars.AppVersionLinkURL).GetAwaiter().GetResult();

		Version onlineAvailableVersion = new(versionsResponse);
		bool isUpdateAvailable = onlineAvailableVersion > App.currentAppVersion;

		// Raise the UpdateAvailable event if there are subscribers
		UpdateAvailable?.Invoke(
			this,
			new UpdateAvailableEventArgs(isUpdateAvailable, onlineAvailableVersion)
		);

		return new UpdateCheckResponse(
			isUpdateAvailable,
			onlineAvailableVersion
		);
	}
}

/// <summary>
/// EventArgs class to provide data for the UpdateAvailable event.
/// </summary>
internal sealed class UpdateAvailableEventArgs(bool isUpdateAvailable, Version availableVersion) : EventArgs
{
	/// <summary>
	/// Indicates whether an update is available.
	/// </summary>
	internal bool IsUpdateAvailable { get; } = isUpdateAvailable;

	/// <summary>
	/// The version of the available update.
	/// </summary>
	internal Version AvailableVersion { get; } = availableVersion;
}
