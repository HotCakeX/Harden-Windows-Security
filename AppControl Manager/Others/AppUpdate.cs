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
using System.Threading.Tasks;
using Windows.Services.Store;
using Microsoft.Windows.BadgeNotifications;
using Microsoft.Windows.AppNotifications;
using WinRT;
using Microsoft.Windows.AppLifecycle;
using Windows.ApplicationModel.Activation;

#if HARDEN_SYSTEM_SECURITY
using AppControlManager.Others;
using HardenSystemSecurity.ViewModels;
namespace HardenSystemSecurity.Others;
#endif
#if APP_CONTROL_MANAGER
using AppControlManager.ViewModels;
namespace AppControlManager.Others;
#endif

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

	internal const string UpdateNotificationActionKey = "action";
	internal const string UpdateNotificationActionValue = "OpenUpdatePage";

	private static void DisplayAvailableUpdateNotifications()
	{
		// Display Toast Notification
		UnelevatedOperations.ToastNotifications.ShowToastNotification(title: "New Update Available",
																	  body: "There is a new update available for the app.",
																	  attributionText: "Please update to the latest version by opening the Microsoft Store.",
																	  group: "New Update",
																	  soundEvent: Microsoft.Windows.AppNotifications.Builder.AppNotificationSoundEvent.Reminder,
																	  arguments: (UpdateNotificationActionKey, UpdateNotificationActionValue));

		// Display a badge on the taskbar icon to indicate that an update is available
		UnelevatedOperations.TaskbarBadge.SetTaskbarBadge(BadgeNotificationGlyph.Alert);
	}

	/// <summary>
	/// Downloads the version file from GitHub,
	/// Checks the online version against the current app version,
	/// and raises the UpdateAvailable event if an update is found.
	/// </summary>
	internal static UpdateCheckResponse CheckGitHub()
	{
		string versionsResponse = SecHttpClient.Instance.GetStringAsync(Atlas.AppVersionLinkURL).GetAwaiter().GetResult().Trim();

		Version onlineAvailableVersion = new(versionsResponse);
		bool isUpdateAvailable = onlineAvailableVersion > Atlas.currentAppVersion;

		// Raise the UpdateAvailable event if there are subscribers
		UpdateAvailable?.Invoke(
			null,
			new UpdateAvailableEventArgs(isUpdateAvailable, onlineAvailableVersion)
		);

		// If a new version is available
		if (isUpdateAvailable)
		{
			// Set the text for the button in the update page
			ViewModelProvider.UpdateVM.UpdateButtonContent = string.Format(
				Atlas.GetStr("InstallVersionMessage"),
				onlineAvailableVersion);

			DisplayAvailableUpdateNotifications();
		}
		else
		{
			Logger.Write(Atlas.GetStr("TheAppIsUpToDate"));
		}

		return new UpdateCheckResponse(
			isUpdateAvailable,
			onlineAvailableVersion
		);
	}

	/// <summary>
	/// Checks for update based on the Store Context.
	/// </summary>
	internal static async Task<UpdateCheckResponse> CheckStore()
	{
		StoreContext _StoreContext = StoreContext.GetDefault();

		// Initialize the dialog using wrapper function for IInitializeWithWindow
		WinRT.Interop.InitializeWithWindow.Initialize(_StoreContext, Atlas.hWnd);

		// Find any available updates to the currently running package
		IReadOnlyList<StorePackageUpdate> updates = await _StoreContext.GetAppAndOptionalStorePackageUpdatesAsync();

		bool isUpdateAvailable = false;

		// This is a dummy value for now until we can get the actual latest version from the Store available update.
		Version latestVersion = new(0, 0, 0, 0);

		if (updates.Count is 0)
		{
			Logger.Write(Atlas.GetStr("TheAppIsUpToDate"));
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
			ViewModelProvider.UpdateVM.UpdateButtonContent = Atlas.GetStr("InstallLatestVer");

			DisplayAvailableUpdateNotifications();
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
				if (Atlas.Settings.AutoCheckForUpdateAtStartup)
				{
					_ = Atlas.PackageSource is 0 ? CheckGitHub() : await CheckStore();
				}
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}
		});
	}

	internal static void QueueUpdatePageNavigation()
	{
		bool wasQueued = Atlas.AppDispatcher.TryEnqueue(async () =>
		{
			try
			{
				App.MainWindow?.Activate();
				await ViewModelProvider.NavigationService.Navigate(typeof(Pages.UpdatePage), null);
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}
		});

		if (!wasQueued)
		{
			Logger.Write("Failed to queue update page navigation from notification activation.");
		}
	}

	internal static void App_NotificationInvoked(AppNotificationManager sender, AppNotificationActivatedEventArgs args)
	{
		bool isUpdateAction = args.Arguments.TryGetValue(UpdateNotificationActionKey, out string? action) &&
			string.Equals(action, UpdateNotificationActionValue, StringComparison.OrdinalIgnoreCase);

		if (!isUpdateAction && !string.IsNullOrWhiteSpace(args.Argument))
		{
			isUpdateAction = args.Argument.Contains($"{UpdateNotificationActionKey}={UpdateNotificationActionValue}", StringComparison.OrdinalIgnoreCase);
		}

		if (isUpdateAction)
		{
			QueueUpdatePageNavigation();
		}
	}

	[DynamicWindowsRuntimeCast(typeof(AppNotificationActivatedEventArgs))]
	internal static bool IsUpdateNotificationActivation(AppActivationArguments? activationArguments)
	{
		if (activationArguments is null)
		{
			return false;
		}

		if (activationArguments.Data is AppNotificationActivatedEventArgs appNotificationArgs)
		{
			bool isUpdateAction = appNotificationArgs.Arguments.TryGetValue(UpdateNotificationActionKey, out string? action) &&
				string.Equals(action, UpdateNotificationActionValue, StringComparison.OrdinalIgnoreCase);

			return isUpdateAction ||
				(!string.IsNullOrWhiteSpace(appNotificationArgs.Argument) &&
				appNotificationArgs.Argument.Contains($"{UpdateNotificationActionKey}={UpdateNotificationActionValue}", StringComparison.OrdinalIgnoreCase));
		}

		if (activationArguments.Data is IToastNotificationActivatedEventArgs toastNotificationArgs)
		{
			return !string.IsNullOrWhiteSpace(toastNotificationArgs.Argument) &&
				toastNotificationArgs.Argument.Contains($"{UpdateNotificationActionKey}={UpdateNotificationActionValue}", StringComparison.OrdinalIgnoreCase);
		}

		return false;
	}
}
