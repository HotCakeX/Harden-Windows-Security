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
using System.IO;
using System.Linq;
using AppControlManager.Others;
using AppControlManager.Taskbar;
using HardenSystemSecurity.Others;
using HardenSystemSecurity.ViewModels;
using HardenSystemSecurity.WindowComponents;
using Microsoft.UI.Xaml;
using Microsoft.Windows.AppLifecycle;
using Windows.ApplicationModel.Activation;
using Windows.Storage;

namespace HardenSystemSecurity;

#pragma warning disable CA1515

public partial class App : Application
{
	// Ephemeral activation context used only during this launch session
	private static string? _activationFilePath;
	private static bool _activationIsFileActivation;

	/// <summary>
	/// Invoked when the application is launched.
	/// </summary>
	/// <param name="args">Details about the launch request and process.</param>
	protected override async void OnLaunched(Microsoft.UI.Xaml.LaunchActivatedEventArgs args)
	{
		// Determines whether the session must prompt for UAC to elevate or not
		bool requireAdminPrivilege = false;

		try
		{
			// https://learn.microsoft.com/windows/apps/windows-app-sdk/migrate-to-windows-app-sdk/guides/applifecycle#file-type-association
			AppActivationArguments activatedEventArgs = AppInstance.GetCurrent().GetActivatedEventArgs();

			if (activatedEventArgs.Kind is ExtendedActivationKind.File)
			{
				Logger.Write(GlobalVars.GetStr("FileActivationDetectedMessage"));

				IFileActivatedEventArgs? fileActivatedArgs = activatedEventArgs.Data as IFileActivatedEventArgs;

				if (fileActivatedArgs is not null)
				{
					IReadOnlyList<IStorageItem>? incomingStorageItems = fileActivatedArgs.Files;

					if (incomingStorageItems is not null && incomingStorageItems.Count > 0)
					{
						foreach (IStorageItem item in incomingStorageItems)
						{
							if (item.Path is not null && File.Exists(item.Path))
							{
								// If the selected file is not accessible with the privileges the app is currently running with, prompt for elevation
								requireAdminPrivilege = !FileAccessCheck.IsFileAccessibleForWrite(item.Path);

								// Store ephemeral activation context
								_activationFilePath = item.Path;
								_activationIsFileActivation = true;

								break;
							}
						}
					}
					else
					{
						Logger.Write(GlobalVars.GetStr("FileActivationNoObjectsMessage"));
					}
				}
				else
				{
					Logger.Write(GlobalVars.GetStr("FileActivationNoArgumentsMessage"));
				}
			}
			else
			{
				Logger.Write($"ExtendedActivationKind: {activatedEventArgs.Kind}");

				string[] possibleArgs = Environment.GetCommandLineArgs();

				// Look for our key
				string? fileArg = possibleArgs.FirstOrDefault(a => a.StartsWith("--file=", StringComparison.OrdinalIgnoreCase));

				if (fileArg is not null)
				{
					string filePath = fileArg["--file=".Length..].Trim('"');

					if (!string.IsNullOrWhiteSpace(filePath))
					{
						if (File.Exists(filePath))
						{
							Logger.Write($"Parsed File: {filePath}");
							_activationFilePath = filePath;

							// If the selected file is not accessible with the privileges the app is currently running with, prompt for elevation
							requireAdminPrivilege = !FileAccessCheck.IsFileAccessibleForWrite(filePath);
						}
						else
						{
							Logger.Write(GlobalVars.GetStr("FileActivationNoObjectsMessage"));
						}
					}
				}
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}

		// If the current session is not elevated and user configured the app to ask for elevation on startup
		// Also prompt for elevation whether or not prompt for elevation setting is on when user selects a file to open from file explorer that requires elevated permissions
		if (!IsElevated && Settings.PromptForElevationOnStartup || !IsElevated && requireAdminPrivilege)
		{
			// Build passthrough arguments so the elevated instance can reconstruct intent.
			if (Relaunch.RelaunchAppElevated(AUMID, BuildRelaunchArguments()))
			{
				// Exit the process
				Environment.Exit(0);
			}
			else if (requireAdminPrivilege)
			{
				Logger.Write(GlobalVars.GetStr("ElevationRequiredButDeniedMessage"));

				// Exit the process anyway since admin privileges were required but user didn't successfully elevate
				Environment.Exit(0);
			}
			else
			{
				Logger.Write(GlobalVars.GetStr("ElevationDeniedMessage"));
			}
		}

		m_window = new MainWindow();

		MainWindowVM.SetCaptionButtonsFlowDirection(string.Equals(Settings.ApplicationGlobalFlowDirection, "LeftToRight", StringComparison.OrdinalIgnoreCase) ? FlowDirection.LeftToRight : FlowDirection.RightToLeft);

		NavigationService.RestoreWindowSize(m_window.AppWindow); // Restore window size on startup
		ViewModelProvider.NavigationService.mainWindowVM.OnIconsStylesChanged(Settings.IconsStyle); // Set the initial Icons styles based on the user's settings
		m_window.Closed += Window_Closed;  // Assign event handler for the window closed event
		m_window.Activate();

		// If the app was forcefully exited previously while there was a badge being displayed on the taskbar icon we have to remove it on app startup otherwise it will be there!
		Badge.ClearBadge();

		#region Initial navigation and file activation processing

		// File activation path (opened via File Explorer or protocol that yielded File activation)
		if (_activationIsFileActivation && !string.IsNullOrWhiteSpace(_activationFilePath))
		{
			Logger.Write(string.Format(GlobalVars.GetStr("FileActivationLaunchMessage"), _activationFilePath));

			try
			{
				await ViewModelProvider.GroupPolicyEditorVM.OpenInGroupPolicyEditor(_activationFilePath);
			}
			catch (Exception ex)
			{
				Logger.Write(ex);

				// Continue doing the normal navigation if there was a problem
				InitialNav();
			}
			finally
			{
				// Clear the file activated launch args after it's been used
				_activationFilePath = null;
				_activationIsFileActivation = false;
			}
		}
		// CLI handoff path: elevated relaunch or direct CLI launch with --file=
		else if (!string.IsNullOrWhiteSpace(_activationFilePath))
		{
			Logger.Write(string.Format(GlobalVars.GetStr("FileActivationLaunchMessage"), _activationFilePath));

			try
			{
				await ViewModelProvider.GroupPolicyEditorVM.OpenInGroupPolicyEditor(_activationFilePath);
			}
			catch (Exception ex)
			{
				Logger.Write(ex);

				// Continue doing the normal navigation if there was a problem
				InitialNav();
			}
			finally
			{
				// Clear after use
				_activationFilePath = null;
			}
		}
		else
		{
			InitialNav();
		}

		#endregion

		// If the user has enabled animated rainbow border for the app window, start it
		if (Settings.IsAnimatedRainbowEnabled)
		{
			CustomUIElements.AppWindowBorderCustomization.StartAnimatedFrame();
		}
		// If the user has set a custom color for the app window border, apply it
		else if (!string.IsNullOrEmpty(Settings.CustomAppWindowsBorder))
		{
			if (RGBHEX.ToRGB(Settings.CustomAppWindowsBorder, out byte r, out byte g, out byte b))
				CustomUIElements.AppWindowBorderCustomization.SetBorderColor(r, g, b);
		}

		// Startup update check
		AppUpdate.CheckAtStartup();
	}

	/// <summary>
	/// Builds the argument string to pass to the elevated instance so that it can re-create the original launch intent.
	/// For Harden System Security app, this currently means passing only the file path if present.
	/// </summary>
	private static string? BuildRelaunchArguments()
	{
		if (!string.IsNullOrWhiteSpace(_activationFilePath))
		{
			// Properly quote the file path for command line parsing (double embedded quotes if any).
			string safePath = _activationFilePath.Replace("\"", "\"\"");
			return $"--file=\"{safePath}\"";
		}

		return null;
	}
}
