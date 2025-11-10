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
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using AppControlManager.Taskbar;
using HardenSystemSecurity.DeviceIntents;
using HardenSystemSecurity.Helpers;
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

	// CLI state carried across elevation
	private static int? _cliPresetIndex;
	private static string? _cliOperation;

	// CLI action token (single-word subcommand parsed after --cli)
	private static string? _cliAction;

	// Device usage intent requested via CLI
	private static Intent? _cliDeviceIntent;

	// Determines whether the session must prompt for UAC to elevate or not
	private static bool requireAdminPrivilege;

	// For navigation restoration passed via command line
	private static string? _cliNavTag;

	private static Type? PageTypeToNavTo;

	/// <summary>
	/// Invoked when the application is launched.
	/// </summary>
	/// <param name="args">Details about the launch request and process.</param>
	protected override async void OnLaunched(Microsoft.UI.Xaml.LaunchActivatedEventArgs args)
	{
		string[] possibleArgs = Environment.GetCommandLineArgs();

		try
		{
			AppActivationArguments? activatedEventArgs = null;

			try
			{   // This won't work if the app is installed for a user with Standard privileges and then launched as Admin (another user that has Admin privilege).
				// https://learn.microsoft.com/windows/apps/windows-app-sdk/migrate-to-windows-app-sdk/guides/applifecycle#file-type-association
				activatedEventArgs = AppInstance.GetCurrent().GetActivatedEventArgs();
			}
#if DEBUG
			catch (Exception ex) { Logger.Write(ex); }
#else
			catch { }
#endif

			if (activatedEventArgs is not null)
			{
				Logger.Write($"ExtendedActivationKind: {activatedEventArgs.Kind}");

				if (activatedEventArgs.Kind is ExtendedActivationKind.File)
				{
					Logger.Write(GlobalVars.GetStr("FileActivationDetectedMessage"));

					if (activatedEventArgs.Data is IFileActivatedEventArgs fileActivatedArgs)
					{
						if (fileActivatedArgs.Files.Count > 0)
						{
							foreach (IStorageItem item in fileActivatedArgs.Files)
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
					ParseArgs(possibleArgs, null);
				}
			}
			else
			{
				ParseArgs(possibleArgs, null);
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}

		// If the current session is not elevated and user configured the app to ask for elevation on startup
		// Also prompt for elevation whether or not prompt for elevation setting is on when user selects a file to open from file explorer that requires elevated permissions
		if (!IsElevated && (Settings.PromptForElevationOnStartup || requireAdminPrivilege))
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

		// If CLI was requested.
		if (Logger.CliRequested)
		{
			try
			{
				// If a CLI preset operation is requested, execute it headlessly.
				if (_cliPresetIndex.HasValue)
				{
					int presetIndex = _cliPresetIndex.Value;

					// Validate the operation
					if (!Enum.TryParse(_cliOperation, true, out MUnitOperation opEnum))
					{
						Logger.Write("Error: --op value was not valid.");
						Environment.Exit(2);
						return;
					}

					Logger.Write($"Running preset {presetIndex} with operation '{opEnum}'...");

					// Run the command
					await ViewModelProvider.ProtectVM.RunPresetFromCliAsync(presetIndex, opEnum);

					Logger.Write("Operation completed successfully.");
				}

				// If a device usage intent is requested, execute it headlessly.
				else if (_cliDeviceIntent.HasValue)
				{
					// Require --op and only support Apply for intents for now
					if (string.IsNullOrWhiteSpace(_cliOperation) ||
						!Enum.TryParse(_cliOperation, true, out MUnitOperation opEnum) ||
						opEnum != MUnitOperation.Apply)
					{
						Logger.Write("Error: --intent requires '--op=Apply'.");
						Environment.Exit(2);
						return;
					}

					if (_cliDeviceIntent.Value == Intent.All)
					{
						Logger.Write("Error: --intent=All is not supported.");
						Environment.Exit(2);
					}

					Logger.Write($"Applying device usage intent '{_cliDeviceIntent.Value}'...");

					await ViewModelProvider.ProtectVM.RunIntentFromCliAsync(_cliDeviceIntent.Value);

					Logger.Write("Intent-based protections applied successfully.");
				}

				// If a standalone CLI action was requested, execute it headlessly.
				else if (!string.IsNullOrWhiteSpace(_cliAction))
				{
					if (string.Equals(_cliAction, "CheckMSStoreAppUpdate", StringComparison.OrdinalIgnoreCase))
					{
						await ViewModelProvider.MainWindowVM.CheckForAllAppUpdates_Internal();
					}
					else
					{
						Logger.Write($"Error: Unknown CLI action '{_cliAction}'.");
						Environment.Exit(2);
						return;
					}
				}

				// When CLI was requested, the GUI should not be loaded. If no valid CLI operation was requested, just exit.
				Environment.Exit(0);
				return;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				Environment.Exit(1);
				return;
			}
		}

		MainWindow = new MainWindow();

		MainWindowVM.SetCaptionButtonsFlowDirection(string.Equals(Settings.ApplicationGlobalFlowDirection, "LeftToRight", StringComparison.OrdinalIgnoreCase) ? FlowDirection.LeftToRight : FlowDirection.RightToLeft);

		NavigationService.RestoreWindowSize(MainWindow.AppWindow); // Restore window size on startup
		ViewModelProvider.NavigationService.mainWindowVM.OnIconsStylesChanged(Settings.IconsStyle); // Set the initial Icons styles based on the user's settings
		MainWindow.Closed += Window_Closed;  // Assign event handler for the window closed
		MainWindow.Activate();

		// If the app was forcefully exited previously while there was a badge being displayed on the taskbar icon we have to remove it on app startup otherwise it will be there!
		Badge.ClearBadge();

		#region Initial navigation and file activation processing

		// File activation path (opened via File Explorer or protocol that yielded File activation)
		if (_activationIsFileActivation && !string.IsNullOrWhiteSpace(_activationFilePath))
		{
			Logger.Write(string.Format(CultureInfo.InvariantCulture, GlobalVars.GetStr("FileActivationLaunchMessage"), _activationFilePath));

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
			Logger.Write(string.Format(CultureInfo.InvariantCulture, GlobalVars.GetStr("FileActivationLaunchMessage"), _activationFilePath));

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
		// Navigation restoration path or user asking for specific page to launch.
		else if (PageTypeToNavTo is not null)
		{
			try
			{
				ViewModelProvider.NavigationService.Navigate(PageTypeToNavTo, null);
			}
			finally
			{
				PageTypeToNavTo = null;
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
	/// </summary>
	private static string? BuildRelaunchArguments()
	{
		List<string> parts = new(capacity: 6);

		// Preserve console across elevation if requested
		if (Logger.CliRequested)
		{
			parts.Add("--cli");
		}

		// Preserve preset and operation across elevation
		if (_cliPresetIndex.HasValue)
		{
			parts.Add($"--preset={_cliPresetIndex.Value}");
		}
		if (!string.IsNullOrWhiteSpace(_cliOperation))
		{
			parts.Add($"--op={_cliOperation}");
		}

		// Preserve device usage intent across elevation
		if (_cliDeviceIntent.HasValue)
		{
			parts.Add($"--intent={_cliDeviceIntent.Value}");
		}

		// Preserve single-token CLI action across elevation
		if (!string.IsNullOrWhiteSpace(_cliAction))
		{
			parts.Add(_cliAction);
		}

		if (!string.IsNullOrWhiteSpace(_activationFilePath))
		{
			// Properly quote the file path for command line parsing (double embedded quotes if any).
			string safePath = _activationFilePath.Replace("\"", "\"\"", StringComparison.OrdinalIgnoreCase);
			parts.Add($"--file=\"{safePath}\"");
		}

		// Navigation arguments
		if (!string.IsNullOrWhiteSpace(_cliNavTag))
		{
			parts.Add($"--navtag={_cliNavTag}");
		}

		if (parts.Count == 0)
		{
			return null;
		}

		StringBuilder builder = new();
		for (int i = 0; i < parts.Count; i++)
		{
			if (i > 0)
			{
				_ = builder.Append(' ');
			}
			_ = builder.Append(parts[i]);
		}
		return builder.ToString();
	}

	private static void ParseArgs(string[]? ArgsLines, string? ArgLine)
	{
		if (ArgsLines is not null)
		{
			// Detect console request and attach/allocate a console.
			Logger.CliRequested = ArgsLines.Any(a => string.Equals(a, "--cli", StringComparison.OrdinalIgnoreCase));
			if (Logger.CliRequested)
			{
				ConsoleHelper.AttachOrAllocate();
				Logger.Write("Harden System Security - CLI mode");

				// Extract a single-token action right after --cli if provided
				int cliIndex = Array.FindIndex(ArgsLines, a => string.Equals(a, "--cli", StringComparison.OrdinalIgnoreCase));
				if (cliIndex >= 0 && cliIndex + 1 < ArgsLines.Length)
				{
					string possibleAction = ArgsLines[cliIndex + 1];
					// Action token must not be another flag (must not begin with "--")
					if (!string.IsNullOrWhiteSpace(possibleAction) && !possibleAction.StartsWith("--", StringComparison.Ordinal))
					{
						_cliAction = possibleAction;
						requireAdminPrivilege = true;
					}
				}
			}

			// Parse CLI: preset index (0,1,2)
			string? presetArg = ArgsLines.FirstOrDefault(a => a.StartsWith("--preset=", StringComparison.OrdinalIgnoreCase));
			if (presetArg is not null)
			{
				string raw = presetArg["--preset=".Length..].Trim();
				if (int.TryParse(raw, out int idx) && idx >= 0 && idx <= 2)
				{
					_cliPresetIndex = idx;
					requireAdminPrivilege = true;
				}
				else
				{
					Logger.Write("--preset must be 0 (Basic), 1 (Recommended), or 2 (Complete).");
					Environment.Exit(2);
					return;
				}
			}

			// Parse CLI: device usage intent
			string? intentArg = ArgsLines.FirstOrDefault(a => a.StartsWith("--intent=", StringComparison.OrdinalIgnoreCase));
			if (intentArg is not null)
			{
				string rawIntent = intentArg["--intent=".Length..].Trim();
				if (Enum.TryParse(rawIntent, true, out Intent parsedIntent))
				{
					_cliDeviceIntent = parsedIntent;
					requireAdminPrivilege = true;
				}
				else
				{
					Logger.Write("Error: --intent value was not valid.");
					Environment.Exit(2);
					return;
				}
			}

			string? opArg = ArgsLines.FirstOrDefault(a => a.StartsWith("--op=", StringComparison.OrdinalIgnoreCase));
			if (opArg is not null)
			{
				// Store raw operation text; validation is done via enum parsing below.
				_cliOperation = opArg["--op=".Length..].Trim();
			}

			// Look for our key
			string? fileArg = ArgsLines.FirstOrDefault(a => a.StartsWith("--file=", StringComparison.OrdinalIgnoreCase));

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

			// Parse navigation restoration arguments
			string? navTagArg = ArgsLines.FirstOrDefault(a => a.StartsWith("--navtag=", StringComparison.OrdinalIgnoreCase));
			if (navTagArg is not null)
			{
				string rawTag = navTagArg["--navtag=".Length..].Trim();
				if (!string.IsNullOrWhiteSpace(rawTag))
				{
					_cliNavTag = rawTag;
					if (!ViewModelProvider.NavigationService.mainWindowVM.NavigationPageToItemContentMap.TryGetValue(_cliNavTag, out PageTypeToNavTo))
					{
						Logger.Write($"{rawTag} is not a valid page tag.");
					}
					else
					{
						// If the page requires elevation, we must ask for it.
						if (!ViewModelProvider.MainWindowVM.UnelevatedPages.Contains(PageTypeToNavTo))
						{
							requireAdminPrivilege = true;
						}
					}
				}
			}
		}
	}
}
