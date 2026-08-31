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
using CommonCore.GroupPolicy;
using HardenSystemSecurity.Helpers;
using HardenSystemSecurity.Others;
using HardenSystemSecurity.ViewModels;
using HardenSystemSecurity.WindowComponents;
using Microsoft.UI.Xaml;
using Microsoft.Windows.AppLifecycle;
using Microsoft.Windows.AppNotifications;
using Microsoft.Windows.BadgeNotifications;
using Windows.ApplicationModel.Activation;
using Windows.Storage;

namespace HardenSystemSecurity;

#pragma warning disable CA1515

public sealed partial class App : Application
{
	// Forwards a Snipping Tool protocol response to the currently loaded Secure Vault page.
	internal static Action<Uri?>? SnippingToolResponseHandler;
	private static AppInstance? _activationInstance;

	/// <summary>
	/// Invoked when the application is launched.
	/// </summary>
	/// <param name="args">Details about the launch request and process.</param>
	protected override async void OnLaunched(Microsoft.UI.Xaml.LaunchActivatedEventArgs args)
	{
		string[] launchArguments = Program.GetLaunchArguments();
		if (launchArguments.Length == 4 &&
			string.Equals(launchArguments[0], "--mcp-protect-worker", StringComparison.OrdinalIgnoreCase) &&
			int.TryParse(launchArguments[3], out int presetIndex))
		{
			await MCP.McpServer.RunProtectWorkerAsync(launchArguments[1], launchArguments[2], presetIndex);
			Environment.Exit(0);
		}
		if (launchArguments.Length >= 1 && string.Equals(launchArguments[0], "--mcp", StringComparison.OrdinalIgnoreCase))
		{
			using Stream input = Console.OpenStandardInput();
			using Stream output = Console.OpenStandardOutput();
			await MCP.McpServer.RunAsync(input, output);
			Environment.Exit(0);
		}

		// Extract the requested Live System Intelligence window or chart target when the app is launched from a Jump List item.
		string? liveSystemIntelligenceLaunchTarget = CommonCore.Taskbar.JumpListMgr.GetLiveSystemIntelligenceLaunchTarget(launchArguments);

		// Register the Jump List Items
		await CommonCore.Taskbar.JumpListMgr.EnsureJumpListAsync();

		// Ephemeral activation path used only during this launch session
		string? _activationFilePath = null;

		// CLI state carried across elevation
		int? _cliPresetIndex = null;
		string? _cliOperation = null;

		// CLI action token (single-word subcommand parsed after --cli)
		string? _cliAction = null;

		// Device usage intent requested via CLI
		Intent? _cliDeviceIntent = null;

		// Determines whether the session must prompt for UAC to elevate or not
		bool requireAdminPrivilege = false;

		// For navigation restoration passed via command line
		string? _cliNavTag = null;

		Type? PageTypeToNavTo = null;

		// CLI import/export arguments
		string? _cliImportPath = null, _cliExportPath = null;
		bool _cliModeFull = true; // --mode defaults to full; partial sets this false

		/// <summary>
		/// Builds the argument string to pass to the elevated instance so that it can re-create the original launch intent.
		/// </summary>
		string BuildRelaunchArguments()
		{
			List<string> parts = new(capacity: 10);

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
				parts.Add($"--file=\"{_activationFilePath.Replace("\"", "\"\"")}\"");
			}

			// Navigation arguments
			if (!string.IsNullOrWhiteSpace(_cliNavTag))
			{
				parts.Add($"--navtag={_cliNavTag}");
			}

			// Include import/export specific arguments
			if (!string.IsNullOrWhiteSpace(_cliImportPath))
			{
				parts.Add($"--in=\"{_cliImportPath.Replace("\"", "\"\"")}\"");
			}
			if (!string.IsNullOrWhiteSpace(_cliExportPath))
			{
				parts.Add($"--out=\"{_cliExportPath.Replace("\"", "\"\"")}\"");
			}
			parts.Add(_cliModeFull ? "--mode=full" : "--mode=partial");

			return string.Join(' ', parts);
		}

		void ParseArgs(string[] ArgsLines)
		{
			// Detect console request and attach/allocate a console.
			int cliIndex = Array.FindIndex(ArgsLines, static a => string.Equals(a, "--cli", StringComparison.OrdinalIgnoreCase));
			Logger.CliRequested = cliIndex >= 0;
			if (Logger.CliRequested)
			{
				ConsoleHelper.AttachOrAllocate();
				Logger.Write("Harden System Security - CLI mode");

				// Extract a single-token action right after --cli if provided
				if (cliIndex >= 0 && cliIndex + 1 < ArgsLines.Length)
				{
					string possibleAction = ArgsLines[cliIndex + 1];
					// Action token must not be another flag (must not begin with "--")
					if (!string.IsNullOrWhiteSpace(possibleAction) && !possibleAction.StartsWith("--", StringComparison.Ordinal))
					{
						_cliAction = possibleAction;
						// Elevation required for both actions
						if (string.Equals(possibleAction, "ExportReport", StringComparison.OrdinalIgnoreCase) ||
							string.Equals(possibleAction, "ImportReport", StringComparison.OrdinalIgnoreCase))
						{
							requireAdminPrivilege = true;
						}
					}
				}
			}

			// Parse CLI: preset index (0,1,2)
			if (ArgsLines.FirstOrDefault(a => a.StartsWith("--preset=", StringComparison.OrdinalIgnoreCase)) is string presetArg)
			{
				if (!int.TryParse(presetArg.AsSpan("--preset=".Length).Trim(), out int idx) || idx < 0 || idx > 2)
				{
					Logger.Write("--preset must be 0 (Basic), 1 (Recommended), or 2 (Complete).");
					Environment.Exit(2);
				}
				_cliPresetIndex = idx;
				requireAdminPrivilege = true;
			}

			// Parse CLI: device usage intent
			if (ArgsLines.FirstOrDefault(a => a.StartsWith("--intent=", StringComparison.OrdinalIgnoreCase)) is string intentArg)
			{
				if (!Enum.TryParse(intentArg.AsSpan("--intent=".Length).Trim(), true, out Intent parsedIntent))
				{
					Logger.Write("Error: --intent value was not valid.");
					Environment.Exit(2);
				}
				_cliDeviceIntent = parsedIntent;
				requireAdminPrivilege = true;
			}

			if (ArgsLines.FirstOrDefault(a => a.StartsWith("--op=", StringComparison.OrdinalIgnoreCase)) is string opArg)
			{
				// Store raw operation text; validation is done via enum parsing below.
				_cliOperation = opArg["--op=".Length..].Trim();
			}

			// Look for our key
			if (ArgsLines.FirstOrDefault(a => a.StartsWith("--file=", StringComparison.OrdinalIgnoreCase)) is string fileArg)
			{
				string filePath = fileArg["--file=".Length..].Trim('"');

				if (File.Exists(filePath))
				{
					Logger.Write($"Parsed File: {filePath}");
					_activationFilePath = filePath;

					// If the selected file is not accessible with the privileges the app is currently running with, prompt for elevation
					requireAdminPrivilege = !FileAccessCheck.IsFileAccessible(filePath: filePath, readAndWrite: true);
				}
				else
				{
					Logger.Write(Atlas.GetStr("FileActivationNoObjectsMessage"));
				}
			}

			// Parse navigation restoration arguments
			if (ArgsLines.FirstOrDefault(a => a.StartsWith("--navtag=", StringComparison.OrdinalIgnoreCase)) is string navTagArg)
			{
				string rawTag = navTagArg["--navtag=".Length..].Trim();
				if (!string.IsNullOrWhiteSpace(rawTag))
				{
					_cliNavTag = rawTag;
					if (!ViewModelProvider.NavigationService.mainWindowVM.NavigationPageToItemContentMap.TryGetValue(_cliNavTag, out PageTypeToNavTo))
					{
						Logger.Write($"{rawTag} is not a valid page tag.");
					}
					// If the page requires elevation, we must ask for it.
					else if (!ViewModelProvider.MainWindowVM.UnelevatedPages.Contains(PageTypeToNavTo))
					{
						requireAdminPrivilege = true;
					}
				}
			}

			// Parse import/export specific arguments
			if (ArgsLines.FirstOrDefault(a => a.StartsWith("--in=", StringComparison.OrdinalIgnoreCase)) is string inArg)
			{
				string rawIn = inArg["--in=".Length..].Trim().Trim('"');
				if (!string.IsNullOrWhiteSpace(rawIn))
				{
					_cliImportPath = rawIn;
					// Elevation required regardless of validation specifics
					requireAdminPrivilege = true;
				}
			}

			if (ArgsLines.FirstOrDefault(a => a.StartsWith("--out=", StringComparison.OrdinalIgnoreCase)) is string outArg)
			{
				string rawOut = outArg["--out=".Length..].Trim().Trim('"');
				if (!string.IsNullOrWhiteSpace(rawOut))
				{
					_cliExportPath = rawOut;
					requireAdminPrivilege = true;
				}
			}

			if (ArgsLines.FirstOrDefault(a => a.StartsWith("--mode=", StringComparison.OrdinalIgnoreCase)) is string modeArg)
			{
				ReadOnlySpan<char> rawMode = modeArg.AsSpan("--mode=".Length).Trim();
				bool isFull = rawMode.Equals("full", StringComparison.OrdinalIgnoreCase);
				if (!isFull && !rawMode.Equals("partial", StringComparison.OrdinalIgnoreCase))
				{
					Logger.Write("Error: --mode must be 'full' or 'partial'.");
					Environment.Exit(2);
				}
				_cliModeFull = isFull;
			}
		}

		// Tracks whether this launch was caused by an update notification or Snipping Tool returning a capture response.
		bool launchToUpdatePageFromNotification = false, launchFromSnippingToolResponse = false;

		try
		{
			AppActivationArguments? activatedEventArgs = null;

			try
			{
				if (AppNotificationManager.IsSupported())
				{
					// This must happen before GetActivatedEventArgs for notification activations.
					AppNotificationManager.Default.NotificationInvoked += AppUpdate.App_NotificationInvoked;
					AppNotificationManager.Default.Register();
				}
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}

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

			launchToUpdatePageFromNotification = AppUpdate.IsUpdateNotificationActivation(activatedEventArgs);

			// Detect a Snipping Tool callback so it can be redirected to the primary app instance.
			launchFromSnippingToolResponse = TryGetSnippingToolResponse(activatedEventArgs, out _);

			try
			{
				_activationInstance = AppInstance.FindOrRegisterForKey("HardenSystemSecurity.NotificationActivation");

				if (_activationInstance.IsCurrent)
				{
					_activationInstance.Activated += App_Activated;
				}
				else if (launchToUpdatePageFromNotification || launchFromSnippingToolResponse || liveSystemIntelligenceLaunchTarget is not null)
				{
					// the redirect brokers across the integrity boundary because it's package-identity-scoped, not token-scoped.
					await _activationInstance.RedirectActivationToAsync(activatedEventArgs);
					Environment.Exit(0);
				}
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}

			if (activatedEventArgs is not null)
			{
				Logger.Write($"ExtendedActivationKind: {activatedEventArgs.Kind}");

				if (activatedEventArgs.Kind is ExtendedActivationKind.File)
				{
					Logger.Write(Atlas.GetStr("FileActivationDetectedMessage"));

					if (activatedEventArgs.Data is not IFileActivatedEventArgs fileActivatedArgs)
					{
						Logger.Write(Atlas.GetStr("FileActivationNoArgumentsMessage"));
					}
					else if (fileActivatedArgs.Files.Count == 0)
					{
						Logger.Write(Atlas.GetStr("FileActivationNoObjectsMessage"));
					}
					else
					{
						foreach (IStorageItem item in fileActivatedArgs.Files)
						{
							if (File.Exists(item.Path))
							{
								// If the selected file is not accessible with the privileges the app is currently running with, prompt for elevation
								requireAdminPrivilege = !FileAccessCheck.IsFileAccessible(filePath: item.Path, readAndWrite: true);

								// Store ephemeral activation context
								_activationFilePath = item.Path;

								break;
							}
						}
					}
				}
				else if (!launchToUpdatePageFromNotification)
				{
					ParseArgs(Program.GetLaunchArguments());
				}
			}
			else
			{
				ParseArgs(Program.GetLaunchArguments());
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}

		// If the current session is not elevated and user configured the app to ask for elevation on startup
		// Also prompt for elevation whether or not prompt for elevation setting is on when user selects a file to open from file explorer that requires elevated permissions
		if (!Atlas.IsElevated && (Atlas.Settings.PromptForElevationOnStartup || requireAdminPrivilege))
		{
			// Build passthrough arguments so the elevated instance can reconstruct intent.
			if (Relaunch.RelaunchAppElevated(Atlas.AUMID, BuildRelaunchArguments()))
			{
				// Exit the process
				Environment.Exit(0);
			}
			else if (requireAdminPrivilege)
			{
				Logger.Write(Atlas.GetStr("ElevationRequiredButDeniedMessage"));

				// Exit the process anyway since admin privileges were required but user didn't successfully elevate
				Environment.Exit(0);
			}
			else
			{
				Logger.Write(Atlas.GetStr("ElevationDeniedMessage"));
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
					// Validate the operation
					if (!Enum.TryParse(_cliOperation, true, out MUnitOperation opEnum))
					{
						Logger.Write("Error: --op value was not valid.");
						Environment.Exit(2);
					}

					Logger.Write($"Running preset {_cliPresetIndex.Value} with operation '{opEnum}'...");

					// Run the command and fail the CLI invocation when the operation did not complete.
					ProtectVM.PresetOperationResult result = await ViewModelProvider.ProtectVM.RunPresetFromCliAsync(_cliPresetIndex.Value, opEnum);
					if (!result.Succeeded)
					{
						throw new InvalidOperationException($"Preset operation '{opEnum}' did not complete.");
					}

					Logger.Write("Operation completed.");
				}

				// If a device usage intent is requested, execute it headlessly.
				else if (_cliDeviceIntent.HasValue)
				{
					// Require --op and only support Apply for intents for now
					if (!Enum.TryParse(_cliOperation, true, out MUnitOperation opEnum) ||
						opEnum != MUnitOperation.Apply)
					{
						Logger.Write("Error: --intent requires '--op=Apply'.");
						Environment.Exit(2);
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
					// Import/Export CLI actions
					if (string.Equals(_cliAction, "ExportReport", StringComparison.OrdinalIgnoreCase))
					{
						// Mandatory --out
						if (string.IsNullOrWhiteSpace(_cliExportPath))
						{
							Logger.Write("Error: ExportReport requires --out=FILEPATH");
							Environment.Exit(2);
						}

						await Traverse.Generator.GenerateTraverseData(_cliExportPath);
					}
					else if (string.Equals(_cliAction, "ImportReport", StringComparison.OrdinalIgnoreCase))
					{
						// Mandatory --in
						if (string.IsNullOrWhiteSpace(_cliImportPath))
						{
							Logger.Write("Error: ImportReport requires --in=FILEPATH");
							Environment.Exit(2);
						}

						await Traverse.Importer.ImportAndApplyAsync(
							filePath: _cliImportPath,
							synchronizeExact: _cliModeFull);
					}
					else if (string.Equals(_cliAction, "CheckMSStoreAppUpdate", StringComparison.OrdinalIgnoreCase))
					{
						await ViewModelProvider.MainWindowVM.CheckForAllAppUpdates_Internal();
					}
					else
					{
						Logger.Write($"Error: Unknown CLI action '{_cliAction}'.");
						Environment.Exit(2);
					}
				}

				// When CLI was requested, the GUI should not be loaded. If no valid CLI operation was requested, just exit.
				Environment.Exit(0);
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				Environment.Exit(1);
			}
		}

		if (liveSystemIntelligenceLaunchTarget is not null)
		{
			ViewModelProvider.HomeVM.OpenLiveGraphsWindow(liveSystemIntelligenceLaunchTarget);
			return;
		}

		MainWindow = new MainWindow();
		MainWindow.Activate();

		// If the app was forcefully exited previously while there was a badge being displayed on the taskbar icon we have to remove it on app startup otherwise it will be there!
		try { BadgeNotificationManager.Current.ClearBadge(); } catch { }

		#region Initial navigation and file activation processing

		// App notification activation path
		if (launchToUpdatePageFromNotification)
		{
			await ViewModelProvider.NavigationService.Navigate(typeof(Pages.UpdatePage), null);
		}
		// File activation (opened via File Explorer or protocol that yielded File activation) or CLI handoff path
		else if (!string.IsNullOrWhiteSpace(_activationFilePath))
		{
			Logger.Write(string.Format(CultureInfo.InvariantCulture, Atlas.GetStr("FileActivationLaunchMessage"), _activationFilePath));

			try
			{
				await ViewModelProvider.GroupPolicyEditorVM.OpenInGroupPolicyEditor(_activationFilePath);
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				// Continue doing the normal navigation if there was a problem
				await InitialNav();
			}
		}
		// Navigation restoration path or user asking for specific page to launch.
		else if (PageTypeToNavTo is not null)
		{
			await ViewModelProvider.NavigationService.Navigate(PageTypeToNavTo, null);
		}
		else
		{
			await InitialNav();
		}

		#endregion

		// If the user has enabled animated rainbow border for the app window, start it
		if (Atlas.Settings.IsAnimatedRainbowEnabled)
		{
			CustomUIElements.AppWindowBorderCustomization.StartAnimatedFrame();
		}
		// If the user has set a custom color for the app window border, apply it
		else if (!string.IsNullOrEmpty(Atlas.Settings.CustomAppWindowsBorder) &&
			RGBHEX.ToRGB(Atlas.Settings.CustomAppWindowsBorder, out byte r, out byte g, out byte b))
		{
			CustomUIElements.AppWindowBorderCustomization.SetBorderColor(r, g, b);
		}

		// Startup update check
		AppUpdate.CheckAtStartup();
	}

	private static void App_Activated(object? sender, AppActivationArguments args)
	{
		// Handle Live System Intelligence chart launch requests from Jump List items.
		if (args.Data is ILaunchActivatedEventArgs launchArgs &&
			CommonCore.Taskbar.JumpListMgr.GetLiveSystemIntelligenceLaunchTarget(launchArgs.Arguments.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries)) is string chartTarget)
		{
			_ = Atlas.AppDispatcher.TryEnqueue(() => ViewModelProvider.HomeVM.OpenLiveGraphsWindow(chartTarget));
		}
		else if (AppUpdate.IsUpdateNotificationActivation(args))
		{
			AppUpdate.QueueUpdatePageNavigation();
		}
		// Forward redirected Snipping Tool callbacks to the active Secure Vault page on the UI dispatcher.
		else if (TryGetSnippingToolResponse(args, out Uri? responseUri))
		{
			_ = Atlas.AppDispatcher.TryEnqueue(() => SnippingToolResponseHandler?.Invoke(responseUri));
		}
	}

	// Validates a protocol activation and extracts this app's Snipping Tool callback URI.
	private static bool TryGetSnippingToolResponse(AppActivationArguments? args, out Uri? responseUri)
	{
		responseUri = null;
		if (args?.Kind is not ExtendedActivationKind.Protocol || args.Data is not IProtocolActivatedEventArgs protocolArgs ||
			!string.Equals(protocolArgs.Uri.Scheme, "harden-system-security-snipping", StringComparison.OrdinalIgnoreCase))
		{
			return false;
		}
		responseUri = protocolArgs.Uri;
		return true;
	}
}
