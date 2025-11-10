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
using System.Text;
using System.Text.RegularExpressions;
using AppControlManager.Others;
using AppControlManager.Taskbar;
using AppControlManager.ViewModels;
using AppControlManager.WindowComponents;
using Microsoft.UI.Xaml;
using Microsoft.Windows.AppLifecycle;
using Windows.ApplicationModel.Activation;
using Windows.Storage;

namespace AppControlManager;

#pragma warning disable CA1515

public partial class App : Application
{
	private static string? _activationAction;
	private static string? _activationFilePath;
	private static bool _activationIsFileActivation;

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
		// Register the Jump List tasks
		/*
		_ = Task.Run(async () =>
		{
			try
			{
				await Taskbar.JumpListMgr.RegisterJumpListTasksAsync();
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}
		});
		*/

		// About single instancing: https://learn.microsoft.com/windows/apps/windows-app-sdk/migrate-to-windows-app-sdk/guides/applifecycle#single-instanced-apps

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

				/*
				Windows.ApplicationModel.Activation.LaunchActivatedEventArgs launchArgs = (Windows.ApplicationModel.Activation.LaunchActivatedEventArgs)activatedEventArgs.Data;
				string passed = launchArgs.Arguments;

				Logger.Write($"Arguments: {passed}");
				*/

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

									// We can only process one XML/CIP file for now
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
				else if (activatedEventArgs.Kind is ExtendedActivationKind.Protocol)
				{
					ProtocolActivatedEventArgs? eventArgs = activatedEventArgs.Data as ProtocolActivatedEventArgs;
					Logger.Write($"Protocol Activation Detected: {eventArgs?.Uri?.OriginalString}");
					ParseArgs(possibleArgs, eventArgs?.Uri?.OriginalString);
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
		if (!IsElevated && Settings.PromptForElevationOnStartup || !IsElevated && requireAdminPrivilege)
		{
			// Build passthrough arguments.
			if (Relaunch.RelaunchAppElevated(AUMID, BuildRelaunchArguments()))
			{
				// Exit the process; the app was successfully relaunched elevated.
				Environment.Exit(0);
			}
			else if (requireAdminPrivilege)
			{
				Logger.Write(GlobalVars.GetStr("ElevationRequiredButDeniedMessage"));

				// Exit the process anyway since admin privileges were required but user didn't successfully elevate.
				Environment.Exit(0);
			}
			else
			{
				Logger.Write(GlobalVars.GetStr("ElevationDeniedMessage"));
			}
		}

		MainWindow = new MainWindow();

		MainWindowVM.SetCaptionButtonsFlowDirection(string.Equals(Settings.ApplicationGlobalFlowDirection, "LeftToRight", StringComparison.OrdinalIgnoreCase) ? FlowDirection.LeftToRight : FlowDirection.RightToLeft);

		NavigationService.RestoreWindowSize(MainWindow.AppWindow); // Restore window size on startup
		ViewModelProvider.NavigationService.mainWindowVM.OnIconsStylesChanged(Settings.IconsStyle); // Set the initial Icons styles based on the user's settings
		MainWindow.Closed += Window_Closed;  // Assign event handler for the window closed event
		MainWindow.Activate();

		// If the app was forcefully exited previously while there was a badge being displayed on the taskbar icon we have to remove it on app startup otherwise it will be there!
		Badge.ClearBadge();

		#region Initial navigation and file activation processing

		// Handle direct file activation
		if (_activationIsFileActivation && !string.IsNullOrWhiteSpace(_activationFilePath))
		{

			Logger.Write(string.Format(GlobalVars.GetStr("FileActivationLaunchMessage"), _activationFilePath));

			try
			{
				await ViewModelProvider.PolicyEditorVM.OpenInPolicyEditor(_activationFilePath);
			}
			catch (Exception ex)
			{
				Logger.Write(string.Format(GlobalVars.GetStr("PolicyEditorLaunchErrorMessage"), ex.Message));

				// Continue doing the normal navigation if there was a problem
				InitialNav();
			}
			finally
			{
				// Clear ephemeral file activation context
				_activationFilePath = null;
				_activationIsFileActivation = false;
			}
		}
		// If there is/was activation through protocol/CLI/context menu (action-based)
		else if (!string.IsNullOrWhiteSpace(_activationAction))
		{
			try
			{
				if (Enum.TryParse(_activationAction, true, out ViewModelBase.LaunchProtocolActions parsedAction))
				{
					switch (parsedAction)
					{
						case ViewModelBase.LaunchProtocolActions.PolicyEditor:
							{
								await ViewModelProvider.PolicyEditorVM.OpenInPolicyEditor(_activationFilePath);
								break;
							}
						case ViewModelBase.LaunchProtocolActions.FileSignature:
							{
								ViewFileCertificatesVM vm = ViewModelProvider.ViewFileCertificatesVM;

								await vm.OpenInViewFileCertificatesVM(_activationFilePath);
								break;
							}
						case ViewModelBase.LaunchProtocolActions.FileHashes:
							{
								GetCIHashesVM vm = ViewModelProvider.GetCIHashesVM;

								await vm.OpenInGetCIHashes(_activationFilePath);
								break;
							}
						case ViewModelBase.LaunchProtocolActions.DeployRMMAuditPolicy:
						case ViewModelBase.LaunchProtocolActions.DeployRMMBlockPolicy:
							{
								await ViewModelProvider.CreatePolicyVM.OpenInCreatePolicy(parsedAction);
								break;
							}
						default:
							{
								InitialNav();
								break;
							}
					}
				}
				else
				{
					InitialNav();
				}
			}
			catch (Exception ex)
			{
				Logger.Write(ex);

				// Continue doing the normal navigation if there was a problem
				InitialNav();
			}
			finally
			{
				// Clear ephemeral action context after it's been used
				_activationAction = null;
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
	/// Group 1 = action (enum token)
	/// Group 2 (optional) = file path.
	/// </summary>
	/// <returns></returns>
	[GeneratedRegex(@"^appcontrol-manager:\s*(--action=[^\s]+)(?:\s+(--file=(?:""[^""]*""|[^\s]+)))?$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
	private static partial Regex Regex1();

	/// <summary>
	/// Builds the argument string to pass to the elevated instance so that it can re-create the original launch intent without persisting anything.
	/// File activation is converted into a PolicyEditor action since the app only supports handling .CIP/XML files from File explorer at the moment.
	/// If in the future more file types are supported we can detect type based on file extenson and implement different behaviors.
	/// </summary>
	private static string? BuildRelaunchArguments()
	{
		List<string> parts = [];

		if (!string.IsNullOrWhiteSpace(_activationAction))
		{
			parts.Add($"--action={_activationAction}");
		}
		else if (_activationIsFileActivation && !string.IsNullOrWhiteSpace(_activationFilePath))
		{
			parts.Add("--action=PolicyEditor");
		}

		if (!string.IsNullOrWhiteSpace(_activationFilePath))
		{
			// Properly quote the file path for command line parsing (double embedded quotes if any).
			string safePath = _activationFilePath.Replace("\"", "\"\"");
			parts.Add($"--file=\"{safePath}\"");
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
		string? actionArg = null;
		string? fileArg = null;
		string? navTagArg = null;

		// Look for our two keys
		if (!string.IsNullOrWhiteSpace(ArgLine))
		{
			Match match = Regex1().Match(ArgLine);

			if (match.Success)
			{
				if (match.Groups[1].Success)
				{
					actionArg = match.Groups[1].Value.Trim();
				}

				if (match.Groups[2].Success)
				{
					fileArg = match.Groups[2].Value;
				}
			}
		}
		else if (ArgsLines is not null)
		{
			actionArg = ArgsLines.FirstOrDefault(a => a.StartsWith("--action=", StringComparison.OrdinalIgnoreCase));
			fileArg = ArgsLines.FirstOrDefault(a => a.StartsWith("--file=", StringComparison.OrdinalIgnoreCase));
			navTagArg = ArgsLines.FirstOrDefault(a => a.StartsWith("--navtag=", StringComparison.OrdinalIgnoreCase));
		}

		// Action is mandatory
		if (actionArg is not null)
		{
			// Extract the action
			string action = actionArg["--action=".Length..].Trim();

			if (!string.IsNullOrWhiteSpace(action))
			{
				Logger.Write($"Parsed Action: {action}");
				_activationAction = action;
			}

			// File is optional
			if (fileArg is not null)
			{
				string filePath = fileArg["--file=".Length..].Trim('"');

				if (!string.IsNullOrWhiteSpace(filePath))
				{
					Logger.Write($"Parsed File: {filePath}");
					_activationFilePath = filePath;

					// If the selected file is not accessible with the privileges the app is currently running with, prompt for elevation
					requireAdminPrivilege = !FileAccessCheck.IsFileAccessibleForWrite(filePath);
				}
			}

			// Elevation policy for action-only operations
			if (!IsElevated &&
				(string.Equals(action, nameof(ViewModelBase.LaunchProtocolActions.DeployRMMAuditPolicy), StringComparison.OrdinalIgnoreCase) ||
				 string.Equals(action, nameof(ViewModelBase.LaunchProtocolActions.DeployRMMBlockPolicy), StringComparison.OrdinalIgnoreCase)))
			{
				requireAdminPrivilege = true;
			}
		}

		// Parse navigation restoration arguments		
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
