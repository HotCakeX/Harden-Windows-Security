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
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using AppControlManager.WindowComponents;
using Microsoft.UI.Xaml;
using Microsoft.Windows.AppLifecycle;
using Microsoft.Windows.AppNotifications;
using Microsoft.Windows.BadgeNotifications;
using Windows.ApplicationModel.Activation;
using Windows.Storage;
using WinRT;

namespace AppControlManager;

#pragma warning disable CA1515

public sealed partial class App : Application
{
	/// <summary>
	/// Invoked when the application is launched.
	/// </summary>
	/// <param name="args">Details about the launch request and process.</param>
	[DynamicWindowsRuntimeCast(typeof(ProtocolActivatedEventArgs))]
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

		string? _activationAction = null, _activationFilePath = null;
		bool _activationIsFileActivation = false;

		// Determines whether the session must prompt for UAC to elevate or not
		bool requireAdminPrivilege = false;

		// For navigation restoration passed via command line
		string? _cliNavTag = null;
		Type? PageTypeToNavTo = null;

		/// <summary>
		/// Builds the argument string to pass to the elevated instance so that it can re-create the original launch intent without persisting anything.
		/// File activation is converted into a PolicyEditor action since the app only supports handling .CIP/XML files from File explorer at the moment.
		/// If in the future more file types are supported we can detect type based on file extension and implement different behaviors.
		/// </summary>
		string? BuildRelaunchArguments()
		{
			List<string> parts = new(capacity: 3);

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
				parts.Add($"--file=\"{_activationFilePath.Replace("\"", "\"\"")}\"");
			}

			// Preserve the requested navigation page across elevation.
			if (!string.IsNullOrWhiteSpace(_cliNavTag))
			{
				parts.Add($"--navtag={_cliNavTag}");
			}

			return parts.Count == 0 ? null : string.Join(' ', parts);
		}

		void ParseArgs(string[]? ArgsLines, string? ArgLine)
		{
			string? actionArg = null, fileArg = null, navTagArg = null;

			// Look for our two keys
			if (!string.IsNullOrWhiteSpace(ArgLine))
			{
				Match match = Regex1().Match(ArgLine);
				if (match.Success)
				{
					actionArg = match.Groups[1].Value.Trim();
					fileArg = match.Groups[2].Success ? match.Groups[2].Value : null;
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
						// If the file extension is not XML then it's not something we write back to so it's ok if we just have read access to the file.
						requireAdminPrivilege = !FileAccessCheck.IsFileAccessible(
							filePath: filePath,
							readAndWrite: string.Equals(Path.GetExtension(filePath), ".xml", StringComparison.OrdinalIgnoreCase));
					}
				}

				// Elevation policy for action-only operations
				if (!Atlas.IsElevated &&
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
					// If the page requires elevation, we must ask for it.
					else if (!ViewModelProvider.MainWindowVM.UnelevatedPages.Contains(PageTypeToNavTo))
					{
						requireAdminPrivilege = true;
					}
				}
			}
		}

		bool launchToUpdatePageFromNotification = false;

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

			try
			{
				AppInstance notificationTargetInstance = AppInstance.FindOrRegisterForKey("AppControlManager.NotificationActivation");

				if (notificationTargetInstance.IsCurrent)
				{
					notificationTargetInstance.Activated += App_Activated;
				}
				else if (launchToUpdatePageFromNotification)
				{
					await notificationTargetInstance.RedirectActivationToAsync(activatedEventArgs);
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
								// If the file extension is not XML then it's not something we write back to so it's ok if we just have read access to the file.
								requireAdminPrivilege = !FileAccessCheck.IsFileAccessible(
									filePath: item.Path,
									readAndWrite: string.Equals(Path.GetExtension(item.Path), ".xml", StringComparison.OrdinalIgnoreCase));

								// Store ephemeral activation context
								_activationFilePath = item.Path;
								_activationIsFileActivation = true;

								// We can only process one XML/CIP file for now
								break;
							}
						}
					}
				}
				else if (activatedEventArgs.Kind is ExtendedActivationKind.Protocol)
				{
					ProtocolActivatedEventArgs? eventArgs = activatedEventArgs.Data as ProtocolActivatedEventArgs;
					Logger.Write($"Protocol Activation Detected: {eventArgs?.Uri?.OriginalString}");
					ParseArgs(Program.GetLaunchArguments(), eventArgs?.Uri?.OriginalString);
				}
				else if (!launchToUpdatePageFromNotification)
				{
					ParseArgs(Program.GetLaunchArguments(), null);
				}
			}
			else
			{
				ParseArgs(Program.GetLaunchArguments(), null);
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
			// Build passthrough arguments.
			if (Relaunch.RelaunchAppElevated(Atlas.AUMID, BuildRelaunchArguments()))
			{
				// Exit the process; the app was successfully relaunched elevated.
				Environment.Exit(0);
			}
			else if (requireAdminPrivilege)
			{
				Logger.Write(Atlas.GetStr("ElevationRequiredButDeniedMessage"));
				// Exit the process anyway since admin privileges were required but user didn't successfully elevate.
				Environment.Exit(0);
			}
			else
			{
				Logger.Write(Atlas.GetStr("ElevationDeniedMessage"));
			}
		}

		MainWindow = new MainWindow();

		MainWindowVM.SetCaptionButtonsFlowDirection(string.Equals(Atlas.Settings.ApplicationGlobalFlowDirection, "LeftToRight", StringComparison.OrdinalIgnoreCase) ? FlowDirection.LeftToRight : FlowDirection.RightToLeft);

		NavigationService.RestoreWindowSize(MainWindow.AppWindow); // Restore window size on startup
		ViewModelProvider.NavigationService.mainWindowVM.OnIconsStylesChanged(Atlas.Settings.IconsStyle); // Set the initial Icons styles based on the user's settings
		MainWindow.Closed += static (_, _) => AppCleanUp();  // Assign event handler for the window closed event
		MainWindow.Activate();

		// If the app was forcefully exited previously while there was a badge being displayed on the taskbar icon we have to remove it on app startup otherwise it will be there!
		try { BadgeNotificationManager.Current.ClearBadge(); } catch { }

		#region Initial navigation and file activation processing

		// App notification activation path
		if (launchToUpdatePageFromNotification)
		{
			await ViewModelProvider.NavigationService.Navigate(typeof(Pages.UpdatePage), null);
		}
		// Handle direct file activation
		else if (_activationIsFileActivation && !string.IsNullOrWhiteSpace(_activationFilePath))
		{
			Logger.Write(string.Format(Atlas.GetStr("FileActivationLaunchMessage"), _activationFilePath));
			try
			{
				SiPolicy.PolicyFileRepresent policyRep = await Task.Run(() => PolicyEditorVM.ParseFilePathAsPolicyRepresent(_activationFilePath));

				await ViewModelProvider.PolicyEditorVM.OpenInPolicyEditor(policyRep);
			}
			catch (Exception ex)
			{
				Logger.Write(string.Format(Atlas.GetStr("PolicyEditorLaunchErrorMessage"), ex.Message));
				// Continue doing the normal navigation if there was a problem
				await InitialNav();
			}
		}
		// If there is/was activation through protocol/CLI/context menu (action-based)
		else if (Enum.TryParse(_activationAction, true, out ViewModelBase.LaunchProtocolActions parsedAction))
		{
			try
			{
				switch (parsedAction)
				{
					case ViewModelBase.LaunchProtocolActions.PolicyEditor:
						{
							if (_activationFilePath is not null)
							{
								await ViewModelProvider.PolicyEditorVM.OpenInPolicyEditor(PolicyEditorVM.ParseFilePathAsPolicyRepresent(_activationFilePath));
							}
							break;
						}
					case ViewModelBase.LaunchProtocolActions.FileSignature:
						{
							await ViewModelProvider.ViewFileCertificatesVM.OpenInViewFileCertificatesVM(_activationFilePath);
							break;
						}
					case ViewModelBase.LaunchProtocolActions.FileHashes:
						{
							await ViewModelProvider.GetCIHashesVM.OpenInGetCIHashes(_activationFilePath);
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
							await InitialNav();
							break;
						}
				}
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
		if (AppUpdate.IsUpdateNotificationActivation(args))
		{
			AppUpdate.QueueUpdatePageNavigation();
		}
	}

	/// <summary>
	/// Group 1 = action (enum token)
	/// Group 2 (optional) = file path.
	/// </summary>
	[GeneratedRegex(@"^appcontrol-manager:\s*(--action=[^\s]+)(?:\s+(--file=(?:""[^""]*""|[^\s]+)))?$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
	private static partial Regex Regex1();
}
