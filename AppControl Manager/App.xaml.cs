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
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AppControlManager.Main;
using AppControlManager.Others;
using CommunityToolkit.WinUI;
using Microsoft.Extensions.Hosting;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.Windows.AppLifecycle;
using Windows.ApplicationModel;
using Windows.ApplicationModel.Activation;
using Windows.Storage;
using Microsoft.Extensions.DependencyInjection;
using AppControlManager.ViewModels;
using AppControlManager.MicrosoftGraph;
using Microsoft.Windows.Globalization;

// To learn more about WinUI abd the WinUI project structure see: http://aka.ms/winui-project-info
// Useful info regarding App Lifecycle events: https://learn.microsoft.com/en-us/windows/apps/windows-app-sdk/applifecycle/applifecycle

namespace AppControlManager;

#pragma warning disable CA1515 // App class cannot be set to internal

/// <summary>
/// Provides application-specific behavior to supplement the default Application class.
/// </summary>
public partial class App : Application
{

#pragma warning restore CA1515


	/// <summary>
	/// Package Family Name of the application
	/// </summary>
	private static readonly string PFN = Package.Current.Id.FamilyName;

	/// <summary>
	/// The App User Model ID which is in the format of PackageFamilyName!App
	/// The "App" is what's defined in the Package.appxmanifest file for ID in Application Id="App"
	/// </summary>
	internal static readonly string AUMID = AppInfo.Current.AppUserModelId;

	/// <summary>
	/// Detects the source of the application.
	/// GitHub => 0
	/// Microsoft Store => 1
	/// Unknown => 2
	/// </summary>
	internal static readonly int PackageSource = string.Equals(PFN, "AppControlManager_sadt7br7jpt02", StringComparison.OrdinalIgnoreCase) ? 0 : (string.Equals(PFN, "VioletHansen.AppControlManager_ea7andspwdn10", StringComparison.OrdinalIgnoreCase) ? 1 : 2);

	/// <summary>
	/// The application settings for AppControl Manager
	/// </summary>
	internal static AppSettings.Main Settings { get; private set; } = null!;

	// Semaphore to ensure only one error dialog is shown at a time
	// Exceptions will stack up and wait in line to be shown to the user
	private static readonly SemaphoreSlim _dialogSemaphore = new(1, 1);

	/// <summary>
	/// Get the current app's version
	/// </summary>
	private static readonly PackageVersion packageVersion = Package.Current.Id.Version;

	/// <summary>
	/// Convert it to a normal Version object
	/// </summary>
	internal static readonly Version currentAppVersion = new(packageVersion.Major, packageVersion.Minor, packageVersion.Build, packageVersion.Revision);

	/// <summary>
	/// Check if another instance of AppControl Manager is running
	/// </summary>
	private static bool IsUniqueAppInstance;

	private static Mutex? _mutex;
	private const string MutexName = "AppControlManagerRunning";

	/// <summary>
	/// To determine whether the app has Administrator privileges
	/// </summary>
	internal static readonly bool IsElevated = Environment.IsPrivilegedProcess;

	/// <summary>
	/// The directory where the logs will be stored
	/// </summary>
	internal static readonly string LogsDirectory = IsElevated ?
		Path.Combine(GlobalVars.UserConfigDir, "Logs") :
		Path.Combine(Path.GetTempPath(), "AppControlManagerLogs");

	// To track the currently open Content Dialog across the app. Every piece of code that tries to display a content dialog, whether custom or generic, must assign it first
	// to this variable before using ShowAsync() method to display it.
	internal static ContentDialog? CurrentlyOpenContentDialog;

	/// <summary>
	/// Provides a static host for the dependency injection container used throughout the application. It configures and
	/// registers various view models as singletons.
	/// </summary>
	internal static IHost AppHost { get; private set; } = null!;

	/// <summary>
	/// Initializes the singleton application object. This is the first line of authored code
	/// executed, and as such is the logical equivalent of main() or WinMain().
	/// </summary>
	internal App()
	{

		// Retrieve the app settings early on to check for elevation at startup and to pass it to DI container for the constructor of the Main app settings class
		ApplicationDataContainer _localSettings = ApplicationData.Current.LocalSettings;

		this.InitializeComponent();

		AppHost = Host.CreateDefaultBuilder()
		.ConfigureServices((context, services) =>
		{
			// If a type has a constructor it must either be public, or it can be internal but the value must be supplied to it via lambda when it takes parameters
			_ = services.AddSingleton(provider => new AppSettings.Main(_localSettings));
			_ = services.AddSingleton<ViewCurrentPoliciesVM>();
			_ = services.AddSingleton<PolicyEditorVM>();
			_ = services.AddSingleton<SettingsVM>();
			_ = services.AddSingleton<MergePoliciesVM>();
			_ = services.AddSingleton<ConfigurePolicyRuleOptionsVM>();
			_ = services.AddSingleton<AllowNewAppsVM>();
			_ = services.AddSingleton<CreateDenyPolicyVM>();
			_ = services.AddSingleton<CreateSupplementalPolicyVM>();
			_ = services.AddSingleton<EventLogsPolicyCreationVM>();
			_ = services.AddSingleton<SimulationVM>();
			_ = services.AddSingleton<MDEAHPolicyCreationVM>();
			_ = services.AddSingleton<ViewFileCertificatesVM>();
			_ = services.AddSingleton<MainWindowVM>();
			_ = services.AddSingleton<CreatePolicyVM>();
			_ = services.AddSingleton<DeploymentVM>();

			// In order to keep the visibility of the ViewOnlinePoliciesVM class's constructor as internal instead of public,
			// We use a lambda factory method to pass in a reference to the ViewModel class manually rather then letting the DI container do it for us automatically because it'd require public constructor.
			_ = services.AddSingleton(provider =>
			{
				ViewModel graphVM = provider.GetRequiredService<ViewModel>();
				return new ViewOnlinePoliciesVM(graphVM);
			});

			_ = services.AddSingleton<ViewModel>();
		})
		.Build();


		Settings = AppHost.Services.GetRequiredService<AppSettings.Main>();

		// Set the language of the application to the user's preferred language
		ApplicationLanguages.PrimaryLanguageOverride = Settings.ApplicationGlobalLanguage;

		// Create the Logs directory if it doesn't exist, won't do anything if it exists
		_ = Directory.CreateDirectory(LogsDirectory);

		// to handle unhandled exceptions
		this.UnhandledException += App_UnhandledException;

		AppDomain.CurrentDomain.UnhandledException += App_UnhandledException;

		// Subscribe to FirstChanceException events
		// AppDomain.CurrentDomain.FirstChanceException += CurrentDomain_FirstChanceException;

		// Subscribe to UnobservedTaskException events
		TaskScheduler.UnobservedTaskException += TaskScheduler_UnobservedTaskException;

		Logger.Write($"App Startup, .NET runtime version: {Environment.Version}");

		// https://github.com/microsoft/WindowsAppSDK/blob/main/specs/VersionInfo/VersionInfo.md
		// Logger.Write($"Built with Windows App SDK: {ReleaseInfo.AsString} - Runtime Info: {RuntimeInfo.AsString}");

		// Give beautiful outline to the UI elements when using the tab key and keyboard for navigation
		// https://learn.microsoft.com/en-us/windows/apps/design/style/reveal-focus
		this.FocusVisualKind = FocusVisualKind.Reveal;

		if (IsElevated)
			MoveUserConfigDirectory();

		#region

		// Check for the SoundSetting in the local settings
		if (Settings.SoundSetting)
		{
			ElementSoundPlayer.State = ElementSoundPlayerState.On;
			ElementSoundPlayer.SpatialAudioMode = ElementSpatialAudioMode.On;
		}
		else
		{
			ElementSoundPlayer.State = ElementSoundPlayerState.Off;
			ElementSoundPlayer.SpatialAudioMode = ElementSpatialAudioMode.Off;
		}

		#endregion
	}



	/*

	/// <summary>
	/// Event handler for FirstChanceException events.
	/// This event is raised as soon as an exception is thrown, before any catch blocks are executed.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void CurrentDomain_FirstChanceException(object? sender, FirstChanceExceptionEventArgs e)
	{
		// Log the first chance exception details.
		// Note: FirstChanceExceptions are raised for all exceptions, even if they are handled later.
		Logger.Write($"FirstChanceException caught: {e.Exception.Message}");
	}

	*/


	/// <summary>
	/// Event handler for UnobservedTaskException events.
	/// This event is raised when a faulted Task's exception is not observed.
	/// UnobservedTaskException doesn't help for exceptions thrown in event handlers.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void TaskScheduler_UnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
	{
		// Log the unobserved task exception details.
		Logger.Write($"UnobservedTaskException caught: {e.Exception.Message}");

		// Mark the exception as observed to prevent the process from terminating.
		e.SetObserved();

		await ShowErrorDialogAsync(e.Exception);
	}


	/// <summary>
	/// Invoked when the application is launched.
	/// </summary>
	/// <param name="args">Details about the launch request and process.</param>
	protected override void OnLaunched(Microsoft.UI.Xaml.LaunchActivatedEventArgs args)
	{

		// About single instancing: https://learn.microsoft.com/windows/apps/windows-app-sdk/migrate-to-windows-app-sdk/guides/applifecycle#single-instanced-apps

		// Creates a named Mutex with the specified unique name
		// The first parameter specifies that this instance initially owns the Mutex if created successfully
		// The third parameter indicates whether this application instance is the first/unique one
		// If "IsUniqueAppInstance" is true, it means no other instance of the app is running; otherwise, another instance exists and it will be false
		_mutex = new Mutex(true, MutexName, out IsUniqueAppInstance);

		if (!IsUniqueAppInstance)
		{
			Logger.Write("There is another instance of the AppControl Manager running. This is just an informational log.");
		}


		// Determines whether the session must prompt for UAC to elevate or not
		bool requireAdminPrivilege = false;

		try
		{

			// https://learn.microsoft.com/windows/apps/windows-app-sdk/migrate-to-windows-app-sdk/guides/applifecycle#file-type-association
			AppActivationArguments activatedEventArgs = Microsoft.Windows.AppLifecycle.AppInstance.GetCurrent().GetActivatedEventArgs();

			if (activatedEventArgs.Kind is ExtendedActivationKind.File)
			{
				Logger.Write("File Activation detected");

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

								Settings.FileActivatedLaunchArg = item.Path;

								// We can only process one XML file for now
								break;
							}
						}
					}
					else
					{
						Logger.Write("App was launched via File activation but arguments didn't have any file objects in them");
					}
				}
				else
				{
					Logger.Write("App was launched via File activation but without any file activation arguments");
				}
			}

		}
		catch (Exception ex)
		{
			Logger.Write(ErrorWriter.FormatException(ex));
		}


		// If the current session is not elevated and user configured the app to ask for elevation on startup
		// if (!IsElevated && _localSettings.Values.TryGetValue("PromptForElevationOnStartup", out object? value) && value is bool typedValue && typedValue)
		// Also prompt for elevation whether or not prompt for elevation setting is on when user selects a file to open from file explorer that requires elevated permissions
		if (!IsElevated && Settings.PromptForElevationOnStartup || !IsElevated && requireAdminPrivilege)
		{
			/*
			ProcessStartInfo processInfo = new()
			{
				FileName = Environment.ProcessPath,
				Verb = "runas",
				UseShellExecute = true
			};

			Process? processStartResult = null;

			try
			{
				processStartResult = Process.Start(processInfo);
			}

			// Error code 1223: The operation was canceled by the user.
			catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
			{
				// Do nothing if the user cancels the UAC prompt.
				Logger.Write("User canceled the UAC prompt.");
			}
			catch (System.ComponentModel.Win32Exception ex)
			{
				Logger.Write(ErrorWriter.FormatException(ex));
				Logger.Write($"Win32Exception.NativeErrorCode: {ex.NativeErrorCode}");
			}
			catch (Exception ex)
			{
				Logger.Write(ErrorWriter.FormatException(ex));
			}
			finally
			{
				processStartResult?.Dispose();
			}

			// Explicitly exit the current instance only after launching the elevated instance
			if (processStartResult is not null)
			{
				// Current.Exit(); doesn't work here

				// Exit the process
				Environment.Exit(0);
			}
			*/

			if (ReLaunch.Action())
			{
				// Exit the process
				Environment.Exit(0);
			}
			else if (requireAdminPrivilege)
			{
				Logger.Write("Elevation request was required to process the selected file but it was denied by the user. Exiting the app.");

				// Exit the process anyway since admin privileges were required but user didn't successfully elevate
				Environment.Exit(0);
			}
			else
			{
				Logger.Write("Elevation request was denied by the user");
			}

		}


		m_window = new MainWindow();
		m_window.Closed += Window_Closed;  // Assign event handler for the window closed event
		m_window.Activate();
	}

	private Window? m_window;

	/// <summary>
	/// Exposes the main application window as a static property. It retrieves the window from the current application
	/// instance.
	/// </summary>
	internal static Window? MainWindow => ((App)Current).m_window;

	/// <summary>
	/// Event handler for unhandled exceptions.
	/// </summary>
	private async void App_UnhandledException(object sender, Microsoft.UI.Xaml.UnhandledExceptionEventArgs e)
	{
		Logger.Write(ErrorWriter.FormatException(e.Exception));

		// Prevent the app from crashing
		// With this set to false, the same error would keep writing to the log file forever. The exception keeps bubbling up since it's unhandled.
		e.Handled = true;

		// Show error dialog to the user
		await ShowErrorDialogAsync(e.Exception);
	}


	private async void App_UnhandledException(object sender, System.UnhandledExceptionEventArgs e)
	{
		Exception ex = (Exception)e.ExceptionObject;

		Logger.Write(ErrorWriter.FormatException(ex));

		// Show error dialog to the user
		await ShowErrorDialogAsync(ex);
	}


	/// <summary>
	/// Event handler for when the window is closed.
	/// </summary>
	private void Window_Closed(object sender, WindowEventArgs e)
	{
		// Clean up the staging area
		if (IsElevated && Directory.Exists(GlobalVars.StagingArea))
		{
			Directory.Delete(GlobalVars.StagingArea, true);
		}

		// Release the Mutex
		_mutex?.Dispose();
	}


	/// <summary>
	/// Displays a ContentDialog with the error message.
	/// </summary>
	private async Task ShowErrorDialogAsync(Exception ex)
	{
		if (m_window is not null)
		{
			// Wait for the semaphore before showing a new error dialog
			await _dialogSemaphore.WaitAsync();

			try
			{
				// Ensure we're on the UI thread before showing the dialog
				await m_window.DispatcherQueue.EnqueueAsync(async () =>
				{

					// Since only 1 content dialog can be displayed at a time, we close any currently active ones before showing the error
					if (CurrentlyOpenContentDialog is ContentDialog dialog)
					{
						dialog.Hide();

						// Remove it after hiding it
						CurrentlyOpenContentDialog = null;
					}

					ContentDialog errorDialog = new()
					{
						Title = "An error occurred",
						BorderBrush = Current.Resources["AccentFillColorDefaultBrush"] as Brush ?? new SolidColorBrush(Colors.Transparent),
						BorderThickness = new Thickness(1),
						Content = $"An unexpected error has occurred:\n{ex.Message}",
						CloseButtonText = "OK",
						XamlRoot = m_window.Content.XamlRoot // Ensure dialog is attached to the main window
					};

					// Show the dialog
					_ = await errorDialog.ShowAsync();
				});
			}
			finally
			{
				// Release the semaphore after the dialog has been handled
				_ = _dialogSemaphore.Release();
			}
		}
	}

	/// <summary>
	/// This method will move everything from the old user config dir to the new one and deletes the old one at the end
	/// This will be removed in few months once all users have installed the new app version and use the new location.
	/// The old location was called "WDACConfig" because it was the location of the module i had created. I maintained the
	/// same location to provide interoperability for both the module and the new app but the module is now deprecated so
	/// it's time to change the user config location name to an appropriate one.
	/// GitHub release: https://github.com/HotCakeX/Harden-Windows-Security/releases/tag/AppControlManager.v.1.9.2.0
	/// </summary>
	private static void MoveUserConfigDirectory()
	{

		// Path to the old user config directory
		string OldUserConfigDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WDACConfig");

		// Ensure the new user config directory exists
		if (!Directory.Exists(GlobalVars.UserConfigDir))
		{
			_ = Directory.CreateDirectory(GlobalVars.UserConfigDir);
		}

		// Check if the old user config directory exists
		if (Directory.Exists(OldUserConfigDir))
		{

			Logger.Write(@"Moving the user config directory to the new location at 'Program Files\AppControl Manager");

			// Step 1: Recreate the directory structure

			// Get all subdirectories (recursively) from the old config directory
			string[] directories = Directory.GetDirectories(OldUserConfigDir, "*", SearchOption.AllDirectories);

			foreach (string oldDir in directories)
			{
				// Calculate the relative path of the old directory compared to the root of the old config
				string relativePath = Path.GetRelativePath(OldUserConfigDir, oldDir);

				// Combine the new config directory with the relative path to get the new directory path
				string newDir = Path.Combine(GlobalVars.UserConfigDir, relativePath);

				// Create the new directory if it does not exist
				if (!Directory.Exists(newDir))
				{
					_ = Directory.CreateDirectory(newDir);
				}
			}

			// Step 2: Move all files while preserving their relative positions

			// Get all files (recursively) from the old config directory
			string[] files = Directory.GetFiles(OldUserConfigDir, "*", SearchOption.AllDirectories);

			foreach (string filePath in files)
			{
				// Calculate the file's relative path from the old config directory
				string relativeFilePath = Path.GetRelativePath(OldUserConfigDir, filePath);

				// Combine with the new config directory to get the target file path
				string destFilePath = Path.Combine(GlobalVars.UserConfigDir, relativeFilePath);

				// Ensure that the destination subdirectory exists (double-check)
				string? destSubDir = Path.GetDirectoryName(destFilePath);

				if (!string.IsNullOrEmpty(destSubDir) && !Directory.Exists(destSubDir))
				{
					_ = Directory.CreateDirectory(destSubDir);
				}

				// Move the file to the new directory
				try
				{
					File.Move(filePath, destFilePath, overwrite: true);
				}
				catch (Exception ex)
				{
					Logger.Write(ErrorWriter.FormatException(ex));
				}
			}

			// Step 3: Delete the old user config directory
			Directory.Delete(OldUserConfigDir, recursive: true);

			// Step 4: Get all of the user configurations from the JSON file
			UserConfiguration config = UserConfiguration.Get();

			string? newSignToolCustomPath = null;
			string? newCertificatePath = null;
			string? newUnsignedPolicyPath = null;
			string? newSignedPolicyPath = null;

			if (!string.IsNullOrEmpty(config.SignToolCustomPath) && config.SignToolCustomPath.Contains(OldUserConfigDir))
			{
				newSignToolCustomPath = config.SignToolCustomPath.Replace(OldUserConfigDir, GlobalVars.UserConfigDir);

				if (!File.Exists(newSignToolCustomPath))
				{
					newSignToolCustomPath = null;
				}
			}
			if (!string.IsNullOrEmpty(config.CertificatePath) && config.CertificatePath.Contains(OldUserConfigDir))
			{
				newCertificatePath = config.CertificatePath.Replace(OldUserConfigDir, GlobalVars.UserConfigDir);

				if (!File.Exists(newCertificatePath))
				{
					newCertificatePath = null;
				}
			}
			if (!string.IsNullOrEmpty(config.UnsignedPolicyPath) && config.UnsignedPolicyPath.Contains(OldUserConfigDir))
			{
				newUnsignedPolicyPath = config.UnsignedPolicyPath.Replace(OldUserConfigDir, GlobalVars.UserConfigDir);

				if (!File.Exists(newUnsignedPolicyPath))
				{
					newUnsignedPolicyPath = null;
				}
			}
			if (!string.IsNullOrEmpty(config.SignedPolicyPath) && config.SignedPolicyPath.Contains(OldUserConfigDir))
			{
				newSignedPolicyPath = config.SignedPolicyPath.Replace(OldUserConfigDir, GlobalVars.UserConfigDir);

				if (!File.Exists(newSignedPolicyPath))
				{
					newSignedPolicyPath = null;
				}
			}

			try
			{
				// Replace the "WDACConfig" with "AppControl Manager" in user configurations JSON file
				_ = UserConfiguration.Set(
					SignedPolicyPath: newSignedPolicyPath,
					UnsignedPolicyPath: newUnsignedPolicyPath,
					SignToolCustomPath: newSignToolCustomPath,
					CertificatePath: newCertificatePath
					);
			}
			catch (Exception ex)
			{
				Logger.Write(ErrorWriter.FormatException(ex));
			}
		}
	}

}
