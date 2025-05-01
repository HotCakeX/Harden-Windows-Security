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
using AppControlManager.MicrosoftGraph;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using AppControlManager.WindowComponents;
using CommunityToolkit.WinUI;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Windows.AppLifecycle;
using Microsoft.Windows.Globalization;
using Windows.ApplicationModel;
using Windows.ApplicationModel.Activation;
using Windows.Graphics;
using Windows.Storage;

// To learn more about WinUI abd the WinUI project structure see: http://aka.ms/winui-project-info
// Useful info regarding App Lifecycle events: https://learn.microsoft.com/windows/apps/windows-app-sdk/applifecycle/applifecycle

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

	internal static NavigationService _nav { get; private set; } = null!;

	/// <summary>
	/// Initializes the singleton application object. This is the first line of authored code
	/// executed, and as such is the logical equivalent of main() or WinMain().
	/// </summary>
	internal App()
	{
		// Retrieve the app settings early on to check for elevation at startup and to pass it to DI container for the constructor of the Main app settings class
		ApplicationDataContainer _localSettings = ApplicationData.Current.LocalSettings;

		this.InitializeComponent();

		HostApplicationBuilderSettings builderSettings = new()
		{
			DisableDefaults = true
		};

		// https://learn.microsoft.com/dotnet/api/microsoft.extensions.hosting.host.createemptyapplicationbuilder
		HostApplicationBuilder builder = Host.CreateEmptyApplicationBuilder(builderSettings);

		// https://learn.microsoft.com/dotnet/api/microsoft.extensions.hosting.hostapplicationbuilder.services
		IServiceCollection services = builder.Services;

		// https://learn.microsoft.com/dotnet/api/microsoft.extensions.dependencyinjection.iservicecollection

		// If a type has a constructor it must either be public so DI can automatically resolve its parameters,
		// or it can be internal but the value must be supplied to it via lambda factory method.
		_ = services.AddSingleton(sp => new AppSettings.Main(_localSettings));
		_ = services.AddSingleton<SidebarVM>();
		_ = services.AddSingleton<ViewCurrentPoliciesVM>();
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
		_ = services.AddSingleton(sp => new MainWindowVM());
		_ = services.AddSingleton<CreatePolicyVM>();
		_ = services.AddSingleton<DeploymentVM>();
		_ = services.AddSingleton<UpdateVM>();
		_ = services.AddSingleton<ValidatePolicyVM>();
		_ = services.AddSingleton<CodeIntegrityInfoVM>();
		_ = services.AddSingleton<GetCIHashesVM>();
		_ = services.AddSingleton(sp => new EventLogUtility());
		_ = services.AddSingleton<NavigationService>(sp => new(sp.GetRequiredService<MainWindowVM>(), sp.GetRequiredService<SidebarVM>()));
		_ = services.AddSingleton<ViewModelForMSGraph>();
		_ = services.AddSingleton<ViewOnlinePoliciesVM>(sp => new(sp.GetRequiredService<ViewModelForMSGraph>()));
		_ = services.AddSingleton<PolicyEditorVM>();

		AppHost = builder.Build();

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
		// https://learn.microsoft.com/windows/apps/design/style/reveal-focus
		this.FocusVisualKind = FocusVisualKind.Reveal;

		// Check for the SoundSetting in the local settings
		ElementSoundPlayer.State = Settings.SoundSetting ? ElementSoundPlayerState.On : ElementSoundPlayerState.Off;
		ElementSoundPlayer.SpatialAudioMode = Settings.SoundSetting ? ElementSpatialAudioMode.On : ElementSpatialAudioMode.Off;
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
		_nav = AppHost.Services.GetRequiredService<NavigationService>(); // Retrieve the navigation instance
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

		if (m_window is not null)
		{
			try
			{
				// Get the current size of the window
				SizeInt32 size = m_window.AppWindow.Size;

				// Save to window width and height to the app settings
				Settings.MainWindowWidth = size.Width;
				Settings.MainWindowHeight = size.Height;

				Win32InteropInternal.WINDOWPLACEMENT windowPlacement = new();

				// Check if the window is maximized
				_ = Win32InteropInternal.GetWindowPlacement(GlobalVars.hWnd, ref windowPlacement);

				// Save the maximized status of the window before closing to the app settings
				Settings.MainWindowIsMaximized = windowPlacement.showCmd is Win32InteropInternal.ShowWindowCommands.SW_SHOWMAXIMIZED;
			}
			catch (Exception ex)
			{
				Logger.Write($"There was a program saving the window size when closing the app: {ex.Message}");
			}
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

					CustomUIElements.ContentDialogV2 errorDialog = new()
					{
						Title = "An error occurred",
						Content = $"An unexpected error has occurred:\n{ex.Message}",
						CloseButtonText = GlobalVars.Rizz.GetString("OK"),
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
}
