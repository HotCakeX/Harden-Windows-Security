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

using System.IO;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.WinUI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Windows.ApplicationModel.WindowsAppRuntime;
using Microsoft.Windows.Globalization;
using Windows.ApplicationModel;
using Windows.Graphics;
using Microsoft.UI.Dispatching;

// To learn more about WinUI and the WinUI project structure see: http://aka.ms/winui-project-info
// Useful info regarding App Lifecycle events: https://learn.microsoft.com/windows/apps/windows-app-sdk/applifecycle/applifecycle

#if HARDEN_SYSTEM_SECURITY
using HardenSystemSecurity.ViewModels;
namespace HardenSystemSecurity;
#endif
#if APP_CONTROL_MANAGER
using AppControlManager.ViewModels;
namespace AppControlManager;
#endif

#pragma warning disable CA1515 // App class cannot be set to internal

/// <summary>
/// Provides application-specific behavior to supplement the default Application class.
/// </summary>
public partial class App : Application
{
#pragma warning restore CA1515

#if HARDEN_SYSTEM_SECURITY
	internal const string AppName = "HardenSystemSecurity";
#endif
#if APP_CONTROL_MANAGER
	internal const string AppName = "AppControlManager";
#endif

	/// <summary>
	/// Package Family Name of the application
	/// </summary>
	internal static readonly string PFN = Package.Current.Id.FamilyName;

	/// <summary>
	/// The App User Model ID which is in the format of PackageFamilyName!App
	/// The "App" is what's defined in the Package.appxmanifest file for ID in Application Id="App"
	/// </summary>
	internal static readonly string AUMID = AppInfo.Current.AppUserModelId;

	/// <summary>
	/// To determine whether the app has Administrator privileges
	/// </summary>
	internal static readonly bool IsElevated = Environment.IsPrivilegedProcess;

	/// <summary>
	/// Detects the source of the application.
	/// GitHub => 0
	/// Microsoft Store => 1
	/// Unknown => 2
	/// </summary>
	internal static readonly int PackageSource = string.Equals(PFN, "AppControlManager_sadt7br7jpt02", StringComparison.OrdinalIgnoreCase) ?
		0 :
		(string.Equals(PFN, "VioletHansen.AppControlManager_ea7andspwdn10", StringComparison.OrdinalIgnoreCase) || string.Equals(PFN, "VioletHansen.HardenSystemSecurity_ea7andspwdn10", StringComparison.OrdinalIgnoreCase)
		? 1 : 2);

	/// <summary>
	/// The application settings for AppControl Manager. Retrieved early in a Non-ThreadSafe manner.
	/// Any references (instance or static) throughout the app to App settings use this property.
	/// </summary>
	internal static AppSettings.Main Settings => ViewModelProvider.AppSettings;

	/// <summary>
	/// Global dispatcher queue for the application that can be accessed from anywhere.
	/// </summary>
	internal static DispatcherQueue AppDispatcher { get; private set; } = null!;

	/// <summary>
	/// Semaphore to ensure only one error dialog is shown at a time.
	/// Exceptions will stack up and wait in line to be shown to the user.
	/// </summary>
	private static readonly SemaphoreSlim _dialogSemaphore = new(1, 1);

	/// <summary>
	/// Convert it to a normal Version object
	/// </summary>
	internal static readonly Version currentAppVersion = new(Package.Current.Id.Version.Major, Package.Current.Id.Version.Minor, Package.Current.Id.Version.Build, Package.Current.Id.Version.Revision);

#if APP_CONTROL_MANAGER
	/// <summary>
	/// The directory where the logs will be stored
	/// </summary>
	internal static readonly string LogsDirectory = IsElevated ?
		Path.Combine(GlobalVars.UserConfigDir, "Logs") :
		Path.Combine(Path.GetTempPath(), $"{AppName}Logs");
#endif

#if HARDEN_SYSTEM_SECURITY
	/// <summary>
	/// The directory where the logs will be stored
	/// </summary>
	internal static readonly string LogsDirectory = Path.Combine(Path.GetTempPath(), $"{AppName}Logs");
#endif

	// To track the currently open Content Dialog across the app. Every piece of code that tries to display a content dialog, whether custom or generic, must assign it first
	// to this variable before using ShowAsync() method to display it.
	internal static ContentDialog? CurrentlyOpenContentDialog;

	/// <summary>
	/// Initializes the singleton application object. This is the first line of authored code
	/// executed, and as such is the logical equivalent of main() or WinMain().
	/// </summary>
	internal App()
	{
		this.InitializeComponent();

		// Location where File/Folder picker dialog will be opened
#if APP_CONTROL_MANAGER
		FileDialogHelper.DirectoryToOpen = IsElevated ? GlobalVars.UserConfigDir : Path.GetPathRoot(Environment.SystemDirectory)!;
#endif
#if HARDEN_SYSTEM_SECURITY
	FileDialogHelper.DirectoryToOpen = Path.GetPathRoot(Environment.SystemDirectory)!;
#endif

		// Capture the dispatcher queue as early as possible.
		AppDispatcher = DispatcherQueue.GetForCurrentThread();

		// Set the language of the application to the user's preferred language
		ApplicationLanguages.PrimaryLanguageOverride = Settings.ApplicationGlobalLanguage;

		// Initialize logging system
		Logger.Configure(logsDirectory: LogsDirectory, appName: AppName);

		// to handle unhandled exceptions
		this.UnhandledException += App_UnhandledException;

		AppDomain.CurrentDomain.UnhandledException += App_UnhandledException;

		// Subscribe to FirstChanceException events
		// AppDomain.CurrentDomain.FirstChanceException += CurrentDomain_FirstChanceException;

		// Subscribe to UnobservedTaskException events
		TaskScheduler.UnobservedTaskException += TaskScheduler_UnobservedTaskException;

		Logger.Write(string.Format(GlobalVars.GetStr("AppStartupMessage"), Environment.Version));

		// https://github.com/microsoft/WindowsAppSDK/blob/main/specs/VersionInfo/VersionInfo.md
		Logger.Write($"Built with Windows App SDK: {ReleaseInfo.AsString} - Runtime Info: {RuntimeInfo.AsString}");

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
		Logger.Write(e.Exception);

		// Mark the exception as observed to prevent the process from terminating.
		e.SetObserved();

		await ShowErrorDialogAsync(e.Exception);
	}

	private Window? m_window;

	/// <summary>
	/// Perform initial navigation.
	/// </summary>
	private static void InitialNav() => ViewModelProvider.NavigationService.Navigate(typeof(AppControlManager.Pages.Home));

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
		Logger.Write(e.Exception);

		// Prevent the app from crashing
		// With this set to false, the same error would keep writing to the log file forever. The exception keeps bubbling up since it's unhandled.
		e.Handled = true;

		// Show error dialog to the user
		await ShowErrorDialogAsync(e.Exception);
	}

	private async void App_UnhandledException(object sender, System.UnhandledExceptionEventArgs e)
	{
		Exception ex = (Exception)e.ExceptionObject;

		Logger.Write(ex);

		// Show error dialog to the user
		await ShowErrorDialogAsync(ex);
	}

	/// <summary>
	/// Event handler for when the window is closed.
	/// </summary>
	private void Window_Closed(object sender, WindowEventArgs e)
	{
#if HARDEN_SYSTEM_SECURITY
		// Terminate our DISM exe if it's still running and user closed the window.
		DismServiceClient.TerminateActiveService();
#endif

		try
		{
			// Stop any active custom border
			CustomUIElements.AppWindowBorderCustomization.StopAnimatedFrameForAppShutdown();
		}
		catch { }

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

				WINDOWPLACEMENT windowPlacement = new();

				// Check if the window is maximized
				_ = NativeMethods.GetWindowPlacement(GlobalVars.hWnd, ref windowPlacement);

				// Save the maximized status of the window before closing to the app settings
				Settings.MainWindowIsMaximized = windowPlacement.showCmd is ShowWindowCommands.SW_SHOWMAXIMIZED;
			}
			catch (Exception ex)
			{
				Logger.Write(string.Format(GlobalVars.GetStr("WindowSizeSaveErrorMessage"), ex.Message));
			}
		}

		try
		{
			// Dispose of disposable ViewModels on App exist
			ViewModelProvider.DisposeCreatedViewModels();
		}
		catch { }
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
#pragma warning disable IDE0001
					using AppControlManager.CustomUIElements.ContentDialogV2 errorDialog = new()
#pragma warning restore IDE0001
					{
						Title = GlobalVars.GetStr("ErrorDialogTitle"),
						Content = string.Format(GlobalVars.GetStr("ErrorDialogContent"), ex.Message),
						CloseButtonText = GlobalVars.GetStr("OK"),
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
