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

using System.Threading;
using System.Threading.Tasks;
using CommonCore.ToolKits;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Windows.ApplicationModel.WindowsAppRuntime;
using Microsoft.Windows.Globalization;
using Windows.Graphics;
using Microsoft.UI.Dispatching;

// To learn more about WinUI and the WinUI project structure see: http://aka.ms/winui-project-info
// Useful info regarding App Lifecycle events: https://learn.microsoft.com/windows/apps/windows-app-sdk/applifecycle/applifecycle

#pragma warning restore CA1515

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
	/// <summary>
	/// Tracks whether the cleanup logics have been run.
	/// </summary>
	private static int CleanUpHappened;

	/// <summary>
	/// Semaphore to ensure only one error dialog is shown at a time.
	/// Exceptions will stack up and wait in line to be shown to the user.
	/// </summary>
	private static readonly SemaphoreSlim _dialogSemaphore = new(1, 1);

	/// <summary>
	/// Initializes the singleton application object. This is the first line of authored code
	/// executed, and as such is the logical equivalent of main() or WinMain().
	/// </summary>
	internal App()
	{
		InitializeComponent();

		// Capture the dispatcher queue as early as possible.
		GlobalVars.AppDispatcher = DispatcherQueue.GetForCurrentThread();

		// Set the language of the application to the user's preferred language
		ApplicationLanguages.PrimaryLanguageOverride = GlobalVars.Settings.ApplicationGlobalLanguage;

		// Initialize logging system
		Logger.Configure(logsDirectory: GlobalVars.LogsDirectory, appName: GlobalVars.AppName);

		// to handle unhandled exceptions
		UnhandledException += App_UnhandledException;

		AppDomain.CurrentDomain.UnhandledException += App_UnhandledException;

		// Subscribe to FirstChanceException events
		// AppDomain.CurrentDomain.FirstChanceException += CurrentDomain_FirstChanceException;

		// Subscribe to UnobservedTaskException events
		TaskScheduler.UnobservedTaskException += TaskScheduler_UnobservedTaskException;

		Logger.Write(string.Format(GlobalVars.GetStr("AppStartupMessage"), Environment.Version));

		// https://github.com/microsoft/WindowsAppSDK/blob/main/specs/VersionInfo/VersionInfo.md
		Logger.Write($"Built with Windows App SDK: {ReleaseInfo.AsString} - Runtime Info: {RuntimeInfo.AsString}");

		try
		{
			// Give beautiful outline to the UI elements when using the tab key and keyboard for navigation
			// https://learn.microsoft.com/windows/apps/design/style/reveal-focus
			FocusVisualKind = FocusVisualKind.Reveal;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}

		try
		{
			// Check for the SoundSetting in the local settings
			ElementSoundPlayer.State = GlobalVars.Settings.SoundSetting ? ElementSoundPlayerState.On : ElementSoundPlayerState.Off;
			ElementSoundPlayer.SpatialAudioMode = GlobalVars.Settings.SoundSetting ? ElementSpatialAudioMode.On : ElementSpatialAudioMode.Off;
		}
		catch (Exception ex)
		{
			Logger.Write("Failed to set the sound settings");
			Logger.Write(ex);
		}

		// Subscribing to ProcessExit because Window_Closed doesn't run when "Application.Current.Exit();" is used.
		AppDomain.CurrentDomain.ProcessExit += (s, e) => AppCleanUp();
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

	/// <summary>
	/// Perform initial navigation.
	/// </summary>
	private static void InitialNav() => ViewModelProvider.NavigationService.Navigate(typeof(AppControlManager.Pages.Home));

	/// <summary>
	/// Exposes the main application window as a static property. It retrieves the window from the current application
	/// instance.
	/// </summary>
	internal static Window? MainWindow { get; private set; }

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
	private void Window_Closed(object sender, WindowEventArgs e) => AppCleanUp();

	/// <summary>
	/// Logics to run when the app is being closed.
	/// </summary>
	private static void AppCleanUp()
	{
		if (Interlocked.Exchange(ref CleanUpHappened, 1) == 1) return;

		try
		{
			// Stop any active custom border
			CustomUIElements.AppWindowBorderCustomization.StopAnimatedFrameForAppShutdown();
		}
		catch { }

		if (MainWindow is not null)
		{
			try
			{
				// Get the current size of the window
				SizeInt32 size = MainWindow.AppWindow.Size;

				// Save to window width and height to the app settings
				GlobalVars.Settings.MainWindowWidth = size.Width;
				GlobalVars.Settings.MainWindowHeight = size.Height;

				WINDOWPLACEMENT windowPlacement = new();

				// Check if the window is maximized
				_ = NativeMethods.GetWindowPlacement(GlobalVars.hWnd, ref windowPlacement);

				// Save the maximized status of the window before closing to the app settings
				GlobalVars.Settings.MainWindowIsMaximized = windowPlacement.showCmd is ShowWindowCommands.SW_SHOWMAXIMIZED;
			}
			catch (Exception ex)
			{
				Logger.Write(string.Format(GlobalVars.GetStr("WindowSizeSaveErrorMessage"), ex.Message));
			}
		}

		// Dispose of disposable ViewModels on App exit
		ViewModelProvider.DisposeCreatedViewModels();

		// WebView2 cleanup
		WebView2Config.CleanUpWebView2();
	}

	/// <summary>
	/// Displays a ContentDialog with the error message.
	/// </summary>
	private async Task ShowErrorDialogAsync(Exception ex)
	{
		if (MainWindow is not null)
		{
			// Wait for the semaphore before showing a new error dialog
			await _dialogSemaphore.WaitAsync();

			try
			{
				// Ensure we're on the UI thread before showing the dialog
				await MainWindow.DispatcherQueue.EnqueueAsync(async () =>
				{
					// Since only 1 content dialog can be displayed at a time, we close any currently active ones before showing the error
					if (GlobalVars.CurrentlyOpenContentDialog is ContentDialog dialog)
					{
						dialog.Hide();

						// Remove it after hiding it
						GlobalVars.CurrentlyOpenContentDialog = null;
					}
					using AppControlManager.CustomUIElements.ContentDialogV2 errorDialog = new()
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
