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
using System.IO;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using AppControlManager.AppSettings;
using AppControlManager.Main;
using AppControlManager.Others;
using CommunityToolkit.WinUI;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.ApplicationModel;

// To learn more about WinUI abd the WinUI project structure see: http://aka.ms/winui-project-info
// Useful info regarding App Lifecycle events: https://learn.microsoft.com/en-us/windows/apps/windows-app-sdk/applifecycle/applifecycle

namespace AppControlManager;

/// <summary>
/// Provides application-specific behavior to supplement the default Application class.
/// </summary>
public partial class App : Application
{
	// Semaphore to ensure only one error dialog is shown at a time
	// Exceptions will stack up and wait in line to be shown to the user
	private static readonly SemaphoreSlim _dialogSemaphore = new(1, 1);

	// Get the current app's version
	private static readonly PackageVersion packageVersion = Package.Current.Id.Version;

	// Convert it to a normal Version object
	internal static readonly Version currentAppVersion = new(packageVersion.Major, packageVersion.Minor, packageVersion.Build, packageVersion.Revision);

	// Check if another instance of AppControl Manager is running
	private static bool IsUniqueAppInstance;

	private static Mutex? _mutex;
	private const string MutexName = "AppControlManagerRunning";

	// To determine whether the app has Administrator privileges
	internal static readonly bool IsElevated = IsRunningAsAdministrator();

	// The directory where the logs will be stored
	internal static readonly string LogsDirectory = IsElevated ?
		Path.Combine(GlobalVars.UserConfigDir, "Logs") :
		Path.Combine(Path.GetTempPath(), "AppControlManagerLogs");

	// To track the currently open Content Dialog across the app. Every piece of code that tries to display a content dialog, whether custom or generic, must assign it first
	// to this variable before using ShowAsync() method to display it.
	internal static ContentDialog? CurrentlyOpenContentDialog;

	// Host for dependency injection container to be used across the app
	internal static IHost AppHost { get; } = Host.CreateDefaultBuilder()
		.ConfigureServices((context, services) =>
		{
			_ = services.AddSingleton<ViewModels.ViewCurrentPoliciesVM>();
			_ = services.AddSingleton<ViewModels.PolicyEditorVM>();
			_ = services.AddSingleton<ViewModels.SettingsVM>();
			_ = services.AddSingleton<ViewModels.MergePoliciesVM>();
			_ = services.AddSingleton<ViewModels.ConfigurePolicyRuleOptionsVM>();
		})
		.Build();

	/// <summary>
	/// Initializes the singleton application object. This is the first line of authored code
	/// executed, and as such is the logical equivalent of main() or WinMain().
	/// </summary>
	public App()
	{
		this.InitializeComponent();

		// Create the Logs directory if it doesn't exist, won't do anything if it exists
		_ = Directory.CreateDirectory(LogsDirectory);

		// to handle unhandled exceptions
		this.UnhandledException += App_UnhandledException;

		// Subscribe to FirstChanceException events
		// AppDomain.CurrentDomain.FirstChanceException += CurrentDomain_FirstChanceException;

		// Subscribe to UnobservedTaskException events
		TaskScheduler.UnobservedTaskException += TaskScheduler_UnobservedTaskException;

		Logger.Write($"App Startup, .NET runtime version: {Environment.Version}");

		// Give beautiful outline to the UI elements when using the tab key and keyboard for navigation
		// https://learn.microsoft.com/en-us/windows/apps/design/style/reveal-focus
		this.FocusVisualKind = FocusVisualKind.Reveal;

		if (IsElevated)
			MoveUserConfigDirectory();

		#region

		// Check for the SoundSetting in the local settings
		bool soundSetting = AppSettingsCls.GetSetting<bool>(AppSettingsCls.SettingKeys.SoundSetting);

		if (soundSetting)
		{
			ElementSoundPlayer.State = ElementSoundPlayerState.On;
			ElementSoundPlayer.SpatialAudioMode = ElementSpatialAudioMode.On;
		}
		else
		{
			ElementSoundPlayer.State = ElementSoundPlayerState.Off;
			ElementSoundPlayer.SpatialAudioMode = ElementSpatialAudioMode.Off;
		}

		// Subscribe to the SoundSettingChanged event to listen for changes globally
		SoundManager.SoundSettingChanged += OnSoundSettingChanged;

		#endregion

	}


	/// <summary>
	/// Event handler for when the sound setting is changed.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void OnSoundSettingChanged(object? sender, SoundSettingChangedEventArgs e)
	{
		// Set the global sound state based on the event
		if (e.IsSoundOn)
		{
			ElementSoundPlayer.State = ElementSoundPlayerState.On;
			ElementSoundPlayer.SpatialAudioMode = ElementSpatialAudioMode.On;
		}
		else
		{
			ElementSoundPlayer.State = ElementSoundPlayerState.Off;
			ElementSoundPlayer.SpatialAudioMode = ElementSpatialAudioMode.Off;
		}
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
	protected override void OnLaunched(LaunchActivatedEventArgs args)
	{

		// Creates a named Mutex with the specified unique name
		// The first parameter specifies that this instance initially owns the Mutex if created successfully
		// The third parameter indicates whether this application instance is the first/unique one
		// If "IsUniqueAppInstance" is true, it means no other instance of the app is running; otherwise, another instance exists and it will be false
		_mutex = new Mutex(true, MutexName, out IsUniqueAppInstance);

		if (!IsUniqueAppInstance)
		{
			Logger.Write("There is another instance of the AppControl Manager running!");
		}

		m_window = new MainWindow();
		m_window.Closed += Window_Closed;  // Assign event handler for the window closed event
		m_window.Activate();
	}

	private Window? m_window;

	// Adding this public property to expose the window
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


	/// <summary>
	/// Event handler for when the window is closed.
	/// </summary>
	private void Window_Closed(object sender, WindowEventArgs e)
	{
		if (IsElevated)
		{
			// Clean up the staging area only if there are no other instance of the AppControl Manager running
			// Don't want to disrupt their workflow
			if (Directory.Exists(GlobalVars.StagingArea) && IsUniqueAppInstance)
			{
				Directory.Delete(GlobalVars.StagingArea, true);
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


	/// <summary>
	/// Checks if the current process is running with administrator privileges.
	/// </summary>
	/// <returns>True if running as admin; otherwise, false.</returns>
	private static bool IsRunningAsAdministrator()
	{
		using WindowsIdentity identity = WindowsIdentity.GetCurrent();

		WindowsPrincipal principal = new(identity);
		return principal.IsInRole(WindowsBuiltInRole.Administrator);
	}
}
