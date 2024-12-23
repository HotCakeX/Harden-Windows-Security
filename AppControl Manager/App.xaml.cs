using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AppControlManager.Logging;
using CommunityToolkit.WinUI;
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

	/// <summary>
	/// Initializes the singleton application object. This is the first line of authored code
	/// executed, and as such is the logical equivalent of main() or WinMain().
	/// </summary>
	public App()
	{
		this.InitializeComponent();

#if DEBUG

		Logger.Write("App Startup");
#endif

		// Give beautiful outline to the UI elements when using the tab key and keyboard for navigation
		// https://learn.microsoft.com/en-us/windows/apps/design/style/reveal-focus
		this.FocusVisualKind = FocusVisualKind.Reveal;

		// to handle unhandled exceptions
		this.UnhandledException += App_UnhandledException;


		#region

		// Check for the SoundSetting in the local settings
		bool soundSetting = AppSettings.GetSetting<bool>(AppSettings.SettingKeys.SoundSetting);

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
	public static Window? MainWindow => ((App)Current).m_window;

	/// <summary>
	/// Event handler for unhandled exceptions.
	/// </summary>
	private async void App_UnhandledException(object sender, Microsoft.UI.Xaml.UnhandledExceptionEventArgs e)
	{
		Logger.Write($"Unhandled exception: {e.Exception.Message}");

		// Prevent the app from crashing
		// With this set to false, the same error would keep writing to the log file forever. The exception keeps bubbling up since it's unhandled.
		e.Handled = true;

		// Log the error to a file
		Logger.Write(e.Exception.ToString());

		// Show error dialog to the user
		await ShowErrorDialogAsync(e.Exception);
	}


	/// <summary>
	/// Event handler for when the window is closed.
	/// </summary>
	private void Window_Closed(object sender, WindowEventArgs e)
	{
		// Clean up the staging area only if there are no other instance of the AppControl Manager running
		// Don't want to disrupt their workflow
		if (Directory.Exists(GlobalVars.StagingArea) && IsUniqueAppInstance)
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
}
