using CommunityToolkit.WinUI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

// Useful info regarding App Lifecycle events: https://learn.microsoft.com/en-us/windows/apps/windows-app-sdk/applifecycle/applifecycle

namespace WDACConfig
{
    /// <summary>
    /// Provides application-specific behavior to supplement the default Application class.
    /// </summary>
    public partial class App : Application
    {
        // Semaphore to ensure only one error dialog is shown at a time
        // Exceptions will stack up and wait in line to be shown to the user
        private static readonly SemaphoreSlim _dialogSemaphore = new(1, 1);

        /// <summary>
        /// Initializes the singleton application object. This is the first line of authored code
        /// executed, and as such is the logical equivalent of main() or WinMain().
        /// </summary>
        public App()
        {
            this.InitializeComponent();

            // to handle unhandled exceptions
            this.UnhandledException += App_UnhandledException;
        }

        /// <summary>
        /// Invoked when the application is launched.
        /// </summary>
        /// <param name="args">Details about the launch request and process.</param>
        protected override void OnLaunched(Microsoft.UI.Xaml.LaunchActivatedEventArgs args)
        {
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
        private void Window_Closed(object sender, Microsoft.UI.Xaml.WindowEventArgs e)
        {
            // Clean up the staging area
            if (Directory.Exists(GlobalVars.StagingArea))
            {
                Directory.Delete(GlobalVars.StagingArea, true);
            }
        }

        /// <summary>
        /// Displays a ContentDialog with the error message.
        /// </summary>
        private async Task ShowErrorDialogAsync(Exception ex)
        {
            if (m_window != null)
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
}
