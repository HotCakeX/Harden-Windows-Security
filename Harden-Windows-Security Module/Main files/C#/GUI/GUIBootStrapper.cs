using System;
using System.Threading;

#nullable enable

namespace HardenWindowsSecurity
{
    public static class GUIBootStrapper
    {
        /// <summary>
        /// Starts and takes control of the entire GUI bootstrapping, startup and exit workflows
        /// Can be started from PowerShell and C# environments.
        /// That means you can use this during development in both Visual Studio and Visual Studio Code.
        /// Runs everything in a new STA thread to satisfy the GUI requirements.
        /// </summary>
        public static void Boot()
        {
            Thread thread = new(() =>
            {
                try
                {
                    // Initialize and run the WPF GUI
                    GUIMain.LoadMainXaml();
                    _ = GUIMain.app!.Run(GUIMain.mainGUIWindow);
                }
                catch (Exception ex)
                {
                    // Log or handle the exception appropriately
                    Logger.LogMessage($"An error occurred: {ex.Message}", LogTypeIntel.Error);
                    throw;
                }
                finally
                {
                    // Ensure proper cleanup
                    ControlledFolderAccessHandler.Reset();
                    Miscellaneous.CleanUp();
                }
            });

            thread.SetApartmentState(ApartmentState.STA);
            // ensures the thread doesn't block the application from closing
            // thread.IsBackground = true;
            thread.Start();
            thread.Join();
        }
    }
}
