using System;
using System.Threading;

#nullable enable

namespace HardenWindowsSecurity
{
    public class GUIBootStrapper
    {
        /// <summary>
        /// Starts and takes control of the entire GUI bootstrapping, startup and exit workflows
        /// Can be started from PowerShell and C# environments.
        /// That means you can use this during development in both Visual Studio and Visual Studio Code.
        /// Runs everything in a new STA thread to satisfy the GUI requirements.
        /// </summary>
        public static void Boot()
        {
            Thread thread = new Thread(() =>
            {
                try
                {
                    // Initialize and run the WPF GUI
                    HardenWindowsSecurity.GUIMain.LoadMainXaml();
                    HardenWindowsSecurity.GUIMain.app!.Run(HardenWindowsSecurity.GUIMain.mainGUIWindow);
                }
                catch (Exception ex)
                {
                    // Log or handle the exception appropriately
                    HardenWindowsSecurity.Logger.LogMessage($"An error occurred: {ex.Message}", LogTypeIntel.Error);
                    throw;
                }
                finally
                {
                    // Ensure proper cleanup
                    HardenWindowsSecurity.ControlledFolderAccessHandler.Reset();
                    HardenWindowsSecurity.Miscellaneous.CleanUp();
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
