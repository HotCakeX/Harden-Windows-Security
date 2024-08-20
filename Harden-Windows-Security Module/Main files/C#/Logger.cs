using System;
using System.Collections;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using System.IO;

#nullable enable

namespace HardenWindowsSecurity
{
    public static class Logger
    {

        /// <summary>
        /// Writes the texts to the log file path user selected. Is used by other methods or directly to store texts only in the log file instead of displaying on the GUI.
        /// Since this method queries GUI elements, it is and must always be called using the dispatcher.
        /// </summary>
        /// <param name="Text">The text to store in the log file.</param>
        public static void LogToFile(string Text)
        {

            // Only proceed further if user enabled logging
            if (GUIProtectWinSecurity.log != null && GUIProtectWinSecurity.log!.IsChecked == true)

            {
                //  if the log file path is not empty
                if (!string.IsNullOrEmpty(GUIProtectWinSecurity.txtFilePath!.Text))
                {

                    // trim any white spaces, single or double quotes in case the user entered the path with quotes around it
                    GUIProtectWinSecurity.txtFilePath!.Text = GUIProtectWinSecurity.txtFilePath.Text.Trim(' ', '\'', '\"'); ;

                    // Ensure the path is absolute
                    GUIProtectWinSecurity.txtFilePath.Text = System.IO.Path.GetFullPath(GUIProtectWinSecurity.txtFilePath.Text);

                    // Append log entries to the file
                    try
                    {
                        using (StreamWriter sw = File.AppendText(GUIProtectWinSecurity.txtFilePath.Text))
                        {
                            sw.WriteLine($"{Text}");
                        }
                    }
                    catch
                    {
                        Console.WriteLine($"Couldn't save the logs in the selected path: {GUIProtectWinSecurity.txtFilePath.Text}");
                    }
                }
            }
        }


        /// <summary>
        /// Writes messages to the GUI and the log file
        /// </summary>
        /// <param name="text">The text to be written</param>
        public static void LogMessage(string text)
        {
            string CurrentText = $"{DateTime.Now}: {text}";

            // If there is no GUI Window, meaning the code is running in Visual Studio, then use Console for writing logs
            if (HardenWindowsSecurity.GUIProtectWinSecurity.View == null)
            {
                Console.WriteLine(CurrentText);
            }
            else
            {
                // Invoke the Dispatcher to update the GUI
                HardenWindowsSecurity.GUIProtectWinSecurity.View.Dispatcher.Invoke(callback: new Action(() =>
                {

                    // if user enabled logging
                    if (GUIProtectWinSecurity.log != null && GUIProtectWinSecurity.log!.IsChecked == true)
                    {
                        // only write the header to the log file if it hasn't already been written to it
                        if (HardenWindowsSecurity.GlobalVars.LogHeaderHasBeenWritten == false)
                        {

                            HardenWindowsSecurity.Logger.LogToFile($"""
**********************
Harden Windows Security operation log start
Start time: {DateTime.Now}
Username: {Environment.UserName}
Machine: {Environment.MachineName}
**********************
""");

                            // set the flag to true so that the log file header will only be written once to the file per session
                            // it is reset back to false in the Initialize() method
                            HardenWindowsSecurity.GlobalVars.LogHeaderHasBeenWritten = true;
                        }
                    }

                    // Add the same text to the log file
                    HardenWindowsSecurity.Logger.LogToFile(CurrentText);

                    // Update the TextBlock with the new log message
                    HardenWindowsSecurity.GUIProtectWinSecurity.outputTextBlock!.Text += CurrentText + "\n";
                    HardenWindowsSecurity.GUIProtectWinSecurity.scrollerForOutputTextBlock!.ScrollToBottom();
                }), priority: DispatcherPriority.Background);
            }
        }
    }
}
