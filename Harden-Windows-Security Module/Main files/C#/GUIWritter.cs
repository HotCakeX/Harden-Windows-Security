using System;
using System.Collections;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

#nullable enable

namespace HardenWindowsSecurity
{
    public static class Logger
    {
        /// <summary>
        /// Writes messages to the GUI and the log file
        /// </summary>
        /// <param name="text">The text to be written</param>
        public static void LogMessage(string text)
        {
            // Add the text to the synchronized array list as log messages
            HardenWindowsSecurity.GUIProtectWinSecurity.Logger.Add(value: $"{DateTime.Now}: {text}");

            // Invoke the Dispatcher to update the GUI
            HardenWindowsSecurity.GUIProtectWinSecurity.window!.Dispatcher.Invoke(callback: new Action(() =>
            {
                // Update the TextBlock with the new log message
                HardenWindowsSecurity.GUIProtectWinSecurity.outputTextBlock!.Text += text + "\n";
                HardenWindowsSecurity.GUIProtectWinSecurity.scrollerForOutputTextBlock!.ScrollToBottom();
            }), priority: DispatcherPriority.Background);
        }
    }
}
