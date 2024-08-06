using System;
using System.Collections;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

namespace HardeningModule
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
            HardeningModule.GUI.Logger.Add($"{DateTime.Now}: {text}");

            // Invoke the Dispatcher to update the GUI
            HardeningModule.GUI.window.Dispatcher.Invoke(new Action(() =>
            {
                // Update the TextBlock with the new log message
                HardeningModule.GUI.outputTextBlock.Text += text + "\n";
                HardeningModule.GUI.scrollerForOutputTextBlock.ScrollToBottom();
            }), DispatcherPriority.Background);
        }
    }
}
