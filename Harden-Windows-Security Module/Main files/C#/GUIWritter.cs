using System;
using System.Collections;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

namespace HardeningModule
{
    public static class Logger
    {
        public static void LogMessage(string text, IList logger, TextBox outputTextBlock, ScrollViewer scrollerForOutputTextBlock, Window window)
        {
            // Add the text to the synchronized array list as log messages
            logger.Add($"{DateTime.Now}: {text}");

            // Check if the window is null
            if (window == null)
            {
                throw new ArgumentNullException(nameof(window), "Window parameter cannot be null");
            }

            // Invoke the Dispatcher to update the GUI
            window.Dispatcher.Invoke(new Action(() =>
            {
                // Update the TextBlock with the new log message
                outputTextBlock.Text += text + "\n";
                scrollerForOutputTextBlock.ScrollToBottom();
            }), DispatcherPriority.Background);
        }
    }
}
