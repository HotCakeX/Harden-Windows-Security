using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Threading;

#nullable enable

namespace HardenWindowsSecurity
{
    // Log type used when calling the LogMessage method
    public enum LogTypeIntel
    {
        Information,
        Error,
        Warning,
        InformationInteractionRequired, // Same as "Information" but also displays DialogBox to the user
        WarningInteractionRequired, // Same as "Warning" but also displays DialogBox to the user
        ErrorInteractionRequired, // Same as "Error" but also displays DialogBox to the user
    }

    /// <summary>
    /// This class is responsible for all of the logging functionalities: Verbose messages, GUI messages, Console messages and so on.
    /// They are all centrally managed from here. No Write-Verbose is used in native PowerShell codes that run directly (i.e. they don't run inside of a PS process in C#)
    /// </summary>
    public static class Logger
    {

        /// <summary>
        /// The main method that manages other methods
        /// Writes the input text to the following destinations depending on their availabilities:
        ///  1) GUI
        ///  2) Console - regular messages - works in both Visual Studio console and PowerShell console
        ///  3) Console - Verbose messages - works only in the PowerShell console
        ///  4) Log file
        ///  5) New WPF Window as DialogBox
        /// </summary>
        /// <param name="text">The text to be written</param>
        /// <param name="LogType">The type of the log message, get it from the enum</param>
        public static void LogMessage(string text, LogTypeIntel LogType)
        {

            // Avoid writing empty messages that only have time stamps
            if (string.IsNullOrWhiteSpace(text) || string.IsNullOrEmpty(text))
            {
                return;
            }

            // attach timestamps to the text
            string CurrentText = $"{DateTime.Now}: {text}";

            // Display DialogBox to the user in addition to all other tasks
            if (LogType is LogTypeIntel.ErrorInteractionRequired)
            {
                DialogMsgHelper.Show(text, $"Error At {DateTime.Now}");
            }
            else if (LogType is LogTypeIntel.WarningInteractionRequired)
            {
                DialogMsgHelper.Show(text, $"Warning At {DateTime.Now}");
            }
            else if (LogType is LogTypeIntel.InformationInteractionRequired)
            {
                DialogMsgHelper.Show(text, $"Information At {DateTime.Now}");
            }


            // If there is no GUI Window, or there was a GUI window but it was closed by the user
            // then use Console for writing logs
            if (GUILogs.View is null || GUILogs.View.Dispatcher.HasShutdownStarted)
            {
                // See if the host is available, meaning PowerShell host is available
                // And also VerbosePreference is not null, in case the methods are running manually by using the Harden Windows Security methods directly in PowerShell like as a library
                // Because then the Verbose Preference is not set in the Initialize method since the module is only imported.
                if (GlobalVars.Host is not null && GlobalVars.VerbosePreference is not null)
                {
                    // Write the message as verbose text on PowerShell console
                    WriteVerbose(CurrentText);
                }
                else
                {
                    // If PowerShell console host is not available then write to the console that works for both C# and PS consoles
                    Console.WriteLine(CurrentText);
                }
            }
            // If GUI Window is available
            else
            {

                // Invoke the Dispatcher to update and Query the GUI elements
                GUILogs.View.Dispatcher.Invoke(callback: new Action(() =>
                {

                    #region Writing to the Log file if user enabled logging
                    if (GUIProtectWinSecurity.log is not null && GUIProtectWinSecurity.log.IsChecked == true)
                    {
                        // only write the header to the log file if it hasn't already been written to it
                        if (!GlobalVars.LogHeaderHasBeenWritten)
                        {

                            Logger.LogToFile($"""
**********************
Harden Windows Security operation log start
Start time: {DateTime.Now}
Username: {Environment.UserName}
Machine: {Environment.MachineName}
**********************
""");

                            // set the flag to true so that the log file header will only be written once to the file per session
                            // it is reset back to false in the Initialize() method
                            GlobalVars.LogHeaderHasBeenWritten = true;
                        }
                    }
                    #endregion

                    #region Writing to the GUI's Logger
                    // Update the TextBlock with the new log message, making sure each log is written to a new line
                    GUILogs.MainLoggerTextBox!.Text += CurrentText + "\n";

                    // scroll down the scroller if Auto-scrolling is enabled
                    if (GUILogs.AutoScroll)
                    {
                        GUILogs.scrollerForOutputTextBox!.ScrollToBottom();
                    }
                    #endregion

                    #region Writing to the log file
                    // The reason this method must run inside of the dispatcher is that it directly uses the text file path from the GUI's textbox element
                    // This could be potentially improved is slowdown is noticed in the GUI's performance by implementing an event handler for the log path's text block
                    // so that upon changes to it, the text will be saved in a global variable and then this method will be able to run outside of the dispatcher
                    // Of course then whether or not logging to file should happen must be performed within the dispatcher, then the result must be saved in a private variable
                    // of the current class and then based on that variable's value logging to file must happen outside of the dispatcher.
                    LogToFile(CurrentText);
                    #endregion

                    #region Writing to the Event Logs
                    // Write the same message to the event logs if event log write is enabled
                    if (GUIProtectWinSecurity.EventLogging is not null && GUIProtectWinSecurity.EventLogging.IsChecked == true)
                    {
                        switch (LogType)
                        {
                            case LogTypeIntel.Information:
                                {
                                    WriteEventLog(CurrentText, EventLogEntryType.Information);
                                    break;
                                }
                            case LogTypeIntel.InformationInteractionRequired:
                                {
                                    WriteEventLog(CurrentText, EventLogEntryType.Information);
                                    break;
                                }
                            case LogTypeIntel.Warning:
                                {
                                    WriteEventLog(CurrentText, EventLogEntryType.Warning);
                                    break;
                                }
                            case LogTypeIntel.WarningInteractionRequired:
                                {
                                    WriteEventLog(CurrentText, EventLogEntryType.Warning);
                                    break;

                                }
                            case LogTypeIntel.Error:
                                {
                                    WriteEventLog(CurrentText, EventLogEntryType.Error);
                                    break;
                                }
                            case LogTypeIntel.ErrorInteractionRequired:
                                {
                                    WriteEventLog(CurrentText, EventLogEntryType.Error);
                                    break;
                                }
                            default:
                                break;
                        }
                    }
                    #endregion


                }), priority: DispatcherPriority.Background);
            }
        }

        /// <summary>
        /// Writes the texts to the log file path user selected. Is used by other methods or directly to store texts only in the log file instead of displaying on the GUI.
        /// Since this method queries GUI elements, it is and must always be called using the dispatcher.
        /// </summary>
        /// <param name="Text">The text to store in the log file.</param>
        private static void LogToFile(string Text)
        {
            //  if the log file path is not empty
            if (GUIProtectWinSecurity.txtFilePath is not null && !string.IsNullOrEmpty(GUIProtectWinSecurity.txtFilePath.Text))
            {

                // trim any white spaces, single or double quotes in case the user entered the path with quotes around it
                GUIProtectWinSecurity.txtFilePath!.Text = GUIProtectWinSecurity.txtFilePath.Text.Trim(' ', '\'', '\"'); ;

                // Ensure the path is absolute
                GUIProtectWinSecurity.txtFilePath.Text = System.IO.Path.GetFullPath(GUIProtectWinSecurity.txtFilePath.Text);

                // Append log entries to the file
                try
                {
                    using StreamWriter sw = File.AppendText(GUIProtectWinSecurity.txtFilePath.Text);
                    sw.WriteLine($"{Text}");
                }
                catch
                {
                    Console.WriteLine($"Couldn't save the logs in the selected path: {GUIProtectWinSecurity.txtFilePath.Text}");
                }
            }
        }


        /// <summary>
        /// Write a verbose message to the console
        /// The verbose messages are not redirectable in PowerShell
        /// https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostuserinterface
        /// </summary>
        /// <param name="message"></param>
        private static void WriteVerbose(string message)
        {
            if (GlobalVars.Host is not null)
            {
                try
                {
                    if (string.Equals(GlobalVars.VerbosePreference, "Continue", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(GlobalVars.VerbosePreference, "Inquire", StringComparison.OrdinalIgnoreCase))
                    {
                        GlobalVars.Host.UI!.WriteVerboseLine(message);
                    }
                }
                // Do not do anything if errors occur
                // Since many methods write to the console asynchronously this can throw errors
                catch { }
            }
        }


        /// <summary>
        /// Writes the log messages to the event viewer log
        /// </summary>
        /// <param name="message"></param>
        /// <param name="Type">Entry type (Information, Warning, Error)</param>
        private static void WriteEventLog(string message, EventLogEntryType Type)
        {
            string eventLogName = "Application";
            string eventLogSource = "Harden-Windows-Security";
            int eventId = 1;
            short category = 0;
            EventLogEntryType entryType = Type;

            // Check if the event source exists, if not, create it
            if (!EventLog.SourceExists(eventLogSource))
            {
                EventLog.CreateEventSource(eventLogSource, eventLogName);
                // Console.WriteLine($"Event source '{eventLogSource}' created.");
            }

            // Write the event log entry
            EventLog.WriteEntry(eventLogSource, message, entryType, eventId, category);

            // Console.WriteLine("Event log entry written successfully.");
        }
    }
}
