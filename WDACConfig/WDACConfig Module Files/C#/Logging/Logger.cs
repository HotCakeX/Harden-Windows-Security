#nullable enable

namespace WDACConfig
{
    public static class Logger
    {
        /// <summary>
        /// Write a verbose message to the console
        /// The verbose messages are not redirectable in PowerShell
        /// https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostuserinterface
        /// </summary>
        /// <param name="message"></param>
        public static void Write(string message)
        {
            try
            {
                if (GlobalVars.VerbosePreference)
                {
                    GlobalVars.Host?.UI.WriteVerboseLine(message);
                }
            }
            // Do not do anything if errors occur
            // Since many methods write to the console asynchronously this can throw errors
            catch { }
        }
    }
}
