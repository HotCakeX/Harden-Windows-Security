#nullable enable

namespace HardenWindowsSecurity
{
    public class ChangePSConsoleTitle
    {
        /// <summary>
        /// Attempts to set the title of the PowerShell console if it exists
        /// Doesn't throw any errors if for some reason this low priority task fails
        /// </summary>
        /// <param name="Title">The string to set as the title of the PowerShell Console</param>
        public static void Set(string Title)
        {
            if (GlobalVars.Host is not null)
            {
                try
                {
                    GlobalVars.Host.UI.RawUI.WindowTitle = Title;
                }
                catch { }
            }
        }
    }
}
