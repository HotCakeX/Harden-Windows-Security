using System;
using System.Net.Http;

#nullable enable

namespace WDACConfig
{
    internal static class AppUpdate
    {
        /// <summary>
        /// Downloads the version file from GitHub
        /// Checks the online version against the current app version
        /// returns a class consisting of necessary info for the calling methods to consume and make decision
        /// </summary>
        /// <returns></returns>
        public static UpdateCheckResponse Check()
        {

            using HttpClient client = new();

            string versionsResponse = client.GetStringAsync(GlobalVars.AppVersionLinkURL).GetAwaiter().GetResult();

            // To store the online version
            Version onlineAvailableVersion = new(versionsResponse);

            return new UpdateCheckResponse(
                onlineAvailableVersion > App.currentAppVersion,
                onlineAvailableVersion
                );
        }
    }
}
