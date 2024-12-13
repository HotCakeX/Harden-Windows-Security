using System;

namespace HardenWindowsSecurity
{
    public static partial class MicrosoftDefender
    {
        /// <summary>
        /// Sets Microsoft Defender Engine and Platform update channels to beta
        /// </summary>
        /// <exception cref="ArgumentNullException"></exception>
        public static void MSFTDefender_BetaChannels()
        {
            if (GlobalVars.path is null)
            {
                throw new ArgumentNullException("GlobalVars.path cannot be null.");
            }

            Logger.LogMessage("Setting Microsoft Defender engine and platform update channel to beta", LogTypeIntel.Information);

            ConfigDefenderHelper.ManageMpPreference("EngineUpdatesChannel", "2", true);

            ConfigDefenderHelper.ManageMpPreference("PlatformUpdatesChannel", "2", true);

        }
    }
}
