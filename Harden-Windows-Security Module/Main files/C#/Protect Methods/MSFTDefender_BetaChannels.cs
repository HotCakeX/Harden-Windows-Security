#nullable enable

namespace HardenWindowsSecurity
{
    public static partial class MicrosoftDefender
    {
        public static void MSFTDefender_BetaChannels()
        {
            if (HardenWindowsSecurity.GlobalVars.path is null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            HardenWindowsSecurity.Logger.LogMessage("Setting Microsoft Defender engine and platform update channel to beta", LogTypeIntel.Information);

            HardenWindowsSecurity.ConfigDefenderHelper.ManageMpPreference<string>("EngineUpdatesChannel", "2", true);

            HardenWindowsSecurity.ConfigDefenderHelper.ManageMpPreference<string>("PlatformUpdatesChannel", "2", true);

        }
    }
}
