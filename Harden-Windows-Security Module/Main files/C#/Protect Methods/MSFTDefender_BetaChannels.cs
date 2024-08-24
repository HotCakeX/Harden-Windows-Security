using System;
using System.IO;
using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;

#nullable enable

namespace HardenWindowsSecurity
{
    public partial class MicrosoftDefender
    {
        public static void MSFTDefender_BetaChannels()
        {
            if (HardenWindowsSecurity.GlobalVars.path == null)
            {
               throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            HardenWindowsSecurity.Logger.LogMessage("Setting Microsoft Defender engine and platform update channel to beta");

            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<string>("EngineUpdatesChannel", "2");

            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<string>("PlatformUpdatesChannel", "2");

        }
    }
}
