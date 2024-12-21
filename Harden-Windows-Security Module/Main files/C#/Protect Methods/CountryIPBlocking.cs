using System;

namespace HardenWindowsSecurity;

    public static partial class CountryIPBlocking
    {
        /// <summary>
        /// Performs country IP blocking operations
        /// </summary>
        public static void Invoke()
        {

            ChangePSConsoleTitle.Set("🧾 Country IPs");

            Logger.LogMessage("Blocking IP ranges of countries in State Sponsors of Terrorism list", LogTypeIntel.Information);

            FirewallHelper.BlockIPAddressListsInGroupPolicy(
                "State Sponsors of Terrorism IP range blocking",
                new Uri("https://raw.githubusercontent.com/HotCakeX/Official-IANA-IP-blocks/main/Curated-Lists/StateSponsorsOfTerrorism.txt"),
                true
                );
        }
    }
