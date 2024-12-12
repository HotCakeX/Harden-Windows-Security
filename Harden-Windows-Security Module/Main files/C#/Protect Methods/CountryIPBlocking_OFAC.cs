using System;

namespace HardenWindowsSecurity
{
    public static partial class CountryIPBlocking
    {
        /// <summary>
        /// Blocks IP address of the countries in the OFAC list
        /// </summary>
        public static void CountryIPBlocking_OFAC()
        {
            Logger.LogMessage("Blocking IP ranges of countries in OFAC sanction list", LogTypeIntel.Information);

            FirewallHelper.BlockIPAddressListsInGroupPolicy(
              "OFAC Sanctioned Countries IP range blocking",
             new Uri("https://raw.githubusercontent.com/HotCakeX/Official-IANA-IP-blocks/main/Curated-Lists/OFACSanctioned.txt"),
              true
              );
        }
    }
}
