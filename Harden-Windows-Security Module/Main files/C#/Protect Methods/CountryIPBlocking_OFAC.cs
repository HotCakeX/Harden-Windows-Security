#nullable enable

namespace HardenWindowsSecurity
{
    public static partial class CountryIPBlocking
    {
        public static void CountryIPBlocking_OFAC()
        {
            HardenWindowsSecurity.Logger.LogMessage("Blocking IP ranges of countries in OFAC sanction list", LogTypeIntel.Information);

            FirewallHelper.BlockIPAddressListsInGroupPolicy(
              "OFAC Sanctioned Countries IP range blocking",
              "https://raw.githubusercontent.com/HotCakeX/Official-IANA-IP-blocks/main/Curated-Lists/OFACSanctioned.txt",
              true
              );
        }
    }
}
