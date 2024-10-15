#nullable enable

namespace HardenWindowsSecurity
{
    public static partial class CountryIPBlocking
    {
        public static void Invoke()
        {

            ChangePSConsoleTitle.Set("🧾 Country IPs");

            HardenWindowsSecurity.Logger.LogMessage("Blocking IP ranges of countries in State Sponsors of Terrorism list", LogTypeIntel.Information);

            FirewallHelper.BlockIPAddressListsInGroupPolicy(
                "State Sponsors of Terrorism IP range blocking",
                "https://raw.githubusercontent.com/HotCakeX/Official-IANA-IP-blocks/main/Curated-Lists/StateSponsorsOfTerrorism.txt",
                true
                );
        }
    }
}
