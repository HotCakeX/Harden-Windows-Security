using System;

#nullable enable

namespace HardenWindowsSecurity
{
    public static class EdgeBrowserConfigurations
    {
        public static void Invoke()
        {
            if (HardenWindowsSecurity.GlobalVars.path is null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }
            if (HardenWindowsSecurity.GlobalVars.RegistryCSVItems is null)
            {
                throw new System.ArgumentNullException("GlobalVars.RegistryCSVItems cannot be null.");
            }

            ChangePSConsoleTitle.Set("🦔 Edge");

            HardenWindowsSecurity.Logger.LogMessage("Running the Edge Browser category", LogTypeIntel.Information);

            HardenWindowsSecurity.Logger.LogMessage("Applying the Edge Browser registry settings", LogTypeIntel.Information);

#nullable disable
            foreach (var Item in (HardenWindowsSecurity.GlobalVars.RegistryCSVItems))
            {
                if (string.Equals(Item.Category, "Edge", StringComparison.OrdinalIgnoreCase))
                {
                    HardenWindowsSecurity.RegistryEditor.EditRegistry(Item.Path, Item.Key, Item.Value, Item.Type, Item.Action);
                }
            }
#nullable enable

        }
    }
}
