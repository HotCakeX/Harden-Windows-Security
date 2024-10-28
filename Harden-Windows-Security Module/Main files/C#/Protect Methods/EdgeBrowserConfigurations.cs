using System;

#nullable enable

namespace HardenWindowsSecurity
{
    public static class EdgeBrowserConfigurations
    {
        public static void Invoke()
        {
            if (GlobalVars.path is null)
            {
                throw new ArgumentNullException("GlobalVars.path cannot be null.");
            }
            if (GlobalVars.RegistryCSVItems is null)
            {
                throw new ArgumentNullException("GlobalVars.RegistryCSVItems cannot be null.");
            }

            ChangePSConsoleTitle.Set("🦔 Edge");

            Logger.LogMessage("Running the Edge Browser category", LogTypeIntel.Information);

            Logger.LogMessage("Applying the Edge Browser registry settings", LogTypeIntel.Information);

            foreach (HardeningRegistryKeys.CsvRecord Item in GlobalVars.RegistryCSVItems)
            {
                if (string.Equals(Item.Category, "Edge", StringComparison.OrdinalIgnoreCase))
                {
                    RegistryEditor.EditRegistry(Item.Path, Item.Key, Item.Value, Item.Type, Item.Action);
                }
            }

        }
    }
}
