using System;

#nullable enable

namespace HardenWindowsSecurity
{
    public static partial class NonAdminCommands
    {
        public static void Invoke()
        {
            if (HardenWindowsSecurity.GlobalVars.path is null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            ChangePSConsoleTitle.Set("🏷️ Non-Admins");

            HardenWindowsSecurity.Logger.LogMessage("Running the Non-Admin category", LogTypeIntel.Information);
            HardenWindowsSecurity.Logger.LogMessage("Applying the Non-Admin registry settings", LogTypeIntel.Information);
#nullable disable
            foreach (var Item in (HardenWindowsSecurity.GlobalVars.RegistryCSVItems))
            {
                if (string.Equals(Item.Category, "NonAdmin", StringComparison.OrdinalIgnoreCase))
                {
                    HardenWindowsSecurity.RegistryEditor.EditRegistry(Item.Path, Item.Key, Item.Value, Item.Type, Item.Action);
                }
            }
#nullable enable

        }
    }
}
