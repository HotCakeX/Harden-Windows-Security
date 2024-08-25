using System;
using System.IO;
using System.Globalization;

#nullable enable

namespace HardenWindowsSecurity
{
    public partial class NonAdminCommands
    {
        public static void Invoke()
        {
            if (HardenWindowsSecurity.GlobalVars.path == null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            HardenWindowsSecurity.Logger.LogMessage("Running the Non-Admin category");
            HardenWindowsSecurity.Logger.LogMessage("Applying the Non-Admin registry settings");
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
