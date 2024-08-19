using System;
using System.IO;
using Microsoft.Win32;

#nullable enable

namespace HardenWindowsSecurity
{
    public class EdgeBrowserConfigurations
    {
        public static void Invoke()
        {
            if (HardenWindowsSecurity.GlobalVars.path == null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }
            if (HardenWindowsSecurity.GlobalVars.RegistryCSVItems == null)
            {
                throw new System.ArgumentNullException("GlobalVars.RegistryCSVItems cannot be null.");
            }

            HardenWindowsSecurity.Logger.LogMessage("Running the Edge Browser category");

            HardenWindowsSecurity.Logger.LogMessage("Applying the Edge Browser registry settings");

#nullable disable
            foreach (var Item in (HardenWindowsSecurity.GlobalVars.RegistryCSVItems))
            {
                if (string.Equals(Item.Category, "Edge", StringComparison.OrdinalIgnoreCase))
                {
                    HardenWindowsSecurity.RegistryEditor.EditRegistry(Item.Path, Item.Key, Item.Value, Item.Type, Item.Action);
                }
            }
#nullable restore

        }
    }
}
