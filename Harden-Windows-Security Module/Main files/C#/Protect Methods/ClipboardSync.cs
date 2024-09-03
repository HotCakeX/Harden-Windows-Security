using System;

#nullable enable

namespace HardenWindowsSecurity
{
    public partial class NonAdminCommands
    {
        public static void ClipboardSync()
        {
            if (HardenWindowsSecurity.GlobalVars.path == null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            HardenWindowsSecurity.Logger.LogMessage("Enabling Clipboard Sync with Microsoft Account", LogTypeIntel.Information);

#nullable disable
            foreach (var Item in (HardenWindowsSecurity.GlobalVars.RegistryCSVItems))
            {
                if (string.Equals(Item.Category, "NonAdmin-ClipboardSync", StringComparison.OrdinalIgnoreCase))
                {
                    HardenWindowsSecurity.RegistryEditor.EditRegistry(Item.Path, Item.Key, Item.Value, Item.Type, Item.Action);
                }
            }
#nullable enable

        }
    }
}
