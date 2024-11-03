using System;
using System.IO;

#nullable enable

namespace HardenWindowsSecurity
{
    public partial class DeviceGuard
    {

        /// <summary>
        /// Applies the Device Guard category policies
        /// </summary>
        /// <exception cref="ArgumentNullException"></exception>
        public static void DeviceGuard_MandatoryVBS()
        {

            if (GlobalVars.path is null)
            {
                throw new ArgumentNullException("GlobalVars.path cannot be null.");
            }

            ChangePSConsoleTitle.Set("🖥️ Device Guard");

            Logger.LogMessage("Setting VBS and Memory Integrity in Mandatory Mode", LogTypeIntel.Information);

            foreach (HardeningRegistryKeys.CsvRecord Item in GlobalVars.RegistryCSVItems!)
            {
                if (string.Equals(Item.Category, "DeviceGuard_MandatoryVBS", StringComparison.OrdinalIgnoreCase))
                {
                    RegistryEditor.EditRegistry(Item.Path, Item.Key, Item.Value, Item.Type, Item.Action);
                }
            }

        }
    }
}
