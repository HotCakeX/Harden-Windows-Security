using Microsoft.Win32;
using System;

#nullable enable

namespace HardenWindowsSecurity
{
    public static class TLSSecurity
    {
        public static void Invoke()
        {
            if (HardenWindowsSecurity.GlobalVars.path is null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            ChangePSConsoleTitle.Set("🛡️ TLS");

            HardenWindowsSecurity.Logger.LogMessage("Running the TLS Security category", LogTypeIntel.Information);

            // Creating these registry keys that have forward slashes in them
            // Values are added to them in the next step using registry.csv file
            string[] cipherKeys =
            [
            "DES 56/56",       // DES 56-bit
            "RC2 40/128",      // RC2 40-bit
            "RC2 56/128",      // RC2 56-bit
            "RC2 128/128",     // RC2 128-bit
            "RC4 40/128",      // RC4 40-bit
            "RC4 56/128",      // RC4 56-bit
            "RC4 64/128",      // RC4 64-bit
            "RC4 128/128",     // RC4 128-bit
            "Triple DES 168"   // 3DES 168-bit (Triple DES 168)
            ];

            foreach (var cipherKey in cipherKeys)
            {
                using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);

                string keyPath = $@"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\{cipherKey}";

                using RegistryKey subKey = baseKey.CreateSubKey(keyPath);
                // Key is created, but no values are set
            }




            HardenWindowsSecurity.Logger.LogMessage("Applying the TLS Security registry settings", LogTypeIntel.Information);

            foreach (var Item in HardenWindowsSecurity.GlobalVars.RegistryCSVItems!)
            {
                if (string.Equals(Item.Category, "TLS", StringComparison.OrdinalIgnoreCase))
                {
                    HardenWindowsSecurity.RegistryEditor.EditRegistry(Item.Path!, Item.Key!, Item.Value!, Item.Type!, Item.Action!);
                }
            }

            HardenWindowsSecurity.Logger.LogMessage("Applying the TLS Security Group Policies", LogTypeIntel.Information);
            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "TLS Security", "registry.pol"), LGPORunner.FileType.POL);

        }
    }
}
