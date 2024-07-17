using System;
using System.Collections.Generic;
using System.Management;
using System.Linq;

/// Sources for the code:
/// https://learn.microsoft.com/en-us/windows/win32/secprov/win32-encryptablevolume
/// https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/msft-volume
/// Example usage:
/// $output = [HardeningModule.BitLockerInfo]::GetEncryptedVolumeInfo("D:")
/// $output
/// $output.KeyProtector

namespace HardeningModule
{
    // Class that stores the information about each key protector
    public class KeyProtector
    {
        public string KeyProtectorType { get; set; }
        public string KeyProtectorID { get; set; }
        public bool AutoUnlockProtector { get; set; }
        public string KeyFileName { get; set; }
        public string RecoveryPassword { get; set; }
        public string KeyCertificateType { get; set; }
        public string Thumbprint { get; set; }
    }

    // class that stores the information about BitLocker protected volumes
    public class BitLockerVolume
    {
        public string MountPoint { get; set; }
        public string EncryptionMethod { get; set; }
        public string EncryptionMethodFlags { get; set; }
        public bool AutoUnlockEnabled { get; set; }
        public bool AutoUnlockKeyStored { get; set; }

        // https://learn.microsoft.com/en-us/windows/win32/secprov/getversion-win32-encryptablevolume#parameters
        public uint MetadataVersion { get; set; }

        public string ConversionStatus { get; set; }
        public string ProtectionStatus { get; set; }
        public string LockStatus { get; set; }
        public string EncryptionPercentage { get; set; }
        public string WipePercentage { get; set; }
        public string WipingStatus { get; set; }
        public string VolumeType { get; set; }
        public string CapacityGB { get; set; }
        public string FileSystemType { get; set; }
        public string FriendlyName { get; set; }
        public string AllocationUnitSize { get; set; }
        public string ReFSDedupMode { get; set; }
        public List<KeyProtector> KeyProtector { get; set; }
    }

    public static class BitLockerInfo
    {

        // Different types of the key protectors
        // https://learn.microsoft.com/en-us/windows/win32/secprov/getkeyprotectortype-win32-encryptablevolume
        private static readonly Dictionary<uint, string> KeyProtectorTypes = new Dictionary<uint, string>
    {
        { 0, "Unknown" },
        { 1, "Tpm" },
        { 2, "ExternalKey" },
        { 3, "RecoveryPassword" },
        { 4, "TpmPin" },
        { 5, "TpmStartupKey" },
        { 6, "TpmPinStartupKey" },
        { 7, "PublicKey" },
        { 8, "Password" },
        { 9, "TpmNetworkKey" },
        { 10, "AdAccountOrGroup" }
    };


        // https://learn.microsoft.com/en-us/windows/win32/secprov/getencryptionmethod-win32-encryptablevolume
        private static readonly Dictionary<uint, string> EncryptionMethods = new Dictionary<uint, string>
    {
        { 0, "None" },
        { 1, "AES_128_WITH_DIFFUSER" },
        { 2, "AES_256_WITH_DIFFUSER" },
        { 3, "AES_128" },
        { 4, "AES_256" },
        { 5, "HARDWARE_ENCRYPTION" },
        { 6, "XTS_AES_128" },
        { 7, "XTS_AES_256" }
    };


        // https://learn.microsoft.com/en-us/windows/win32/secprov/getprotectionstatus-win32-encryptablevolume
        private static readonly Dictionary<uint, string> ProtectionStatuses = new Dictionary<uint, string>
    {
        { 0, "Unprotected" },
        { 1, "Protected" },
        { 2, "Unknown" }
    };


        // https://learn.microsoft.com/en-us/windows/win32/secprov/getlockstatus-win32-encryptablevolume
        private static readonly Dictionary<uint, string> LockStatuses = new Dictionary<uint, string>
    {
        { 0, "Unlocked" },
        { 1, "Locked" }
    };

        // https://learn.microsoft.com/en-us/windows/win32/secprov/win32-encryptablevolume#properties
        private static readonly Dictionary<uint, string> VolumeTypes = new Dictionary<uint, string>
    {
        { 0, "OperationSystem" },
        { 1, "FixedDisk" },
        { 2, "Removable" }
    };

        // https://learn.microsoft.com/en-us/windows/win32/secprov/getconversionstatus-win32-encryptablevolume
        private static readonly Dictionary<uint, string> ConversionStatuses = new Dictionary<uint, string>
    {
        { 0, "FULLY DECRYPTED" },
        { 1, "FULLY ENCRYPTED" },
        { 2, "ENCRYPTION IN PROGRESS" },
        { 3, "DECRYPTION IN PROGRESS" },
        { 4, "ENCRYPTION PAUSED" },
        { 5, "DECRYPTION PAUSED" }
    };

        // https://learn.microsoft.com/en-us/windows/win32/secprov/getconversionstatus-win32-encryptablevolume
        private static readonly Dictionary<uint, string> WipingStatuses = new Dictionary<uint, string>
    {
        { 0, "FreeSpaceNotWiped" },
        { 1, "FreeSpaceWiped" },
        { 2, "FreeSpaceWipingInProgress" },
        { 3, "FreeSpaceWipingPaused" }
    };

        // https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/msft-volume#properties
        private static readonly Dictionary<ushort, string> FileSystemTypes = new Dictionary<ushort, string>
    {
        { 0, "Unknown" },
        { 2, "UFS" },
        { 3, "HFS" },
        { 4, "FAT" },
        { 5, "FAT16" },
        { 6, "FAT32" },
        { 7, "NTFS4" },
        { 8, "NTFS5" },
        { 9, "XFS" },
        { 10, "AFS" },
        { 11, "EXT2" },
        { 12, "EXT3" },
        { 13, "ReiserFS" },
        { 14, "NTFS" },
        { 15, "ReFS" }
    };

        // https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/msft-volume#properties
        private static readonly Dictionary<uint, string> ReFSDedupModes = new Dictionary<uint, string>
    {
        { 0, "Disabled" },
        { 1, "GeneralPurpose" },
        { 2, "HyperV" },
        { 3, "Backup" },
        { 4, "NotAvailable" }
    };

        // The main method that will generate as much useful info as possible about every BitLocker volume
        public static BitLockerVolume GetEncryptedVolumeInfo(string targetVolume)
        {
            // The MSFT_Volume class requires the volume name without the colon
            var targetVolumeVer2 = targetVolume.Replace(":", "");

            // Create a new instance of the BitLockerVolume class
            BitLockerVolume newInstance = new BitLockerVolume();

            // Get the information about the volume using Win32_EncryptableVolume class
            // This is used a lot as the main input object to get information from other classes
            ManagementBaseObject volume = GetCimInstance("Root\\CIMV2\\Security\\MicrosoftVolumeEncryption", "Win32_EncryptableVolume", $"DriveLetter = '{targetVolume}'");
            newInstance.MountPoint = volume["DriveLetter"].ToString();
            newInstance.ProtectionStatus = ProtectionStatuses[Convert.ToUInt32(volume["ProtectionStatus"])];
            newInstance.VolumeType = VolumeTypes[Convert.ToUInt32(volume["VolumeType"])];

            ManagementBaseObject currentLockStatus = InvokeCimMethod(volume, "GetLockStatus");
            if (Convert.ToUInt32(currentLockStatus["ReturnValue"]) == 0)
            {
                newInstance.LockStatus = LockStatuses[Convert.ToUInt32(currentLockStatus["LockStatus"])];
            }

            ManagementBaseObject currentVolConversionStatus = InvokeCimMethod(volume, "GetConversionStatus");
            if (Convert.ToUInt32(currentVolConversionStatus["ReturnValue"]) == 0)
            {
                newInstance.EncryptionPercentage = currentVolConversionStatus["EncryptionPercentage"].ToString();
                newInstance.WipePercentage = currentVolConversionStatus["WipingPercentage"].ToString();
                newInstance.ConversionStatus = ConversionStatuses[Convert.ToUInt32(currentVolConversionStatus["ConversionStatus"])];
                newInstance.WipingStatus = WipingStatuses[Convert.ToUInt32(currentVolConversionStatus["WipingStatus"])];
            }

            ManagementBaseObject currentEncryptionMethod = InvokeCimMethod(volume, "GetEncryptionMethod");
            if (Convert.ToUInt32(currentEncryptionMethod["ReturnValue"]) == 0)
            {
                newInstance.EncryptionMethod = EncryptionMethods[Convert.ToUInt32(currentEncryptionMethod["EncryptionMethod"])];
                newInstance.EncryptionMethodFlags = currentEncryptionMethod["EncryptionMethodFlags"].ToString();
            }

            ManagementBaseObject currentVolVersion = InvokeCimMethod(volume, "GetVersion");
            if (Convert.ToUInt32(currentVolVersion["ReturnValue"]) == 0)
            {
                newInstance.MetadataVersion = Convert.ToUInt32(currentVolVersion["Version"]);
            }

            // Get volume information using the MSFT_Volume class
            ManagementBaseObject currentStorage = GetCimInstance("Root\\Microsoft\\Windows\\Storage", "MSFT_Volume", $"DriveLetter = '{targetVolumeVer2}'");
            newInstance.CapacityGB = Math.Round(Convert.ToDouble(currentStorage["Size"]) / (1024 * 1024 * 1024), 4).ToString();
            newInstance.FileSystemType = FileSystemTypes[Convert.ToUInt16(currentStorage["FileSystemType"])];
            newInstance.FriendlyName = currentStorage["FileSystemLabel"].ToString();
            newInstance.AllocationUnitSize = currentStorage["AllocationUnitSize"].ToString();
            newInstance.ReFSDedupMode = ReFSDedupModes[Convert.ToUInt32(currentStorage["ReFSDedupMode"])];

            // Only attempt to get key protectors if the volume is unlocked
            //   if (Convert.ToUInt32(currentLockStatus["LockStatus"]) == 0) // 0 corresponds to Unlocked
            //   {

            // Get all of the key protectors for the volume
            ManagementBaseObject keyProtectors = InvokeCimMethod(volume, "GetKeyProtectors");

            // Create a new list of KeyProtector objects
            newInstance.KeyProtector = new List<KeyProtector>();

            // Iterate through all of the key protectors' IDs
            foreach (var keyProtectorID in (string[])keyProtectors["VolumeKeyProtectorID"])
            {

                // Set them all to null initially so we don't accidentally use them for the wrong key protector type
                string type = null;
                string recoveryPassword = null;
                bool autoUnlockProtector = false;
                string keyProtectorFileName = null;
                string keyProtectorThumbprint = null;
                string keyProtectorCertificateType = null;

                // Get the type of the current key protector in the loop
                ManagementBaseObject keyProtectorTypeResult = InvokeCimMethod(volume, "GetKeyProtectorType", new Dictionary<string, object> { { "VolumeKeyProtectorID", keyProtectorID } });
                var keyProtectorType = Convert.ToUInt32(keyProtectorTypeResult["KeyProtectorType"]);

                // Get the friendly name for the key protector type
                type = KeyProtectorTypes[keyProtectorType];

                // if the current key protector is RecoveryPassword / Numerical password
                if (keyProtectorType == 3)
                {
                    ManagementBaseObject numericalPassword = InvokeCimMethod(volume, "GetKeyProtectorNumericalPassword", new Dictionary<string, object> { { "VolumeKeyProtectorID", keyProtectorID } });

                    // If the return value is 0, the method succeeded
                    if (Convert.ToUInt32(numericalPassword["ReturnValue"]) == 0)
                    {
                        recoveryPassword = numericalPassword["NumericalPassword"].ToString();
                    }
                }

                // if the current key protector is ExternalKey
                if (keyProtectorType == 2)
                {
                    ManagementBaseObject autoUnlockEnabledResult = InvokeCimMethod(volume, "IsAutoUnlockEnabled");

                    // check if it was successful
                    if (Convert.ToUInt32(autoUnlockEnabledResult["ReturnValue"]) == 0)
                    {

                        // Check if AutoUnlock is enabled
                        if (Convert.ToBoolean(autoUnlockEnabledResult["IsAutoUnlockEnabled"]))
                        {
                            // Check if the volume key protector ID is the same as the key protector ID
                            if (autoUnlockEnabledResult["VolumeKeyProtectorID"].ToString() == keyProtectorID)
                            {
                                autoUnlockProtector = true;
                            }
                        }
                    }

                    ManagementBaseObject keyProtectorFileNameResult = InvokeCimMethod(volume, "GetExternalKeyFileName", new Dictionary<string, object> { { "VolumeKeyProtectorID", keyProtectorID } });

                    // check if successful
                    if (Convert.ToUInt32(keyProtectorFileNameResult["ReturnValue"]) == 0)
                    {
                        keyProtectorFileName = keyProtectorFileNameResult["FileName"].ToString();
                    }
                }

                // if the current key protector is PublicKey or TpmNetworkKey
                if (keyProtectorType == 7 || keyProtectorType == 9)
                {
                    ManagementBaseObject keyProtectorCertificateResult = InvokeCimMethod(volume, "GetKeyProtectorCertificate", new Dictionary<string, object> { { "VolumeKeyProtectorID", keyProtectorID } });

                    // check if successful
                    if (Convert.ToUInt32(keyProtectorCertificateResult["ReturnValue"]) == 0)
                    {
                        keyProtectorThumbprint = keyProtectorCertificateResult["CertThumbprint"].ToString();
                        keyProtectorCertificateType = keyProtectorCertificateResult["CertType"].ToString();
                    }
                }

                newInstance.KeyProtector.Add(new KeyProtector
                {
                    KeyProtectorID = keyProtectorID,
                    KeyProtectorType = type,
                    RecoveryPassword = recoveryPassword,
                    AutoUnlockProtector = autoUnlockProtector,
                    KeyFileName = keyProtectorFileName,
                    KeyCertificateType = keyProtectorCertificateType,
                    Thumbprint = keyProtectorThumbprint
                });
            }
            //    }

            return newInstance;
        }

        // Helper method to get the information from the WMI classes
        private static ManagementBaseObject GetCimInstance(string @namespace, string className, string filter)
        {
            SelectQuery query = new SelectQuery(className, filter);
            using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(@namespace, query.QueryString))
            {
                return searcher.Get().Cast<ManagementBaseObject>().FirstOrDefault();
            }
        }

        // Helper method to invoke a method on a WMI class
        private static ManagementBaseObject InvokeCimMethod(ManagementBaseObject instance, string methodName, Dictionary<string, object> parameters = null)
        {
            ManagementClass managementClass = new ManagementClass(instance.ClassPath);
            var inParams = managementClass.GetMethodParameters(methodName);
            if (parameters != null)
            {
                foreach (var param in parameters)
                {
                    inParams[param.Key] = param.Value;
                }
            }
            return ((ManagementObject)instance).InvokeMethod(methodName, inParams, null);
        }

        // Method to get the drive letters of all volumes on the system, encrypted or not
        public static string[] GetAllDriveLetters()
        {
            List<string> driveLetters = new List<string>();

            ManagementObjectCollection storages = GetCimInstances("Root\\Microsoft\\Windows\\Storage", "MSFT_Volume", string.Empty);

            foreach (ManagementBaseObject storage in storages)
            {
                // Iterate through the properties of the storage object
                foreach (PropertyData property in storage.Properties)
                {
                    if (property.Name == "DriveLetter" && property.Value != null)
                    {
                        driveLetters.Add(property.Value.ToString());
                    }
                }
            }

            return driveLetters.ToArray();
        }

        private static ManagementObjectCollection GetCimInstances(string namespacePath, string className, string filter)
        {
            ManagementScope scope = new ManagementScope(namespacePath);
            string queryString = string.IsNullOrEmpty(filter) ? $"SELECT * FROM {className}" : $"SELECT * FROM {className} WHERE {filter}";
            ObjectQuery query = new ObjectQuery(queryString);
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);
            return searcher.Get();
        }

        // Get the BitLocker info of all of the volumes on the system
        public static List<BitLockerVolume> GetAllEncryptedVolumeInfo()
        {
            // Create a new list of BitLockerVolume objects
            List<BitLockerVolume> volumes = new List<BitLockerVolume>();

            // Call the GetAllDriveLetters method to get all of the drive letters
            string[] driveLetters = GetAllDriveLetters();

            // Iterate through all of the drive letters
            foreach (string driveLetter in driveLetters)
            {
                // the method requires the drive letter with the colon
                BitLockerVolume volume = GetEncryptedVolumeInfo(driveLetter + ":");
                volumes.Add(volume);
            }

            return volumes;
        }
    }
}
