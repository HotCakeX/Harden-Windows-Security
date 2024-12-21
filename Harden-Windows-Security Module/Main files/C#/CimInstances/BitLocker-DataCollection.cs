using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Management;

/// Sources for the code:
/// https://learn.microsoft.com/en-us/windows/win32/secprov/win32-encryptablevolume
/// https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/msft-volume
/// Example usage:
/// $output = [HardenWindowsSecurity.BitLocker]::GetEncryptedVolumeInfo("D:")
/// $output
/// $output.KeyProtector

namespace HardenWindowsSecurity;


internal partial class BitLocker
{

	// Class that stores the information about each key protector
	internal sealed class KeyProtector
	{
		internal KeyProtectorType? KeyProtectorType { get; set; }
		internal string? KeyProtectorID { get; set; }
		internal bool AutoUnlockProtector { get; set; }
		internal string? KeyFileName { get; set; }
		internal string? RecoveryPassword { get; set; }
		internal string? KeyCertificateType { get; set; }
		internal string? Thumbprint { get; set; }
	}

	// class that stores the information about BitLocker protected volumes
	internal sealed class BitLockerVolume
	{
		internal string? MountPoint { get; set; }
		internal EncryptionMethod? EncryptionMethod { get; set; }
		internal string? EncryptionMethodFlags { get; set; }
		internal bool AutoUnlockEnabled { get; set; }
		internal bool AutoUnlockKeyStored { get; set; }

		// https://learn.microsoft.com/en-us/windows/win32/secprov/getversion-win32-encryptablevolume#parameters
		internal uint MetadataVersion { get; set; }

		internal ConversionStatus? ConversionStatus { get; set; }
		internal ProtectionStatus? ProtectionStatus { get; set; }
		internal LockStatus? LockStatus { get; set; }
		internal string? EncryptionPercentage { get; set; }
		internal string? WipePercentage { get; set; }
		internal WipingStatus? WipingStatus { get; set; }
		internal VolumeType? VolumeType { get; set; }
		internal string? CapacityGB { get; set; }
		internal FileSystemType? FileSystemType { get; set; }
		internal string? FriendlyName { get; set; }
		internal string? AllocationUnitSize { get; set; }
		internal ReFSDedupMode? ReFSDedupMode { get; set; }
		internal List<KeyProtector>? KeyProtector { get; set; }
	}

	// Different types of the key protectors
	// https://learn.microsoft.com/en-us/windows/win32/secprov/getkeyprotectortype-win32-encryptablevolume
	internal enum KeyProtectorType : uint
	{
		Unknown = 0,
		Tpm = 1,
		ExternalKey = 2,
		RecoveryPassword = 3,
		TpmPin = 4,
		TpmStartupKey = 5,
		TpmPinStartupKey = 6,
		PublicKey = 7,
		Password = 8,
		TpmNetworkKey = 9,
		AdAccountOrGroup = 10
	}

	// https://learn.microsoft.com/en-us/windows/win32/secprov/getencryptionmethod-win32-encryptablevolume
	internal enum EncryptionMethod : uint
	{
		None = 0,
		AES_128_WITH_DIFFUSER = 1,
		AES_256_WITH_DIFFUSER = 2,
		AES_128 = 3,
		AES_256 = 4,
		HARDWARE_ENCRYPTION = 5,
		XTS_AES_128 = 6,
		XTS_AES_256 = 7
	}

	// https://learn.microsoft.com/en-us/windows/win32/secprov/getprotectionstatus-win32-encryptablevolume
	internal enum ProtectionStatus : uint
	{
		Unprotected = 0,
		Protected = 1,
		Unknown = 2
	}

	// https://learn.microsoft.com/en-us/windows/win32/secprov/getlockstatus-win32-encryptablevolume
	internal enum LockStatus
	{
		Unlocked = 0,
		Locked = 1
	}

	// https://learn.microsoft.com/en-us/windows/win32/secprov/win32-encryptablevolume#properties
	internal enum VolumeType
	{
		OperationSystem = 0,
		FixedDisk = 1,
		Removable = 2
	}

	// https://learn.microsoft.com/en-us/windows/win32/secprov/getconversionstatus-win32-encryptablevolume
	internal enum ConversionStatus : uint
	{
		FullyDecrypted = 0,
		FullyEncrypted = 1,
		EncryptionInProgress = 2,
		DecryptionInProgress = 3,
		EncryptionPaused = 4,
		DecryptionPaused = 5
	}

	// https://learn.microsoft.com/en-us/windows/win32/secprov/getconversionstatus-win32-encryptablevolume
	internal enum WipingStatus : uint
	{
		FreeSpaceNotWiped = 0,
		FreeSpaceWiped = 1,
		FreeSpaceWipingInProgress = 2,
		FreeSpaceWipingPaused = 3
	}

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/msft-volume#properties
	internal enum FileSystemType : ushort
	{
		Unknown = 0,
		UFS = 2,
		HFS = 3,
		FAT = 4,
		FAT16 = 5,
		FAT32 = 6,
		NTFS4 = 7,
		NTFS5 = 8,
		XFS = 9,
		AFS = 10,
		EXT2 = 11,
		EXT3 = 12,
		ReiserFS = 13,
		NTFS = 14,
		ReFS = 15
	}

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/msft-volume#properties
	internal enum ReFSDedupMode : uint
	{
		Disabled = 0,
		GeneralPurpose = 1,
		HyperV = 2,
		Backup = 3,
		NotAvailable = 4
	}


	// The main method that will generate as much useful info as possible about every BitLocker volume
	internal static BitLockerVolume GetEncryptedVolumeInfo(string targetVolume)
	{
		// The MSFT_Volume class requires the volume name without the colon
		string targetVolumeVer2 = targetVolume.Replace(":", "", StringComparison.OrdinalIgnoreCase);

		// Create a new instance of the BitLockerVolume class
		BitLockerVolume newInstance = new();

		// Get the information about the volume using Win32_EncryptableVolume class
		// This is used a lot as the main input object to get information from other classes
		ManagementBaseObject? volume = GetCimInstance("Root\\CIMV2\\Security\\MicrosoftVolumeEncryption", "Win32_EncryptableVolume", $"DriveLetter = '{targetVolume}'");

		// Make sure there is data
		if (volume is not null)
		{
			// Set the MountPoint property of the final object to the drive letter
			newInstance.MountPoint = volume["DriveLetter"]?.ToString();

			try
			{
				// Set the ProtectionStatus property if it exists
				newInstance.ProtectionStatus = (ProtectionStatus)Convert.ToUInt32(volume["ProtectionStatus"], CultureInfo.InvariantCulture);
			}
			catch { /* ignore */ }

			try
			{
				// Set the VolumeType property if it exists
				newInstance.VolumeType = (VolumeType)Convert.ToUInt32(volume["VolumeType"], CultureInfo.InvariantCulture);
			}
			catch { /* ignore */ }

			try
			{
				// Try to use the GetLockStatus method to get the CurrentLockStatus
				ManagementBaseObject currentLockStatus = InvokeCimMethod(volume, "GetLockStatus", null);
				if (currentLockStatus is not null && Convert.ToUInt32(currentLockStatus["ReturnValue"], CultureInfo.InvariantCulture) == 0)
				{
					// Set the LockStatus property if it exists
					newInstance.LockStatus = (LockStatus)Convert.ToUInt32(currentLockStatus["LockStatus"], CultureInfo.InvariantCulture);
				}
			}
			catch { /* ignore */ }

			try
			{
				ManagementBaseObject currentVolConversionStatus = InvokeCimMethod(volume, "GetConversionStatus", null);
				if (currentVolConversionStatus is not null && Convert.ToUInt32(currentVolConversionStatus["ReturnValue"], CultureInfo.InvariantCulture) == 0)
				{
					newInstance.EncryptionPercentage = currentVolConversionStatus["EncryptionPercentage"]?.ToString();
					newInstance.WipePercentage = currentVolConversionStatus["WipingPercentage"]?.ToString();
					newInstance.ConversionStatus = (ConversionStatus)Convert.ToUInt32(currentVolConversionStatus["ConversionStatus"], CultureInfo.InvariantCulture);
					newInstance.WipingStatus = (WipingStatus)Convert.ToUInt32(currentVolConversionStatus["WipingStatus"], CultureInfo.InvariantCulture);
				}
			}
			catch { /* ignore */ }

			try
			{
				// Try to use the GetEncryptionMethod method to get the EncryptionMethod and EncryptionMethodFlags properties
				ManagementBaseObject? currentEncryptionMethod = InvokeCimMethod(volume, "GetEncryptionMethod", null);
				if (currentEncryptionMethod is not null && Convert.ToUInt32(currentEncryptionMethod["ReturnValue"], CultureInfo.InvariantCulture) == 0)
				{
					uint EncryptionMethodNum = Convert.ToUInt32(currentEncryptionMethod["EncryptionMethod"], CultureInfo.InvariantCulture);

					// Cast the uint to the EncryptionMethod enum
					newInstance.EncryptionMethod = (EncryptionMethod)EncryptionMethodNum;

					newInstance.EncryptionMethodFlags = currentEncryptionMethod["EncryptionMethodFlags"]?.ToString();
				}
			}
			catch { /* ignore */ }

			try
			{
				// Use the GetVersion method
				ManagementBaseObject currentVolVersion = InvokeCimMethod(volume, "GetVersion", null);
				if (currentVolVersion is not null && Convert.ToUInt32(currentVolVersion["ReturnValue"], CultureInfo.InvariantCulture) == 0)
				{
					newInstance.MetadataVersion = Convert.ToUInt32(currentVolVersion["Version"], CultureInfo.InvariantCulture);
				}
			}
			catch { /* ignore */ }

			try
			{
				// Use the GetKeyProtectors method
				ManagementBaseObject keyProtectors = InvokeCimMethod(volume, "GetKeyProtectors", null);

				// If there are any key protectors
				if (keyProtectors is not null)
				{
					// Create a new list of KeyProtector objects to store the results of processing each key protector in the loop below
					newInstance.KeyProtector = [];

					// Iterate through all of the key protectors' IDs
					foreach (string keyProtectorID in (string[])keyProtectors["VolumeKeyProtectorID"])
					{
						// Set them all to null initially so we don't accidentally use them for the wrong key protector type
						KeyProtectorType? type = null;
						string? recoveryPassword = null;
						bool autoUnlockProtector = false;
						string? keyProtectorFileName = null;
						string? keyProtectorThumbprint = null;
						string? keyProtectorCertificateType = null;

						try
						{
							// Use the GetKeyProtectorType method
							ManagementBaseObject keyProtectorTypeResult = InvokeCimMethod(volume, "GetKeyProtectorType", new Dictionary<string, object> { { "VolumeKeyProtectorID", keyProtectorID } });
							if (keyProtectorTypeResult is not null)
							{
								uint keyProtectorType = Convert.ToUInt32(keyProtectorTypeResult["KeyProtectorType"], CultureInfo.InvariantCulture);
								// Cast the uint value to the KeyProtectorType enum
								type = (KeyProtectorType)keyProtectorType;

								// if the current key protector is RecoveryPassword / Numerical password
								if (keyProtectorType == 3)
								{
									ManagementBaseObject numericalPassword = InvokeCimMethod(volume, "GetKeyProtectorNumericalPassword", new Dictionary<string, object> { { "VolumeKeyProtectorID", keyProtectorID } });
									if (numericalPassword is not null && Convert.ToUInt32(numericalPassword["ReturnValue"], CultureInfo.InvariantCulture) == 0)
									{
										recoveryPassword = numericalPassword["NumericalPassword"]?.ToString();
									}
								}

								// if the current key protector is ExternalKey
								if (keyProtectorType == 2)
								{
									ManagementBaseObject autoUnlockEnabledResult = InvokeCimMethod(volume, "IsAutoUnlockEnabled", null);
									if (autoUnlockEnabledResult is not null && Convert.ToUInt32(autoUnlockEnabledResult["ReturnValue"], CultureInfo.InvariantCulture) == 0)
									{
										bool isAutoUnlockEnabled = Convert.ToBoolean(autoUnlockEnabledResult["IsAutoUnlockEnabled"], CultureInfo.InvariantCulture);
										string? volumeKeyProtectorID = autoUnlockEnabledResult["VolumeKeyProtectorID"]?.ToString();

										if (isAutoUnlockEnabled && string.Equals(volumeKeyProtectorID, keyProtectorID, StringComparison.Ordinal))
										{
											autoUnlockProtector = true;
										}
									}

									ManagementBaseObject keyProtectorFileNameResult = InvokeCimMethod(volume, "GetExternalKeyFileName", new Dictionary<string, object> { { "VolumeKeyProtectorID", keyProtectorID } });
									if (keyProtectorFileNameResult is not null && Convert.ToUInt32(keyProtectorFileNameResult["ReturnValue"], CultureInfo.InvariantCulture) == 0)
									{
										keyProtectorFileName = keyProtectorFileNameResult["FileName"]?.ToString();
									}
								}

								// if the current key protector is PublicKey or TpmNetworkKey
								if (keyProtectorType is 7 or 9)
								{
									ManagementBaseObject keyProtectorCertificateResult = InvokeCimMethod(volume, "GetKeyProtectorCertificate", new Dictionary<string, object> { { "VolumeKeyProtectorID", keyProtectorID } });
									if (keyProtectorCertificateResult is not null && Convert.ToUInt32(keyProtectorCertificateResult["ReturnValue"], CultureInfo.InvariantCulture) == 0)
									{
										keyProtectorThumbprint = keyProtectorCertificateResult["CertThumbprint"]?.ToString();
										keyProtectorCertificateType = keyProtectorCertificateResult["CertType"]?.ToString();
									}
								}

								// Create a new KeyProtector class instance and add it to the KeyProtector property of the output object as an array member
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
						}
						catch { /* ignore */ }
					}
				}
			}
			catch { /* ignore */ }
		}

		// Get volume information using the MSFT_Volume class
		ManagementBaseObject? currentStorage = GetCimInstance("Root\\Microsoft\\Windows\\Storage", "MSFT_Volume", $"DriveLetter = '{targetVolumeVer2}'");
		if (currentStorage is not null)
		{
			try
			{
				newInstance.CapacityGB = Math.Round(Convert.ToDouble(currentStorage["Size"], CultureInfo.InvariantCulture) / (1024 * 1024 * 1024), 4).ToString(CultureInfo.InvariantCulture);
			}
			catch { /* ignore */ }

			try
			{
				newInstance.FileSystemType = (FileSystemType)Convert.ToUInt16(currentStorage["FileSystemType"], CultureInfo.InvariantCulture);
			}
			catch { /* ignore */ }

			try
			{
				newInstance.FriendlyName = currentStorage["FileSystemLabel"]?.ToString();
			}
			catch { /* ignore */ }

			try
			{
				newInstance.AllocationUnitSize = currentStorage["AllocationUnitSize"]?.ToString();
			}
			catch { /* ignore */ }

			try
			{
				newInstance.ReFSDedupMode = (ReFSDedupMode)Convert.ToUInt32(currentStorage["ReFSDedupMode"], CultureInfo.InvariantCulture);
			}
			catch { /* ignore */ }
		}

		return newInstance;
	}


	// Helper method to get the information from the WMI classes
	private static ManagementBaseObject? GetCimInstance(string @namespace, string className, string filter)
	{
		SelectQuery query = new(className, filter);
		using ManagementObjectSearcher searcher = new(@namespace, query.QueryString);

		return searcher.Get().Cast<ManagementBaseObject>().FirstOrDefault();
	}

	// Helper method to invoke a method on a WMI class
	private static ManagementBaseObject InvokeCimMethod(ManagementBaseObject instance, string methodName, Dictionary<string, object>? parameters)
	{
		using ManagementClass managementClass = new(instance.ClassPath);

		ManagementBaseObject inParams = managementClass.GetMethodParameters(methodName);
		if (parameters is not null)
		{
			foreach (KeyValuePair<string, object> param in parameters)
			{
				inParams[param.Key] = param.Value;
			}
		}
		return ((ManagementObject)instance).InvokeMethod(methodName, inParams, null);
	}

	// Method to get the drive letters of all volumes on the system, encrypted or not
	internal static string[] GetAllDriveLetters()
	{
		List<string> driveLetters = [];

		ManagementObjectCollection storages = GetCimInstances("Root\\Microsoft\\Windows\\Storage", "MSFT_Volume", string.Empty);

		foreach (ManagementBaseObject storage in storages)
		{
			// Iterate through the properties of the storage object
			foreach (PropertyData property in storage.Properties)
			{
				if (string.Equals(property.Name, "DriveLetter", StringComparison.OrdinalIgnoreCase) && property.Value is not null)
				{
					driveLetters.Add(property.Value?.ToString() ?? string.Empty);
				}
			}
		}

		return [.. driveLetters];
	}


	private static ManagementObjectCollection GetCimInstances(string namespacePath, string className, string filter)
	{
		ManagementScope scope = new(namespacePath);
		string queryString = string.IsNullOrEmpty(filter) ? $"SELECT * FROM {className}" : $"SELECT * FROM {className} WHERE {filter}";
		ObjectQuery query = new(queryString);

		// Declare the collection to return
		ManagementObjectCollection result;

		using (ManagementObjectSearcher searcher = new(scope, query))
		{
			// Get the collection from the searcher
			result = searcher.Get();
		}

		return result;
	}


	/// <summary>
	/// Gets the BitLocker info of all of the volumes on the system
	/// </summary>
	/// <param name="OnlyRemovableDrives">Will only return Removable Drives</param>
	/// <param name="OnlyNonOSDrives">Will only return Non-OSDrives, excluding Removable Drives</param>
	/// <returns></returns>
	internal static List<BitLockerVolume> GetAllEncryptedVolumeInfo(bool OnlyNonOSDrives, bool OnlyRemovableDrives)
	{
		// Create a new list of BitLockerVolume objects
		List<BitLockerVolume> volumes = [];

		// Call the GetAllDriveLetters method to get all of the drive letters
		string[] driveLetters = GetAllDriveLetters();

		// Iterate through all of the drive letters
		foreach (string driveLetter in driveLetters)
		{
			// the method requires the drive letter with the colon
			BitLockerVolume volume = GetEncryptedVolumeInfo(driveLetter + ":");

			// If only Non-OS Drives are requested, skip any other drive types
			if (OnlyNonOSDrives && volume.VolumeType is not VolumeType.FixedDisk)
			{
				continue;
			}

			// If only Removable Drives are requested, skip any other drive types
			if (OnlyRemovableDrives && volume.VolumeType is not VolumeType.Removable)
			{
				continue;
			}

			volumes.Add(volume);
		}

		return volumes;
	}
}
