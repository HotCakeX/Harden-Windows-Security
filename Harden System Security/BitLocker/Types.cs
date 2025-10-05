// MIT License
//
// Copyright (c) 2023-Present - Violet Hansen - (aka HotCakeX on GitHub) - Email Address: spynetgirl@outlook.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// See here for more information: https://github.com/HotCakeX/Harden-Windows-Security/blob/main/LICENSE
//

using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace HardenSystemSecurity.BitLocker;

/// <summary>
/// Class that stores the information about each key protector
/// </summary>
/// <param name="type">Type of the key protector.</param>
/// <param name="id">The unique ID of the key protector.</param>
/// <param name="autoUnlockProtector">Whether this key protector is the auto-unlock protector.</param>
/// <param name="keyFileName">External key file name (if applicable).</param>
/// <param name="recoveryPassword">Recovery password when the protector type is RecoveryPassword.</param>
/// <param name="keyCertificateType">Certificate type for certificate-based protectors.</param>
/// <param name="thumbprint">Certificate thumbprint, if available.</param>
internal sealed class KeyProtector(
	KeyProtectorType? type,
	string id,
	bool autoUnlockProtector,
	string keyFileName,
	string recoveryPassword,
	string keyCertificateType,
	string thumbprint
)
{
	[JsonInclude]
	internal KeyProtectorType? Type => type;

	[JsonInclude]
	internal string ID => id;

	[JsonInclude]
	internal bool AutoUnlockProtector => autoUnlockProtector;

	[JsonInclude]
	internal string KeyFileName => keyFileName;

	[JsonInclude]
	internal string RecoveryPassword => recoveryPassword;

	[JsonInclude]
	internal string KeyCertificateType => keyCertificateType;

	[JsonInclude]
	internal string Thumbprint => thumbprint;
}

/// <summary>
/// Class that stores the information about each BitLocker protected volume.
/// </summary>
/// <param name="mountPoint">Volume mount point (e.g. C:).</param>
/// <param name="encryptionMethod">BitLocker encryption method.</param>
/// <param name="encryptionMethodFlags">Additional encryption method flags.</param>
/// <param name="autoUnlockEnabled">Indicates whether auto-unlock is enabled.</param>
/// <param name="autoUnlockKeyStored">Indicates whether an auto-unlock key is stored.</param>
/// <param name="metadataVersion">BitLocker metadata version.</param>
/// <param name="conversionStatus">Conversion status of the volume.</param>
/// <param name="protectionStatus">Protection status.</param>
/// <param name="lockStatus">Current lock status.</param>
/// <param name="encryptionPercentage">Encryption completion percentage as string.</param>
/// <param name="wipePercentage">Free space wipe progress percentage as string.</param>
/// <param name="wipingStatus">Wiping status enumeration.</param>
/// <param name="volumeType">Volume type.</param>
/// <param name="capacityGB">Capacity in gigabytes.</param>
/// <param name="fileSystemType">File system type enumeration.</param>
/// <param name="friendlyName">Volume label / friendly name.</param>
/// <param name="allocationUnitSize">Allocation unit size in bytes.</param>
/// <param name="reFSDedupMode">ReFS deduplication mode if applicable.</param>
/// <param name="keyProtectors">Collection of key protectors for the volume.</param>
internal sealed class BitLockerVolume(
	string mountPoint,
	EncryptionMethod encryptionMethod,
	string encryptionMethodFlags,
	bool autoUnlockEnabled,
	bool autoUnlockKeyStored,
	uint metadataVersion,
	ConversionStatus conversionStatus,
	ProtectionStatus protectionStatus,
	LockStatus lockStatus,
	string encryptionPercentage,
	string wipePercentage,
	WipingStatus wipingStatus,
	VolumeType volumeType,
	string capacityGB,
	FileSystemType fileSystemType,
	string friendlyName,
	string allocationUnitSize,
	ReFSDedupMode reFSDedupMode,
	List<KeyProtector> keyProtectors
)
{
	[JsonInclude]
	internal string MountPoint => mountPoint;

	[JsonInclude]
	internal EncryptionMethod EncryptionMethod => encryptionMethod;

	[JsonInclude]
	internal string EncryptionMethodFlags => encryptionMethodFlags;

	[JsonInclude]
	internal bool AutoUnlockEnabled => autoUnlockEnabled;

	[JsonInclude]
	internal bool AutoUnlockKeyStored => autoUnlockKeyStored;

	/// <summary>
	/// https://learn.microsoft.com/windows/win32/secprov/getversion-win32-encryptablevolume#parameters
	/// </summary>
	[JsonInclude]
	internal uint MetadataVersion => metadataVersion;

	[JsonInclude]
	internal ConversionStatus ConversionStatus => conversionStatus;

	[JsonInclude]
	internal ProtectionStatus ProtectionStatus => protectionStatus;

	[JsonInclude]
	internal LockStatus LockStatus => lockStatus;

	[JsonInclude]
	internal string EncryptionPercentage => encryptionPercentage;

	[JsonInclude]
	internal string WipePercentage => wipePercentage;

	[JsonInclude]
	internal WipingStatus WipingStatus => wipingStatus;

	[JsonInclude]
	internal VolumeType VolumeType => volumeType;

	[JsonInclude]
	internal string CapacityGB => capacityGB;

	[JsonInclude]
	internal FileSystemType FileSystemType => fileSystemType;

	[JsonInclude]
	internal string FriendlyName => friendlyName;

	[JsonInclude]
	internal string AllocationUnitSize => allocationUnitSize;

	[JsonInclude]
	internal ReFSDedupMode ReFSDedupMode => reFSDedupMode;

	[JsonInclude]
	internal List<KeyProtector> KeyProtectors => keyProtectors;
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
	AdAccountOrGroup = 10,
	AutoUnlock = 11 // Added by me, not available in the official headers.
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

/// <summary>
/// Source-generated JSON context for deserializing BitLocker info from ComManager.
/// </summary>
[JsonSourceGenerationOptions(
	PropertyNameCaseInsensitive = true,
	// Enums values will be written as string instead of numbers during serialization.
	// For Deserialization, both strings and numbers are supported for parsing enum values.
	Converters =
	[
		typeof(JsonStringEnumConverter<KeyProtectorType>),
		typeof(JsonStringEnumConverter<EncryptionMethod>),
		typeof(JsonStringEnumConverter<ProtectionStatus>),
		typeof(JsonStringEnumConverter<LockStatus>),
		typeof(JsonStringEnumConverter<ConversionStatus>),
		typeof(JsonStringEnumConverter<WipingStatus>),
		typeof(JsonStringEnumConverter<VolumeType>),
		typeof(JsonStringEnumConverter<FileSystemType>),
		typeof(JsonStringEnumConverter<ReFSDedupMode>)
	],
	WriteIndented = true)]
[JsonSerializable(typeof(BitLockerVolume[]))]
internal sealed partial class BitLockerJsonContext : JsonSerializerContext
{
}
