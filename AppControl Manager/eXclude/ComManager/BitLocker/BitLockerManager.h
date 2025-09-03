#pragma once
#include <windows.h>
#include <Wbemidl.h>
#include <string>
#include <vector>

using namespace std;

namespace BitLocker {

	// BitLocker WMI namespace/class constants
	inline constexpr const wchar_t* WmiNamespace = L"root\\cimv2\\Security\\MicrosoftVolumeEncryption";
	inline constexpr const wchar_t* ClassName = L"Win32_EncryptableVolume";
	inline constexpr const wchar_t* StorageNamespace = L"root\\microsoft\\windows\\storage";

	// Forward declaration for types referenced before full definitions.
	struct VolumeInfo;

	// Provides: ok flag, pSvc / pLoc pointers, automatic cleanup, and optional COM uninit.
	struct WmiConnection
	{
		IWbemLocator* pLoc = nullptr;
		IWbemServices* pSvc = nullptr;
		bool didInitCOM = false;
		bool ok = false;

		WmiConnection();
		~WmiConnection();
	};

	// Each function returns true on success and false on failure.
	//
	// Drive letters must be in the form L"C:" (no trailing backslash).
	[[nodiscard]] bool AddPasswordProtector(const wchar_t* driveLetter, const wchar_t* passPhrase);
	[[nodiscard]] bool AddRecoveryPassword(const wchar_t* driveLetter, const wchar_t* numericalPassword /* can be nullptr or empty to let system generate */);
	[[nodiscard]] bool AddTpmProtector(const wchar_t* driveLetter);
	[[nodiscard]] bool AddTpmAndPinProtector(const wchar_t* driveLetter, const wchar_t* pin);
	[[nodiscard]] bool AddTpmAndStartupKeyProtector(const wchar_t* driveLetter, const wchar_t* startupKeyPath);
	[[nodiscard]] bool AddTpmAndPinAndStartupKeyProtector(const wchar_t* driveLetter, const wchar_t* startupKeyPath, const wchar_t* pin);
	[[nodiscard]] bool AddStartupKeyProtector_OR_RecoveryKeyProtector(const wchar_t* driveLetter, const wchar_t* startupKeyPath);
	[[nodiscard]] bool AddSidProtector(const wchar_t* driveLetter, const wchar_t* sid, bool serviceAccount);
	[[nodiscard]] bool FindVolumeInstancePath(IWbemServices* pSvc, const wchar_t* driveLetter, wstring& outPath);
	IWbemClassObject* SpawnInParams(IWbemServices* pSvc, const wchar_t* methodName);
	bool SetParamBstr(IWbemClassObject* inParams, const wchar_t* name, const wchar_t* value);
	IWbemClassObject* ExecMethodSimple(IWbemServices* svc, const wchar_t* instancePath, const wchar_t* method, IWbemClassObject* inParams);
	wstring FormatReturnCode(unsigned long code);
	wstring FormatReturnCode(HRESULT hr);
	void LogError(const wstring& msg);
	bool IsNullOrWhiteSpace(const wchar_t* s);
	bool HandleReturnValue(IWbemClassObject* pOutParams, const wstring& successMsg, const wstring& contextMsg = L"");
	bool SetParamNull(IWbemClassObject* inParams, const wchar_t* name);
	bool SetParamUint32(IWbemClassObject* inParams, const wchar_t* name, unsigned long val);
	bool GetProtectorId(IWbemClassObject* outParams, wstring& idOut);
	bool RemoveKeyProtectorsOfType(IWbemServices* pSvc, const wstring& instancePath, unsigned long keyProtectorType);
	bool GetInstancePath(const wchar_t* driveLetter, wstring& pathOut, WmiConnection& conn);
	bool ReadULong(IWbemClassObject* obj, const wchar_t* name, unsigned long& outVal);
	bool ReadBstr(IWbemClassObject* obj, const wchar_t* name, wstring& outStr);
	bool EnumerateAllDriveLetters(vector<wstring>& outLetters);
	void PopulateStorageInfo(const wchar_t* driveLetterNoColon, VolumeInfo& info);
	void FillKeyProtectors(IWbemServices* svc, const wstring& instancePath, VolumeInfo& info);

	// Different types of the key protectors
	// https://learn.microsoft.com/windows/win32/secprov/getkeyprotectortype-win32-encryptablevolume
	enum class KeyProtectorType : unsigned long
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
	};

	// https://learn.microsoft.com/windows/win32/secprov/getencryptionmethod-win32-encryptablevolume
	enum class EncryptionMethod : unsigned long
	{
		None = 0,
		AES_128_WITH_DIFFUSER = 1,
		AES_256_WITH_DIFFUSER = 2,
		AES_128 = 3,
		AES_256 = 4,
		HARDWARE_ENCRYPTION = 5,
		XTS_AES_128 = 6,
		XTS_AES_256 = 7
	};

	// https://learn.microsoft.com/windows/win32/secprov/getprotectionstatus-win32-encryptablevolume
	enum class ProtectionStatus : unsigned long
	{
		Unprotected = 0,
		Protected = 1,
		Unknown = 2
	};

	// https://learn.microsoft.com/windows/win32/secprov/getlockstatus-win32-encryptablevolume
	enum class LockStatus : unsigned long
	{
		Unlocked = 0,
		Locked = 1
	};

	// https://learn.microsoft.com/windows/win32/secprov/win32-encryptablevolume#properties
	enum class VolumeType : unsigned long
	{
		OperationSystem = 0,
		FixedDisk = 1,
		Removable = 2
	};

	// https://learn.microsoft.com/windows/win32/secprov/getconversionstatus-win32-encryptablevolume
	enum class ConversionStatus : unsigned long
	{
		FullyDecrypted = 0,
		FullyEncrypted = 1,
		EncryptionInProgress = 2,
		DecryptionInProgress = 3,
		EncryptionPaused = 4,
		DecryptionPaused = 5
	};

	// https://learn.microsoft.com/windows/win32/secprov/getconversionstatus-win32-encryptablevolume
	enum class WipingStatus : unsigned long
	{
		FreeSpaceNotWiped = 0,
		FreeSpaceWiped = 1,
		FreeSpaceWipingInProgress = 2,
		FreeSpaceWipingPaused = 3
	};

	// https://learn.microsoft.com/windows-hardware/drivers/storage/msft-volume#properties
	enum class FileSystemType : unsigned short
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
	};

	// https://learn.microsoft.com/windows-hardware/drivers/storage/msft-volume#properties
	enum class ReFSDedupMode : unsigned long
	{
		Disabled = 0,
		GeneralPurpose = 1,
		HyperV = 2,
		Backup = 3,
		NotAvailable = 4
	};

	// Stores the information about each key protector
	struct KeyProtectorInfo
	{
		KeyProtectorType type = KeyProtectorType::Unknown;
		wstring id;
		bool autoUnlockProtector = false;
		wstring keyFileName;
		wstring recoveryPassword;
		wstring keyCertificateType;
		wstring thumbprint;
	};

	// Stores the information about BitLocker protected volumes
	struct VolumeInfo
	{
		wstring mountPoint;                 // e.g. L"C:"
		EncryptionMethod encryptionMethod = EncryptionMethod::None;
		wstring encryptionMethodFlags;
		bool autoUnlockEnabled = false;          // (filled when an ExternalKey is auto-unlock protector)
		bool autoUnlockKeyStored = false;        // (best effort; not all paths populate this)
		unsigned long metadataVersion = 0; // https://learn.microsoft.com/windows/win32/secprov/getversion-win32-encryptablevolume#parameters
		ConversionStatus conversionStatus = ConversionStatus::FullyDecrypted;
		ProtectionStatus protectionStatus = ProtectionStatus::Unknown;
		LockStatus lockStatus = LockStatus::Unlocked;
		wstring encryptionPercentage;
		wstring wipePercentage;
		WipingStatus wipingStatus = WipingStatus::FreeSpaceNotWiped;
		VolumeType volumeType = VolumeType::FixedDisk;

		// Storage (MSFT_Volume)
		wstring capacityGB;
		FileSystemType fileSystemType = FileSystemType::Unknown;
		wstring friendlyName;
		wstring allocationUnitSize;
		ReFSDedupMode reFSDedupMode = ReFSDedupMode::NotAvailable;

		vector<KeyProtectorInfo> keyProtectors;
	};

	// Retrieve info for a single volume (driveLetter must be like L"C:")
	[[nodiscard]] bool GetVolumeInfo(const wchar_t* driveLetter, VolumeInfo& outInfo);

	// List all volumes (BitLocker + storage info). If onlyNonOS is true, returns only FixedDisk (non-OS) volumes.
	// If onlyRemovable is true, returns only Removable volumes. Both false -> all.
	[[nodiscard]] bool ListAllVolumes(vector<VolumeInfo>& outList, bool onlyNonOS, bool onlyRemovable);

	// print a single volume as JSON to stdout
	[[nodiscard]] bool PrintVolumeInfoJson(const VolumeInfo& info);

	// print list of volumes as JSON array
	[[nodiscard]] bool PrintVolumeListJson(const vector<VolumeInfo>& list);


	// TPM WMI namespace
	inline constexpr const wchar_t* TpmNamespace = L"root\\CIMV2\\Security\\MicrosoftTpm";

	// Performs the TPM readiness test
	// Returns true only if Win32_Tpm reports IsEnabled, IsOwned, IsActivated, and IsSrkAuthCompatible are all TRUE.
	// Optional out parameters can be nullptr.
	[[nodiscard]] bool IsTpmReady(bool* isEnabled = nullptr,
		bool* isOwned = nullptr,
		bool* isActivated = nullptr,
		bool* isSrkAuthCompatible = nullptr);

	// If not WinPE (MiniNT key absent) => true.
	// If WinPE => requires TPM IsEnabled && IsActivated.
	[[nodiscard]] bool IsSystemEntropyReady();

}