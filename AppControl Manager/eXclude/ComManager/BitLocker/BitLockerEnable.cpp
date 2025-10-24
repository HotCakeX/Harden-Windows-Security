#include "..\Globals.h"
#include "..\StringUtilities.h"
#include <Wbemidl.h>
#include <comdef.h>
#include <sstream>
#include <iostream>
#include <vector>
#include <algorithm>
#include "BitLockerManager.h"
#include "..\ComHelpers.h"
#include "BitLockerEnable.h"

using namespace std;

namespace BitLocker {

	static const wchar_t* ToString(EncryptionMethod m)
	{
		switch (m)
		{
		case EncryptionMethod::XTS_AES_256: return L"XTS_AES_256";
		case EncryptionMethod::XTS_AES_128: return L"XTS_AES_128";
		case EncryptionMethod::AES_256: return L"AES_256";
		case EncryptionMethod::AES_128: return L"AES_128";
		default: return L"Other";
		}
	}
	static const wchar_t* ToString(ConversionStatus s)
	{
		switch (s)
		{
		case ConversionStatus::FullyEncrypted: return L"FullyEncrypted";
		case ConversionStatus::FullyDecrypted: return L"FullyDecrypted";
		case ConversionStatus::EncryptionInProgress: return L"EncryptionInProgress";
		case ConversionStatus::DecryptionInProgress: return L"DecryptionInProgress";
		case ConversionStatus::EncryptionPaused: return L"EncryptionPaused";
		case ConversionStatus::DecryptionPaused: return L"DecryptionPaused";
		default: return L"Unknown";
		}
	}
	static const wchar_t* ToString(OSEncryptionType t)
	{
		return (t == OSEncryptionType::Normal) ? L"Normal" : L"Enhanced";
	}

	// Generic volume method invoker
	static bool InvokeVolumeMethod(IWbemServices* svc,
		const wstring& instancePath,
		const wchar_t* methodName,
		const vector<pair<const wchar_t*, unsigned long>>& uintParams,
		const vector<pair<const wchar_t*, const wchar_t*>>& bstrParams,
		unsigned long& outCode,
		const vector<unsigned long>& allowedExtraSuccessCodes = {},
		const wstring& successMsg = L"")
	{
		outCode = static_cast<unsigned long>(-1);

		IWbemClassObject* pIn = SpawnInParams(svc, methodName);
		if (!pIn)
		{
			wstringstream ss;
			ss << L"Failed to prepare parameters for " << methodName << L".";
			SetLastErrorMsg(ss.str());
			return false;
		}

		for (auto& up : uintParams)
		{
			if (!SetParamUint32(pIn, up.first, up.second))
			{
				pIn->Release();
				wstringstream ss;
				ss << L"Failed to set UINT32 parameter " << up.first << L" for " << methodName;
				SetLastErrorMsg(ss.str());
				return false;
			}
		}
		for (auto& bp : bstrParams)
		{
			if (!SetParamBstr(pIn, bp.first, bp.second))
			{
				pIn->Release();
				wstringstream ss;
				ss << L"Failed to set BSTR parameter " << bp.first << L" for " << methodName;
				SetLastErrorMsg(ss.str());
				return false;
			}
		}

		IWbemClassObject* pOut = ExecMethodSimple(svc, instancePath.c_str(), methodName, pIn);
		pIn->Release();
		if (!pOut)
		{
			wstringstream ss;
			ss << L"ExecMethod " << methodName << L" failed.";
			SetLastErrorMsg(ss.str());
			return false;
		}

		// reading ReturnValue from method invocation result
		VARIANT vRet; VariantInit(&vRet);
		if (FAILED(pOut->Get(_bstr_t(L"ReturnValue"), 0, &vRet, nullptr, nullptr)))
		{
			VariantClear(&vRet);
			pOut->Release();
			wstringstream ss;
			ss << methodName << L" did not return ReturnValue.";
			SetLastErrorMsg(ss.str());
			return false;
		}

		if (vRet.vt == VT_I4) outCode = static_cast<unsigned long>(vRet.lVal);
		else if (vRet.vt == VT_UI4) outCode = vRet.ulVal;
		VariantClear(&vRet);
		pOut->Release();

		// treat 0 as success and whitelist extra values (like FVE_E_NOT_DECRYPTED for PrepareVolume)
		if (outCode == 0 ||
			(find(allowedExtraSuccessCodes.begin(), allowedExtraSuccessCodes.end(), outCode) != allowedExtraSuccessCodes.end()))
		{
			if (!successMsg.empty())
				LogOut(successMsg.c_str());
			return true;
		}

		// on non-zero non-whitelisted, log & abort
		wstringstream ss;
		ss << methodName << L" failed " << FormatReturnCode(outCode);
		SetLastErrorMsg(ss.str());
		LogErr(ss.str().c_str());
		return false;
	}

	// PrepareVolume invocation + ReturnValue evaluation (special-case FVE_E_NOT_DECRYPTED 2150694969)
	static bool PrepareVolume(IWbemServices* svc, const wstring& instancePath, bool usedSpaceOnly)
	{
		unsigned long rv = 0;
		const unsigned long initializationFlags = usedSpaceOnly ? 256u : 0u; // 256 = FVE_PROVISIONING_MODIFIER_USED_SPACE
		return InvokeVolumeMethod(svc, instancePath, L"PrepareVolumeEx",
			{
				{L"InitializationFlags", initializationFlags}
			},
			{
				{L"DiscoveryVolumeType", L"<default>"}
			},
			rv,
			{ 2150694969UL }, // FVE_E_NOT_DECRYPTED treated as already prepared; proceed
			rv == 0 ? (wstring(L"Successfully prepared the drive for encryption.")) :
			(rv == 2150694969UL ? wstring(L"The volume has already been prepared, continuing...") : wstring()));
	}

	// Encrypt method
	static bool EncryptVolume(IWbemServices* svc, const wstring& instancePath, bool freePlusUsedSpace)
	{
		unsigned long rv = 0;
		return InvokeVolumeMethod(svc, instancePath, L"Encrypt",
			{
				{L"EncryptionMethod", 7},                           // XTS-AES-256
				{L"EncryptionFlags", freePlusUsedSpace ? 0u : 1u}    // 0 = Used + Free, 1 = Used only
			},
			{},
			rv,
			{},
			L"Successfully Encrypted the drive.");
	}

	// Enables BitLocker encryption for the OS Drive,
	// Note: Password Protector cannot/should not be used for OS the drive. Secure TPM-Based key protectors should be used for the OS drive.
	// https://learn.microsoft.com/windows/win32/secprov/preparevolume-win32-encryptablevolume
	// 1) Full Space (instead of Used-space only)
	// 2) Skip hardware test
	// 3) Unspecified encryption between hardware/software
	// 4) Encryption Method = XTS-AES-256
	// DriveLetter: must be in the form L"C:" (no trailing backslash).
	// OSEncryptionType: Normal or Enhanced
	// PIN: required for both Normal and Enhanced levels. Startup PIN
	// StartupKeyPath: For Enhanced level only. Folder path where the startup key file will be saved to.
	// FreePlusUsedSpace: if true, both used and free space will be encrypted
	// AllowDowngradeEnhancedToNormal: If true, if OS Drive is encrypted with Enhanced level, it will downgrade to Normal if Normal is the selected OSEncryptionType.
	bool EnableOsDrive(const wchar_t* driveLetter,
		OSEncryptionType type,
		const wchar_t* pin,
		const wchar_t* startupKeyPath,
		bool freePlusUsedSpace,
		bool allowDowngradeEnhancedToNormal)
	{
		ClearLastErrorMsg();

		if (!driveLetter || wcslen(driveLetter) != 2 || driveLetter[1] != L':')
		{
			SetLastErrorMsg(L"DriveLetter must be in the form L\"C:\"");
			return false;
		}

		VolumeInfo vol;
		if (!GetVolumeInfo(driveLetter, vol))
			return false;

		// Validate encryption method & key protectors
		if (vol.conversionStatus == ConversionStatus::FullyEncrypted)
		{
			LogOut(L"The OS drive is fully encrypted, will check if it conforms to the selected ", ToString(type), L" level.");

			if (vol.encryptionMethod != EncryptionMethod::XTS_AES_256)
			{
				LogOut(L"The OS drive is encrypted but with ", ToString(vol.encryptionMethod),
					L" instead of the more secure XTS_AES_256. This is an informational notice.");
			}

			if (vol.keyProtectors.empty())
			{
				LogErr(L"The OS drive is encrypted but it has no key protectors");
				SetLastErrorMsg(L"OS drive has no key protectors.");
				return false;
			}

			bool hasRecovery = false;
			bool hasTpmPin = false;
			bool hasTpmPinStartupKey = false;

			for (const auto& kp : vol.keyProtectors)
			{
				if (kp.type == KeyProtectorType::RecoveryPassword) hasRecovery = true;
				else if (kp.type == KeyProtectorType::TpmPin) hasTpmPin = true;
				else if (kp.type == KeyProtectorType::TpmPinStartupKey) hasTpmPinStartupKey = true;
			}

			// Normal security path
			if (type == OSEncryptionType::Normal)
			{
				if (hasRecovery && hasTpmPin)
				{
					LogOut(L"The OS Drive is already fully encrypted with Normal Security level.");
					return true;
				}

				// Add RecoveryPassword if missing
				if (!hasRecovery)
				{
					LogOut(L"OS drive is encrypted, selected encryption is Normal but there is no RecoveryPassword key protector, adding it now.");
					if (!AddRecoveryPassword(driveLetter, nullptr)) return false;
				}

				// Detect Enhanced (TpmPinStartupKey) when Normal requested; conditionally downgrade
				if (hasTpmPinStartupKey)
				{
					LogOut(L"For OS Drive encryption, Normal level was selected by the user but Enhanced level already detected.");
					if (!allowDowngradeEnhancedToNormal)
					{
						LogOut(L"Skipping changing Enhanced to Normal encryption level for the OS Drive.");
						return true;
					}
					else
					{
						LogOut(L"Downgrading Enhanced to Normal encryption level for the OS Drive.");
					}
				}

				// Add TpmPin if missing (requires PIN input)
				if (!hasTpmPin)
				{
					if (!pin || *pin == L'\0')
					{
						LogErr(L"No PIN was specified for the NormalSecurity Level, exiting");
						SetLastErrorMsg(L"PIN missing for Normal level.");
						return false;
					}
					LogOut(L"OS drive is encrypted, selected encryption is Normal but there is no TpmPin key protector, adding it now.");
					if (!AddTpmAndPinProtector(driveLetter, pin)) return false;
				}
			}
			else
			{
				// Enhanced security path
				if (hasRecovery && hasTpmPinStartupKey)
				{
					LogOut(L"The OS Drive is already fully encrypted with Enhanced Security level.");
					return true;
				}

				// Add RecoveryPassword if missing
				if (!hasRecovery)
				{
					LogOut(L"OS drive is encrypted, selected encryption is Enhanced but there is no RecoveryPassword key protector, adding it now.");
					if (!AddRecoveryPassword(driveLetter, nullptr)) return false;
				}

				// Add TpmPinStartupKey if missing (requires PIN + StartupKeyPath)
				if (!hasTpmPinStartupKey)
				{
					if (!pin || *pin == L'\0' || !startupKeyPath || *startupKeyPath == L'\0')
					{
						LogErr(L"No PIN or Startup Key was specified for the Enhanced Security Level, exiting");
						SetLastErrorMsg(L"PIN or StartupKey missing for Enhanced level.");
						return false;
					}
					LogOut(L"OS drive is encrypted, selected encryption is Enhanced but there is no TpmPinStartupKey key protector, adding it now.");
					if (!AddTpmAndPinAndStartupKeyProtector(driveLetter, startupKeyPath, pin)) return false;
				}
			}
			return true;
		}
		// Perform full initial enablement
		else if (vol.conversionStatus == ConversionStatus::FullyDecrypted)
		{

			// If not in WinPE (MiniNT key absent) it returns true.
			// If in WinPE, requires TPM IsEnabled && IsActivated.
			if (!IsSystemEntropyReady())
			{
				wstringstream ss;
				ss << L"System entropy (TPM readiness) check failed " << FormatReturnCode(TPM_E_DEACTIVATED)
					<< L" (TPM not enabled/activated in this environment).";
				LogErr(ss.str().c_str());
				SetLastErrorMsg(ss.str());
				return false;
			}

			WmiConnection conn;
			if (!conn.ok)
			{
				SetLastErrorMsg(L"Failed to connect to BitLocker WMI namespace.");
				return false;
			}
			wstring instancePath;
			if (!FindVolumeInstancePath(conn.pSvc, driveLetter, instancePath))
			{
				SetLastErrorMsg(L"Failed to locate the BitLocker volume instance path.");
				return false;
			}

			// PrepareVolume (idempotent; treat FVE_E_NOT_DECRYPTED as already-prepared)
			if (!PrepareVolume(conn.pSvc, instancePath, !freePlusUsedSpace))
				return false;

			// Add TPM-based + Recovery protectors depending on selected security level
			if (type == OSEncryptionType::Normal)
			{
				if (!pin || *pin == L'\0')
				{
					LogErr(L"No PIN was specified for the NormalSecurity Level, exiting");
					SetLastErrorMsg(L"PIN missing for Normal level.");
					return false;
				}
				if (!AddTpmAndPinProtector(driveLetter, pin)) return false;
				if (!AddRecoveryPassword(driveLetter, nullptr)) return false;
			}
			else
			{
				if (!pin || *pin == L'\0' || !startupKeyPath || *startupKeyPath == L'\0')
				{
					LogErr(L"No PIN or Startup Key was specified for the Enhanced Security Level, exiting");
					SetLastErrorMsg(L"PIN or StartupKey missing for Enhanced level.");
					return false;
				}
				if (!AddTpmAndPinAndStartupKeyProtector(driveLetter, startupKeyPath, pin)) return false;
				if (!AddRecoveryPassword(driveLetter, nullptr)) return false;
			}

			if (!FindVolumeInstancePath(conn.pSvc, driveLetter, instancePath))
			{
				SetLastErrorMsg(L"Failed to re-acquire the BitLocker volume instance path prior to Encrypt.");
				return false;
			}

			// Encrypt
			if (!EncryptVolume(conn.pSvc, instancePath, freePlusUsedSpace))
				return false;

			// EnableKeyProtectors
			if (!EnableKeyProtectors(driveLetter)) return false;

			return true;
		}
		else
		{
			LogErr(L"For full disk encryption, the drive's conversion status must be FullyDecrypted, "
				"The OS drive is fully encrypted, will check if it conforms to the selected ",
				ToString(vol.conversionStatus),
				L" at the moment.");
			SetLastErrorMsg(L"Incompatible OS drive conversion status.");
			return false;
		}
	}

	// Enables BitLocker encryption for Fixed drives (Non-OS drives)
	// 1) Full Space (instead of Used-space only)
	// 2) Skip hardware test
	// 3) Unspecified encryption between hardware/software
	// 4) Encryption Method = XTS-AES-256
	// FreePlusUsedSpace: if true, both used and free space will be encrypted.
	bool EnableFixedDrive(const wchar_t* driveLetter,
		bool freePlusUsedSpace)
	{
		ClearLastErrorMsg();

		if (!driveLetter || wcslen(driveLetter) != 2 || driveLetter[1] != L':')
		{
			SetLastErrorMsg(L"DriveLetter must be in the form L\"C:\"");
			return false;
		}

		// Ensure OS drive is encrypted first
		vector<VolumeInfo> all;
		if (!ListAllVolumes(all, false, false))
			return false;

		bool osProtected = false;
		for (const auto& v : all)
		{
			if (v.volumeType == VolumeType::OperationSystem &&
				v.protectionStatus == ProtectionStatus::Protected)
			{
				osProtected = true;
				break;
			}
		}
		if (!osProtected)
		{
			LogErr(L"Operating System drive must be encrypted first before encrypting Non-OS drives.");
			SetLastErrorMsg(L"OS drive not protected.");
			return false;
		}

		// Acquire target volume info
		VolumeInfo vol;
		if (!GetVolumeInfo(driveLetter, vol))
			return false;

		// Already fully encrypted -> check required key protectors
		if (vol.conversionStatus == ConversionStatus::FullyEncrypted)
		{
			LogOut(L"The drive ", driveLetter, L" is fully encrypted, will check its key protectors.");

			// Encryption method (warn if not XTS_AES_256)
			if (vol.encryptionMethod != EncryptionMethod::XTS_AES_256)
			{
				LogOut(L"The drive ", driveLetter, L" is encrypted but with ",
					ToString(vol.encryptionMethod),
					L" instead of the more secure XTS_AES_256. This is an informational notice.");
			}

			// Error if no key protectors present
			if (vol.keyProtectors.empty())
			{
				LogErr(L"The drive ", driveLetter, L" is encrypted but it has no key protectors");
				SetLastErrorMsg(L"Drive has no key protectors.");
				return false;
			}

			// Discover presence of RecoveryPassword & ExternalKey protectors
			bool hasRecovery = false;
			bool hasExternal = false;
			for (const auto& kp : vol.keyProtectors)
			{
				if (kp.type == KeyProtectorType::RecoveryPassword) hasRecovery = true;
				if (kp.type == KeyProtectorType::ExternalKey) hasExternal = true;
			}

			// Already has both required protectors
			if (hasRecovery && hasExternal)
			{
				// Remove all ExternalKey protectors (best-effort) to flush stale/unbound ones
				for (const auto& kp : vol.keyProtectors)
				{
					if (kp.type == KeyProtectorType::ExternalKey && !kp.id.empty())
					{
						LogOut(L"Removing ExternalKey key protector with the ID ", kp.id.c_str(),
							L" for the drive ", driveLetter,
							L". Will set a new one bound to the OS drive in the next step.");
						(void)RemoveKeyProtector(driveLetter, kp.id.c_str(), true);
					}
				}

				// Refresh volume info after removals
				if (!GetVolumeInfo(driveLetter, vol))
					return false;

				hasExternal = false;
				size_t recoveryCount = 0;
				for (const auto& kp : vol.keyProtectors)
				{
					if (kp.type == KeyProtectorType::ExternalKey) hasExternal = true;
					if (kp.type == KeyProtectorType::RecoveryPassword) ++recoveryCount;
				}
				// If all ExternalKeys removed (none bound), add a new auto-unlock protector
				if (!hasExternal)
				{
					LogOut(L"Adding a new ExternalKey key protector for Auto-unlock to the drive ", driveLetter, L".");
					if (!EnableAutoUnlock(driveLetter)) return false;
				}
				// Informational: multiple recovery passwords present
				if (recoveryCount > 1)
				{
					LogOut(L"drive ", driveLetter, L" has ", recoveryCount,
						L" recovery password key protectors. Usually only one is enough.");
				}
				LogOut(L"The drive ", driveLetter, L" is fully encrypted with all the required key protectors.");
				return true;
			}

			// Add missing RecoveryPassword
			if (!hasRecovery)
			{
				LogOut(L"Drive ", driveLetter, L" is encrypted, but there is no RecoveryPassword key protector, adding it now.");
				if (!AddRecoveryPassword(driveLetter, nullptr)) return false;
			}

			// Add Missing ExternalKey (AutoUnlock) protector
			if (!hasExternal)
			{
				LogOut(L"Drive ", driveLetter, L" is encrypted, but there is no ExternalKey key protector for Auto-unlock, adding it now.");
				if (!EnableAutoUnlock(driveLetter)) return false;
			}
			return true;
		}
		// FullyDecrypted -> full initial enable sequence
		else if (vol.conversionStatus == ConversionStatus::FullyDecrypted)
		{
			WmiConnection conn;
			if (!conn.ok)
			{
				SetLastErrorMsg(L"Failed to connect to BitLocker WMI namespace.");
				return false;
			}
			wstring instancePath;
			if (!FindVolumeInstancePath(conn.pSvc, driveLetter, instancePath))
			{
				SetLastErrorMsg(L"Failed to locate the BitLocker volume instance path.");
				return false;
			}

			// PrepareVolume
			if (!PrepareVolume(conn.pSvc, instancePath, !freePlusUsedSpace))
				return false;

			// Add Recovery + ExternalKey (AutoUnlock) before encryption
			if (!AddRecoveryPassword(driveLetter, nullptr)) return false;
			if (!EnableAutoUnlock(driveLetter)) return false;

			if (!FindVolumeInstancePath(conn.pSvc, driveLetter, instancePath))
			{
				SetLastErrorMsg(L"Failed to re-acquire the BitLocker volume instance path prior to Encrypt.");
				return false;
			}

			// Encrypt (XTS AES-256, full vs used space)
			if (!EncryptVolume(conn.pSvc, instancePath, freePlusUsedSpace))
				return false;

			return true;
		}
		// Unsupported intermediate conversion states
		else
		{
			LogErr(L"For full disk encryption, the drive's conversion status must be FullyDecrypted, and for key protector check it must be FullyEncrypted, but it is ",
				ToString(vol.conversionStatus), L" at the moment.");
			SetLastErrorMsg(L"Incompatible drive conversion status.");
			return false;
		}
	}

	// Enables BitLocker encryption for Removable drives
	// 1) Full Space (instead of Used-space only)
	// 2) Skip hardware test
	// 3) Unspecified encryption between hardware/software
	// 4) Encryption Method = XTS-AES-256
	// </summary>
	// FreePlusUsedSpace: if true, both used and free space will be encrypted.
	bool EnableRemovableDrive(const wchar_t* driveLetter,
		const wchar_t* password,
		bool freePlusUsedSpace)
	{
		ClearLastErrorMsg();

		if (!driveLetter || wcslen(driveLetter) != 2 || driveLetter[1] != L':')
		{
			SetLastErrorMsg(L"DriveLetter must be in the form L\"C:\"");
			return false;
		}

		if (!password || *password == L'\0')
		{
			SetLastErrorMsg(L"No password supplied for removable drive encryption.");
			LogErr(L"No Password was specified for the Removable Drive Encryption, exiting");
			return false;
		}

		// Acquire current volume state
		VolumeInfo vol;
		if (!GetVolumeInfo(driveLetter, vol))
			return false;

		// Must be FullyDecrypted to proceed
		if (vol.conversionStatus != ConversionStatus::FullyDecrypted)
		{
			LogErr(L"In order to encrypt a volume with this method, its Conversion Status must be FullyDecrypted, but it is ",
				ToString(vol.conversionStatus), L" at the moment.");
			SetLastErrorMsg(L"Removable drive not FullyDecrypted.");
			return false;
		}

		// WMI connection and instance path resolution
		WmiConnection conn;
		if (!conn.ok)
		{
			SetLastErrorMsg(L"Failed to connect to BitLocker WMI namespace.");
			return false;
		}
		wstring instancePath;
		if (!FindVolumeInstancePath(conn.pSvc, driveLetter, instancePath))
		{
			SetLastErrorMsg(L"Failed to locate the BitLocker volume instance path.");
			return false;
		}

		// PrepareVolume
		if (!PrepareVolume(conn.pSvc, instancePath, !freePlusUsedSpace))
			return false;

		// Add password protector + recovery password prior to encryption
		if (!AddPasswordProtector(driveLetter, password)) return false;
		if (!AddRecoveryPassword(driveLetter, nullptr)) return false;

		if (!FindVolumeInstancePath(conn.pSvc, driveLetter, instancePath))
		{
			SetLastErrorMsg(L"Failed to re-acquire the BitLocker volume instance path prior to Encrypt.");
			return false;
		}

		// Encrypt (EncryptionMethod=7, EncryptionFlags set by freePlusUsedSpace)
		if (!EncryptVolume(conn.pSvc, instancePath, freePlusUsedSpace))
			return false;

		return true;
	}
}
