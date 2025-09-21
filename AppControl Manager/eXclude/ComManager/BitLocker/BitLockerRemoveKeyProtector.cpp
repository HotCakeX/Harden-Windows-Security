#include "BitLockerRemoveKeyProtector.h"
#include "..\Globals.h"
#include "..\StringUtilities.h"
#include "BitLockerManager.h"
#include "..\ComHelpers.h"

using namespace std;

namespace BitLocker {

	// Removes a key protector of an encrypted volume based on the key protector ID.
	// If the key protector being deleted is bound to the volume and used to keep the drive unlocked then do not throw errors.
	// This usually happens when trying to remove all ExternalKey key protectors of a Non-OS Drive when it is detected to have more than 1.
	bool RemoveKeyProtector(const wchar_t* driveLetter, const wchar_t* keyProtectorId, bool noErrorIfBound)
	{
		ClearLastErrorMsg();

		// Validate parameters similar to existing BitLocker functions.
		if (!driveLetter || wcslen(driveLetter) != 2 || driveLetter[1] != L':')
		{
			SetLastErrorMsg(L"DriveLetter must be in the form L\"C:\"");
			return false;
		}
		if (!keyProtectorId || *keyProtectorId == L'\0')
		{
			SetLastErrorMsg(L"KeyProtectorID cannot be null or empty.");
			return false;
		}

		// Obtain extended volume info (to enumerate key protectors and their types).
		VolumeInfo volInfo;
		if (!GetVolumeInfo(driveLetter, volInfo))
		{
			// Error already set by GetVolumeInfo.
			return false;
		}

		// Locate the requested key protector by ID (case-insensitive).
		const KeyProtectorInfo* targetKP = nullptr;
		for (const auto& kp : volInfo.keyProtectors)
		{
			if (EqualsOrdinalIgnoreCase(kp.id.c_str(), keyProtectorId))
			{
				targetKP = &kp;
				break;
			}
		}

		if (!targetKP)
		{
			LogOut(L"Key protector with the ID ", keyProtectorId,
				L" not found on the volume ", driveLetter, L".");
			return true;
		}

		if (targetKP->type == KeyProtectorType::TpmNetworkKey)
		{
			LogOut(L"The detected Key Protector type is TpmNetworkKey; it must be disabled and removed via group policies.");
			return true;
		}
		if (targetKP->type == KeyProtectorType::PublicKey)
		{
			LogOut(L"Removal of PublicKey type key protector not supported yet.");
			return true;
		}

		// Connect to BitLocker namespace for deletion work.
		IWbemLocator* pLoc = nullptr;
		IWbemServices* pSvc = nullptr;
		bool didInitCOM = false;
		if (!ConnectToWmiNamespace(WmiNamespace, &pLoc, &pSvc, didInitCOM) || !pSvc)
		{
			// Error set by helper.
			if (pLoc) pLoc->Release();
			if (pSvc) pSvc->Release();
			return false;
		}

		// Find the instance path needed for method execution.
		wstring instancePath;
		if (!FindVolumeInstancePath(pSvc, driveLetter, instancePath))
		{
			SetLastErrorMsg(L"Failed to locate the BitLocker volume instance path.");
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		// Helper lambda to attempt a single DeleteKeyProtector call.
		// https://learn.microsoft.com/windows/win32/secprov/deletekeyprotectors-win32-encryptablevolume
		auto attemptDelete = [&](unsigned long& outReturnCode) -> bool
			{
				outReturnCode = static_cast<unsigned long>(-1);
				IWbemClassObject* pIn = SpawnInParams(pSvc, L"DeleteKeyProtector");
				if (!pIn)
				{
					SetLastErrorMsg(L"Failed to prepare DeleteKeyProtector input parameters.");
					return false;
				}
				if (!SetParamBstr(pIn, L"VolumeKeyProtectorID", targetKP->id.c_str()))
				{
					pIn->Release();
					SetLastErrorMsg(L"Failed to set VolumeKeyProtectorID for DeleteKeyProtector.");
					return false;
				}

				IWbemClassObject* pOut = ExecMethodSimple(pSvc, instancePath.c_str(), L"DeleteKeyProtector", pIn);
				pIn->Release();
				if (!pOut)
				{
					SetLastErrorMsg(L"ExecMethod DeleteKeyProtector failed.");
					return false;
				}
				bool haveRV = ReadULong(pOut, L"ReturnValue", outReturnCode);
				pOut->Release();
				if (!haveRV)
				{
					SetLastErrorMsg(L"DeleteKeyProtector did not return a valid ReturnValue.");
					return false;
				}
				return true;
			};

		// Perform initial deletion attempt.
		unsigned long delCode = 0;
		if (!attemptDelete(delCode))
		{
			// Fatal error already recorded.
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		// Handle special case: key protectors must be disabled first.
		if (delCode == FVE_E_KEY_REQUIRED)
		{
			LogOut(L"The key protectors need to be disabled first, disabling now.");

			// DisableKeyProtectors has no input parameters.
			IWbemClassObject* pDisableOut = ExecMethodSimple(pSvc, instancePath.c_str(), L"DisableKeyProtectors", nullptr);
			if (!pDisableOut)
			{
				SetLastErrorMsg(L"ExecMethod DisableKeyProtectors failed.");
				pSvc->Release();
				pLoc->Release();
				if (!g_skipCOMInit && didInitCOM) CoUninitialize();
				return false;
			}
			unsigned long disableCode = 1;
			ReadULong(pDisableOut, L"ReturnValue", disableCode);
			pDisableOut->Release();

			if (disableCode == 0)
			{
				LogOut(L"Successfully disabled the key protectors, attempting the deletion again.");
				// Retry deletion
				if (!attemptDelete(delCode))
				{
					// Fatal error during retry.
					pSvc->Release();
					pLoc->Release();
					if (!g_skipCOMInit && didInitCOM) CoUninitialize();
					return false;
				}
			}
			else
			{
				LogErr(L"Failed to disable key protectors ", FormatReturnCode(disableCode));
				SetLastErrorMsg(L"Failed to disable key protectors before deletion.");
				pSvc->Release();
				pLoc->Release();
				if (!g_skipCOMInit && didInitCOM) CoUninitialize();
				return false;
			}
		}

		// Final evaluation of deletion result.
		bool overallSuccess = false;
		if (delCode == 0)
		{
			LogOut(L"Successfully deleted the key protector.");
			overallSuccess = true;
		}
		else if (noErrorIfBound && delCode == FVE_E_VOLUME_BOUND_ALREADY)
		{
			LogOut(L"The key protector is bound to the volume and used to keep the drive unlocked, skipping the deletion.");
			overallSuccess = true;
		}
		else
		{
			LogErr(L"Failed to delete key protector ", FormatReturnCode(delCode));
			SetLastErrorMsg(wstring(L"DeleteKeyProtector failed ") + FormatReturnCode(delCode));
			overallSuccess = false;
		}

		// Cleanup
		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM) CoUninitialize();

		return overallSuccess;
	}
}
