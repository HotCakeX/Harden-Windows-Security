#include "BitLockerDisable.h"
#include "BitLockerManager.h"
#include "..\ComHelpers.h"
#include "..\Globals.h"
#include "..\StringUtilities.h"
#include <Wbemidl.h>
#include <comdef.h>
#include <sstream>
#include <iostream>

using namespace std;

namespace BitLocker {

	// Constant used to signal the presence of stored auto-unlock keys preventing OS drive decryption.
	// https://learn.microsoft.com/windows/win32/secprov/decrypt-win32-encryptablevolume#return-value
	static constexpr unsigned long BL_ERROR_AUTO_UNLOCK_KEYS_PRESENT = 2150694953UL;

	// Decrypts a BitLocker encrypted drive
	// If the drive is OS drive, it will check if it has auto-unlock keys that belong to other data drives.
	[[nodiscard]] bool DisableDrive(const wchar_t* driveLetter)
	{
		// Clear last error at the start of the operation.
		ClearLastErrorMsg();

		// Validate drive letter format L"C:"
		if (!driveLetter || wcslen(driveLetter) != 2 || driveLetter[1] != L':')
		{
			SetLastErrorMsg(L"DriveLetter must be in the form L\"C:\"");
			return false;
		}

		// Get the volume info based on the drive letter
		VolumeInfo vol;
		if (!GetVolumeInfo(driveLetter, vol))
		{
			// GetVolumeInfo sets the last error.
			return false;
		}

		// Already fully decrypted
		if (vol.conversionStatus == ConversionStatus::FullyDecrypted)
		{
			wcout << L"The drive " << driveLetter << L" is already decrypted" << endl;
			return true; // Not an error
		}

		// Decryption already in progress
		if (vol.conversionStatus == ConversionStatus::DecryptionInProgress)
		{
			wcout << L"The drive " << driveLetter << L" is being decrypted, please wait." << endl;
			return true; // Not an error
		}

		// If OS drive: check for stored auto-unlock keys (IsAutoUnlockKeyStored)
		if (vol.volumeType == VolumeType::OperationSystem)
		{
			wcout << L"Operation system drive detected during BitLocker disablement" << endl;
			wcout << L"Checking whether the Operation System drive has auto-unlock keys that belong to other data drives." << endl;

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

			// Invoke IsAutoUnlockKeyStored (no inputs)
			IWbemClassObject* pOut = ExecMethodSimple(conn.pSvc, instancePath.c_str(), L"IsAutoUnlockKeyStored", nullptr);
			if (!pOut)
			{
				SetLastErrorMsg(L"ExecMethod IsAutoUnlockKeyStored failed.");
				return false;
			}

			unsigned long rv = static_cast<unsigned long>(-1);
			ReadULong(pOut, L"ReturnValue", rv);
			if (rv != 0)
			{
				wstringstream ss;
				ss << L"IsAutoUnlockKeyStored failed " << FormatReturnCode(rv);
				SetLastErrorMsg(ss.str());
				wcerr << ss.str() << endl;
				pOut->Release();
				return false;
			}

			wcout << L"Successfully checked the OS Drive for any stored auto-unlock keys." << endl;

			// Evaluate IsAutoUnlockKeyStored property
			bool stored = false;
			{
				VARIANT v; VariantInit(&v);
				if (SUCCEEDED(pOut->Get(_bstr_t(L"IsAutoUnlockKeyStored"), 0, &v, nullptr, nullptr)) && v.vt == VT_BOOL)
				{
					stored = (v.boolVal == VARIANT_TRUE);
				}
				VariantClear(&v);
			}
			pOut->Release();

			if (stored)
			{
				wstringstream ss;
				ss << L"Auto-unlock keys for other data drives are stored on the OS drive. Decryption cannot proceed "
					<< FormatReturnCode(BL_ERROR_AUTO_UNLOCK_KEYS_PRESENT);
				wcerr << ss.str() << endl;
				SetLastErrorMsg(ss.str());
				return false;
			}

			// Re-fetch volume info after the preliminary check
			if (!GetVolumeInfo(driveLetter, vol))
				return false;
		}

		// Proceed with Decrypt for any (non FullyDecrypted / non DecryptionInProgress) volume.

		// Create a WMI connection for method invocation.
		WmiConnection connDec;
		if (!connDec.ok)
		{
			SetLastErrorMsg(L"Failed to connect to BitLocker WMI namespace.");
			return false;
		}

		wstring instPath;
		if (!FindVolumeInstancePath(connDec.pSvc, driveLetter, instPath))
		{
			SetLastErrorMsg(L"Failed to locate the BitLocker volume instance path.");
			return false;
		}

		// Decrypt has no input parameters; call directly.
		IWbemClassObject* pDecryptOut = ExecMethodSimple(connDec.pSvc, instPath.c_str(), L"Decrypt", nullptr);
		if (!pDecryptOut)
		{
			SetLastErrorMsg(L"ExecMethod Decrypt failed.");
			return false;
		}

		// Output handling for Decrypt
		unsigned long decryptRv = static_cast<unsigned long>(-1);
		ReadULong(pDecryptOut, L"ReturnValue", decryptRv);
		pDecryptOut->Release();

		if (decryptRv == 0)
		{
			wcout << L"Successfully started decrypting the drive " << driveLetter << endl;
			return true;
		}
		else
		{
			wstringstream ss;
			ss << L"Decrypt failed " << FormatReturnCode(decryptRv);
			wcerr << ss.str() << endl;
			SetLastErrorMsg(ss.str());
			return false;
		}
	}
}
