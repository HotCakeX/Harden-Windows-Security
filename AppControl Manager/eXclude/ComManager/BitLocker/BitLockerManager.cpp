#include "BitLockerManager.h"
#include "..\Globals.h"
#include "..\StringUtilities.h"
#include "..\ComHelpers.h"
#include <comdef.h>
#include <sstream>
#include <vector>
#include <cwctype>
#include <sddl.h>

using namespace std;

namespace BitLocker {

	// ctor/dtor implementation for WmiConnection defined in the header.
	WmiConnection::WmiConnection()
	{
		ok = ConnectToWmiNamespace(WmiNamespace, &pLoc, &pSvc, didInitCOM);
		if (!ok)
		{
			LogError(L"BitLocker: Failed to connect to BitLocker WMI namespace.");
		}
	}
	WmiConnection::~WmiConnection()
	{
		if (pSvc) pSvc->Release();
		if (pLoc) pLoc->Release();
		if (!g_skipCOMInit && didInitCOM) CoUninitialize();
	}

	// Helper: write error message
	void LogError(const wstring& msg)
	{
		LogErr(msg.c_str());
		SetLastErrorMsg(msg);
	}

	// Helper equivalent to string.IsNullOrWhiteSpace in C#
	bool IsNullOrWhiteSpace(const wchar_t* s)
	{
		if (!s) return true;
		for (const wchar_t* p = s; *p; ++p)
		{
			if (!iswspace(*p)) return false;
		}
		return true;
	}

	// Overload to accept HRESULT directly.
	// We cast through DWORD to preserve the original bit pattern (e.g. 0x8000001D) before formatting.
	wstring FormatReturnCode(HRESULT hr)
	{
		return FormatReturnCode(static_cast<unsigned long>(static_cast<DWORD>(hr)));
	}

	// Find instance path (__PATH) for a volume by DriveLetter (case-insensitive)
	// Gives us the volume information acquired from the Win32_EncryptableVolume CIM Instance
	[[nodiscard]] bool FindVolumeInstancePath(IWbemServices* pSvc, const wchar_t* driveLetter, wstring& outPath)
	{
		if (!pSvc || !driveLetter || *driveLetter == L'\0')
			return false;

		IEnumWbemClassObject* pEnum = nullptr;
		HRESULT hr = pSvc->ExecQuery(
			_bstr_t(L"WQL"),
			_bstr_t(L"SELECT __PATH, DriveLetter FROM Win32_EncryptableVolume"),
			WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
			nullptr,
			&pEnum);
		if (FAILED(hr) || !pEnum)
		{
			LogError(L"BitLocker: ExecQuery for Win32_EncryptableVolume failed.");
			return false;
		}

		bool found = false;

		for (;;)
		{
			IWbemClassObject* pObj = nullptr;
			ULONG uRet = 0;
			hr = pEnum->Next(WBEM_INFINITE, 1, &pObj, &uRet);
			if (hr != S_OK || uRet == 0) break;

			VARIANT vDrive;
			VariantInit(&vDrive);
			if (SUCCEEDED(pObj->Get(_bstr_t(L"DriveLetter"), 0, &vDrive, nullptr, nullptr)) &&
				vDrive.vt == VT_BSTR && vDrive.bstrVal)
			{
				if (EqualsOrdinalIgnoreCase(vDrive.bstrVal, driveLetter))
				{
					VARIANT vPath;
					VariantInit(&vPath);
					if (SUCCEEDED(pObj->Get(_bstr_t(L"__PATH"), 0, &vPath, nullptr, nullptr)) &&
						vPath.vt == VT_BSTR && vPath.bstrVal)
					{
						outPath.assign(vPath.bstrVal);
						found = true;
					}
					VariantClear(&vPath);
				}
			}
			VariantClear(&vDrive);
			pObj->Release();
			if (found) break;
		}

		pEnum->Release();

		if (!found)
		{
			wstringstream ss;
			ss << L"BitLocker: Volume for drive letter '" << driveLetter << L"' not found.";
			LogError(ss.str());
		}
		return found;
	}

	// Helper: standard ReturnValue handling
	bool HandleReturnValue(IWbemClassObject* pOutParams, const wstring& successMsg, const wstring& contextMsg)
	{
		if (!pOutParams)
		{
			LogError(L"BitLocker: No output parameters returned." + (contextMsg.empty() ? L"" : (L" " + contextMsg)));
			return false;
		}
		VARIANT vRet;
		VariantInit(&vRet);
		HRESULT hr = pOutParams->Get(_bstr_t(L"ReturnValue"), 0, &vRet, nullptr, nullptr);
		if (FAILED(hr))
		{
			LogError(L"BitLocker: Failed to read ReturnValue." + (contextMsg.empty() ? L"" : (L" " + contextMsg)));
			VariantClear(&vRet);
			return false;
		}
		unsigned long code = 0;
		if (vRet.vt == VT_I4) code = static_cast<unsigned long>(vRet.lVal);
		else if (vRet.vt == VT_UI4) code = vRet.ulVal;
		else
		{
			LogError(L"BitLocker: Unexpected ReturnValue variant type.");
			VariantClear(&vRet);
			return false;
		}
		VariantClear(&vRet);

		if (code == 0)
		{
			if (!successMsg.empty())
				LogOut(successMsg.c_str());

			return true;
		}
		wstringstream ss;
		ss << L"BitLocker: Operation failed (ReturnValue=" << code << L")";
		if (!contextMsg.empty()) ss << L" - " << contextMsg;
		LogError(ss.str());
		return false;
	}

	// Helper: retrieve method input definition
	IWbemClassObject* SpawnInParams(IWbemServices* pSvc, const wchar_t* methodName)
	{
		if (!pSvc) return nullptr;
		IWbemClassObject* pClass = nullptr;
		HRESULT hr = pSvc->GetObject(_bstr_t(ClassName), 0, nullptr, &pClass, nullptr);
		if (FAILED(hr) || !pClass)
			return nullptr;

		IWbemClassObject* pInDef = nullptr;
		hr = pClass->GetMethod(_bstr_t(methodName), 0, &pInDef, nullptr);
		pClass->Release();
		if (FAILED(hr) || !pInDef)
			return nullptr;

		IWbemClassObject* pInParams = nullptr;
		hr = pInDef->SpawnInstance(0, &pInParams);
		pInDef->Release();
		if (FAILED(hr) || !pInParams)
			return nullptr;

		return pInParams;
	}

	// Helper: set BSTR parameter (takes ownership copy inside Put)
	bool SetParamBstr(IWbemClassObject* inParams, const wchar_t* name, const wchar_t* value)
	{
		if (!inParams) return false;
		VARIANT v; VariantInit(&v);
		if (value == nullptr)
		{
			v.vt = VT_NULL;
		}
		else
		{
			v.vt = VT_BSTR;
			v.bstrVal = SysAllocString(value);
			if (!v.bstrVal) return false;
		}
		HRESULT hr = inParams->Put(_bstr_t(name), 0, &v, 0);
		VariantClear(&v);
		return SUCCEEDED(hr);
	}

	// Helper: set NULL param explicitly
	bool SetParamNull(IWbemClassObject* inParams, const wchar_t* name)
	{
		if (!inParams) return false;
		VARIANT v; VariantInit(&v);
		v.vt = VT_NULL;
		HRESULT hr = inParams->Put(_bstr_t(name), 0, &v, 0);
		VariantClear(&v);
		return SUCCEEDED(hr);
	}

	// Performs a first Put using VT_UI4 (canonical for CIM uint32).
	// If that fails, retries using VT_I4. If the fallback succeeds, logs the fallback usage.
	// Returns false only if both attempts fail.
	bool SetParamUint32(IWbemClassObject* inParams, const wchar_t* name, unsigned long val)
	{
		if (!inParams || !name)
			return false;

		// First attempt: VT_UI4 (unsigned 32-bit)
		VARIANT v; VariantInit(&v);
		v.vt = VT_UI4;
		v.ulVal = val;
		HRESULT hrUI4 = inParams->Put(_bstr_t(name), 0, &v, 0);
		VariantClear(&v);
		if (SUCCEEDED(hrUI4))
		{
			return true;
		}

		// Fallback attempt: VT_I4 (signed 32-bit) - some provider builds accept only this, such as the PrepareVolumeEx method.
		VARIANT v2; VariantInit(&v2);
		v2.vt = VT_I4;
		v2.lVal = static_cast<LONG>(val);
		HRESULT hrI4 = inParams->Put(_bstr_t(name), 0, &v2, 0);
		VariantClear(&v2);

		if (SUCCEEDED(hrI4))
		{
			wstringstream ss;
			ss << L"[SetParamUint32] Primary VT_UI4 Put failed (hr=0x"
				<< hex << uppercase << static_cast<unsigned long>(hrUI4)
				<< dec << L") but fallback VT_I4 succeeded for parameter '"
				<< name << L"' with value " << val << L".";
			LogOut(ss.str().c_str());
			return true;
		}

		// Both attempts failed.
		LogErr(L"[SetParamUint32] Failed to set UINT32 parameter '", name,
			L"' value ", val,
			L" (VT_UI4 hr=0x", hex, uppercase, static_cast<unsigned long>(hrUI4),
			L", VT_I4 hr=0x", static_cast<unsigned long>(hrI4),
			dec, L").");
		return false;
	}

	// Helper: read VolumeKeyProtectorID/Id from output params
	bool GetProtectorId(IWbemClassObject* outParams, wstring& idOut)
	{
		if (!outParams) return false;

		VARIANT v; VariantInit(&v);
		if (SUCCEEDED(outParams->Get(_bstr_t(L"VolumeKeyProtectorID"), 0, &v, nullptr, nullptr)) &&
			v.vt == VT_BSTR && v.bstrVal)
		{
			idOut.assign(v.bstrVal);
			VariantClear(&v);
			return true;
		}
		VariantClear(&v);
		return false;
	}

	// Removes all key protectors of the specified type from the specified drive
	// https://learn.microsoft.com/windows/win32/secprov/getkeyprotectors-win32-encryptablevolume
	bool RemoveKeyProtectorsOfType(IWbemServices* pSvc, const wstring& instancePath, unsigned long keyProtectorType)
	{
		IWbemClassObject* pInParams = SpawnInParams(pSvc, L"GetKeyProtectors");
		if (!pInParams)
		{
			LogError(L"BitLocker: Failed to prepare GetKeyProtectors parameters.");
			return false;
		}

		// Set the KeyProtectorType argument to the specified type.
		if (!SetParamUint32(pInParams, L"KeyProtectorType", keyProtectorType))
		{
			pInParams->Release();
			LogError(L"BitLocker: Failed to set KeyProtectorType for GetKeyProtectors.");
			return false;
		}

		IWbemClassObject* pOut = nullptr;
		HRESULT hr = pSvc->ExecMethod(_bstr_t(instancePath.c_str()), _bstr_t(L"GetKeyProtectors"), 0, nullptr, pInParams, &pOut, nullptr);
		pInParams->Release();
		if (FAILED(hr) || !pOut)
		{
			LogError(L"BitLocker: ExecMethod GetKeyProtectors failed.");
			return false;
		}

		// Handle return code
		VARIANT vRet; VariantInit(&vRet);
		bool ok = true;
		if (SUCCEEDED(pOut->Get(_bstr_t(L"ReturnValue"), 0, &vRet, nullptr, nullptr)))
		{
			unsigned long code = (vRet.vt == VT_I4) ? static_cast<unsigned long>(vRet.lVal) :
				(vRet.vt == VT_UI4 ? vRet.ulVal : 0xFFFFFFFFul);

			if (code != 0)
			{
				wstringstream ss;
				ss << L"BitLocker: GetKeyProtectors returned error code " << code;
				LogError(ss.str());
				ok = false;
			}
		}
		VariantClear(&vRet);

		if (!ok)
		{
			pOut->Release();
			return false;
		}

		// Retrieve the array of VolumeKeyProtectorID
		VARIANT vArr; VariantInit(&vArr);
		if (SUCCEEDED(pOut->Get(_bstr_t(L"VolumeKeyProtectorID"), 0, &vArr, nullptr, nullptr)) &&
			(vArr.vt == (VT_ARRAY | VT_BSTR)) && vArr.parray)
		{
			SAFEARRAY* psa = vArr.parray;
			LONG lBound = 0, uBound = -1;
			if (SUCCEEDED(SafeArrayGetLBound(psa, 1, &lBound)) &&
				SUCCEEDED(SafeArrayGetUBound(psa, 1, &uBound)) &&
				uBound >= lBound)
			{
				for (LONG i = lBound; i <= uBound; ++i)
				{
					BSTR protectorId{};
					if (SUCCEEDED(SafeArrayGetElement(psa, &i, &protectorId)) && protectorId)
					{
						// DeleteKeyProtector
						IWbemClassObject* pDelIn = SpawnInParams(pSvc, L"DeleteKeyProtector");
						if (!pDelIn)
						{
							LogError(L"BitLocker: Failed to prepare DeleteKeyProtector parameters.");
							SysFreeString(protectorId);
							ok = false;
							break;
						}
						// Set VolumeKeyProtectorID
						VARIANT v; VariantInit(&v);
						v.vt = VT_BSTR;
						v.bstrVal = protectorId; // ownership temporary
						HRESULT hrSet = pDelIn->Put(_bstr_t(L"VolumeKeyProtectorID"), 0, &v, 0);
						VariantClear(&v); // does not free protectorId (SAFEARRAY element copy)
						if (FAILED(hrSet))
						{
							LogError(L"BitLocker: Failed to set VolumeKeyProtectorID for deletion.");
							pDelIn->Release();
							SysFreeString(protectorId);
							ok = false;
							break;
						}

						IWbemClassObject* pDelOut = nullptr;
						HRESULT hrDel = pSvc->ExecMethod(_bstr_t(instancePath.c_str()), _bstr_t(L"DeleteKeyProtector"), 0, nullptr, pDelIn, &pDelOut, nullptr);
						pDelIn->Release();
						if (FAILED(hrDel) || !pDelOut)
						{
							LogError(L"BitLocker: ExecMethod DeleteKeyProtector failed.");
							SysFreeString(protectorId);
							ok = false;
							break;
						}

						wstringstream successMsg;
						successMsg << L"Successfully removed a key protector of type " << keyProtectorType;

						bool delOk = HandleReturnValue(pDelOut,
							successMsg.str(),
							L"DeleteKeyProtector");
						pDelOut->Release();
						SysFreeString(protectorId);
						if (!delOk)
						{
							ok = false;
							break;
						}
					}
				}
			}
			else
			{
				// No elements
			}
		}
		else
		{
			// No key protectors of that type
			wstringstream ss;
			ss << L"No key protector of type " << keyProtectorType << L" found.";
			LogOut(ss.str());
		}

		VariantClear(&vArr);
		pOut->Release();
		return ok;
	}

	// Function to get instance path
	bool GetInstancePath(const wchar_t* driveLetter, wstring& pathOut, WmiConnection& conn)
	{
		if (!conn.ok) return false;
		if (!driveLetter || *driveLetter == L'\0')
		{
			LogError(L"BitLocker: DriveLetter is null or empty.");
			return false;
		}
		return FindVolumeInstancePath(conn.pSvc, driveLetter, pathOut);
	}

	// Adds the recovery password protector (NumericalPassword) to the specified drive
	// This is the same RecoveryPassword that is used to unlock the drive in case of a forgotten password.
	// https://learn.microsoft.com/windows/win32/secprov/protectkeywithnumericalpassword-win32-encryptablevolume
	// If we supply the password ourselves then it can be used, otherwise it should be null.
	// If it's null, the CIM method will automatically assign a random password
	// If we want to supply in a password ourselves, it should be in the following format otherwise the return value will be non-zero indicating there was an error
	// "111111-111111-111111-111111-111111-111111-111111-111111"
	// Note that even the example above which only consists of 1s is acceptable since it follows the correct format.
	[[nodiscard]] bool AddRecoveryPassword(const wchar_t* driveLetter, const wchar_t* numericalPassword)
	{
		ClearLastErrorMsg();
		WmiConnection conn;
		wstring instancePath;
		if (!GetInstancePath(driveLetter, instancePath, conn)) return false;

		IWbemClassObject* pIn = SpawnInParams(conn.pSvc, L"ProtectKeyWithNumericalPassword");
		if (!pIn)
		{
			LogError(L"BitLocker: Failed to prepare parameters for ProtectKeyWithNumericalPassword.");
			return false;
		}

		if (!SetParamNull(pIn, L"FriendlyName"))
		{
			pIn->Release();
			LogError(L"BitLocker: Failed to set FriendlyName.");
			return false;
		}

		// NumericalPassword: null for auto, or provided (treat whitespace-only as null)
		if (!IsNullOrWhiteSpace(numericalPassword))
		{
			if (!SetParamBstr(pIn, L"NumericalPassword", numericalPassword))
			{
				pIn->Release();
				LogError(L"BitLocker: Failed to set NumericalPassword.");
				return false;
			}
		}
		else
		{
			if (!SetParamNull(pIn, L"NumericalPassword"))
			{
				pIn->Release();
				LogError(L"BitLocker: Failed to set NumericalPassword null.");
				return false;
			}
		}

		IWbemClassObject* pOut = nullptr;
		HRESULT hr = conn.pSvc->ExecMethod(_bstr_t(instancePath.c_str()), _bstr_t(L"ProtectKeyWithNumericalPassword"), 0, nullptr, pIn, &pOut, nullptr);
		pIn->Release();
		if (FAILED(hr) || !pOut)
		{
			LogError(L"BitLocker: ExecMethod ProtectKeyWithNumericalPassword failed.");
			return false;
		}

		bool ok = HandleReturnValue(pOut, L"Successfully added the Recovery Password key protector.");
		pOut->Release();
		return ok;
	}

	// Adds the password protector (PassPhrase) to the specified drive
	// If the OS-drive is using TpmPin or TpmPinStartupKey then this cannot be used, so mostly suitable for non-OS drives
	// If the drive already has this type of key protector and user tries to add it again to it, results in an error.
	// https://learn.microsoft.com/windows/win32/secprov/protectkeywithpassphrase-win32-encryptablevolume
	// PassPhrase: The password to be used as a key protector, e.g: "1a2b3c4b"
	[[nodiscard]] bool AddPasswordProtector(const wchar_t* driveLetter, const wchar_t* passPhrase)
	{
		ClearLastErrorMsg();
		if (IsNullOrWhiteSpace(passPhrase))
		{
			LogError(L"BitLocker: PassPhrase cannot be null or empty.");
			return false;
		}

		WmiConnection conn;
		wstring instancePath;
		if (!GetInstancePath(driveLetter, instancePath, conn)) return false;

		IWbemClassObject* pIn = SpawnInParams(conn.pSvc, L"ProtectKeyWithPassphrase");
		if (!pIn)
		{
			LogError(L"BitLocker: Failed to prepare parameters for ProtectKeyWithPassphrase.");
			return false;
		}

		if (!SetParamNull(pIn, L"FriendlyName") ||
			!SetParamBstr(pIn, L"PassPhrase", passPhrase))
		{
			pIn->Release();
			LogError(L"BitLocker: Failed to set method parameters (PassPhrase).");
			return false;
		}

		IWbemClassObject* pOut = nullptr;
		HRESULT hr = conn.pSvc->ExecMethod(_bstr_t(instancePath.c_str()), _bstr_t(L"ProtectKeyWithPassphrase"), 0, nullptr, pIn, &pOut, nullptr);
		pIn->Release();
		if (FAILED(hr) || !pOut)
		{
			LogError(L"BitLocker: ExecMethod ProtectKeyWithPassphrase failed.");
			return false;
		}

		bool ok = HandleReturnValue(pOut, L"Successfully added Password key protector (aka Passphrase).");
		pOut->Release();
		return ok;
	}

	// Adds the Tpm protector to the specified drive
	// Naturally, The group policy must allow the TPM-only protector otherwise this method results in an error
	// If other TPM based key protectors exist, they will be removed only after this one is added.
	// But adding this type of key protector while it is already added will result in an error.
	// https://learn.microsoft.com/windows/win32/secprov/protectkeywithtpm-win32-encryptablevolume
	[[nodiscard]] bool AddTpmProtector(const wchar_t* driveLetter)
	{
		ClearLastErrorMsg();

		// Perform TPM entropy readiness check
		if (!IsSystemEntropyReady())
		{
			wstringstream ss;
			ss << L"System entropy (TPM readiness) check failed " << FormatReturnCode(TPM_E_DEACTIVATED)
				<< L" (TPM not enabled/activated in this environment).";
			LogError(ss.str());
			return false;
		}

		WmiConnection conn;
		wstring instancePath;
		if (!GetInstancePath(driveLetter, instancePath, conn)) return false;

		IWbemClassObject* pIn = SpawnInParams(conn.pSvc, L"ProtectKeyWithTPM");
		if (!pIn)
		{
			LogError(L"BitLocker: Failed to prepare parameters for ProtectKeyWithTPM.");
			return false;
		}

		if (!SetParamNull(pIn, L"FriendlyName") ||
			!SetParamNull(pIn, L"PlatformValidationProfile"))
		{
			pIn->Release();
			LogError(L"BitLocker: Failed to set parameter(s) for ProtectKeyWithTPM.");
			return false;
		}

		IWbemClassObject* pOut = nullptr;
		HRESULT hr = conn.pSvc->ExecMethod(_bstr_t(instancePath.c_str()), _bstr_t(L"ProtectKeyWithTPM"), 0, nullptr, pIn, &pOut, nullptr);
		pIn->Release();
		if (FAILED(hr) || !pOut)
		{
			LogError(L"BitLocker: ExecMethod ProtectKeyWithTPM failed.");
			return false;
		}

		bool ok = HandleReturnValue(pOut, L"Successfully added the TPM key protector.");
		pOut->Release();
		if (!ok) return false;

		// Have to remove all other TPM based key protectors
		// There can only be 1 of this type
		RemoveKeyProtectorsOfType(conn.pSvc, instancePath, 6); // TpmPinStartupKey
		RemoveKeyProtectorsOfType(conn.pSvc, instancePath, 5); // TpmStartupKey
		RemoveKeyProtectorsOfType(conn.pSvc, instancePath, 4); // TpmPin
		return true;
	}

	// Adds the TpmAndPin protector to the specified drive
	// If other TPM based key protectors exist, they will be removed only after this one is added.
	// But adding this type of key protector while it is already added will result in an error.
	// https://learn.microsoft.com/windows/win32/secprov/protectkeywithtpmandpin-win32-encryptablevolume
	// PIN: Startup PIN to be used during system boot
	[[nodiscard]] bool AddTpmAndPinProtector(const wchar_t* driveLetter, const wchar_t* pin)
	{
		ClearLastErrorMsg();
		if (IsNullOrWhiteSpace(pin))
		{
			LogError(L"BitLocker: PIN cannot be null or empty.");
			return false;
		}

		// Perform TPM entropy readiness check
		if (!IsSystemEntropyReady())
		{
			wstringstream ss;
			ss << L"System entropy (TPM readiness) check failed " << FormatReturnCode(TPM_E_DEACTIVATED)
				<< L" (TPM not enabled/activated in this environment).";
			LogError(ss.str());
			return false;
		}

		WmiConnection conn;
		wstring instancePath;
		if (!GetInstancePath(driveLetter, instancePath, conn)) return false;

		IWbemClassObject* pIn = SpawnInParams(conn.pSvc, L"ProtectKeyWithTPMAndPin");
		if (!pIn)
		{
			LogError(L"BitLocker: Failed to prepare parameters for ProtectKeyWithTPMAndPin.");
			return false;
		}

		if (!SetParamNull(pIn, L"FriendlyName") ||
			!SetParamNull(pIn, L"PlatformValidationProfile") ||
			!SetParamBstr(pIn, L"PIN", pin))
		{
			pIn->Release();
			LogError(L"BitLocker: Failed to set parameter(s) for ProtectKeyWithTPMAndPin.");
			return false;
		}

		IWbemClassObject* pOut = nullptr;
		HRESULT hr = conn.pSvc->ExecMethod(_bstr_t(instancePath.c_str()), _bstr_t(L"ProtectKeyWithTPMAndPin"), 0, nullptr, pIn, &pOut, nullptr);
		pIn->Release();
		if (FAILED(hr) || !pOut)
		{
			LogError(L"BitLocker: ExecMethod ProtectKeyWithTPMAndPin failed.");
			return false;
		}

		bool ok = HandleReturnValue(pOut, L"Successfully added the TpmAndPin key protector.");
		pOut->Release();
		if (!ok) return false;

		// Remove 6 (TpmPinStartupKey), 5 (TpmStartupKey), 1 (Tpm)
		RemoveKeyProtectorsOfType(conn.pSvc, instancePath, 6);
		RemoveKeyProtectorsOfType(conn.pSvc, instancePath, 5);
		RemoveKeyProtectorsOfType(conn.pSvc, instancePath, 1);
		return true;
	}

	// Adds the TPM + StartupKey key protector
	// If other TPM based key protectors exist, they will be removed only after this one is added.
	// But adding this type of key protector while it is already added will result in an error.
	// https://learn.microsoft.com/windows/win32/secprov/protectkeywithtpmandstartupkey-win32-encryptablevolume
	// https://learn.microsoft.com/windows/win32/secprov/saveexternalkeytofile-win32-encryptablevolume
	// StartupKeyPath: Path to a Drive or Folder, such as: @"C:\". The folder/drive path must exist otherwise error is thrown.
	[[nodiscard]] bool AddTpmAndStartupKeyProtector(const wchar_t* driveLetter, const wchar_t* startupKeyPath)
	{
		ClearLastErrorMsg();
		if (IsNullOrWhiteSpace(startupKeyPath))
		{
			LogError(L"BitLocker: Startup Key Path cannot be null or empty.");
			return false;
		}

		// Perform TPM entropy readiness check
		if (!IsSystemEntropyReady())
		{
			wstringstream ss;
			ss << L"System entropy (TPM readiness) check failed " << FormatReturnCode(TPM_E_DEACTIVATED)
				<< L" (TPM not enabled/activated in this environment).";
			LogError(ss.str());
			return false;
		}

		WmiConnection conn;
		wstring instancePath;
		if (!GetInstancePath(driveLetter, instancePath, conn)) return false;

		IWbemClassObject* pIn = SpawnInParams(conn.pSvc, L"ProtectKeyWithTPMAndStartupKey");
		if (!pIn)
		{
			LogError(L"BitLocker: Failed to prepare parameters for ProtectKeyWithTPMAndStartupKey.");
			return false;
		}

		if (!SetParamNull(pIn, L"FriendlyName") ||
			!SetParamNull(pIn, L"PlatformValidationProfile") ||
			!SetParamNull(pIn, L"ExternalKey"))
		{
			pIn->Release();
			LogError(L"BitLocker: Failed to set parameters for ProtectKeyWithTPMAndStartupKey.");
			return false;
		}

		IWbemClassObject* pOut = nullptr;
		HRESULT hr = conn.pSvc->ExecMethod(_bstr_t(instancePath.c_str()), _bstr_t(L"ProtectKeyWithTPMAndStartupKey"), 0, nullptr, pIn, &pOut, nullptr);
		pIn->Release();
		if (FAILED(hr) || !pOut)
		{
			LogError(L"BitLocker: ExecMethod ProtectKeyWithTPMAndStartupKey failed.");
			return false;
		}

		if (!HandleReturnValue(pOut, L"The TpmAndStartupKey key protector was successfully added. Backing up the Startup key in the next step."))
		{
			pOut->Release();
			return false;
		}

		wstring protectorId;
		if (!GetProtectorId(pOut, protectorId))
		{
			pOut->Release();
			LogError(L"BitLocker: Failed to retrieve VolumeKeyProtectorID for backup.");
			return false;
		}
		pOut->Release();

		// SaveExternalKeyToFile
		IWbemClassObject* pSaveIn = SpawnInParams(conn.pSvc, L"SaveExternalKeyToFile");
		if (!pSaveIn)
		{
			LogError(L"BitLocker: Failed to prepare parameters for SaveExternalKeyToFile.");
			return false;
		}

		// Set VolumeKeyProtectorID
		if (!SetParamBstr(pSaveIn, L"VolumeKeyProtectorID", protectorId.c_str()) ||
			!SetParamBstr(pSaveIn, L"Path", startupKeyPath))
		{
			pSaveIn->Release();
			LogError(L"BitLocker: Failed to set parameters for SaveExternalKeyToFile.");
			return false;
		}

		IWbemClassObject* pSaveOut = nullptr;
		HRESULT hr2 = conn.pSvc->ExecMethod(_bstr_t(instancePath.c_str()), _bstr_t(L"SaveExternalKeyToFile"), 0, nullptr, pSaveIn, &pSaveOut, nullptr);
		pSaveIn->Release();
		if (FAILED(hr2) || !pSaveOut)
		{
			LogError(L"BitLocker: ExecMethod SaveExternalKeyToFile failed.");
			return false;
		}

		wstring backupSuccessMsg = L"Successfully backed up the Startup key to " + wstring(startupKeyPath);
		bool saveOk = HandleReturnValue(pSaveOut, backupSuccessMsg, L"SaveExternalKeyToFile");
		pSaveOut->Release();

		if (saveOk)
		{
			// Delete all other TPM based protectors, there can only be 1 of this type
			RemoveKeyProtectorsOfType(conn.pSvc, instancePath, 4); // TpmPin
			RemoveKeyProtectorsOfType(conn.pSvc, instancePath, 1); // Tpm
			RemoveKeyProtectorsOfType(conn.pSvc, instancePath, 6); // TpmPinStartupKey
			return true;
		}
		else
		{
			// If the key wasn't saved successfully, remove the protector as a safety measure
			IWbemClassObject* pDelIn = SpawnInParams(conn.pSvc, L"DeleteKeyProtector");
			if (pDelIn)
			{
				SetParamBstr(pDelIn, L"VolumeKeyProtectorID", protectorId.c_str());
				IWbemClassObject* pDelOut = nullptr;
				conn.pSvc->ExecMethod(_bstr_t(instancePath.c_str()), _bstr_t(L"DeleteKeyProtector"), 0, nullptr, pDelIn, &pDelOut, nullptr);
				if (pDelOut) pDelOut->Release();
				pDelIn->Release();
			}
			return false;
		}
	}

	// Add the TpmAndPinAndStartupKeyProtector to the drive
	// If other TPM based key protectors exist, they will be removed only after this one is added.
	// But adding this type of key protector while it is already added will result in an error.
	// StartupKeyPath: Path to a Drive or Folder, such as: @"C:\". The folder/drive path must exist otherwise error is thrown.
	// PIN: A pin, its minimum length defined by policies.
	[[nodiscard]] bool AddTpmAndPinAndStartupKeyProtector(const wchar_t* driveLetter, const wchar_t* startupKeyPath, const wchar_t* pin)
	{
		ClearLastErrorMsg();
		if (IsNullOrWhiteSpace(pin) || IsNullOrWhiteSpace(startupKeyPath))
		{
			LogError(L"BitLocker: PIN or Startup Key Path cannot be null or empty.");
			return false;
		}

		// Perform TPM entropy readiness check
		if (!IsSystemEntropyReady())
		{
			wstringstream ss;
			ss << L"System entropy (TPM readiness) check failed " << FormatReturnCode(TPM_E_DEACTIVATED)
				<< L" (TPM not enabled/activated in this environment).";
			LogError(ss.str());
			return false;
		}

		WmiConnection conn;
		wstring instancePath;
		if (!GetInstancePath(driveLetter, instancePath, conn)) return false;

		IWbemClassObject* pIn = SpawnInParams(conn.pSvc, L"ProtectKeyWithTPMAndPinAndStartupKey");
		if (!pIn)
		{
			LogError(L"BitLocker: Failed to prepare parameters for ProtectKeyWithTPMAndPinAndStartupKey.");
			return false;
		}

		if (!SetParamNull(pIn, L"FriendlyName") ||
			!SetParamNull(pIn, L"PlatformValidationProfile") ||
			!SetParamNull(pIn, L"ExternalKey") ||
			!SetParamBstr(pIn, L"PIN", pin))
		{
			pIn->Release();
			LogError(L"BitLocker: Failed to set parameters for ProtectKeyWithTPMAndPinAndStartupKey.");
			return false;
		}

		IWbemClassObject* pOut = nullptr;
		HRESULT hr = conn.pSvc->ExecMethod(_bstr_t(instancePath.c_str()), _bstr_t(L"ProtectKeyWithTPMAndPinAndStartupKey"), 0, nullptr, pIn, &pOut, nullptr);
		pIn->Release();
		if (FAILED(hr) || !pOut)
		{
			LogError(L"BitLocker: ExecMethod ProtectKeyWithTPMAndPinAndStartupKey failed.");
			return false;
		}

		if (!HandleReturnValue(pOut, L"The TpmAndPinAndStartupKey key protector was successfully added. Will backup the startup key in the next step."))
		{
			pOut->Release();
			return false;
		}

		wstring protectorId;
		if (!GetProtectorId(pOut, protectorId))
		{
			pOut->Release();
			LogError(L"BitLocker: Failed to retrieve VolumeKeyProtectorID for backup.");
			return false;
		}
		pOut->Release();

		// Save external key
		IWbemClassObject* pSaveIn = SpawnInParams(conn.pSvc, L"SaveExternalKeyToFile");
		if (!pSaveIn)
		{
			LogError(L"BitLocker: Failed to prepare parameters for SaveExternalKeyToFile.");
			return false;
		}
		if (!SetParamBstr(pSaveIn, L"VolumeKeyProtectorID", protectorId.c_str()) ||
			!SetParamBstr(pSaveIn, L"Path", startupKeyPath))
		{
			pSaveIn->Release();
			LogError(L"BitLocker: Failed to set parameters for SaveExternalKeyToFile.");
			return false;
		}

		IWbemClassObject* pSaveOut = nullptr;
		HRESULT hr2 = conn.pSvc->ExecMethod(_bstr_t(instancePath.c_str()), _bstr_t(L"SaveExternalKeyToFile"), 0, nullptr, pSaveIn, &pSaveOut, nullptr);
		pSaveIn->Release();
		if (FAILED(hr2) || !pSaveOut)
		{
			LogError(L"BitLocker: ExecMethod SaveExternalKeyToFile failed.");
			return false;
		}

		wstring backupSuccessMsg = L"Successfully backed up the startup key to " + wstring(startupKeyPath);
		bool saveOk = HandleReturnValue(pSaveOut, backupSuccessMsg, L"SaveExternalKeyToFile");
		pSaveOut->Release();

		if (saveOk)
		{
			// Delete all other TPM based protectors, there can only be 1 of this type
			RemoveKeyProtectorsOfType(conn.pSvc, instancePath, 4); // TpmPin
			RemoveKeyProtectorsOfType(conn.pSvc, instancePath, 1); // Tpm
			RemoveKeyProtectorsOfType(conn.pSvc, instancePath, 5); // TpmStartupKey
			return true;
		}
		else
		{
			// If the key wasn't saved successfully, remove the protector as a safety measure
			IWbemClassObject* pDelIn = SpawnInParams(conn.pSvc, L"DeleteKeyProtector");
			if (pDelIn)
			{
				SetParamBstr(pDelIn, L"VolumeKeyProtectorID", protectorId.c_str());
				IWbemClassObject* pDelOut = nullptr;
				conn.pSvc->ExecMethod(_bstr_t(instancePath.c_str()), _bstr_t(L"DeleteKeyProtector"), 0, nullptr, pDelIn, &pDelOut, nullptr);
				if (pDelOut) pDelOut->Release();
				pDelIn->Release();
			}
			return false;
		}
	}

	// Adds the StartupKeyProtector or RecoveryKeyProtector, same thing
	// They can be added even if the volume already has a StartupKey key protector, there can be multiple Startup Key protectors (aka ExternalKey key protectors) for 1 drive.
	// It also works if the drive already has a TpmPinStartupKey key protector.
	// https://learn.microsoft.com/windows/win32/secprov/protectkeywithexternalkey-win32-encryptablevolume
	// StartupKeyPath = Path to a Drive or Folder, such as: @"C:\". The folder/drive path must exist otherwise error is thrown.
	[[nodiscard]] bool AddStartupKeyProtector_OR_RecoveryKeyProtector(const wchar_t* driveLetter, const wchar_t* startupKeyPath)
	{
		ClearLastErrorMsg();
		if (IsNullOrWhiteSpace(startupKeyPath))
		{
			LogError(L"BitLocker: Startup Key Path cannot be null or empty.");
			return false;
		}

		WmiConnection conn;
		wstring instancePath;
		if (!GetInstancePath(driveLetter, instancePath, conn)) return false;

		// ProtectKeyWithExternalKey
		IWbemClassObject* pIn = SpawnInParams(conn.pSvc, L"ProtectKeyWithExternalKey");
		if (!pIn)
		{
			LogError(L"BitLocker: Failed to prepare parameters for ProtectKeyWithExternalKey.");
			return false;
		}

		if (!SetParamNull(pIn, L"FriendlyName") ||
			!SetParamNull(pIn, L"ExternalKey"))
		{
			pIn->Release();
			LogError(L"BitLocker: Failed to set parameters for ProtectKeyWithExternalKey.");
			return false;
		}

		IWbemClassObject* pOut = nullptr;
		HRESULT hr = conn.pSvc->ExecMethod(_bstr_t(instancePath.c_str()), _bstr_t(L"ProtectKeyWithExternalKey"), 0, nullptr, pIn, &pOut, nullptr);
		pIn->Release();
		if (FAILED(hr) || !pOut)
		{
			LogError(L"BitLocker: ExecMethod ProtectKeyWithExternalKey failed.");
			return false;
		}

		if (!HandleReturnValue(pOut, L"The StartupKey key protector was successfully added. Will back up it in the next step."))
		{
			pOut->Release();
			return false;
		}

		wstring protectorId;
		if (!GetProtectorId(pOut, protectorId))
		{
			pOut->Release();
			LogError(L"BitLocker: Failed to retrieve VolumeKeyProtectorID for backup.");
			return false;
		}
		pOut->Release();

		// SaveExternalKeyToFile
		IWbemClassObject* pSaveIn = SpawnInParams(conn.pSvc, L"SaveExternalKeyToFile");
		if (!pSaveIn)
		{
			LogError(L"BitLocker: Failed to prepare parameters for SaveExternalKeyToFile.");
			return false;
		}
		if (!SetParamBstr(pSaveIn, L"VolumeKeyProtectorID", protectorId.c_str()) ||
			!SetParamBstr(pSaveIn, L"Path", startupKeyPath))
		{
			pSaveIn->Release();
			LogError(L"BitLocker: Failed to set parameters for SaveExternalKeyToFile.");
			return false;
		}

		IWbemClassObject* pSaveOut = nullptr;
		HRESULT hr2 = conn.pSvc->ExecMethod(_bstr_t(instancePath.c_str()), _bstr_t(L"SaveExternalKeyToFile"), 0, nullptr, pSaveIn, &pSaveOut, nullptr);
		pSaveIn->Release();
		if (FAILED(hr2) || !pSaveOut)
		{
			LogError(L"BitLocker: ExecMethod SaveExternalKeyToFile failed.");
			return false;
		}

		wstring backupSuccessMsg = L"Successfully backed up the Startup key to " + wstring(startupKeyPath);
		bool saveOk = HandleReturnValue(pSaveOut, backupSuccessMsg, L"SaveExternalKeyToFile");
		pSaveOut->Release();
		if (!saveOk)
		{
			// Delete protector
			IWbemClassObject* pDelIn = SpawnInParams(conn.pSvc, L"DeleteKeyProtector");
			if (pDelIn)
			{
				SetParamBstr(pDelIn, L"VolumeKeyProtectorID", protectorId.c_str());
				IWbemClassObject* pDelOut = nullptr;
				conn.pSvc->ExecMethod(_bstr_t(instancePath.c_str()), _bstr_t(L"DeleteKeyProtector"), 0, nullptr, pDelIn, &pDelOut, nullptr);
				if (pDelOut) pDelOut->Release();
				pDelIn->Release();
			}
			LogError(L"Error saving the Startup key in the defined path, removing the Startup key KeyProtector.");
			return false;
		}
		return true;
	}

	// Adds the SidProtector to the drive
	// https://learn.microsoft.com/windows/win32/secprov/protectkeywithadsid-win32-encryptablevolume
	// More info: https://learn.microsoft.com/windows/security/operating-system-security/data-protection/bitlocker/operations-guide?tabs=powershell#add-a-password-protector
	[[nodiscard]] bool AddSidProtector(const wchar_t* driveLetter, const wchar_t* sid, bool serviceAccount)
	{
		ClearLastErrorMsg();
		if (IsNullOrWhiteSpace(sid))
		{
			LogError(L"BitLocker: SID cannot be null or empty.");
			return false;
		}

		// Validate and canonicalize SID string:
		// 1) Convert the input SID string to a PSID to validate its structure.
		// 2) Convert the PSID back to a string form (ConvertSidToStringSidW) to get a canonical representation.
		PSID pSidTmp = nullptr;
		if (!ConvertStringSidToSidW(sid, &pSidTmp))
		{
			LogError(L"BitLocker: Invalid SID format.");
			if (pSidTmp) LocalFree(pSidTmp);
			return false;
		}

		LPWSTR canonicalSid = nullptr;
		if (!ConvertSidToStringSidW(pSidTmp, &canonicalSid))
		{
			LocalFree(pSidTmp);
			LogError(L"BitLocker: Failed to canonicalize SID.");
			return false;
		}

		// Copy canonical SID into wstring
		wstring canonicalSidStr = canonicalSid ? canonicalSid : L"";

		// Free allocated resources from Windows APIs
		if (canonicalSid) LocalFree(canonicalSid);
		if (pSidTmp) LocalFree(pSidTmp);

		if (canonicalSidStr.empty())
		{
			LogError(L"BitLocker: Canonical SID is empty after conversion.");
			return false;
		}

		WmiConnection conn;
		wstring instancePath;
		if (!GetInstancePath(driveLetter, instancePath, conn)) return false;

		IWbemClassObject* pIn = SpawnInParams(conn.pSvc, L"ProtectKeyWithAdSid");
		if (!pIn)
		{
			LogError(L"BitLocker: Failed to prepare parameters for ProtectKeyWithAdSid.");
			return false;
		}

		if (!SetParamNull(pIn, L"FriendlyName") ||
			!SetParamBstr(pIn, L"SidString", canonicalSidStr.c_str()) ||
			!SetParamUint32(pIn, L"Flags", serviceAccount ? 1u : 0u)) // 1 means FVE_DPAPI_NG_FLAG_UNLOCK_AS_SERVICE_ACCOUNT
		{
			pIn->Release();
			LogError(L"BitLocker: Failed to set parameters for ProtectKeyWithAdSid.");
			return false;
		}

		IWbemClassObject* pOut = nullptr;
		HRESULT hr = conn.pSvc->ExecMethod(_bstr_t(instancePath.c_str()), _bstr_t(L"ProtectKeyWithAdSid"), 0, nullptr, pIn, &pOut, nullptr);
		pIn->Release();
		if (FAILED(hr) || !pOut)
		{
			LogError(L"BitLocker: ExecMethod ProtectKeyWithAdSid failed.");
			return false;
		}

		bool ok = HandleReturnValue(pOut, L"Successfully added the SID key protector.");
		pOut->Release();
		return ok;
	}

	// Beginning of DATA COLLECTION Section

	struct WmiObjectReleaser
	{
		IWbemClassObject* obj = nullptr;
		~WmiObjectReleaser() { if (obj) obj->Release(); }
	};

	// Helper: invoke a method with optional inParams; returns output object (caller releases) or nullptr.
	IWbemClassObject* ExecMethodSimple(IWbemServices* svc, const wchar_t* instancePath, const wchar_t* method, IWbemClassObject* inParams)
	{
		if (!svc || !instancePath || !method) return nullptr;
		IWbemClassObject* pOut = nullptr;
		HRESULT hr = svc->ExecMethod(_bstr_t(instancePath), _bstr_t(method), 0, nullptr, inParams, &pOut, nullptr);
		if (FAILED(hr) || !pOut) return nullptr;
		return pOut;
	}

	// Helper: extract unsigned long property safely
	bool ReadULong(IWbemClassObject* obj, const wchar_t* name, unsigned long& outVal)
	{
		if (!obj || !name) return false;
		VARIANT v; VariantInit(&v);
		HRESULT hr = obj->Get(_bstr_t(name), 0, &v, nullptr, nullptr);
		if (FAILED(hr))
		{
			VariantClear(&v);
			return false;
		}
		bool ok = false;
		if (v.vt == VT_I4)
		{
			outVal = static_cast<unsigned long>(v.lVal);
			ok = true;
		}
		else if (v.vt == VT_UI4)
		{
			outVal = v.ulVal;
			ok = true;
		}
		VariantClear(&v);
		return ok;
	}

	// Helper: read BSTR property into wstring
	bool ReadBstr(IWbemClassObject* obj, const wchar_t* name, wstring& outStr)
	{
		if (!obj || !name) return false;
		VARIANT v; VariantInit(&v);
		HRESULT hr = obj->Get(_bstr_t(name), 0, &v, nullptr, nullptr);
		if (FAILED(hr))
		{
			VariantClear(&v);
			return false;
		}
		bool ok = false;
		if (v.vt == VT_BSTR && v.bstrVal)
		{
			outStr.assign(v.bstrVal);
			ok = true;
		}
		VariantClear(&v);
		return ok;
	}

	// Internal: enumerate drive letters via MSFT_Volume (no colon)
	bool EnumerateAllDriveLetters(vector<wstring>& outLetters)
	{
		outLetters.clear();

		IWbemLocator* pLoc = nullptr;
		IWbemServices* pSvc = nullptr;
		bool didInitCOM = false;
		if (!ConnectToWmiNamespace(StorageNamespace, &pLoc, &pSvc, didInitCOM) || !pSvc)
		{
			// Error already logged by helper.
			if (pLoc) pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		IEnumWbemClassObject* pEnum = nullptr;
		HRESULT hr = pSvc->ExecQuery(
			_bstr_t(L"WQL"),
			_bstr_t(L"SELECT DriveLetter FROM MSFT_Volume"),
			WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
			nullptr,
			&pEnum);
		if (FAILED(hr) || !pEnum)
		{
			if (pSvc) pSvc->Release();
			if (pLoc) pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		for (;;)
		{
			IWbemClassObject* pObj = nullptr;
			ULONG uRet = 0;
			hr = pEnum->Next(WBEM_INFINITE, 1, &pObj, &uRet);
			if (hr != S_OK || uRet == 0) break;

			VARIANT v; VariantInit(&v);
			if (SUCCEEDED(pObj->Get(_bstr_t(L"DriveLetter"), 0, &v, nullptr, nullptr)))
			{
				if (v.vt == VT_BSTR && v.bstrVal && *v.bstrVal)
				{
					// Normal string form
					outLetters.emplace_back(v.bstrVal);
				}
				else if (v.vt == VT_I2 || v.vt == VT_UI2 || v.vt == VT_I4 || v.vt == VT_UI4)
				{
					// Numeric code form (e.g. 67 => 'C')
					unsigned long code = 0;
					if (v.vt == VT_I2)      code = static_cast<unsigned short>(v.iVal);
					else if (v.vt == VT_UI2) code = v.uiVal;
					else if (v.vt == VT_I4)  code = static_cast<unsigned long>(v.lVal);
					else if (v.vt == VT_UI4) code = v.ulVal;

					if (code != 0)
					{
						wchar_t ch = static_cast<wchar_t>(code);
						// Accept letters A–Z / a–z only
						if ((ch >= L'A' && ch <= L'Z') || (ch >= L'a' && ch <= L'z'))
						{
							wchar_t buf[2]{ ch, L'\0' };
							outLetters.emplace_back(buf);
						}
					}
				}
				// else: other variant types are ignored (nulls represent volumes without a letter)
			}
			VariantClear(&v);
			pObj->Release();
		}

		pEnum->Release();
		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM) CoUninitialize();

		return true;
	}

	// Populate MSFT_Volume related info (capacity / filesystem / dedup, etc.)
	void PopulateStorageInfo(const wchar_t* driveLetterNoColon, VolumeInfo& info)
	{
		if (!driveLetterNoColon || !*driveLetterNoColon) return;

		IWbemLocator* pLoc = nullptr;
		IWbemServices* pSvc = nullptr;
		bool didInitCOM = false;
		if (!ConnectToWmiNamespace(StorageNamespace, &pLoc, &pSvc, didInitCOM) || !pSvc)
		{
			if (pLoc) pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return;
		}

		wstringstream wql;
		wql << L"SELECT Size, FileSystemType, FileSystemLabel, AllocationUnitSize, ReFSDedupMode "
			<< L"FROM MSFT_Volume WHERE DriveLetter = '" << driveLetterNoColon << L"'";

		IEnumWbemClassObject* pEnum = nullptr;
		HRESULT hr = pSvc->ExecQuery(
			_bstr_t(L"WQL"),
			_bstr_t(wql.str().c_str()),
			WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
			nullptr,
			&pEnum);
		if (FAILED(hr) || !pEnum)
		{
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return;
		}

		IWbemClassObject* pObj = nullptr;
		ULONG uRet = 0;
		hr = pEnum->Next(WBEM_INFINITE, 1, &pObj, &uRet);
		pEnum->Release();
		if (hr != S_OK || uRet == 0)
		{
			if (pSvc) pSvc->Release();
			if (pLoc) pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return;
		}

		// Size -> capacityGB
		VARIANT v; VariantInit(&v);
		if (SUCCEEDED(pObj->Get(_bstr_t(L"Size"), 0, &v, nullptr, nullptr)))
		{
			unsigned long long sizeBytes = 0;
			bool haveSize = false;

			if (v.vt == VT_UI8)
			{
				sizeBytes = v.ullVal;
				haveSize = true;
			}
			else if (v.vt == VT_I8)
			{
				if (v.llVal >= 0)
				{
					sizeBytes = static_cast<unsigned long long>(v.llVal);
					haveSize = true;
				}
			}
			else if (v.vt == VT_UI4)
			{
				sizeBytes = static_cast<unsigned long long>(v.ulVal);
				haveSize = true;
			}
			else if (v.vt == VT_I4)
			{
				if (v.lVal >= 0)
				{
					sizeBytes = static_cast<unsigned long long>(v.lVal);
					haveSize = true;
				}
			}
			else if (v.vt == VT_BSTR && v.bstrVal)
			{
				// Some providers/marshallers may return a numeric CIM UINT64 as a string (BSTR). Handle it.
				const wchar_t* p = v.bstrVal;
				if (p && *p)
				{
					wchar_t* endPtr = nullptr;
					unsigned long long parsed = wcstoull(p, &endPtr, 10);
					if (endPtr != p) // parsed something
					{
						sizeBytes = parsed;
						haveSize = true;
					}
				}
			}

			if (haveSize)
			{
				double gb = static_cast<double>(sizeBytes) / (1024.0 * 1024.0 * 1024.0);
				wchar_t buf[64];
				// Keep 4 decimal places
				swprintf_s(buf, L"%.4f", gb);
				info.capacityGB = buf;
			}
		}
		VariantClear(&v);

		unsigned long fsType = 0;
		if (ReadULong(pObj, L"FileSystemType", fsType))
			info.fileSystemType = static_cast<FileSystemType>(static_cast<unsigned short>(fsType));

		ReadBstr(pObj, L"FileSystemLabel", info.friendlyName);

		// AllocationUnitSize is a numeric (UINT64) in MSFT_Volume
		VariantInit(&v);
		if (SUCCEEDED(pObj->Get(_bstr_t(L"AllocationUnitSize"), 0, &v, nullptr, nullptr)))
		{
			if (v.vt == VT_UI8)
			{
				info.allocationUnitSize = to_wstring(v.ullVal);
			}
			else if (v.vt == VT_I8)
			{
				if (v.llVal >= 0)
					info.allocationUnitSize = to_wstring(static_cast<unsigned long long>(v.llVal));
			}
			else if (v.vt == VT_UI4)
			{
				info.allocationUnitSize = to_wstring(static_cast<unsigned long long>(v.ulVal));
			}
			else if (v.vt == VT_I4)
			{
				if (v.lVal >= 0)
					info.allocationUnitSize = to_wstring(static_cast<long long>(v.lVal));
			}
			else if (v.vt == VT_BSTR && v.bstrVal)
			{
				// Fallback if provided as string
				info.allocationUnitSize = v.bstrVal;
			}
		}
		VariantClear(&v);

		unsigned long dedup = 0;
		if (ReadULong(pObj, L"ReFSDedupMode", dedup))
			info.reFSDedupMode = static_cast<ReFSDedupMode>(dedup);

		pObj->Release();
		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM) CoUninitialize();
	}

	// Retrieve key protector detailed info
	void FillKeyProtectors(IWbemServices* svc, const wstring& instancePath, VolumeInfo& info)
	{
		IWbemClassObject* pIn = SpawnInParams(svc, L"GetKeyProtectors");
		if (!pIn) return;

		// Call without filtering (KeyProtectorType param absent => all)
		IWbemClassObject* pOut = nullptr;
		HRESULT hr = svc->ExecMethod(_bstr_t(instancePath.c_str()), _bstr_t(L"GetKeyProtectors"), 0, nullptr, pIn, &pOut, nullptr);
		pIn->Release();
		if (FAILED(hr) || !pOut) return;

		VARIANT vArr; VariantInit(&vArr);
		if (SUCCEEDED(pOut->Get(_bstr_t(L"VolumeKeyProtectorID"), 0, &vArr, nullptr, nullptr)) &&
			(vArr.vt == (VT_ARRAY | VT_BSTR)) && vArr.parray)
		{
			SAFEARRAY* psa = vArr.parray;
			LONG lBound = 0, uBound = -1;
			if (SUCCEEDED(SafeArrayGetLBound(psa, 1, &lBound)) &&
				SUCCEEDED(SafeArrayGetUBound(psa, 1, &uBound)) &&
				uBound >= lBound)
			{
				for (LONG i = lBound; i <= uBound; ++i)
				{
					BSTR kpId{};
					if (FAILED(SafeArrayGetElement(psa, &i, &kpId)) || !kpId) continue;

					KeyProtectorInfo kp;
					kp.id = kpId;

					// GetKeyProtectorType
					IWbemClassObject* pTypeIn = SpawnInParams(svc, L"GetKeyProtectorType");
					if (pTypeIn)
					{
						SetParamBstr(pTypeIn, L"VolumeKeyProtectorID", kp.id.c_str());
						IWbemClassObject* pTypeOut = nullptr;
						if (SUCCEEDED(svc->ExecMethod(_bstr_t(instancePath.c_str()), _bstr_t(L"GetKeyProtectorType"), 0, nullptr, pTypeIn, &pTypeOut, nullptr)) && pTypeOut)
						{
							unsigned long t = 0;
							ReadULong(pTypeOut, L"KeyProtectorType", t);
							kp.type = static_cast<KeyProtectorType>(t);
							pTypeOut->Release();
						}
						pTypeIn->Release();
					}

					// Recovery password
					if (kp.type == KeyProtectorType::RecoveryPassword)
					{
						IWbemClassObject* pNPIn = SpawnInParams(svc, L"GetKeyProtectorNumericalPassword");
						if (pNPIn)
						{
							SetParamBstr(pNPIn, L"VolumeKeyProtectorID", kp.id.c_str());
							IWbemClassObject* pNPOut = nullptr;
							if (SUCCEEDED(svc->ExecMethod(_bstr_t(instancePath.c_str()), _bstr_t(L"GetKeyProtectorNumericalPassword"), 0, nullptr, pNPIn, &pNPOut, nullptr)) && pNPOut)
							{
								wstring np;
								ReadBstr(pNPOut, L"NumericalPassword", np);
								kp.recoveryPassword = np;
								pNPOut->Release();
							}
							pNPIn->Release();
						}
					}

					// ExternalKey (auto-unlock + filename)
					if (kp.type == KeyProtectorType::ExternalKey)
					{
						// AutoUnlock detection
						IWbemClassObject* pAUOut = ExecMethodSimple(svc, instancePath.c_str(), L"IsAutoUnlockEnabled", nullptr);
						if (pAUOut)
						{
							unsigned long rv = 1;
							ReadULong(pAUOut, L"ReturnValue", rv);
							if (rv == 0)
							{
								VARIANT v; VariantInit(&v);
								if (SUCCEEDED(pAUOut->Get(_bstr_t(L"IsAutoUnlockEnabled"), 0, &v, nullptr, nullptr)) &&
									v.vt == VT_BOOL)
								{
									bool enabled = (v.boolVal == VARIANT_TRUE);
									VariantClear(&v);

									// Confirm same protector
									VARIANT vId; VariantInit(&vId);
									if (SUCCEEDED(pAUOut->Get(_bstr_t(L"VolumeKeyProtectorID"), 0, &vId, nullptr, nullptr)) &&
										vId.vt == VT_BSTR && vId.bstrVal)
									{
										if (enabled && EqualsOrdinalIgnoreCase(vId.bstrVal, kp.id.c_str()))
											kp.autoUnlockProtector = true;
									}
									VariantClear(&vId);
								}
								else
								{
									VariantClear(&v);
								}
							}
							pAUOut->Release();
						}

						// FileName
						IWbemClassObject* pFNIn = SpawnInParams(svc, L"GetExternalKeyFileName");
						if (pFNIn)
						{
							SetParamBstr(pFNIn, L"VolumeKeyProtectorID", kp.id.c_str());
							IWbemClassObject* pFNOut = nullptr;
							if (SUCCEEDED(svc->ExecMethod(_bstr_t(instancePath.c_str()), _bstr_t(L"GetExternalKeyFileName"), 0, nullptr, pFNIn, &pFNOut, nullptr)) && pFNOut)
							{
								ReadBstr(pFNOut, L"FileName", kp.keyFileName);
								pFNOut->Release();
							}
							pFNIn->Release();
						}
					}

					// Certificate (PublicKey / TpmNetworkKey)
					if (kp.type == KeyProtectorType::PublicKey || kp.type == KeyProtectorType::TpmNetworkKey)
					{
						IWbemClassObject* pCertIn = SpawnInParams(svc, L"GetKeyProtectorCertificate");
						if (pCertIn)
						{
							SetParamBstr(pCertIn, L"VolumeKeyProtectorID", kp.id.c_str());
							IWbemClassObject* pCertOut = nullptr;
							if (SUCCEEDED(svc->ExecMethod(_bstr_t(instancePath.c_str()), _bstr_t(L"GetKeyProtectorCertificate"), 0, nullptr, pCertIn, &pCertOut, nullptr)) && pCertOut)
							{
								ReadBstr(pCertOut, L"CertThumbprint", kp.thumbprint);
								ReadBstr(pCertOut, L"CertType", kp.keyCertificateType);
								pCertOut->Release();
							}
							pCertIn->Release();
						}
					}

					info.keyProtectors.push_back(move(kp));
					if (kpId) SysFreeString(kpId);
				}
			}
		}
		VariantClear(&vArr);
		pOut->Release();
	}

	// Core info retrieval
	bool GetVolumeInfo(const wchar_t* driveLetter, VolumeInfo& outInfo)
	{
		// Reset last error buffer at the start of a public API call to ensure consumers
		// only see errors originating from THIS invocation.
		ClearLastErrorMsg();

		// Validate input pointer and content early to avoid any WMI work on bad input.
		if (IsNullOrWhiteSpace(driveLetter))
		{
			SetLastErrorMsg(L"DriveLetter is null or empty.");
			return false;
		}

		// Expect format L"C:" (validate)
		// This strict validation prevents ambiguous inputs like "C", "C:\", or longer paths.
		if (wcslen(driveLetter) != 2 || driveLetter[1] != L':')
		{
			SetLastErrorMsg(L"DriveLetter must be in form L\"C:\"");
			return false;
		}

		// Connect to BitLocker namespace
		// A single RAII connection object is used – each call creates its own connection rather than caching globally
		// to avoid lifetime / thread-affinity complications and to keep the function self-contained.
		WmiConnection conn;
		if (!conn.ok) return false;

		// Locate instance path
		// We must resolve the drive letter to a concrete instance path (__PATH) before invoking instance methods.
		wstring instancePath;
		if (!FindVolumeInstancePath(conn.pSvc, driveLetter, instancePath))
		{
			// Error already logged
			return false;
		}

		// Store the mount point as provided (assumed valid because of earlier checks).
		outInfo.mountPoint = driveLetter;

		// Get base instance (for simple properties)
		// Only properties directly on the Win32_EncryptableVolume class that do NOT require an ExecMethod are fetched here.
		IWbemClassObject* pVol = nullptr;
		HRESULT hr = conn.pSvc->GetObject(_bstr_t(instancePath.c_str()), 0, nullptr, &pVol, nullptr);
		if (SUCCEEDED(hr) && pVol)
		{
			unsigned long tmp = 0;
			if (ReadULong(pVol, L"ProtectionStatus", tmp))
				outInfo.protectionStatus = static_cast<ProtectionStatus>(tmp);
			if (ReadULong(pVol, L"VolumeType", tmp))
				outInfo.volumeType = static_cast<VolumeType>(tmp);
			pVol->Release();
		}

		// Lock status
		// GetLockStatus is an instance method; we call it and only trust the data if ReturnValue == 0 (success).
		if (IWbemClassObject* pLock = ExecMethodSimple(conn.pSvc, instancePath.c_str(), L"GetLockStatus", nullptr))
		{
			unsigned long rv = 1;
			if (ReadULong(pLock, L"ReturnValue", rv) && rv == 0)
			{
				unsigned long ls = 0;
				if (ReadULong(pLock, L"LockStatus", ls))
					outInfo.lockStatus = static_cast<LockStatus>(ls);
			}
			pLock->Release();
		}

		// Conversion status
		// Collects: ConversionStatus, WipingStatus, and both percentage fields.
		if (IWbemClassObject* pConv = ExecMethodSimple(conn.pSvc, instancePath.c_str(), L"GetConversionStatus", nullptr))
		{
			unsigned long rv = 1;
			if (ReadULong(pConv, L"ReturnValue", rv) && rv == 0)
			{
				unsigned long cv = 0;
				if (ReadULong(pConv, L"ConversionStatus", cv))
					outInfo.conversionStatus = static_cast<ConversionStatus>(cv);
				unsigned long wp = 0;
				if (ReadULong(pConv, L"WipingStatus", wp))
					outInfo.wipingStatus = static_cast<WipingStatus>(wp);

				// EncryptionPercentage & WipingPercentage (numeric -> "value.0")
				// This inner lambda normalizes several possible VARIANT numeric forms (and string fallbacks) to a
				// consistent "<integer>.0" textual representation, capping at 100.
				auto readPercentage = [&](const wchar_t* propName, wstring& target)
					{
						VARIANT vPct; VariantInit(&vPct);
						if (SUCCEEDED(pConv->Get(_bstr_t(propName), 0, &vPct, nullptr, nullptr)))
						{
							unsigned long val = 0;
							bool ok = false;
							if (vPct.vt == VT_UI4) { val = vPct.ulVal; ok = true; }
							else if (vPct.vt == VT_I4 && vPct.lVal >= 0) { val = static_cast<unsigned long>(vPct.lVal); ok = true; }
							else if (vPct.vt == VT_UI8) { val = static_cast<unsigned long>(vPct.ullVal > 100ULL ? 100ULL : vPct.ullVal); ok = true; }
							else if (vPct.vt == VT_I8 && vPct.llVal >= 0)
							{
								unsigned long long t = static_cast<unsigned long long>(vPct.llVal);
								val = static_cast<unsigned long>(t > 100ULL ? 100ULL : t);
								ok = true;
							}
							else if (vPct.vt == VT_BSTR && vPct.bstrVal)
							{
								const wchar_t* p = vPct.bstrVal;
								if (p && *p)
								{
									wchar_t* endPtr = nullptr;
									unsigned long parsed = static_cast<unsigned long>(wcstoul(p, &endPtr, 10));
									if (endPtr != p) { val = parsed; ok = true; }
								}
							}
							if (ok)
							{
								if (val > 100) val = 100;
								wchar_t buf[32];
								swprintf_s(buf, L"%u.0", val);
								target = buf;
							}
						}
						VariantClear(&vPct);
					};

				readPercentage(L"EncryptionPercentage", outInfo.encryptionPercentage);
				readPercentage(L"WipingPercentage", outInfo.wipePercentage);
			}
			pConv->Release();
		}

		// Encryption method
		// The ExecMethod returns both EncryptionMethod and EncryptionMethodFlags (which may appear as multiple numeric widths).
		if (IWbemClassObject* pEnc = ExecMethodSimple(conn.pSvc, instancePath.c_str(), L"GetEncryptionMethod", nullptr))
		{
			unsigned long rv = 1;
			if (ReadULong(pEnc, L"ReturnValue", rv) && rv == 0)
			{
				unsigned long em = 0;
				if (ReadULong(pEnc, L"EncryptionMethod", em))
					outInfo.encryptionMethod = static_cast<EncryptionMethod>(em);

				// EncryptionMethodFlags numeric or BSTR -> store as decimal text
				// We preserve the numeric value as string (not parsed to integer type in struct) to keep flexibility during JSON emission.
				VARIANT vFlags; VariantInit(&vFlags);
				if (SUCCEEDED(pEnc->Get(_bstr_t(L"EncryptionMethodFlags"), 0, &vFlags, nullptr, nullptr)))
				{
					if (vFlags.vt == VT_UI8)
						outInfo.encryptionMethodFlags = to_wstring(vFlags.ullVal);
					else if (vFlags.vt == VT_I8 && vFlags.llVal >= 0)
						outInfo.encryptionMethodFlags = to_wstring(static_cast<unsigned long long>(vFlags.llVal));
					else if (vFlags.vt == VT_UI4)
						outInfo.encryptionMethodFlags = to_wstring(static_cast<unsigned long long>(vFlags.ulVal));
					else if (vFlags.vt == VT_I4 && vFlags.lVal >= 0)
						outInfo.encryptionMethodFlags = to_wstring(static_cast<long long>(vFlags.lVal));
					else if (vFlags.vt == VT_BSTR && vFlags.bstrVal)
						outInfo.encryptionMethodFlags = vFlags.bstrVal; // fallback
				}
				VariantClear(&vFlags);
			}
			pEnc->Release();
		}

		// Version
		// GetVersion supplies the MetadataVersion (FVE metadata format version).
		if (IWbemClassObject* pVer = ExecMethodSimple(conn.pSvc, instancePath.c_str(), L"GetVersion", nullptr))
		{
			unsigned long rv = 1;
			if (ReadULong(pVer, L"ReturnValue", rv) && rv == 0)
			{
				unsigned long ver = 0;
				if (ReadULong(pVer, L"Version", ver))
					outInfo.metadataVersion = ver;
			}
			pVer->Release();
		}

		// Key protectors (fills kp.autoUnlock flags)
		// This populates outInfo.keyProtectors and marks individual ExternalKey protectors that correspond to auto-unlock.
		FillKeyProtectors(conn.pSvc, instancePath, outInfo);

		// Aggregate volume-level AutoUnlockEnabled based on any ExternalKey protector flagged autoUnlock.
		// Only one auto-unlock ExternalKey protector is expected; loop breaks early when found.
		for (const auto& kp : outInfo.keyProtectors)
		{
			if (kp.autoUnlockProtector)
			{
				outInfo.autoUnlockEnabled = true;
				break;
			}
		}

		// Retrieve whether an auto-unlock key is stored (distinct from AutoUnlockEnabled).
		// We call the BitLocker WMI method IsAutoUnlockKeyStored. If it returns success (ReturnValue == 0)
		// and the output BOOL is VARIANT_TRUE, we set autoUnlockKeyStored = true. Otherwise we leave it false
		if (IWbemClassObject* pStored = ExecMethodSimple(conn.pSvc, instancePath.c_str(), L"IsAutoUnlockKeyStored", nullptr))
		{
			unsigned long rv = 1;
			if (ReadULong(pStored, L"ReturnValue", rv) && rv == 0)
			{
				VARIANT vStored; VariantInit(&vStored);
				if (SUCCEEDED(pStored->Get(_bstr_t(L"IsAutoUnlockKeyStored"), 0, &vStored, nullptr, nullptr)) &&
					vStored.vt == VT_BOOL && vStored.boolVal == VARIANT_TRUE)
				{
					outInfo.autoUnlockKeyStored = true;
				}
				VariantClear(&vStored);
			}
			pStored->Release();
		}

		// Storage info (DriveLetter without colon)
		// MSFT_Volume expects drive letter WITHOUT colon; only first character is used (validated earlier).
		wchar_t driveChar[3] = { driveLetter[0], L'\0', L'\0' };
		PopulateStorageInfo(driveChar, outInfo);

		return true;
	}

	// Gets the BitLocker info of all of the volumes on the system
	// onlyRemovable: Will only return Removable Drives.
	// onlyNonOS: Will only return Non-OSDrives, excluding Removable Drives.
	bool ListAllVolumes(vector<VolumeInfo>& outList, bool onlyNonOS, bool onlyRemovable)
	{
		// Ensure caller receives a clean container even on failure.
		outList.clear();

		// Enumerate all candidate drive letters via MSFT_Volume (includes unencrypted + encrypted volumes).
		vector<wstring> letters;
		if (!EnumerateAllDriveLetters(letters))
		{
			// Enumeration failure is fatal only if we cannot produce any data at all.
			SetLastErrorMsg(L"Failed to enumerate volumes.");
			return false;
		}

		bool allOk = true; // Tracks whether every GetVolumeInfo succeeded (best-effort semantics).
		for (const auto& dl : letters)
		{
			if (dl.empty()) continue; // Defensive: skip empty entries.

			// Reconstruct drive letter with colon for downstream calls (e.g., "C" -> "C:").
			wstring withColon = dl + L":";

			VolumeInfo vi;
			if (GetVolumeInfo(withColon.c_str(), vi))
			{
				// Apply post-fetch filtering based on flags:
				// onlyNonOS => include only FixedDisk (i.e., non-OS data volumes; OS volume has VolumeType::OperationSystem)
				if (onlyNonOS && vi.volumeType != VolumeType::FixedDisk)
					continue;

				// onlyRemovable => include only Removable
				if (onlyRemovable && vi.volumeType != VolumeType::Removable)
					continue;

				outList.push_back(move(vi));
			}
			else
			{
				// Record that at least one retrieval failed but continue enumerating others.
				allOk = false;
			}
		}

		// Return true if all succeeded OR at least one volume's info could be returned.
		return allOk || !outList.empty();
	}

	bool PrintVolumeInfoJson(const VolumeInfo& info)
	{
		wstringstream jsonOut;
		jsonOut << L"{";
		auto printKVP = [&](const wchar_t* key, const wstring& val, bool& first)
			{
				if (!first) jsonOut << L",";
				first = false;
				wstring esc = Utf8ToWide(escapeJSON(WideToUtf8(val.c_str())));
				jsonOut << L"\"" << key << L"\":\"" << esc << L"\"";
			};
		auto printKVPNum = [&](const wchar_t* key, unsigned long val, bool& first)
			{
				if (!first) jsonOut << L",";
				first = false;
				jsonOut << L"\"" << key << L"\":" << val;
			};
		auto printKVPBool = [&](const wchar_t* key, bool val, bool& first)
			{
				if (!first) jsonOut << L",";
				first = false;
				jsonOut << L"\"" << key << L"\":" << (val ? L"true" : L"false");
			};

		bool first = true;

		// Core scalar fields
		printKVP(L"MountPoint", info.mountPoint, first);
		printKVPNum(L"ProtectionStatus", static_cast<unsigned long>(info.protectionStatus), first);
		printKVPNum(L"VolumeType", static_cast<unsigned long>(info.volumeType), first);
		printKVPNum(L"LockStatus", static_cast<unsigned long>(info.lockStatus), first);
		printKVPNum(L"ConversionStatus", static_cast<unsigned long>(info.conversionStatus), first);
		printKVPNum(L"WipingStatus", static_cast<unsigned long>(info.wipingStatus), first);
		printKVPNum(L"EncryptionMethod", static_cast<unsigned long>(info.encryptionMethod), first);
		printKVP(L"EncryptionMethodFlags", info.encryptionMethodFlags, first);
		printKVP(L"EncryptionPercentage", info.encryptionPercentage, first);
		printKVP(L"WipePercentage", info.wipePercentage, first);
		printKVPNum(L"MetadataVersion", info.metadataVersion, first);
		printKVPBool(L"AutoUnlockEnabled", info.autoUnlockEnabled, first);
		printKVPBool(L"AutoUnlockKeyStored", info.autoUnlockKeyStored, first);
		printKVP(L"CapacityGB", info.capacityGB, first);
		printKVPNum(L"FileSystemType", static_cast<unsigned long>(info.fileSystemType), first);
		printKVP(L"FriendlyName", info.friendlyName, first);
		printKVP(L"AllocationUnitSize", info.allocationUnitSize, first);
		printKVPNum(L"ReFSDedupMode", static_cast<unsigned long>(info.reFSDedupMode), first);

		if (!first) jsonOut << L",";
		first = false;
		jsonOut << L"\"KeyProtectors\":[";
		for (size_t i = 0; i < info.keyProtectors.size(); ++i)
		{
			const auto& kp = info.keyProtectors[i];
			if (i != 0) jsonOut << L",";

			jsonOut << L"{";
			bool firstKP = true;
			auto kvpKPStr = [&](const wchar_t* k, const wstring& v)
				{
					if (!firstKP) jsonOut << L",";
					firstKP = false;
					wstring esc = Utf8ToWide(escapeJSON(WideToUtf8(v.c_str())));
					jsonOut << L"\"" << k << L"\":\"" << esc << L"\"";
				};
			auto kvpKPNum = [&](const wchar_t* k, unsigned long v)
				{
					if (!firstKP) jsonOut << L",";
					firstKP = false;
					jsonOut << L"\"" << k << L"\":" << v;
				};
			auto kvpKPBool = [&](const wchar_t* k, bool v)
				{
					if (!firstKP) jsonOut << L",";
					firstKP = false;
					jsonOut << L"\"" << k << L"\":" << (v ? L"true" : L"false");
				};

			kvpKPNum(L"Type", static_cast<unsigned long>(kp.type));
			kvpKPStr(L"ID", kp.id);
			kvpKPBool(L"AutoUnlockProtector", kp.autoUnlockProtector);
			kvpKPStr(L"KeyFileName", kp.keyFileName);
			kvpKPStr(L"RecoveryPassword", kp.recoveryPassword);
			kvpKPStr(L"KeyCertificateType", kp.keyCertificateType);
			kvpKPStr(L"Thumbprint", kp.thumbprint);

			jsonOut << L"}";
		}
		jsonOut << L"]";
		jsonOut << L"}";
		LogOut(jsonOut.str().c_str());
		return true;
	}

	bool PrintVolumeListJson(const vector<VolumeInfo>& list)
	{
		// Begin JSON array for the list of volumes.
		LogOut(L"[");
		for (size_t i = 0; i < list.size(); ++i)
		{
			// Emit comma before every element except the first for valid JSON.
			if (i != 0) LogOut(L",");
			(void)PrintVolumeInfoJson(list[i]); // Reuse single-volume serializer.
		}
		LogOut(L"]");
		return true;
	}

	// Helper: format a Win32 / BitLocker return value into a string (decimal + hex)
	wstring FormatReturnCode(unsigned long code)
	{
		wstringstream ss;
		ss << L"(ReturnValue=" << code << L", 0x" << hex << uppercase << code << L")";
		return ss.str();
	}


	// Executes a Win32_Tpm boolean status method (e.g., "IsEnabled") and extracts
	// the boolean output property with the same name.
	// Returns true only if the method invocation succeeded (ReturnValue == 0)
	// and the output property was present and VT_BOOL.
	static bool ExecTpmBool(
		IWbemServices* svc,
		const wchar_t* instancePath,
		const wchar_t* methodName,
		bool& outVal)
	{
		outVal = false;
		if (!svc || !instancePath || !methodName)
			return false;

		IWbemClassObject* pOut = nullptr;
		HRESULT hr = svc->ExecMethod(
			_bstr_t(instancePath),
			_bstr_t(methodName),
			0, nullptr, nullptr, &pOut, nullptr);
		if (FAILED(hr) || !pOut)
			return false;

		unsigned long rv = 1;
		ReadULong(pOut, L"ReturnValue", rv);
		if (rv != 0)
		{
			pOut->Release();
			return false;
		}

		VARIANT v; VariantInit(&v);
		bool ok = false;
		if (SUCCEEDED(pOut->Get(_bstr_t(methodName), 0, &v, nullptr, nullptr)) &&
			v.vt == VT_BOOL)
		{
			outVal = (v.boolVal == VARIANT_TRUE);
			ok = true;
		}
		VariantClear(&v);
		pOut->Release();
		return ok;
	}

	// Success only if all four TPM readiness booleans are TRUE and their method calls succeeded.
	bool IsTpmReady(bool* isEnabled, bool* isOwned, bool* isActivated, bool* isSrkAuthCompatible)
	{
		if (isEnabled) *isEnabled = false;
		if (isOwned) *isOwned = false;
		if (isActivated) *isActivated = false;
		if (isSrkAuthCompatible) *isSrkAuthCompatible = false;

		IWbemLocator* pLoc = nullptr;
		IWbemServices* pSvc = nullptr;
		bool didInitCOM = false;
		if (!ConnectToWmiNamespace(TpmNamespace, &pLoc, &pSvc, didInitCOM) || !pSvc)
		{
			if (pLoc) pLoc->Release();
			if (pSvc) pSvc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		IEnumWbemClassObject* pEnum = nullptr;
		HRESULT hr = pSvc->ExecQuery(
			_bstr_t(L"WQL"),
			_bstr_t(L"SELECT __PATH FROM Win32_Tpm"),
			WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
			nullptr,
			&pEnum);
		if (FAILED(hr) || !pEnum)
		{
			if (pEnum) pEnum->Release();
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		IWbemClassObject* pObj = nullptr;
		ULONG uRet = 0;
		hr = pEnum->Next(WBEM_INFINITE, 1, &pObj, &uRet);
		if (hr != S_OK || uRet == 0 || !pObj)
		{
			if (pObj) pObj->Release();
			pEnum->Release();
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		wstring tpmPath;
		VARIANT vPath; VariantInit(&vPath);
		if (SUCCEEDED(pObj->Get(_bstr_t(L"__PATH"), 0, &vPath, nullptr, nullptr)) &&
			vPath.vt == VT_BSTR && vPath.bstrVal)
		{
			tpmPath.assign(vPath.bstrVal);
		}
		VariantClear(&vPath);
		pObj->Release();
		pEnum->Release();

		if (tpmPath.empty())
		{
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		bool enabled = false, owned = false, activated = false, srk = false;
		bool okEnabled = ExecTpmBool(pSvc, tpmPath.c_str(), L"IsEnabled", enabled);
		bool okOwned = ExecTpmBool(pSvc, tpmPath.c_str(), L"IsOwned", owned);
		bool okActivated = ExecTpmBool(pSvc, tpmPath.c_str(), L"IsActivated", activated);
		bool okSrk = ExecTpmBool(pSvc, tpmPath.c_str(), L"IsSrkAuthCompatible", srk);

		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM) CoUninitialize();

		if (okEnabled && okOwned && okActivated && okSrk &&
			enabled && owned && activated && srk)
		{
			if (isEnabled) *isEnabled = enabled;
			if (isOwned) *isOwned = owned;
			if (isActivated) *isActivated = activated;
			if (isSrkAuthCompatible) *isSrkAuthCompatible = srk;
			return true;
		}
		return false;
	}

	// Not WinPE -> true.
	// WinPE -> require IsEnabled && IsActivated (only).
	bool IsSystemEntropyReady()
	{
		HKEY hKey;
		LSTATUS ls = RegOpenKeyExW(
			HKEY_LOCAL_MACHINE,
			L"SYSTEM\\CurrentControlSet\\Control\\MiniNT",
			0, KEY_READ, &hKey);

		if (ls != ERROR_SUCCESS)
		{
			// Not WinPE
			return true;
		}
		RegCloseKey(hKey); // In WinPE

		IWbemLocator* pLoc = nullptr;
		IWbemServices* pSvc = nullptr;
		bool didInitCOM = false;
		if (!ConnectToWmiNamespace(TpmNamespace, &pLoc, &pSvc, didInitCOM) || !pSvc)
		{
			if (pLoc) pLoc->Release();
			if (pSvc) pSvc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		IEnumWbemClassObject* pEnum = nullptr;
		HRESULT hr = pSvc->ExecQuery(
			_bstr_t(L"WQL"),
			_bstr_t(L"SELECT __PATH FROM Win32_Tpm"),
			WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
			nullptr,
			&pEnum);
		if (FAILED(hr) || !pEnum)
		{
			if (pEnum) pEnum->Release();
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		IWbemClassObject* pObj = nullptr;
		ULONG uRet = 0;
		hr = pEnum->Next(WBEM_INFINITE, 1, &pObj, &uRet);
		if (hr != S_OK || uRet == 0 || !pObj)
		{
			if (pObj) pObj->Release();
			pEnum->Release();
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		wstring tpmPath;
		VARIANT vPath; VariantInit(&vPath);
		if (SUCCEEDED(pObj->Get(_bstr_t(L"__PATH"), 0, &vPath, nullptr, nullptr)) &&
			vPath.vt == VT_BSTR && vPath.bstrVal)
		{
			tpmPath.assign(vPath.bstrVal);
		}
		VariantClear(&vPath);
		pObj->Release();
		pEnum->Release();

		bool isEnabled = false;
		bool isActivated = false;
		bool okEnabled = false;
		bool okActivated = false;

		if (!tpmPath.empty())
		{
			okEnabled = ExecTpmBool(pSvc, tpmPath.c_str(), L"IsEnabled", isEnabled);
			okActivated = ExecTpmBool(pSvc, tpmPath.c_str(), L"IsActivated", isActivated);
		}

		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM) CoUninitialize();

		return okEnabled && okActivated && isEnabled && isActivated;
	}
}
