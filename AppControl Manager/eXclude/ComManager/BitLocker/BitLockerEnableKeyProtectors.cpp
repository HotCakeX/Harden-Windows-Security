#include "BitLockerEnableKeyProtectors.h"
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

	// Enables (Resumes) the key protectors of an encrypted volume, doesn't decrypt or encrypt the drive.
	// The drive can remain encrypted and you use Suspend-BitLocker cmdlet to turn the protection off.
	// After using this method, the "Protection Status" will be on.
	// Same as Resume-BitLocker PowerShell cmdlet.
	// This method must run at the end of the operation when turning on (enabling) BitLocker for the OS drive when it's fully decrypted and has no key protectors.
	// It can run on a drive where key protectors are already enabled, won't change anything.
	// https://learn.microsoft.com/windows/win32/secprov/enablekeyprotectors-win32-encryptablevolume
	[[nodiscard]] bool EnableKeyProtectors(const wchar_t* driveLetter)
	{
		// Reset last error buffer for this public API call.
		ClearLastErrorMsg();

		// Basic validation.
		if (!driveLetter || wcslen(driveLetter) != 2 || driveLetter[1] != L':')
		{
			SetLastErrorMsg(L"DriveLetter must be in the form L\"C:\"");
			return false;
		}

		// Connect to BitLocker WMI namespace.
		IWbemLocator* pLoc = nullptr;
		IWbemServices* pSvc = nullptr;
		bool didInitCOM = false;
		if (!ConnectToWmiNamespace(WmiNamespace, &pLoc, &pSvc, didInitCOM) || !pSvc)
		{
			// Error already populated by helper.
			if (pLoc) pLoc->Release();
			if (pSvc) pSvc->Release();
			return false;
		}

		// Resolve instance path for the specified drive.
		wstring instancePath;
		if (!FindVolumeInstancePath(pSvc, driveLetter, instancePath))
		{
			SetLastErrorMsg(L"Failed to locate the BitLocker volume instance path.");
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		// Invoke EnableKeyProtectors (no input parameters).
		IWbemClassObject* pOut = nullptr;
		HRESULT hr = pSvc->ExecMethod(_bstr_t(instancePath.c_str()),
			_bstr_t(L"EnableKeyProtectors"),
			0,
			nullptr,
			nullptr,
			&pOut,
			nullptr);

		if (FAILED(hr) || !pOut)
		{
			SetLastErrorMsg(L"ExecMethod EnableKeyProtectors failed.");
			if (pOut) pOut->Release();
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		// Extract ReturnValue.
		unsigned long rv = static_cast<unsigned long>(-1);
		VARIANT vRet;
		VariantInit(&vRet);
		if (SUCCEEDED(pOut->Get(_bstr_t(L"ReturnValue"), 0, &vRet, nullptr, nullptr)))
		{
			if (vRet.vt == VT_I4)
				rv = static_cast<unsigned long>(vRet.lVal);
			else if (vRet.vt == VT_UI4)
				rv = vRet.ulVal;
		}
		VariantClear(&vRet);

		// Release output object.
		pOut->Release();

		bool success = false;
		if (rv == 0)
		{
			LogOut(L"Successfully enabled the key protectors of the drive ", driveLetter, L".");
			success = true;
		}
		else
		{
			wstringstream ss;
			ss << L"EnableKeyProtectors failed " << FormatReturnCode(rv);
			SetLastErrorMsg(ss.str());
			LogErr(ss.str().c_str());
			success = false;
		}

		// Cleanup COM objects.
		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM) CoUninitialize();

		return success;
	}
}
