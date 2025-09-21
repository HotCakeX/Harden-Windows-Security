#include "BitLockerSuspend.h"
#include "..\Globals.h"
#include "..\StringUtilities.h"
#include "BitLockerManager.h"
#include "BitLockerEnableKeyProtectors.h"
#include "..\ComHelpers.h"
#include <Wbemidl.h>
#include <comdef.h>
#include <sstream>
#include <iostream>

using namespace std;

namespace BitLocker {

	// If a reboot count is supplied, pass DisableCount; otherwise call method without params.
	[[nodiscard]] bool SuspendKeyProtectors(const wchar_t* driveLetter, int rebootCount)
	{
		ClearLastErrorMsg();

		// Validate drive letter (pattern L"C:")
		if (!driveLetter || wcslen(driveLetter) != 2 || driveLetter[1] != L':')
		{
			SetLastErrorMsg(L"DriveLetter must be in the form L\"C:\"");
			return false;
		}

		// Validate rebootCount range when specified
		if (rebootCount < -1 || rebootCount > 15)
		{
			SetLastErrorMsg(L"RebootCount must be between 0 and 15, or -1 for default.");
			return false;
		}

		// Connect to BitLocker WMI namespace.
		IWbemLocator* pLoc = nullptr;
		IWbemServices* pSvc = nullptr;
		bool didInitCOM = false;
		if (!ConnectToWmiNamespace(WmiNamespace, &pLoc, &pSvc, didInitCOM) || !pSvc)
		{
			if (pLoc) pLoc->Release();
			if (pSvc) pSvc->Release();
			return false; // Error already set by helper.
		}

		// Resolve instance path for the target volume.
		wstring instancePath;
		if (!FindVolumeInstancePath(pSvc, driveLetter, instancePath))
		{
			SetLastErrorMsg(L"Failed to locate the BitLocker volume instance path.");
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		// Prepare input parameters only if rebootCount is explicitly specified.
		IWbemClassObject* pIn = nullptr;
		if (rebootCount >= 0)
		{
			pIn = SpawnInParams(pSvc, L"DisableKeyProtectors");
			if (!pIn)
			{
				SetLastErrorMsg(L"Failed to prepare parameters for DisableKeyProtectors.");
				pSvc->Release();
				pLoc->Release();
				if (!g_skipCOMInit && didInitCOM) CoUninitialize();
				return false;
			}
			if (!SetParamUint32(pIn, L"DisableCount", static_cast<unsigned long>(rebootCount)))
			{
				pIn->Release();
				SetLastErrorMsg(L"Failed to set DisableCount parameter for DisableKeyProtectors.");
				pSvc->Release();
				pLoc->Release();
				if (!g_skipCOMInit && didInitCOM) CoUninitialize();
				return false;
			}
		}

		// Execute DisableKeyProtectors.
		IWbemClassObject* pOut = nullptr;
		HRESULT hr = pSvc->ExecMethod(
			_bstr_t(instancePath.c_str()),
			_bstr_t(L"DisableKeyProtectors"),
			0,
			nullptr,
			pIn,
			&pOut,
			nullptr);

		if (pIn) pIn->Release();

		if (FAILED(hr) || !pOut)
		{
			SetLastErrorMsg(L"ExecMethod DisableKeyProtectors failed.");
			if (pOut) pOut->Release();
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		// Extract ReturnValue.
		unsigned long rv = static_cast<unsigned long>(-1);
		VARIANT vRet; VariantInit(&vRet);
		if (SUCCEEDED(pOut->Get(_bstr_t(L"ReturnValue"), 0, &vRet, nullptr, nullptr)))
		{
			if (vRet.vt == VT_I4) rv = static_cast<unsigned long>(vRet.lVal);
			else if (vRet.vt == VT_UI4) rv = vRet.ulVal;
		}
		VariantClear(&vRet);
		pOut->Release();

		if (rv != 0)
		{
			wstringstream ss;
			ss << L"DisableKeyProtectors failed " << FormatReturnCode(rv);
			SetLastErrorMsg(ss.str());
			LogErr(ss.str());
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		// Success message (distinct if reboot count specified).
		if (rebootCount >= 0)
		{
			LogOut(
				L"Successfully suspended key protectors for drive ",
				driveLetter,
				L" (auto-resume after ",
				rebootCount,
				(rebootCount == 1 ? L" reboot)." : L" reboots).")
			);
		}
		else
		{
			LogOut(L"Successfully suspended key protectors for drive ", driveLetter, L".");
		}

		// Cleanup
		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM) CoUninitialize();
		return true;
	}
}
