#include "BitLockerEnableAutoUnlock.h"
#include "BitLockerManager.h"
#include "BitLockerRemoveKeyProtector.h"
#include "..\ComHelpers.h"
#include "..\Globals.h"
#include "..\StringUtilities.h"
#include <Wbemidl.h>
#include <comdef.h>
#include <sstream>
#include <iostream>

using namespace std;

namespace BitLocker {

	// Enables Auto unlock | Suitable for Non-OS Drives
	// https://learn.microsoft.com/windows/win32/secprov/isautounlockenabled-win32-encryptablevolume
	// https://learn.microsoft.com/windows/win32/secprov/enableautounlock-win32-encryptablevolume
	[[nodiscard]] bool EnableAutoUnlock(const wchar_t* driveLetter)
	{
		// Reset last error for this public API invocation.
		ClearLastErrorMsg();

		// Validate drive letter strictly (must match pattern L"C:")
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
			// Error already populated by helper
			if (pLoc) pLoc->Release();
			if (pSvc) pSvc->Release();
			return false;
		}

		// Resolve volume instance path (__PATH) from drive letter.
		wstring instancePath;
		if (!FindVolumeInstancePath(pSvc, driveLetter, instancePath))
		{
			SetLastErrorMsg(L"Failed to locate the BitLocker volume instance path.");
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		// 1. Query IsAutoUnlockEnabled.
		IWbemClassObject* pIsIn = SpawnInParams(pSvc, L"IsAutoUnlockEnabled");
		IWbemClassObject* pIsOut = nullptr;
		HRESULT hr = pSvc->ExecMethod(
			_bstr_t(instancePath.c_str()),
			_bstr_t(L"IsAutoUnlockEnabled"),
			0,
			nullptr,
			pIsIn,
			&pIsOut,
			nullptr);
		if (pIsIn) pIsIn->Release();

		if (FAILED(hr) || !pIsOut)
		{
			SetLastErrorMsg(L"ExecMethod IsAutoUnlockEnabled failed.");
			if (pIsOut) pIsOut->Release();
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		// Extract ReturnValue
		unsigned long rv = static_cast<unsigned long>(-1);
		{
			VARIANT vRet; VariantInit(&vRet);
			if (SUCCEEDED(pIsOut->Get(_bstr_t(L"ReturnValue"), 0, &vRet, nullptr, nullptr)))
			{
				if (vRet.vt == VT_I4) rv = static_cast<unsigned long>(vRet.lVal);
				else if (vRet.vt == VT_UI4) rv = vRet.ulVal;
			}
			VariantClear(&vRet);
		}

		if (rv == 0)
		{
			LogOut(L"Successfully queried the Auto-unlock status of the drive ", driveLetter, L".");
		}
		else
		{
			wstringstream ss;
			ss << L"IsAutoUnlockEnabled failed " << FormatReturnCode(rv);
			SetLastErrorMsg(ss.str());
			LogErr(ss.str().c_str());
			pIsOut->Release();
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		// Check current status (property IsAutoUnlockEnabled) - only meaningful when ReturnValue == 0.
		bool alreadyEnabled = false;
		{
			VARIANT vState; VariantInit(&vState);
			if (SUCCEEDED(pIsOut->Get(_bstr_t(L"IsAutoUnlockEnabled"), 0, &vState, nullptr, nullptr)) && vState.vt == VT_BOOL)
			{
				alreadyEnabled = (vState.boolVal == VARIANT_TRUE);
			}
			VariantClear(&vState);
		}
		pIsOut->Release();

		if (alreadyEnabled)
		{
			LogOut(L"Auto-unlock is already enabled on the drive ", driveLetter, L".");
			// Cleanup
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return true;
		}

		LogOut(L"Auto-unlock is not enabled on the drive ", driveLetter, L", enabling it now.");

		// 2. Add ExternalKey key protector (ProtectKeyWithExternalKey).
		IWbemClassObject* pExtIn = SpawnInParams(pSvc, L"ProtectKeyWithExternalKey");
		if (!pExtIn)
		{
			SetLastErrorMsg(L"Failed to prepare parameters for ProtectKeyWithExternalKey.");
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		if (!SetParamNull(pExtIn, L"FriendlyName") ||
			!SetParamNull(pExtIn, L"ExternalKey"))
		{
			pExtIn->Release();
			SetLastErrorMsg(L"Failed to set parameters for ProtectKeyWithExternalKey.");
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		IWbemClassObject* pExtOut = nullptr;
		hr = pSvc->ExecMethod(
			_bstr_t(instancePath.c_str()),
			_bstr_t(L"ProtectKeyWithExternalKey"),
			0,
			nullptr,
			pExtIn,
			&pExtOut,
			nullptr);
		pExtIn->Release();

		if (FAILED(hr) || !pExtOut)
		{
			SetLastErrorMsg(L"ExecMethod ProtectKeyWithExternalKey failed.");
			if (pExtOut) pExtOut->Release();
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		unsigned long pkRv = static_cast<unsigned long>(-1);
		{
			VARIANT vRet; VariantInit(&vRet);
			if (SUCCEEDED(pExtOut->Get(_bstr_t(L"ReturnValue"), 0, &vRet, nullptr, nullptr)))
			{
				if (vRet.vt == VT_I4) pkRv = static_cast<unsigned long>(vRet.lVal);
				else if (vRet.vt == VT_UI4) pkRv = vRet.ulVal;
			}
			VariantClear(&vRet);
		}

		if (pkRv != 0)
		{
			wstringstream ss;
			ss << L"ProtectKeyWithExternalKey failed " << FormatReturnCode(pkRv);
			SetLastErrorMsg(ss.str());
			LogErr(ss.str().c_str());
			pExtOut->Release();
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		LogOut(L"The ExternalKey key protector was successfully added.");

		// Retrieve VolumeKeyProtectorID from output for next step.
		wstring protectorId;
		if (!GetProtectorId(pExtOut, protectorId) || protectorId.empty())
		{
			pExtOut->Release();
			SetLastErrorMsg(L"Failed to retrieve VolumeKeyProtectorID after adding ExternalKey protector.");
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}
		pExtOut->Release();

		// 3. EnableAutoUnlock with VolumeKeyProtectorID.
		IWbemClassObject* pEnableIn = SpawnInParams(pSvc, L"EnableAutoUnlock");
		if (!pEnableIn)
		{
			SetLastErrorMsg(L"Failed to prepare parameters for EnableAutoUnlock.");
			// Remove previously added protector (best-effort; result intentionally ignored).
			const bool removed = RemoveKeyProtector(driveLetter, protectorId.c_str(), false);
			(void)removed;
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		if (!SetParamBstr(pEnableIn, L"VolumeKeyProtectorID", protectorId.c_str()))
		{
			pEnableIn->Release();
			SetLastErrorMsg(L"Failed to set VolumeKeyProtectorID for EnableAutoUnlock.");
			// Best-effort cleanup of the previously added protector; ignore its success.
			const bool removed = RemoveKeyProtector(driveLetter, protectorId.c_str(), false);
			(void)removed;
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		IWbemClassObject* pEnableOut = nullptr;
		hr = pSvc->ExecMethod(
			_bstr_t(instancePath.c_str()),
			_bstr_t(L"EnableAutoUnlock"),
			0,
			nullptr,
			pEnableIn,
			&pEnableOut,
			nullptr);
		pEnableIn->Release();

		if (FAILED(hr) || !pEnableOut)
		{
			SetLastErrorMsg(L"ExecMethod EnableAutoUnlock failed.");
			// Attempt to remove the protector (ignore result).
			const bool removed = RemoveKeyProtector(driveLetter, protectorId.c_str(), false);
			(void)removed;
			if (pEnableOut) pEnableOut->Release();
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		unsigned long eaRv = static_cast<unsigned long>(-1);
		{
			VARIANT vRet; VariantInit(&vRet);
			if (SUCCEEDED(pEnableOut->Get(_bstr_t(L"ReturnValue"), 0, &vRet, nullptr, nullptr)))
			{
				if (vRet.vt == VT_I4) eaRv = static_cast<unsigned long>(vRet.lVal);
				else if (vRet.vt == VT_UI4) eaRv = vRet.ulVal;
			}
			VariantClear(&vRet);
		}

		if (eaRv != 0)
		{
			wstringstream ss;
			ss << L"EnableAutoUnlock failed " << FormatReturnCode(eaRv);
			SetLastErrorMsg(ss.str());
			LogErr(ss.str().c_str());

			pEnableOut->Release();

			// Remove the external key protector added earlier (best-effort; ignore result).
			LogErr(L"Error enabling Auto-Unlock; removing previously added ExternalKey key protector.");
			const bool removed = RemoveKeyProtector(driveLetter, protectorId.c_str(), false);
			(void)removed;

			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		pEnableOut->Release();

		LogOut(L"Auto-Unlock has been successfully enabled for the drive: ", driveLetter);

		// Cleanup COM objects.
		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM) CoUninitialize();

		return true;
	}
}
