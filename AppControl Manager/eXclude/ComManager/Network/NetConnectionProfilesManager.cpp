#include <windows.h>
#include <vector>
#include <string>
#include <sstream>
#include "../Globals.h"
#include "../StringUtilities.h"
#include "../ComHelpers.h"
#include "../Firewall/FirewallManager.h"

using namespace std;

namespace NetworkProfiles
{
	// WMI namespace and class for network connection profiles
	static constexpr const wchar_t* HWS_WMI_NS_STANDARDCIMV2 = L"root\\StandardCimv2";
	static constexpr const wchar_t* HWS_WMI_NET_CONNECTION_PROFILE = L"MSFT_NetConnectionProfile";

	// NetworkCategory Enum:
	// 0 = Public
	// 1 = Private
	// 2 = DomainAuthenticated (read-only; cannot be set manually)
	//
	// Internal enumeration helper:
	//   Collects the __PATH of each MSFT_NetConnectionProfile instance and computes whether all are Public.
	//   Outputs:
	//     anyFound: true if at least one instance enumerated
	//     allPublic: true if every instance has NetworkCategory==0; false if any differ
	//     paths: vector of __PATH strings for later modification
	//   Returns true on successful enumeration, false on failure (error set).
	static bool EnumerateConnectionProfiles(IWbemServices* pSvc,
		bool& anyFound,
		bool& allPublic,
		vector<wstring>& paths)
	{
		anyFound = false;
		allPublic = true;
		paths.clear();
		if (!pSvc) return false;

		IEnumWbemClassObject* pEnum = nullptr;
		HRESULT hr = pSvc->ExecQuery(
			_bstr_t(L"WQL"),
			// Projection includes only needed properties; __PATH used to re-fetch full instance when modifying.
			_bstr_t(L"SELECT __PATH, NetworkCategory FROM MSFT_NetConnectionProfile"),
			WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
			nullptr,
			&pEnum);
		if (FAILED(hr) || !pEnum)
		{
			SetLastErrorMsg(L"ExecQuery for MSFT_NetConnectionProfile failed.");
			if (pEnum) pEnum->Release();
			return false;
		}

		for (;;)
		{
			IWbemClassObject* pObj = nullptr;
			ULONG uRet = 0;
			HRESULT hrNext = pEnum->Next(WBEM_INFINITE, 1, &pObj, &uRet);
			if (hrNext != S_OK || uRet == 0 || !pObj)
				break;

			anyFound = true;

			// Read NetworkCategory
			bool isPublic = false;
			{
				VARIANT v; VariantInit(&v);
				if (SUCCEEDED(pObj->Get(_bstr_t(L"NetworkCategory"), 0, &v, nullptr, nullptr)))
				{
					long catVal = -1;
					switch (v.vt)
					{
					case VT_I2: catVal = v.iVal; break;
					case VT_UI2: catVal = v.uiVal; break;
					case VT_I4: catVal = v.lVal; break;
					case VT_UI4: catVal = static_cast<long>(v.ulVal); break;
					case VT_BSTR:
						if (v.bstrVal)
						{
							if (EqualsOrdinalIgnoreCase(v.bstrVal, L"0")) catVal = 0;
							else if (EqualsOrdinalIgnoreCase(v.bstrVal, L"1")) catVal = 1;
							else if (EqualsOrdinalIgnoreCase(v.bstrVal, L"2")) catVal = 2;
						}
						break;
					default: break;
					}
					isPublic = (catVal == 0);
				}
				VariantClear(&v);
			}
			if (!isPublic)
			{
				allPublic = false;
			}

			// Capture __PATH
			VARIANT vPath; VariantInit(&vPath);
			if (SUCCEEDED(pObj->Get(_bstr_t(L"__PATH"), 0, &vPath, nullptr, nullptr)) &&
				vPath.vt == VT_BSTR && vPath.bstrVal)
			{
				paths.emplace_back(vPath.bstrVal);
			}
			VariantClear(&vPath);

			pObj->Release();
		}

		pEnum->Release();
		return true;
	}

	extern "C" __declspec(dllexport) bool __stdcall NET_AreAllNetworkLocationsPublic()
	{
		ClearLastErrorMsg();

		IWbemLocator* pLoc = nullptr;
		IWbemServices* pSvc = nullptr;
		bool didInitCOM = false;
		if (!ConnectToWmiNamespace(HWS_WMI_NS_STANDARDCIMV2, &pLoc, &pSvc, didInitCOM) || !pSvc)
		{
			if (pLoc) pLoc->Release();
			if (pSvc) pSvc->Release();
			return false;
		}

		bool anyFound = false;
		bool allPublic = true;
		vector<wstring> paths;
		bool okEnum = EnumerateConnectionProfiles(pSvc, anyFound, allPublic, paths);

		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM) CoUninitialize();

		if (!okEnum)
		{
			return false; // error set
		}

		// If none found, treat as true (no profile violates "Public")
		if (!anyFound)
		{
			return true;
		}

		return allPublic;
	}

	extern "C" __declspec(dllexport) bool __stdcall NET_SetAllNetworkLocationsCategory(int category)
	{
		ClearLastErrorMsg();

		// Validate category (0=Public,1=Private); 2 is read-only and cannot be set manually which is for Domain.
		if (category < 0 || category > 1)
		{
			if (category == 2)
			{
				SetLastErrorMsg(L"DomainAuthenticated (2) cannot be set manually; it is assigned automatically by Windows.");
			}
			else
			{
				SetLastErrorMsg(L"Category must be 0 (Public) or 1 (Private).");
			}
			return false;
		}

		IWbemLocator* pLoc = nullptr;
		IWbemServices* pSvc = nullptr;
		bool didInitCOM = false;
		if (!ConnectToWmiNamespace(HWS_WMI_NS_STANDARDCIMV2, &pLoc, &pSvc, didInitCOM) || !pSvc)
		{
			if (pLoc) pLoc->Release();
			if (pSvc) pSvc->Release();
			return false;
		}

		bool anyFound = false;
		bool allPublicIgnore = true;
		vector<wstring> paths;
		if (!EnumerateConnectionProfiles(pSvc, anyFound, allPublicIgnore, paths))
		{
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		// If none found -> success (nothing to modify)
		if (!anyFound)
		{
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return true;
		}

		bool allOk = true;

		for (const wstring& path : paths)
		{
			if (path.empty()) continue;

			IWbemClassObject* pFull = nullptr;
			HRESULT hrGet = pSvc->GetObject(_bstr_t(path.c_str()), 0, nullptr, &pFull, nullptr);
			if (FAILED(hrGet) || !pFull)
			{
				allOk = false;
				std::string hex = ErrorCodeHexString(hrGet);
				wstring whex = Utf8ToWide(hex);
				std::wstringstream wss;
				wss << L"Failed to retrieve full connection profile instance. HRESULT=" << whex
					<< L" Msg=" << _com_error(hrGet).ErrorMessage();
				SetLastErrorMsg(wss.str());
				LogErr(wss.str().c_str());
				if (pFull) pFull->Release();
				continue;
			}

			VARIANT vSet; VariantInit(&vSet);
			vSet.vt = VT_I4;
			vSet.lVal = static_cast<LONG>(category);

			HRESULT hrPutProp = pFull->Put(_bstr_t(L"NetworkCategory"), 0, &vSet, 0);
			VariantClear(&vSet);
			if (FAILED(hrPutProp))
			{
				allOk = false;
				std::string hex = ErrorCodeHexString(hrPutProp);
				wstring whex = Utf8ToWide(hex);
				std::wstringstream wss;
				wss << L"Failed to set NetworkCategory property. HRESULT=" << whex
					<< L" Msg=" << _com_error(hrPutProp).ErrorMessage();
				SetLastErrorMsg(wss.str());
				LogErr(wss.str().c_str());
				pFull->Release();
				continue;
			}

			// Commit with transient retry
			const int kMaxAttempts = 8;
			DWORD delayMs = 100;
			HRESULT hrCommit = E_FAIL;
			for (int attempt = 1; attempt <= kMaxAttempts; ++attempt)
			{
				hrCommit = pSvc->PutInstance(pFull, WBEM_FLAG_UPDATE_ONLY, nullptr, nullptr);
				if (SUCCEEDED(hrCommit))
					break;
				if (!Firewall::IsTransientHresult(hrCommit))
					break;
				::Sleep(delayMs);
				if (delayMs < 2000) delayMs <<= 1;
			}

			if (FAILED(hrCommit))
			{
				allOk = false;
				std::string hex = ErrorCodeHexString(hrCommit);
				wstring whex = Utf8ToWide(hex);
				std::wstringstream wss;
				wss << L"PutInstance failed while updating NetworkCategory. HRESULT=" << whex
					<< L" Msg=" << _com_error(hrCommit).ErrorMessage();
				SetLastErrorMsg(wss.str());
				LogErr(wss.str().c_str());
				pFull->Release();
				continue;
			}

			pFull->Release();
		}

		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM) CoUninitialize();

		return allOk;
	}
}
