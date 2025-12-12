#include <windows.h>
#include "../Globals.h"
#include "FirewallManager.h"
#include "../StringUtilities.h"
#include "../ComHelpers.h"

namespace Firewall {

	// WMI namespace and class constants for firewall operations
	static constexpr const wchar_t* HWS_WMI_NS_STANDARDCIMV2 = L"root\\StandardCimv2";
	static constexpr const wchar_t* HWS_WMI_FIREWALL_RULE = L"MSFT_NetFirewallRule";

	// Forward declaration so DeleteFirewallRulesInPolicyStore can use it.
	bool IsTransientHresult(HRESULT hr);

	/// <summary>
	/// Downloads content from a URL and parses it into a vector of IP address strings
	/// by splitting on newlines and filtering out comments and empty lines.
	/// </summary>
	/// <param name="url">The URL to download from (must be a valid HTTP/HTTPS URL)</param>
	/// <param name="ipList">Reference to vector that will be populated with IP addresses</param>
	/// <returns>True if download and parsing succeeded, false otherwise</returns>
	[[nodiscard]] bool DownloadIPList(const wchar_t* url, vector<wstring>& ipList)
	{
		// Validate input parameters
		if (!url || *url == L'\0')
		{
			SetLastErrorMsg(L"URL is null or empty.");
			return false;
		}

		// format last error with message text
		auto makeWin32ErrorMessage = [](const wchar_t* api, DWORD err) -> wstring
			{
				wchar_t* buf = nullptr;
				DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
				DWORD len = ::FormatMessageW(flags, nullptr, err, 0, reinterpret_cast<LPWSTR>(&buf), 0, nullptr);
				wstring msg = (len && buf) ? wstring(buf, len) : L"";
				if (buf) ::LocalFree(buf);

				// Trim trailing CR/LF and spaces
				while (!msg.empty() && (msg.back() == L'\r' || msg.back() == L'\n' || msg.back() == L' '))
					msg.pop_back();

				wstringstream ss;
				ss << api << L" failed. Win32=" << err;
				if (!msg.empty()) ss << L" (" << msg << L")";
				return ss.str();
			};

		// Parse the URL into components using WinHTTP URL cracking
		URL_COMPONENTS urlComp = {};
		urlComp.dwStructSize = sizeof(urlComp);
		urlComp.dwSchemeLength = static_cast<DWORD>(-1);      // Let WinHTTP determine scheme length
		urlComp.dwHostNameLength = static_cast<DWORD>(-1);    // Let WinHTTP determine hostname length
		urlComp.dwUrlPathLength = static_cast<DWORD>(-1);     // Let WinHTTP determine URL path length
		urlComp.dwExtraInfoLength = static_cast<DWORD>(-1);   // Capture query string ("extra info")

		if (!WinHttpCrackUrl(url, 0, 0, &urlComp))
		{
			DWORD err = ::GetLastError();
			SetLastErrorMsg(makeWin32ErrorMessage(L"WinHttpCrackUrl", err));
			return false;
		}

		// Extract URL components - check for null pointers
		wstring hostname = (urlComp.lpszHostName && urlComp.dwHostNameLength > 0)
			? wstring(urlComp.lpszHostName, urlComp.dwHostNameLength)
			: wstring();

		// Combine path + query
		wstring path = (urlComp.lpszUrlPath && urlComp.dwUrlPathLength > 0)
			? wstring(urlComp.lpszUrlPath, urlComp.dwUrlPathLength)
			: wstring();

		wstring extra = (urlComp.lpszExtraInfo && urlComp.dwExtraInfoLength > 0)
			? wstring(urlComp.lpszExtraInfo, urlComp.dwExtraInfoLength)
			: wstring();

		wstring pathAndQuery = path;
		if (!extra.empty())
			pathAndQuery += extra;
		if (pathAndQuery.empty())
			pathAndQuery = L"/";

		// Initialize WinHTTP session with a custom user agent
		HINTERNET hSession = WinHttpOpen(L"ComManager/1.0",
			WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
			WINHTTP_NO_PROXY_NAME,
			WINHTTP_NO_PROXY_BYPASS,
			0);
		if (!hSession)
		{
			DWORD err = ::GetLastError();
			SetLastErrorMsg(makeWin32ErrorMessage(L"WinHttpOpen", err));
			return false;
		}

		// Parameters: resolve, connect, send, receive (milliseconds)
		if (!WinHttpSetTimeouts(hSession, 90000, 90000, 90000, 100000))
		{
			// Non-fatal; keep going. Log for diagnostics but do not overwrite last error on success.
			DWORD err = ::GetLastError();
			LogErr(L"WinHttpSetTimeouts warning: ", makeWin32ErrorMessage(L"WinHttpSetTimeouts", err));
		}

		// Connect to the target server
		HINTERNET hConnect = WinHttpConnect(hSession, hostname.c_str(), urlComp.nPort, 0);
		if (!hConnect)
		{
			DWORD err = ::GetLastError();
			SetLastErrorMsg(makeWin32ErrorMessage(L"WinHttpConnect", err));
			WinHttpCloseHandle(hSession);
			return false;
		}

		// Create HTTP request - set secure flag for HTTPS URLs
		DWORD dwFlags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
		HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", pathAndQuery.c_str(),
			nullptr, WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES,
			dwFlags);
		if (!hRequest)
		{
			DWORD err = ::GetLastError();
			SetLastErrorMsg(makeWin32ErrorMessage(L"WinHttpOpenRequest", err));
			WinHttpCloseHandle(hConnect);
			WinHttpCloseHandle(hSession);
			return false;
		}

		// Redirect behavior (disallow HTTPS -> HTTP downgrades) and limit max redirects
		{
			DWORD policy = WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP;
			WinHttpSetOption(hRequest, WINHTTP_OPTION_REDIRECT_POLICY, &policy, sizeof(policy));

			DWORD maxRedirects = 10;
			WinHttpSetOption(hRequest, WINHTTP_OPTION_MAX_HTTP_AUTOMATIC_REDIRECTS, &maxRedirects, sizeof(maxRedirects));
		}

		// Enable automatic decompression (gzip/deflate, and brotli when available)
		{
			DWORD decompFlags = 0;
			decompFlags |= WINHTTP_DECOMPRESSION_FLAG_GZIP;
			decompFlags |= WINHTTP_DECOMPRESSION_FLAG_DEFLATE;
#ifdef WINHTTP_DECOMPRESSION_FLAG_BROTLI
			decompFlags |= WINHTTP_DECOMPRESSION_FLAG_BROTLI;
#endif

			if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_DECOMPRESSION, &decompFlags, sizeof(decompFlags)))
			{
				// Non-fatal; keep going. Log for diagnostics but do not overwrite last error on success.
				DWORD err = ::GetLastError();
				LogErr(L"WinHttpSetOption(WINHTTP_OPTION_DECOMPRESSION) warning: ",
					makeWin32ErrorMessage(L"WinHttpSetOption(WINHTTP_OPTION_DECOMPRESSION)", err));
			}
			else
			{
				// Hint to the server that we can accept compressed content
#ifndef WINHTTP_DECOMPRESSION_FLAG_BROTLI
				static constexpr wchar_t kAcceptEnc[] = L"Accept-Encoding: gzip, deflate\r\n";
#else
				static constexpr wchar_t kAcceptEnc[] = L"Accept-Encoding: gzip, deflate, br\r\n";
#endif
				WinHttpAddRequestHeaders(hRequest, kAcceptEnc, (DWORD)wcslen(kAcceptEnc), WINHTTP_ADDREQ_FLAG_ADD);
			}
		}

		// Send the HTTP request
		if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
			WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
		{
			DWORD err = ::GetLastError();
			SetLastErrorMsg(makeWin32ErrorMessage(L"WinHttpSendRequest", err));
			WinHttpCloseHandle(hRequest);
			WinHttpCloseHandle(hConnect);
			WinHttpCloseHandle(hSession);
			return false;
		}

		// Wait for and receive the HTTP response
		if (!WinHttpReceiveResponse(hRequest, nullptr))
		{
			DWORD err = ::GetLastError();
			SetLastErrorMsg(makeWin32ErrorMessage(L"WinHttpReceiveResponse", err));
			WinHttpCloseHandle(hRequest);
			WinHttpCloseHandle(hConnect);
			WinHttpCloseHandle(hSession);
			return false;
		}

		// Check HTTP status code - proceed only if 200 (OK)
		DWORD dwStatusCode = 0;
		DWORD dwSize = sizeof(dwStatusCode);
		if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
			nullptr, &dwStatusCode, &dwSize, nullptr))
		{
			DWORD err = ::GetLastError();
			SetLastErrorMsg(makeWin32ErrorMessage(L"WinHttpQueryHeaders(STATUS_CODE)", err));
			WinHttpCloseHandle(hRequest);
			WinHttpCloseHandle(hConnect);
			WinHttpCloseHandle(hSession);
			return false;
		}

		if (dwStatusCode != 200)
		{
			wstring msg = L"HTTP request failed with status code: " + to_wstring(dwStatusCode);
			SetLastErrorMsg(msg);
			WinHttpCloseHandle(hRequest);
			WinHttpCloseHandle(hConnect);
			WinHttpCloseHandle(hSession);
			return false;
		}

		// Read response data in chunks
		string responseData;
		DWORD dwBytesRead = 0;
		char buffer[8192]{};  // 8KB buffer

		do
		{
			dwBytesRead = 0;
			if (!WinHttpReadData(hRequest, buffer, sizeof(buffer), &dwBytesRead))
			{
				DWORD err = ::GetLastError();
				SetLastErrorMsg(makeWin32ErrorMessage(L"WinHttpReadData", err));
				WinHttpCloseHandle(hRequest);
				WinHttpCloseHandle(hConnect);
				WinHttpCloseHandle(hSession);
				return false;
			}
			if (dwBytesRead)
			{
				responseData.append(buffer, dwBytesRead);
			}
		} while (dwBytesRead > 0);

		// Clean up WinHTTP handles
		WinHttpCloseHandle(hRequest);
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);

		// Process the downloaded content - convert to wide string and split by lines
		// Basically the same as string.Split behavior with "\r\n" and "\n" separators in C#
		wstring wideContent = Utf8ToWide(responseData);

		// Strip a leading UTF-8 BOM if present (U+FEFF) so the first parsed token isn't corrupted
		if (!wideContent.empty() && wideContent.front() == 0xFEFF)
		{
			wideContent.erase(wideContent.begin());
		}

		wistringstream stream(wideContent);
		wstring line;

		// Clear the output vector and process each line
		ipList.clear();
		while (getline(stream, line))
		{
			// Remove carriage return if present (handles both \r\n and \n line endings)
			if (!line.empty() && line.back() == L'\r')
			{
				line.pop_back();
			}

			// Trim whitespace from both ends
			size_t first = line.find_first_not_of(L" \t\r\n");
			if (first == wstring::npos)
				continue;  // Skip empty lines

			size_t last = line.find_last_not_of(L" \t\r\n");
			wstring trimmed = line.substr(first, last - first + 1);

			// Skip empty lines and comments (lines starting with # or ;)
			if (trimmed.empty() || trimmed[0] == L'#' || trimmed[0] == L';')
				continue;

			// Add valid IP address/range to the list
			ipList.push_back(trimmed);
		}

		return true;
	}

	/// <summary>
	/// Deletes firewall rules in PolicyStore=localhost that match the specified DisplayName.
	/// Also checks ElementName as a fallback for legacy compatibility.
	/// This function is thorough and will delete any number of matching rules in both
	/// inbound and outbound sections of the Group Policy firewall rules.
	/// </summary>
	/// <param name="pSvc">WMI services interface</param>
	/// <param name="displayName">Display name of rules to delete</param>
	/// <returns>True if deletion succeeded, false otherwise</returns>
	[[nodiscard]] bool DeleteFirewallRulesInPolicyStore(IWbemServices* pSvc, const wchar_t* displayName)
	{
		if (!pSvc || !displayName || *displayName == L'\0') return false;

		// Create context with PolicyStore=localhost for Group Policy rules
		IWbemContext* pCtx = nullptr;
		HRESULT hr = CreateContextAndSetString(&pCtx, L"PolicyStore", L"localhost");
		if (FAILED(hr) || !pCtx)
		{
			SetLastErrorMsg(L"Failed to create IWbemContext for PolicyStore.");
			return false;
		}

		// Query for existing firewall rules - we need __PATH for deletion, plus DisplayName and ElementName for matching
		IEnumWbemClassObject* pEnum = nullptr;
		hr = pSvc->ExecQuery(
			_bstr_t(L"WQL"),
			_bstr_t(L"SELECT __PATH, DisplayName, ElementName FROM MSFT_NetFirewallRule"),
			WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
			pCtx,
			&pEnum
		);
		if (FAILED(hr) || !pEnum)
		{
			SetLastErrorMsg(L"ExecQuery for MSFT_NetFirewallRule failed.");
			pCtx->Release();
			return false;
		}

		bool ok = true;

		// Enumerate through all firewall rules and delete matching ones
		for (;;)
		{
			IWbemClassObject* pObj = nullptr;
			ULONG uRet = 0;
			hr = pEnum->Next(WBEM_INFINITE, 1, &pObj, &uRet);
			if (hr != S_OK || uRet == 0)
			{
				break;  // No more objects
			}

			bool match = false;

			// First check DisplayName for a match (primary match method)
			VARIANT vDisp;
			VariantInit(&vDisp);
			if (SUCCEEDED(pObj->Get(_bstr_t(L"DisplayName"), 0, &vDisp, nullptr, nullptr)) &&
				vDisp.vt == VT_BSTR && vDisp.bstrVal != nullptr)
			{
				if (EqualsOrdinalIgnoreCase(vDisp.bstrVal, displayName))
				{
					match = true;
				}
			}
			VariantClear(&vDisp);

			// If no match on DisplayName, check ElementName as fallback (for legacy rules)
			if (!match)
			{
				VARIANT vElem;
				VariantInit(&vElem);
				if (SUCCEEDED(pObj->Get(_bstr_t(L"ElementName"), 0, &vElem, nullptr, nullptr)) &&
					vElem.vt == VT_BSTR && vElem.bstrVal != nullptr)
				{
					if (EqualsOrdinalIgnoreCase(vElem.bstrVal, displayName))
					{
						match = true;
					}
				}
				VariantClear(&vElem);
			}

			// If we found a matching rule, delete it using its WMI path
			if (match)
			{
				VARIANT vPath;
				VariantInit(&vPath);
				if (SUCCEEDED(pObj->Get(_bstr_t(L"__PATH"), 0, &vPath, nullptr, nullptr)) &&
					vPath.vt == VT_BSTR && vPath.bstrVal != nullptr)
				{
					// Retry only on transient HRESULTs determined by IsTransientHresult; otherwise fail fast.
					const int kMaxAttempts = 8;     // modest window to ride out brief provider/policy contention (~12.7s worst-case)
					DWORD delayMs = 100;
					HRESULT hrDel = E_FAIL;

					for (int attempt = 1; attempt <= kMaxAttempts; ++attempt)
					{
						hrDel = pSvc->DeleteInstance(vPath.bstrVal, 0, pCtx, nullptr);

						// Success -> break
						if (SUCCEEDED(hrDel))
							break;

						// Only retry if transient per helper; otherwise break and fail below
						if (!IsTransientHresult(hrDel))
							break;

						::Sleep(delayMs);
						if (delayMs < 2000) delayMs <<= 1; // exponential backoff up to ~2s cap
					}

					if (FAILED(hrDel))
					{
						ok = false;  // Mark as failed but continue deleting other matches

						// Record a detailed error message so callers don't see a blank "Error:".
						string hex = ErrorCodeHexString(hrDel);
						wstring whex = Utf8ToWide(hex);
						wstringstream wss;
						wss << L"DeleteInstance (firewall rule) failed. HRESULT=" << whex;
						SetLastErrorMsg(wss.str());
					}
				}
				VariantClear(&vPath);
			}

			pObj->Release();
		}

		pEnum->Release();
		pCtx->Release();
		return ok;
	}

	// Helper to detect transient HRESULTs worth retrying for the PutInstance operation.
	// These are known to occur under provider/RPC load and during short policy/store contention windows.
	bool IsTransientHresult(HRESULT hr)
	{
		switch (static_cast<unsigned long>(hr))
		{
		case 0x8001010A: // RPC_E_SERVERCALL_RETRYLATER
		case 0x8001010B: // RPC_E_SERVERCALL_REJECTED
		case 0x800706BA: // RPC_S_SERVER_UNAVAILABLE (HRESULT_FROM_WIN32)
		case 0x800706BE: // RPC_S_CALL_FAILED (HRESULT_FROM_WIN32)
		case 0x80041015: // WBEM_E_TRANSPORT_FAILURE
		case 0x80041003: // WBEM_E_ACCESS_DENIED (transient in this provider/store under system load)
			return true;
		default:
			return false;
		}
	}

	/// <summary>
	/// Creates a single firewall rule (inbound or outbound) in PolicyStore=localhost
	/// with the provided RemoteAddress array.
	/// </summary>
	/// <param name="pSvc">WMI services interface</param>
	/// <param name="displayName">Display name for the new firewall rule</param>
	/// <param name="inbound">True for inbound rule, false for outbound rule</param>
	/// <param name="remoteIps">Vector of IP addresses/ranges to block</param>
	/// <returns>True if rule creation succeeded, false otherwise</returns>
	[[nodiscard]] bool CreateFirewallRuleInPolicyStore(IWbemServices* pSvc, const wchar_t* displayName, bool inbound, const vector<wstring>& remoteIps)
	{
		if (!pSvc || !displayName || *displayName == L'\0') return false;

		// Create context with PolicyStore=localhost for Group Policy rules
		IWbemContext* pCtx = nullptr;
		HRESULT hr = CreateContextAndSetString(&pCtx, L"PolicyStore", L"localhost");
		if (FAILED(hr) || !pCtx)
		{
			SetLastErrorMsg(L"Failed to create IWbemContext for PolicyStore.");
			return false;
		}

		// Set LocalAddress to empty array -> "Any"
		SAFEARRAY* saLocal = nullptr;
		vector<wstring> emptyList;
		hr = CreateSafeArrayOfBSTR(emptyList, &saLocal);
		if (FAILED(hr))
		{
			pCtx->Release();
			SetLastErrorMsg(L"Failed to create SAFEARRAY for LocalAddress.");
			return false;
		}
		hr = ContextSetStringArray(pCtx, L"LocalAddress", saLocal);
		SafeArrayDestroy(saLocal);  // Context makes a copy, so we can destroy our copy
		if (FAILED(hr))
		{
			pCtx->Release();
			SetLastErrorMsg(L"Failed to set LocalAddress context.");
			return false;
		}

		// Set RemoteAddress array to the provided IP list
		SAFEARRAY* saRemote = nullptr;
		hr = CreateSafeArrayOfBSTR(remoteIps, &saRemote);
		if (FAILED(hr))
		{
			pCtx->Release();
			SetLastErrorMsg(L"Failed to create SAFEARRAY for RemoteAddress.");
			return false;
		}
		hr = ContextSetStringArray(pCtx, L"RemoteAddress", saRemote);
		SafeArrayDestroy(saRemote);  // Context makes a copy, so we can destroy our copy
		if (FAILED(hr))
		{
			pCtx->Release();
			SetLastErrorMsg(L"Failed to set RemoteAddress context.");
			return false;
		}

		// Get the MSFT_NetFirewallRule class definition and spawn an instance
		IWbemClassObject* pClass = nullptr;
		hr = pSvc->GetObject(_bstr_t(HWS_WMI_FIREWALL_RULE), 0, nullptr, &pClass, nullptr);
		if (FAILED(hr) || !pClass)
		{
			pCtx->Release();
			SetLastErrorMsg(L"Failed to get MSFT_NetFirewallRule class.");
			return false;
		}

		IWbemClassObject* pInst = nullptr;
		hr = pClass->SpawnInstance(0, &pInst);
		if (FAILED(hr) || !pInst)
		{
			pClass->Release();
			pCtx->Release();
			SetLastErrorMsg(L"Failed to spawn MSFT_NetFirewallRule instance.");
			return false;
		}

		// Set firewall rule properties
		VARIANT v;
		VariantInit(&v);

		// ElementName
		v.vt = VT_BSTR;
		v.bstrVal = SysAllocString(displayName);
		hr = pInst->Put(_bstr_t(L"ElementName"), 0, &v, 0);
		VariantClear(&v);
		if (FAILED(hr))
		{
			pInst->Release();
			pClass->Release();
			pCtx->Release();
			SetLastErrorMsg(L"Failed to set ElementName.");
			return false;
		}

		// DisplayName (set to same value as ElementName)
		v.vt = VT_BSTR;
		v.bstrVal = SysAllocString(displayName);
		hr = pInst->Put(_bstr_t(L"DisplayName"), 0, &v, 0);
		VariantClear(&v);
		if (FAILED(hr))
		{
			pInst->Release();
			pClass->Release();
			pCtx->Release();
			SetLastErrorMsg(L"Failed to set DisplayName.");
			return false;
		}

		// Description (set to same value as ElementName)
		v.vt = VT_BSTR;
		v.bstrVal = SysAllocString(displayName);
		hr = pInst->Put(_bstr_t(L"Description"), 0, &v, 0);
		VariantClear(&v);
		if (FAILED(hr))
		{
			pInst->Release();
			pClass->Release();
			pCtx->Release();
			SetLastErrorMsg(L"Failed to set Description.");
			return false;
		}

		// Direction: 1 for inbound, 2 for outbound (NetSecurityDirection enum)
		v.vt = VT_I4;
		v.lVal = static_cast<LONG>(inbound ? NetSecurityDirection::Inbound : NetSecurityDirection::Outbound);
		hr = pInst->Put(_bstr_t(L"Direction"), 0, &v, 0);
		VariantClear(&v);
		if (FAILED(hr))
		{
			pInst->Release();
			pClass->Release();
			pCtx->Release();
			SetLastErrorMsg(L"Failed to set Direction.");
			return false;
		}

		// Action: 4 = Block (NetSecurityAction.Block)
		v.vt = VT_I4;
		v.lVal = static_cast<LONG>(NetSecurityAction::Block);
		hr = pInst->Put(_bstr_t(L"Action"), 0, &v, 0);
		VariantClear(&v);
		if (FAILED(hr))
		{
			pInst->Release();
			pClass->Release();
			pCtx->Release();
			SetLastErrorMsg(L"Failed to set Action.");
			return false;
		}

		// Enabled: 1 = True (NetSecurityEnabled.True)
		v.vt = VT_I4;
		v.lVal = static_cast<LONG>(NetSecurityEnabled::True);
		hr = pInst->Put(_bstr_t(L"Enabled"), 0, &v, 0);
		VariantClear(&v);
		if (FAILED(hr))
		{
			pInst->Release();
			pClass->Release();
			pCtx->Release();
			SetLastErrorMsg(L"Failed to set Enabled.");
			return false;
		}

		// Profiles: 0 = Any (NetSecurityProfile.Any)
		v.vt = VT_I4;
		v.lVal = static_cast<LONG>(NetSecurityProfile::Any);
		hr = pInst->Put(_bstr_t(L"Profiles"), 0, &v, 0);
		VariantClear(&v);
		if (FAILED(hr))
		{
			pInst->Release();
			pClass->Release();
			pCtx->Release();
			SetLastErrorMsg(L"Failed to set Profiles.");
			return false;
		}

		// EdgeTraversalPolicy: 0 = Block (NetSecurityEdgeTraversal.Block)
		v.vt = VT_I4;
		v.lVal = static_cast<LONG>(NetSecurityEdgeTraversal::Block);
		hr = pInst->Put(_bstr_t(L"EdgeTraversalPolicy"), 0, &v, 0);
		VariantClear(&v);
		if (FAILED(hr))
		{
			pInst->Release();
			pClass->Release();
			pCtx->Release();
			SetLastErrorMsg(L"Failed to set EdgeTraversalPolicy.");
			return false;
		}

		// Create the firewall rule instance with the configured context
		// Retry only on transient HRESULTs determined by IsTransientHresult; otherwise fail fast.
		const int kMaxAttempts = 8;     // modest window to ride out brief provider/policy contention (~12.7s worst-case)
		DWORD delayMs = 100;
		HRESULT hrPut = E_FAIL;

		for (int attempt = 1; attempt <= kMaxAttempts; ++attempt)
		{
			hrPut = pSvc->PutInstance(pInst, 0, pCtx, nullptr);

			// Success -> break
			if (SUCCEEDED(hrPut))
				break;

			// Only retry if transient per helper; otherwise break and fail below
			if (!IsTransientHresult(hrPut))
				break;

			::Sleep(delayMs);
			if (delayMs < 2000) delayMs <<= 1; // exponential backoff up to ~2s cap
		}

		if (FAILED(hrPut))
		{
			pInst->Release();
			pClass->Release();
			pCtx->Release();
			SetLastErrorMsg(L"PutInstance for firewall rule failed.");
			return false;
		}

		// Clean up resources
		pInst->Release();
		pClass->Release();
		pCtx->Release();
		return true;
	}


	/// <summary>
	/// This function can Add or Remove Firewall rules added to the Group Policy store that are responsible for blocking pre-defined country IP Addresses.
	/// If the same rules already exist, the function will delete the old ones and recreate new ones in order to let the system have up to date IP ranges.
	/// Group Policy is idempotent so it will actively maintain the policies set in it.
	/// Another benefit of using LocalStore is that it supports large arrays of IP addresses.
	/// The default store which goes to Windows firewall store does not support large arrays and throws: "The array bounds are invalid" error.
	/// </summary>
	/// <param name="displayName">Display name for the firewall rules</param>
	/// <param name="listDownloadURL">URL to download IP addresses from (can be null/empty when removing rules)</param>
	/// <param name="toAdd">True to add rules (requires valid URL), false to remove rules</param>
	/// <returns>True if operation succeeded, false otherwise</returns>
	extern "C" __declspec(dllexport) bool __stdcall FW_BlockIPAddressListsInGroupPolicy(const wchar_t* displayName, const wchar_t* listDownloadURL, bool toAdd)
	{
		ClearLastErrorMsg();

		// Validate display name parameter (required in all cases)
		if (displayName == nullptr || *displayName == L'\0')
		{
			SetLastErrorMsg(L"DisplayName is null or empty.");
			return false;
		}

		// Process IP list download if we're adding rules
		vector<wstring> ipList;
		if (toAdd)
		{
			// Validate URL parameter when adding rules
			if (listDownloadURL == nullptr || *listDownloadURL == L'\0')
			{
				SetLastErrorMsg(L"ListDownloadURL cannot be null or empty when creating Firewall rules.");
				return false;
			}

			// Download the IP Address list
			if (!DownloadIPList(listDownloadURL, ipList))
			{
				// Error message already set by DownloadIPList
				return false;
			}

			// Ensure we have some IP addresses to work with
			if (ipList.empty())
			{
				SetLastErrorMsg(L"Downloaded IP list is empty.");
				return false;
			}
		}

		// Connect to WMI namespace for firewall operations
		IWbemLocator* pLoc = nullptr;
		IWbemServices* pSvc = nullptr;
		bool didInitCOM = false;

		if (!ConnectToWmiNamespace(HWS_WMI_NS_STANDARDCIMV2, &pLoc, &pSvc, didInitCOM))
		{
			// Error message already set by ConnectToWmiNamespace
			return false;
		}

		// Always delete existing rules by DisplayName.
		// it is thorough, any number of firewall rules that match
		// the same name in both inbound and outbound sections of the Group policy firewall rules will be included.
		bool deletedOk = DeleteFirewallRulesInPolicyStore(pSvc, displayName);
		bool finalResult = deletedOk;

		// Create new rules if requested
		if (toAdd)
		{
			// Create both inbound and outbound rules
			bool inOk = CreateFirewallRuleInPolicyStore(pSvc, displayName, true, ipList);   // Inbound rule
			bool outOk = CreateFirewallRuleInPolicyStore(pSvc, displayName, false, ipList); // Outbound rule
			finalResult = deletedOk && inOk && outOk;
		}

		// Clean up WMI resources
		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM)
		{
			CoUninitialize();
		}

		return finalResult;
	}

	/// <summary>
	/// Exported firewall function callable from C# via DllImport/LibraryImport.
	/// This function provides the same interface as the existing firewall functionality
	/// but accepts a pre-populated IP array instead of downloading from URL.
	/// </summary>
	/// <param name="displayName">Display name for the firewall rules</param>
	/// <param name="ipArray">Array of IP addresses/ranges to block</param>
	/// <param name="arraySize">Number of elements in the IP array</param>
	/// <param name="toAdd">True to add rules, false to remove rules</param>
	/// <returns>True if operation succeeded, false otherwise</returns>
	extern "C" __declspec(dllexport) bool __stdcall FW_BlockIpListInGpo(const wchar_t* displayName, const wchar_t** ipArray, int arraySize, bool toAdd)
	{
		ClearLastErrorMsg();

		// Validate display name parameter
		if (displayName == nullptr || *displayName == L'\0')
		{
			SetLastErrorMsg(L"DisplayName is null or empty.");
			return false;
		}

		// Process IP array if we're adding rules
		vector<wstring> ipList;
		if (toAdd)
		{
			// Validate IP array parameters
			if (ipArray == nullptr || arraySize < 0)
			{
				SetLastErrorMsg(L"Invalid IP array.");
				return false;
			}

			// Reserve space for efficiency and process each IP address
			ipList.reserve(static_cast<size_t>(arraySize));
			for (int i = 0; i < arraySize; i++)
			{
				const wchar_t* p = ipArray[i];
				if (!p) continue;  // Skip null pointers

				// Trim whitespace from the IP address string
				wstring s(p);
				size_t first = s.find_first_not_of(L" \t\r\n");
				size_t last = s.find_last_not_of(L" \t\r\n");
				if (first == wstring::npos)
					continue;  // Skip empty strings

				wstring t = s.substr(first, last - first + 1);
				if (t.empty()) continue;  // Skip empty trimmed strings

				// Skip comment lines
				if (t[0] == L'#' || t[0] == L';') continue;

				ipList.push_back(t);
			}
		}

		// Connect to WMI namespace for firewall operations
		IWbemLocator* pLoc = nullptr;
		IWbemServices* pSvc = nullptr;
		bool didInitCOM = false;

		if (!ConnectToWmiNamespace(HWS_WMI_NS_STANDARDCIMV2, &pLoc, &pSvc, didInitCOM))
		{
			// Error message already set by ConnectToWmiNamespace
			return false;
		}

		// Always delete existing rules by DisplayName (and legacy ElementName fallback)
		// This ensures idempotent behavior - existing rules are removed before new ones are added
		bool deletedOk = DeleteFirewallRulesInPolicyStore(pSvc, displayName);
		bool finalResult = deletedOk;

		// Create new rules if requested (both inbound and outbound)
		if (toAdd)
		{
			bool inOk = CreateFirewallRuleInPolicyStore(pSvc, displayName, true, ipList);   // Inbound rule
			bool outOk = CreateFirewallRuleInPolicyStore(pSvc, displayName, false, ipList); // Outbound rule
			finalResult = deletedOk && inOk && outOk;
		}

		// Clean up WMI resources
		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM)
		{
			CoUninitialize();
		}

		return finalResult;
	}

	// Deletes firewall rule(s) from PolicyStore=localhost using ElementName as the primary key,
	// with DisplayName as a fallback (the code assigns both the same when creating rules).
	extern "C" __declspec(dllexport) bool __stdcall FW_DeleteFirewallRuleByElementName(const wchar_t* elementName)
	{
		ClearLastErrorMsg();

		if (elementName == nullptr || *elementName == L'\0')
		{
			SetLastErrorMsg(L"ElementName is null or empty.");
			return false;
		}

		// Connect to WMI namespace for firewall operations (same as other firewall features)
		IWbemLocator* pLoc = nullptr;
		IWbemServices* pSvc = nullptr;
		bool didInitCOM = false;

		if (!ConnectToWmiNamespace(HWS_WMI_NS_STANDARDCIMV2, &pLoc, &pSvc, didInitCOM))
		{
			// Error message already set by ConnectToWmiNamespace
			return false;
		}

		// Create context with PolicyStore=localhost to ensure we only touch the store used by this program.
		IWbemContext* pCtx = nullptr;
		HRESULT hr = CreateContextAndSetString(&pCtx, L"PolicyStore", L"localhost");
		if (FAILED(hr) || !pCtx)
		{
			SetLastErrorMsg(L"Failed to create IWbemContext for PolicyStore.");
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		// Enumerate instances so we can delete by __PATH and match on ElementName (primary) or DisplayName (fallback).
		IEnumWbemClassObject* pEnum = nullptr;
		hr = pSvc->ExecQuery(
			_bstr_t(L"WQL"),
			_bstr_t(L"SELECT __PATH, DisplayName, ElementName FROM MSFT_NetFirewallRule"),
			WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
			pCtx,
			&pEnum
		);
		if (FAILED(hr) || !pEnum)
		{
			SetLastErrorMsg(L"ExecQuery for MSFT_NetFirewallRule failed.");
			if (pEnum) pEnum->Release();
			pCtx->Release();
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		bool ok = true;

		for (;;)
		{
			IWbemClassObject* pObj = nullptr;
			ULONG uRet = 0;
			HRESULT hrNext = pEnum->Next(WBEM_INFINITE, 1, &pObj, &uRet);
			if (hrNext != S_OK || uRet == 0 || !pObj)
				break;

			bool match = false;

			// Primary: ElementName
			{
				VARIANT vElem;
				VariantInit(&vElem);
				if (SUCCEEDED(pObj->Get(_bstr_t(L"ElementName"), 0, &vElem, nullptr, nullptr)) &&
					vElem.vt == VT_BSTR && vElem.bstrVal != nullptr)
				{
					if (EqualsOrdinalIgnoreCase(vElem.bstrVal, elementName))
					{
						match = true;
					}
				}
				VariantClear(&vElem);
			}

			// Fallback: DisplayName
			if (!match)
			{
				VARIANT vDisp;
				VariantInit(&vDisp);
				if (SUCCEEDED(pObj->Get(_bstr_t(L"DisplayName"), 0, &vDisp, nullptr, nullptr)) &&
					vDisp.vt == VT_BSTR && vDisp.bstrVal != nullptr)
				{
					if (EqualsOrdinalIgnoreCase(vDisp.bstrVal, elementName))
					{
						match = true;
					}
				}
				VariantClear(&vDisp);
			}

			if (match)
			{
				VARIANT vPath;
				VariantInit(&vPath);
				if (SUCCEEDED(pObj->Get(_bstr_t(L"__PATH"), 0, &vPath, nullptr, nullptr)) &&
					vPath.vt == VT_BSTR && vPath.bstrVal != nullptr)
				{
					// Retry only on transient HRESULTs determined by IsTransientHresult; otherwise fail fast.
					const int kMaxAttempts = 8;
					DWORD delayMs = 100;
					HRESULT hrDel = E_FAIL;

					for (int attempt = 1; attempt <= kMaxAttempts; ++attempt)
					{
						hrDel = pSvc->DeleteInstance(vPath.bstrVal, 0, pCtx, nullptr);

						if (SUCCEEDED(hrDel))
							break;

						if (!IsTransientHresult(hrDel))
							break;

						::Sleep(delayMs);
						if (delayMs < 2000) delayMs <<= 1;
					}

					if (FAILED(hrDel))
					{
						ok = false;

						string hex = ErrorCodeHexString(hrDel);
						wstring whex = Utf8ToWide(hex);
						wstringstream wss;
						wss << L"DeleteInstance (firewall rule) failed. HRESULT=" << whex;
						SetLastErrorMsg(wss.str());
					}
				}
				VariantClear(&vPath);
			}

			pObj->Release();
		}

		pEnum->Release();
		pCtx->Release();
		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM) CoUninitialize();

		return ok;
	}

	/// <summary>
	/// Helper to delete existing program rules that match Name + Group + Direction.
	/// Deduplication Logic: if in the "HardenSystemSecurity" group there is a rule for
	/// the same name with the same direction then delete all those rules.
	/// </summary>
	static bool DeleteProgramRulesInGroup(IWbemServices* pSvc, IWbemContext* pCtx, const wchar_t* displayName, const wchar_t* groupName, NetSecurityDirection direction)
	{
		IEnumWbemClassObject* pEnum = nullptr;
		// Select enough fields to verify the match logic
		HRESULT hr = pSvc->ExecQuery(
			_bstr_t(L"WQL"),
			_bstr_t(L"SELECT __PATH, DisplayName, RuleGroup, Direction FROM MSFT_NetFirewallRule"),
			WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
			pCtx,
			&pEnum
		);
		if (FAILED(hr) || !pEnum)
		{
			SetLastErrorMsg(L"ExecQuery failed during rule deduplication.");
			return false;
		}

		bool ok = true;
		for (;;)
		{
			IWbemClassObject* pObj = nullptr;
			ULONG uRet = 0;
			HRESULT hrNext = pEnum->Next(WBEM_INFINITE, 1, &pObj, &uRet);
			if (hrNext != S_OK || uRet == 0) break;

			bool matchName = false;
			bool matchGroup = false;
			bool matchDir = false;

			// Check DisplayName
			VARIANT v; VariantInit(&v);
			if (SUCCEEDED(pObj->Get(_bstr_t(L"DisplayName"), 0, &v, nullptr, nullptr)) && v.vt == VT_BSTR && v.bstrVal)
			{
				if (EqualsOrdinalIgnoreCase(v.bstrVal, displayName)) matchName = true;
			}
			VariantClear(&v);

			// Check RuleGroup
			VariantInit(&v);
			if (SUCCEEDED(pObj->Get(_bstr_t(L"RuleGroup"), 0, &v, nullptr, nullptr)) && v.vt == VT_BSTR && v.bstrVal)
			{
				if (EqualsOrdinalIgnoreCase(v.bstrVal, groupName)) matchGroup = true;
			}
			VariantClear(&v);

			// Check Direction
			VariantInit(&v);
			if (SUCCEEDED(pObj->Get(_bstr_t(L"Direction"), 0, &v, nullptr, nullptr)))
			{
				LONG d = -1;
				if (v.vt == VT_I4) d = v.lVal;
				else if (v.vt == VT_UI2) d = v.uiVal; // Schema defines it as uint16

				if (d == static_cast<LONG>(direction)) matchDir = true;
			}
			VariantClear(&v);

			if (matchName && matchGroup && matchDir)
			{
				// Match found -> Delete it
				VariantInit(&v);
				if (SUCCEEDED(pObj->Get(_bstr_t(L"__PATH"), 0, &v, nullptr, nullptr)) && v.vt == VT_BSTR && v.bstrVal)
				{
					// Retry loop for transient errors
					const int kMaxAttempts = 5;
					DWORD delayMs = 100;
					HRESULT hrDel = E_FAIL;
					for (int i = 0; i < kMaxAttempts; ++i)
					{
						hrDel = pSvc->DeleteInstance(v.bstrVal, 0, pCtx, nullptr);
						if (SUCCEEDED(hrDel)) break;
						if (!IsTransientHresult(hrDel)) break;
						::Sleep(delayMs);
						delayMs *= 2;
					}
					if (FAILED(hrDel)) ok = false;
				}
				VariantClear(&v);
			}

			pObj->Release();
		}
		pEnum->Release();
		return ok;
	}

	extern "C" __declspec(dllexport) bool __stdcall FW_AddProgramFirewallRule(
		const wchar_t* displayName,
		const wchar_t* programPath,
		const wchar_t* direction,
		const wchar_t* action,
		const wchar_t* description,
		const wchar_t* policyAppId,
		const wchar_t* packageFamilyName
	)
	{
		ClearLastErrorMsg();

		if (!displayName || *displayName == L'\0') {
			SetLastErrorMsg(L"DisplayName is required.");
			return false;
		}
		if (!programPath || *programPath == L'\0') {
			SetLastErrorMsg(L"ProgramPath is required.");
			return false;
		}
		if (!direction || *direction == L'\0') {
			SetLastErrorMsg(L"Direction is required.");
			return false;
		}
		if (!action || *action == L'\0') {
			SetLastErrorMsg(L"Action is required.");
			return false;
		}

		// Parse direction
		NetSecurityDirection dirEnum;
		if (EqualsOrdinalIgnoreCase(direction, L"Inbound") || EqualsOrdinalIgnoreCase(direction, L"1")) {
			dirEnum = NetSecurityDirection::Inbound;
		}
		else if (EqualsOrdinalIgnoreCase(direction, L"Outbound") || EqualsOrdinalIgnoreCase(direction, L"2")) {
			dirEnum = NetSecurityDirection::Outbound;
		}
		else {
			SetLastErrorMsg(L"Invalid Direction (use Inbound/Outbound).");
			return false;
		}

		// Parse action
		NetSecurityAction actionEnum;
		if (EqualsOrdinalIgnoreCase(action, L"Allow") || EqualsOrdinalIgnoreCase(action, L"2")) {
			actionEnum = NetSecurityAction::Allow;
		}
		else if (EqualsOrdinalIgnoreCase(action, L"Block") || EqualsOrdinalIgnoreCase(action, L"4")) {
			actionEnum = NetSecurityAction::Block;
		}
		else {
			SetLastErrorMsg(L"Invalid Action (use Allow/Block).");
			return false;
		}

		// Connect to WMI
		IWbemLocator* pLoc = nullptr;
		IWbemServices* pSvc = nullptr;
		bool didInitCOM = false;
		if (!ConnectToWmiNamespace(HWS_WMI_NS_STANDARDCIMV2, &pLoc, &pSvc, didInitCOM))
		{
			return false;
		}

		// Create Context for PolicyStore=localhost (Group Policy)
		IWbemContext* pCtx = nullptr;
		HRESULT hr = CreateContextAndSetString(&pCtx, L"PolicyStore", L"localhost");
		if (FAILED(hr) || !pCtx)
		{
			SetLastErrorMsg(L"Failed to create IWbemContext for PolicyStore.");
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		const wchar_t* targetGroup = L"HardenSystemSecurity";

		// Deduplication: delete existing rule(s) with same DisplayName, Direction and Group.
		if (!DeleteProgramRulesInGroup(pSvc, pCtx, displayName, targetGroup, dirEnum))
		{
			SetLastErrorMsg(L"Failed to remove existing rules during deduplication.");
			pCtx->Release();
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		// Create the new rule
		IWbemClassObject* pClass = nullptr;
		hr = pSvc->GetObject(_bstr_t(HWS_WMI_FIREWALL_RULE), 0, nullptr, &pClass, nullptr);
		if (FAILED(hr) || !pClass)
		{
			SetLastErrorMsg(L"Failed to get MSFT_NetFirewallRule class.");
			pCtx->Release();
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		IWbemClassObject* pInst = nullptr;
		hr = pClass->SpawnInstance(0, &pInst);
		if (FAILED(hr) || !pInst)
		{
			SetLastErrorMsg(L"Failed to spawn MSFT_NetFirewallRule instance.");
			pClass->Release();
			pCtx->Release();
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		// Helper to set property
		auto setProp = [&](const wchar_t* name, const VARIANT& val) -> bool {
			HRESULT h = pInst->Put(_bstr_t(name), 0, (VARIANT*)&val, 0);
			return SUCCEEDED(h);
			};

		auto setStr = [&](const wchar_t* name, const wchar_t* val) -> bool {
			if (!val) return true; // allow nulls if optional logic handled elsewhere
			VARIANT v; VariantInit(&v);
			v.vt = VT_BSTR;
			v.bstrVal = SysAllocString(val);
			bool r = setProp(name, v);
			VariantClear(&v);
			return r;
			};

		auto setInt = [&](const wchar_t* name, int val) -> bool {
			VARIANT v; VariantInit(&v);
			v.vt = VT_I4;
			v.lVal = val;
			bool r = setProp(name, v);
			VariantClear(&v);
			return r;
			};

		// Mandatory fields on the Rule Instance
		if (!setStr(L"ElementName", displayName) ||
			!setStr(L"DisplayName", displayName) ||
			!setStr(L"Description", description) ||
			!setStr(L"RuleGroup", targetGroup) ||
			!setInt(L"Direction", static_cast<int>(dirEnum)) ||
			!setInt(L"Action", static_cast<int>(actionEnum)) ||
			!setInt(L"Enabled", static_cast<int>(NetSecurityEnabled::True)) ||
			!setInt(L"Profiles", static_cast<int>(NetSecurityProfile::Any)) ||
			!setInt(L"EdgeTraversalPolicy", static_cast<int>(NetSecurityEdgeTraversal::Block)))
		{
			SetLastErrorMsg(L"Failed to set one or more mandatory properties.");
			pInst->Release();
			pClass->Release();
			pCtx->Release();
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		// Fields set via Context (Filters)
		// Program (Application Filter) is Mandatory for this function logic
		if (FAILED(ContextSetString(pCtx, L"Program", programPath)))
		{
			SetLastErrorMsg(L"Failed to set Program in context.");
			pInst->Release();
			pClass->Release();
			pCtx->Release();
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		// Optional fields (Filters)
		if (policyAppId && *policyAppId)
		{
			if (FAILED(ContextSetString(pCtx, L"PolicyAppId", policyAppId)))
			{
				// Fail strict to be safe.
				SetLastErrorMsg(L"Failed to set PolicyAppId in context.");
				pInst->Release();
				pClass->Release();
				pCtx->Release();
				pSvc->Release();
				pLoc->Release();
				if (!g_skipCOMInit && didInitCOM) CoUninitialize();
				return false;
			}
		}
		if (packageFamilyName && *packageFamilyName)
		{
			if (FAILED(ContextSetString(pCtx, L"PackageFamilyName", packageFamilyName)))
			{
				SetLastErrorMsg(L"Failed to set PackageFamilyName in context.");
				pInst->Release();
				pClass->Release();
				pCtx->Release();
				pSvc->Release();
				pLoc->Release();
				if (!g_skipCOMInit && didInitCOM) CoUninitialize();
				return false;
			}
		}

		// Commit
		const int kMaxAttempts = 8;
		DWORD delayMs = 100;
		HRESULT hrPut = E_FAIL;
		for (int attempt = 1; attempt <= kMaxAttempts; ++attempt)
		{
			hrPut = pSvc->PutInstance(pInst, 0, pCtx, nullptr);
			if (SUCCEEDED(hrPut)) break;
			if (!IsTransientHresult(hrPut)) break;
			::Sleep(delayMs);
			if (delayMs < 2000) delayMs <<= 1;
		}

		if (FAILED(hrPut))
		{
			string hex = ErrorCodeHexString(hrPut);
			wstring whex = Utf8ToWide(hex);
			wstring msg = L"PutInstance for program rule failed. HRESULT=" + whex;
			SetLastErrorMsg(msg);
		}

		pInst->Release();
		pClass->Release();
		pCtx->Release();
		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM) CoUninitialize();

		return SUCCEEDED(hrPut);
	}

	// Lists firewall rules from the same PolicyStore used by this program (PolicyStore=localhost),
	// filtered down to RuleGroup="HardenSystemSecurity".
	// Output is written to stdout as a JSON array.
	// Returns true on success, false on error (error set).
	extern "C" __declspec(dllexport) bool __stdcall FW_ListProgramFirewallRulesInHardenSystemSecurityGroupJson()
	{
		ClearLastErrorMsg();

		// Connect to WMI namespace
		IWbemLocator* pLoc = nullptr;
		IWbemServices* pSvc = nullptr;
		bool didInitCOM = false;

		if (!ConnectToWmiNamespace(HWS_WMI_NS_STANDARDCIMV2, &pLoc, &pSvc, didInitCOM) || !pSvc)
		{
			if (pLoc) pLoc->Release();
			if (pSvc) pSvc->Release();
			return false;
		}

		// Create context with PolicyStore=localhost to ensure we only read the store used by this program.
		IWbemContext* pCtx = nullptr;
		HRESULT hr = CreateContextAndSetString(&pCtx, L"PolicyStore", L"localhost");
		if (FAILED(hr) || !pCtx)
		{
			SetLastErrorMsg(L"Failed to create IWbemContext for PolicyStore.");
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		// Enumerate rules in this policy store.
		IEnumWbemClassObject* pEnum = nullptr;
		hr = pSvc->ExecQuery(
			_bstr_t(L"WQL"),
			_bstr_t(L"SELECT ElementName, DisplayName, RuleGroup, Direction, Action FROM MSFT_NetFirewallRule"),
			WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
			pCtx,
			&pEnum
		);
		if (FAILED(hr) || !pEnum)
		{
			SetLastErrorMsg(L"ExecQuery for MSFT_NetFirewallRule failed (firewallprogramlist).");
			if (pEnum) pEnum->Release();
			pCtx->Release();
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		const wchar_t* targetGroup = L"HardenSystemSecurity";

		struct RuleInfo
		{
			wstring name;
			LONG direction;
			LONG action;
		};

		vector<RuleInfo> rules;
		rules.reserve(64);

		for (;;)
		{
			IWbemClassObject* pObj = nullptr;
			ULONG uRet = 0;
			HRESULT hrNext = pEnum->Next(WBEM_INFINITE, 1, &pObj, &uRet);
			if (hrNext != S_OK || uRet == 0 || !pObj)
				break;

			bool groupMatch = false;

			// RuleGroup filter
			{
				VARIANT vGroup;
				VariantInit(&vGroup);
				if (SUCCEEDED(pObj->Get(_bstr_t(L"RuleGroup"), 0, &vGroup, nullptr, nullptr)) &&
					vGroup.vt == VT_BSTR && vGroup.bstrVal != nullptr)
				{
					if (EqualsOrdinalIgnoreCase(vGroup.bstrVal, targetGroup))
					{
						groupMatch = true;
					}
				}
				VariantClear(&vGroup);
			}

			if (!groupMatch)
			{
				pObj->Release();
				continue;
			}

			RuleInfo info{};
			info.direction = -1;
			info.action = -1;

			// Name: ElementName (primary), DisplayName (fallback).
			{
				VARIANT vElem;
				VariantInit(&vElem);
				if (SUCCEEDED(pObj->Get(_bstr_t(L"ElementName"), 0, &vElem, nullptr, nullptr)) &&
					vElem.vt == VT_BSTR && vElem.bstrVal != nullptr && vElem.bstrVal[0] != L'\0')
				{
					info.name.assign(vElem.bstrVal, SysStringLen(vElem.bstrVal));
				}
				VariantClear(&vElem);
			}
			if (info.name.empty())
			{
				VARIANT vDisp;
				VariantInit(&vDisp);
				if (SUCCEEDED(pObj->Get(_bstr_t(L"DisplayName"), 0, &vDisp, nullptr, nullptr)) &&
					vDisp.vt == VT_BSTR && vDisp.bstrVal != nullptr && vDisp.bstrVal[0] != L'\0')
				{
					info.name.assign(vDisp.bstrVal, SysStringLen(vDisp.bstrVal));
				}
				VariantClear(&vDisp);
			}

			// Direction
			{
				VARIANT vDir;
				VariantInit(&vDir);
				if (SUCCEEDED(pObj->Get(_bstr_t(L"Direction"), 0, &vDir, nullptr, nullptr)))
				{
					if (vDir.vt == VT_I4) info.direction = vDir.lVal;
					else if (vDir.vt == VT_UI2) info.direction = vDir.uiVal; // Schema defines it as uint16
					else if (vDir.vt == VT_I2) info.direction = vDir.iVal;
					else if (vDir.vt == VT_UI4) info.direction = static_cast<LONG>(vDir.ulVal);
				}
				VariantClear(&vDir);
			}

			// Action
			{
				VARIANT vAct;
				VariantInit(&vAct);
				if (SUCCEEDED(pObj->Get(_bstr_t(L"Action"), 0, &vAct, nullptr, nullptr)))
				{
					if (vAct.vt == VT_I4) info.action = vAct.lVal;
					else if (vAct.vt == VT_UI2) info.action = vAct.uiVal; // Schema defines it as uint16
					else if (vAct.vt == VT_I2) info.action = vAct.iVal;
					else if (vAct.vt == VT_UI4) info.action = static_cast<LONG>(vAct.ulVal);
				}
				VariantClear(&vAct);
			}

			// If name is missing, skip; we need a stable identifier for deletion later.
			if (!info.name.empty())
			{
				rules.push_back(std::move(info));
			}

			pObj->Release();
		}

		pEnum->Release();
		pCtx->Release();
		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM) CoUninitialize();

		// Build JSON output.
		// Schema:
		// [
		//   { "name":"...", "direction":"Inbound", "action":"Allow" }
		// ]
		std::ostringstream oss;
		oss << "[";
		bool first = true;

		auto dirText = [](LONG d) -> const char*
			{
				if (d == static_cast<LONG>(NetSecurityDirection::Inbound)) return "Inbound";
				if (d == static_cast<LONG>(NetSecurityDirection::Outbound)) return "Outbound";
				return "Unknown";
			};

		auto actionText = [](LONG a) -> const char*
			{
				const LONG allowFlag = static_cast<LONG>(NetSecurityAction::Allow);
				const LONG blockFlag = static_cast<LONG>(NetSecurityAction::Block);

				if ((a & blockFlag) == blockFlag) return "Block";
				if ((a & allowFlag) == allowFlag) return "Allow";
				if (a == static_cast<LONG>(NetSecurityAction::NotConfigured)) return "NotConfigured";
				return "Unknown";
			};

		for (const RuleInfo& r : rules)
		{
			if (!first) oss << ",";
			first = false;

			std::string nameUtf8 = WideToUtf8(r.name.c_str());

			oss << "{";
			oss << "\"name\":\"" << escapeJSON(nameUtf8) << "\"";
			oss << ",\"direction\":\"" << dirText(r.direction) << "\"";
			oss << ",\"action\":\"" << actionText(r.action) << "\"";
			oss << "}";
		}

		oss << "]";

		// Write to stdout as a single JSON token.
		std::cout << oss.str();
		return true;
	}

	/// Enumerates MSFT_NetFirewallRule instances, filters for the mDNS rule group and inbound direction.
	/// Collects matching IWbemClassObject pointers (AddRef'd) into matchedObjects for optional later modification.
	/// Outputs flags: anyFound (at least one match), anyEnabled (one or more currently enabled).
	/// </summary>
	/// <param name="pSvc">Connected IWbemServices pointer</param>
	/// <param name="anyFound">Set to true if any matching rules are found</param>
	/// <param name="anyEnabled">Set to true if any matching rules are enabled</param>
	/// <param name="matchedObjects">Vector receiving AddRef'ed IWbemClassObject pointers for matches</param>
	/// <returns>True on successful enumeration, false on failure (error set)</returns>
	static bool EnumerateMdnsInboundRules(IWbemServices* pSvc,
		bool& anyFound,
		bool& anyEnabled,
		vector<wstring>& instancePaths)
	{
		anyFound = false;
		anyEnabled = false;
		instancePaths.clear();
		if (!pSvc) return false;

		IEnumWbemClassObject* pEnum = nullptr;
		HRESULT hr = pSvc->ExecQuery(
			_bstr_t(L"WQL"),
			_bstr_t(L"SELECT __PATH, RuleGroup, Direction, Enabled FROM MSFT_NetFirewallRule WHERE Direction=1"),
			WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
			nullptr,
			&pEnum);
		if (FAILED(hr) || !pEnum)
		{
			SetLastErrorMsg(L"ExecQuery for MSFT_NetFirewallRule (mDNS enumeration) failed.");
			if (pEnum) pEnum->Release();
			return false;
		}

		const wchar_t* targetGroup = L"@%SystemRoot%\\system32\\firewallapi.dll,-37302";

		for (;;)
		{
			IWbemClassObject* pObj = nullptr;
			ULONG uRet = 0;
			HRESULT hrNext = pEnum->Next(WBEM_INFINITE, 1, &pObj, &uRet);
			if (hrNext != S_OK || uRet == 0 || !pObj)
				break;

			bool groupMatch = false;
			{
				VARIANT v; VariantInit(&v);
				if (SUCCEEDED(pObj->Get(_bstr_t(L"RuleGroup"), 0, &v, nullptr, nullptr)) &&
					v.vt == VT_BSTR && v.bstrVal)
				{
					if (EqualsOrdinalIgnoreCase(v.bstrVal, targetGroup))
						groupMatch = true;
				}
				VariantClear(&v);
			}
			if (!groupMatch)
			{
				pObj->Release();
				continue;
			}

			bool isEnabled = false;
			{
				VARIANT v; VariantInit(&v);
				if (SUCCEEDED(pObj->Get(_bstr_t(L"Enabled"), 0, &v, nullptr, nullptr)))
				{
					LONG enabledVal = -1;
					switch (v.vt)
					{
					case VT_I2: enabledVal = v.iVal; break;
					case VT_UI2: enabledVal = v.uiVal; break;
					case VT_I4: enabledVal = v.lVal; break;
					case VT_UI4: enabledVal = static_cast<LONG>(v.ulVal); break;
					case VT_BSTR:
						if (v.bstrVal)
						{
							if (EqualsOrdinalIgnoreCase(v.bstrVal, L"1")) enabledVal = 1;
							else if (EqualsOrdinalIgnoreCase(v.bstrVal, L"2")) enabledVal = 2;
						}
						break;
					default: break;
					}
					isEnabled = (enabledVal == static_cast<LONG>(NetSecurityEnabled::True));
				}
				VariantClear(&v);
			}

			anyFound = true;
			if (isEnabled) anyEnabled = true;

			// Capture __PATH
			VARIANT vPath; VariantInit(&vPath);
			if (SUCCEEDED(pObj->Get(_bstr_t(L"__PATH"), 0, &vPath, nullptr, nullptr)) &&
				vPath.vt == VT_BSTR && vPath.bstrVal)
			{
				instancePaths.emplace_back(vPath.bstrVal);
			}
			VariantClear(&vPath);

			pObj->Release();
		}

		pEnum->Release();
		return true;
	}

	// PowerShell equivalent: Get-NetFirewallRule |
	// Where - Object - FilterScript{ ($_.RuleGroup - eq '@%SystemRoot%\system32\firewallapi.dll,-37302') - and ($_.Direction - eq 'inbound') } |
	// ForEach - Object - Process{ Disable - NetFirewallRule - DisplayName $_.DisplayName }

	// mDNS UDP-In firewall rule management (RuleGroup + Direction)
	// RuleGroup resource token: "@%SystemRoot%\\system32\\firewallapi.dll,-37302"
	// Direction: Inbound (1)
	// Returns true if all matching rules are disabled (Enabled != 1) OR none exist.
	// Returns false if any matching rule is enabled OR on enumeration failure.
	// Caller can differentiate error by checking GetLastErrorMessage().
	extern "C" __declspec(dllexport) bool __stdcall FW_AreMdnsInboundRulesDisabled()
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
		bool anyEnabled = false;
		vector<wstring> paths;
		bool enumOk = EnumerateMdnsInboundRules(pSvc, anyFound, anyEnabled, paths);

		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM) CoUninitialize();

		if (!enumOk)
		{
			return false;
		}

		// No matches -> treat as disabled
		if (!anyFound)
		{
			return true;
		}

		return !anyEnabled;
	}

	/// <summary>
	/// Enables or disables all mDNS inbound firewall rules.
	/// enable == true  -> Enabled=1 (rule active)
	/// enable == false -> Enabled=2 (rule disabled)
	/// Returns true if all modifications succeed (or none found), false otherwise.
	/// </summary>
	extern "C" __declspec(dllexport) bool __stdcall FW_SetMdnsInboundRulesEnabled(bool enable)
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
		bool anyEnabledIgnore = false;
		vector<wstring> paths;
		if (!EnumerateMdnsInboundRules(pSvc, anyFound, anyEnabledIgnore, paths))
		{
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		// No matching rules -> nothing to change (idempotent success)
		if (!anyFound)
		{
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return true;
		}

		bool allOk = true;

		// For each path, re-fetch the full instance (projection instances are incomplete -> WBEM_E_INVALID_OBJECT on PutInstance).
		for (const wstring& path : paths)
		{
			if (path.empty()) continue;

			IWbemClassObject* pFull = nullptr;
			HRESULT hrGet = pSvc->GetObject(_bstr_t(path.c_str()), 0, nullptr, &pFull, nullptr);
			if (FAILED(hrGet) || !pFull)
			{
				allOk = false;
				string hex = ErrorCodeHexString(hrGet);
				wstring whex = Utf8ToWide(hex);
				wstringstream wss;
				wss << L"Failed to retrieve full firewall rule instance. HRESULT=" << whex
					<< L" Msg=" << _com_error(hrGet).ErrorMessage();
				SetLastErrorMsg(wss.str());
				LogErr(wss.str().c_str());
				if (pFull) pFull->Release();
				continue;
			}

			// Set Enabled property
			VARIANT vSet; VariantInit(&vSet);
			vSet.vt = VT_I4;
			vSet.lVal = enable ? static_cast<LONG>(NetSecurityEnabled::True)
				: static_cast<LONG>(NetSecurityEnabled::False);

			HRESULT hrPutProp = pFull->Put(_bstr_t(L"Enabled"), 0, &vSet, 0);
			VariantClear(&vSet);
			if (FAILED(hrPutProp))
			{
				allOk = false;
				string hex = ErrorCodeHexString(hrPutProp);
				wstring whex = Utf8ToWide(hex);
				wstringstream wss;
				wss << L"Failed to set Enabled property. HRESULT=" << whex
					<< L" Msg=" << _com_error(hrPutProp).ErrorMessage();
				SetLastErrorMsg(wss.str());
				LogErr(wss.str().c_str());
				pFull->Release();
				continue;
			}

			// Commit updated instance (UPDATE_ONLY to indicate modification)
			const int kMaxAttempts = 8;
			DWORD delayMs = 100;
			HRESULT hrCommit = E_FAIL;
			for (int attempt = 1; attempt <= kMaxAttempts; ++attempt)
			{
				hrCommit = pSvc->PutInstance(pFull, WBEM_FLAG_UPDATE_ONLY, nullptr, nullptr);
				if (SUCCEEDED(hrCommit))
					break;
				if (!IsTransientHresult(hrCommit))
					break;
				::Sleep(delayMs);
				if (delayMs < 2000) delayMs <<= 1;
			}

			if (FAILED(hrCommit))
			{
				allOk = false;
				string hex = ErrorCodeHexString(hrCommit);
				wstring whex = Utf8ToWide(hex);
				wstringstream wss;
				wss << L"PutInstance failed while updating Enabled state. HRESULT=" << whex
					<< L" Msg=" << _com_error(hrCommit).ErrorMessage();
				SetLastErrorMsg(wss.str());
				LogErr(wss.str().c_str());
				pFull->Release();
				continue;
			}

			// Success for this instance
			pFull->Release();
		}

		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM) CoUninitialize();

		return allOk;
	}

}
