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
	static inline bool IsTransientHresult(HRESULT hr);

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
	static inline bool IsTransientHresult(HRESULT hr)
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

		// ElementName (this is equivalent to DisplayName)
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

}
