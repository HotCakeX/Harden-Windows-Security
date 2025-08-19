#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <format>
#include <comdef.h>
#include <Wbemidl.h>
#include <windows.h>
#include <cwchar>
#include <ctime>
#include <mutex>
#include <winhttp.h>
#include <array>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "winhttp.lib")

// Bringing the std namespace into scope to avoid prefixing with std::
// std (aka Standard Library is C++ equivalent of System; namespace in C#)
// wcout is used for normal output(typically goes to stdout)
// wcerr is used for error output (goes to stderr).
using namespace std;

// Global variable and mutex for storing the last error message.
static wstring g_lastErrorMsg;
static mutex g_errorMutex;

// Global flag to indicate if the code is running as a library (DLL mode).
// When set to true, COM initialization and security are skipped because they are assumed to be already initialized.
// In packaged WinUI3 apps, Com and Com Security are already initialized so we cannot reinitialize them otherwise we'd get errors.
constinit bool g_skipCOMInit = false;

// Exported function to allow setting the DLL mode from external callers (e.g. C# via DllImport).
extern "C" __declspec(dllexport) void __stdcall SetDllMode(bool skipInit)
{
	g_skipCOMInit = skipInit;
}

// Set the global error message (thread-safe)
static void SetLastErrorMsg(const wstring& msg)
{
	lock_guard<mutex> lock(g_errorMutex);
	g_lastErrorMsg = msg;
}

// Clear the global error message.
static void ClearLastErrorMsg()
{
	lock_guard<mutex> lock(g_errorMutex);
	g_lastErrorMsg.clear();
}

// Exported function to retrieve the last error message using a pointer to its wide string representation.
// The pointer is valid until the next call to any function in this DLL.
extern "C" __declspec(dllexport) const wchar_t* __stdcall GetLastErrorMessage()
{
	lock_guard<mutex> lock(g_errorMutex);
	return g_lastErrorMsg.c_str();
}

// Helper function to escape a string's control characters for JSON output.
static string escapeJSON(string_view s)
{
	string result;
	result.reserve(s.size()); // capacity hint to avoid reallocations

	for (unsigned char uc : s)
	{
		char c = static_cast<char>(uc);
		switch (c)
		{
		case '\\': result.append("\\\\"); break;  // Escape backslash.
		case '\"': result.append("\\\""); break;  // Escape double quote.
		case '\b': result.append("\\b"); break;   // Escape backspace.
		case '\f': result.append("\\f"); break;   // Escape form feed.
		case '\n': result.append("\\n"); break;   // Escape newline.
		case '\r': result.append("\\r"); break;   // Escape carriage return.
		case '\t': result.append("\\t"); break;   // Escape tab.
		default:
			if (uc <= 0x1F || uc == 0x7F)
			{
				result += format("\\u{:04X}", static_cast<unsigned int>(uc));
			}
			else
			{
				// Append the character as is.
				result.push_back(c);
			}
			break;
		}
	}
	return result;
}

// Convert wide string to UTF-8 narrow string for JSON output.
static string WideToUtf8(const wchar_t* s)
{
	if (!s) return string();
	int len = lstrlenW(s);
	if (len <= 0) return string();

	int sizeNeeded = ::WideCharToMultiByte(CP_UTF8, 0, s, len, nullptr, 0, nullptr, nullptr);
	if (sizeNeeded <= 0) return string();

	string result(static_cast<size_t>(sizeNeeded), '\0');
	int written = ::WideCharToMultiByte(CP_UTF8, 0, s, len, result.data(), sizeNeeded, nullptr, nullptr);
	if (written <= 0) return string();

	return result;
}

static string BstrToUtf8(BSTR s)
{
	if (!s) return string();
	UINT len = SysStringLen(s); // Use BSTR's length
	if (len == 0) return string();

	int sizeNeeded = ::WideCharToMultiByte(CP_UTF8, 0, s, static_cast<int>(len), nullptr, 0, nullptr, nullptr);
	if (sizeNeeded <= 0) return string();

	string result(static_cast<size_t>(sizeNeeded), '\0');
	int written = ::WideCharToMultiByte(CP_UTF8, 0, s, static_cast<int>(len), result.data(), sizeNeeded, nullptr, nullptr);
	if (written <= 0) return string();

	return result;
}

// Format a COM DATE to ISO 8601 "YYYY-MM-DDTHH:MM:SS" string.
// Returns true on success and writes the result to outIso8601; returns false on failure.
static bool TryFormatDateIso8601(DATE date, string& outIso8601)
{
	SYSTEMTIME st{};
	if (!VariantTimeToSystemTime(date, &st))
	{
		return false;
	}

	outIso8601 = format("{:04d}-{:02d}-{:02d}T{:02d}:{:02d}:{:02d}",
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
	return true;
}

// Quote a BSTR as a JSON string with UTF-8 encoding and escaping.
// Returns a fully-formed JSON string token e.g., "text".
static string QuoteBstrJson(BSTR s)
{
	if (!s) return "\"\"";
	string utf8 = BstrToUtf8(s);
	return "\"" + escapeJSON(utf8) + "\"";
}

// Format an SCODE as unsigned hex with "0x" prefix (lowercase hex), without quotes.
static string ErrorCodeHexString(SCODE sc)
{
	return format("0x{:x}", static_cast<unsigned long>(sc));
}

// copy an "effective" variant by resolving VT_BYREF and VT_VARIANT wrappers.
// - 'out' must be VariantInit'd by the caller.
// - Returns true if 'out' received a valid copy, else false.
static bool CopyEffectiveVariant(const VARIANT& in, VARIANT& out)
{
	// Resolve BYREF indirection when present.
	if (in.vt & VT_BYREF)
	{
		return SUCCEEDED(VariantCopyInd(&out, const_cast<VARIANT*>(&in)));
	}

	// Resolve embedded VT_VARIANT pointer when present.
	if (in.vt == VT_VARIANT && in.pvarVal != nullptr)
	{
		return SUCCEEDED(VariantCopy(&out, in.pvarVal));
	}

	// Fallback: direct copy.
	return SUCCEEDED(VariantCopy(&out, const_cast<VARIANT*>(&in)));
}

// Helper function to process SAFEARRAY of different types and return JSON array string.
template<typename T>
static string ProcessSafeArray(SAFEARRAY* psa)
{
	// Variables to hold the lower and upper bounds.
	LONG lBound = 0, uBound = 0;
	// Get array boundaries from the SAFEARRAY.
	if (FAILED(SafeArrayGetLBound(psa, 1, &lBound)) ||
		FAILED(SafeArrayGetUBound(psa, 1, &uBound)))
		return "[]"; // return empty JSON array on failure
	// Return an empty JSON array string if the array has no members.
	if ((uBound - lBound + 1) <= 0)
		return "[]";

	// Stream to build the JSON array string.
	ostringstream json;
	// Start the JSON array.
	json << "[";
	// Boolean flag to handle comma separation between elements.
	bool first = true;

	// Iterate through the array elements.
	for (LONG i = lBound; i <= uBound; i++)
	{
		// Variable to store the element.
		T element{};
		// Retrieve the element; continue to next iteration if retrieval fails.
		if (FAILED(SafeArrayGetElement(psa, &i, &element)))
			continue;

		// Inserting a comma if this is not the first element.
		if (!first)
			json << ",";

		// Handle different types appropriately for JSON output
		if constexpr (is_same_v<T, BSTR>)
		{
			// For BSTR elements, convert to UTF-8 JSON string and escape
			// QuoteBstrJson does not free the BSTR; we free it after use.
			json << QuoteBstrJson(element);
			if (element) SysFreeString(element);
		}
		else if constexpr (is_same_v<T, VARIANT_BOOL>)
		{
			// For boolean values, convert to "true" or "false"
			json << (element ? "true" : "false");
		}
		else if constexpr (is_same_v<T, DATE>)
		{
			// For DATE values, format as ISO 8601 string
			string dateStr;
			if (TryFormatDateIso8601(element, dateStr))
			{
				json << "\"" << dateStr << "\"";
			}
			else
			{
				json << "null";
			}
		}
		else if constexpr (is_same_v<T, CY>)
		{
			// For currency values, convert to double representation
			double currencyValue = 0.0;
			if (SUCCEEDED(VarR8FromCy(element, &currencyValue)))
				json << format("{:.17g}", currencyValue); // culture-invariant
			else
				json << "null";
		}
		else if constexpr (is_same_v<T, DECIMAL>)
		{
			// For decimal values, convert to double representation
			double decimalValue = 0.0;
			if (SUCCEEDED(VarR8FromDec(&element, &decimalValue)))
				json << format("{:.17g}", decimalValue); // culture-invariant
			else
				json << "null";
		}
		else if constexpr (is_same_v<T, SCODE>)
		{
			// For error codes, output as hex string; keep it quoted as JSON string
			json << "\"" << ErrorCodeHexString(element) << "\"";
		}
		else if constexpr (is_same_v<T, signed char>)
		{
			// Ensure 8-bit signed integers are emitted as numbers, not characters
			json << format("{}", static_cast<int>(element)); // culture-invariant integer formatting
		}
		else if constexpr (is_same_v<T, unsigned char>)
		{
			// Ensure 8-bit unsigned integers are emitted as numbers, not characters
			json << format("{}", static_cast<unsigned int>(element)); // culture-invariant integer formatting
		}
		else if constexpr (is_same_v<T, short>)
		{
			json << format("{}", element);
		}
		else if constexpr (is_same_v<T, unsigned short>)
		{
			json << format("{}", element);
		}
		else if constexpr (is_same_v<T, int>)
		{
			json << format("{}", element);
		}
		else if constexpr (is_same_v<T, unsigned int>)
		{
			json << format("{}", element);
		}
		else if constexpr (is_same_v<T, long>)
		{
			json << format("{}", element);
		}
		else if constexpr (is_same_v<T, unsigned long>)
		{
			json << format("{}", element);
		}
		else if constexpr (is_same_v<T, long long>)
		{
			json << format("{}", element);
		}
		else if constexpr (is_same_v<T, unsigned long long>)
		{
			json << format("{}", element);
		}
		else if constexpr (is_same_v<T, float>)
		{
			// Culture-invariant float formatting; map non-finite (NaN/Inf) to null
			double dv = static_cast<double>(element);
			bool notFinite = (dv != dv) || ((dv - dv) != (dv - dv));
			if (notFinite)
				json << "null";
			else
				json << format("{:.9g}", dv);
		}
		else if constexpr (is_same_v<T, double>)
		{
			// Culture-invariant double formatting; map non-finite (NaN/Inf) to null
			double dv = element;
			bool notFinite = (dv != dv) || ((dv - dv) != (dv - dv));
			if (notFinite)
				json << "null";
			else
				json << format("{:.17g}", dv);
		}
		else
		{
			// For numeric types, output directly
			json << element;
		}

		// Update the flag after processing the first element.
		first = false;
	}
	// End the JSON array.
	json << "]";
	// Return the complete JSON array string.
	return json.str();
}

// VariantToString converts a VARIANT to its JSON string representation.
// For JSON output, proper types are used:
// - Strings are output directly.
// - Numbers and booleans are output directly.
// - VT_NULL and VT_EMPTY return null.
// - When the variant type is a SAFEARRAY (for strings or integers) and the array has no members,
//   it returns an empty string (i.e. nothing is output).
static string VariantToString(const VARIANT& vt)
{
	// A string stream to convert numeric values to a string.
	ostringstream oss;

	// Get the variant type
	VARTYPE vtType = vt.vt;

	// Handle SAFEARRAY types first
	if (vtType & VT_ARRAY)
	{
		SAFEARRAY* psa = vt.parray;
		if (!psa) return "[]";

		// Get base type by removing VT_ARRAY flag
		VARTYPE baseType = vtType & ~VT_ARRAY;

		switch (baseType)
		{
		case VT_I1: // SAFEARRAY of signed chars
			return ProcessSafeArray<signed char>(psa);
		case VT_UI1: // SAFEARRAY of unsigned chars
			return ProcessSafeArray<unsigned char>(psa);
		case VT_I2: // SAFEARRAY of 16-bit signed integers
			return ProcessSafeArray<short>(psa);
		case VT_UI2: // SAFEARRAY of 16-bit unsigned integers
			return ProcessSafeArray<unsigned short>(psa);
		case VT_I4: // SAFEARRAY of 32-bit signed integers
			return ProcessSafeArray<int>(psa);
		case VT_UI4: // SAFEARRAY of 32-bit unsigned integers
			return ProcessSafeArray<unsigned int>(psa);
		case VT_I8: // SAFEARRAY of 64-bit signed integers
			return ProcessSafeArray<long long>(psa);
		case VT_UI8: // SAFEARRAY of 64-bit unsigned integers
			return ProcessSafeArray<unsigned long long>(psa);
		case VT_R4: // SAFEARRAY of floats
			return ProcessSafeArray<float>(psa);
		case VT_R8: // SAFEARRAY of doubles
			return ProcessSafeArray<double>(psa);
		case VT_BOOL: // SAFEARRAY of booleans
			return ProcessSafeArray<VARIANT_BOOL>(psa);
		case VT_DATE: // SAFEARRAY of dates
			return ProcessSafeArray<DATE>(psa);
		case VT_CY: // SAFEARRAY of currency
			return ProcessSafeArray<CY>(psa);
		case VT_ERROR: // SAFEARRAY of error codes
			return ProcessSafeArray<SCODE>(psa);
		case VT_DECIMAL: // SAFEARRAY of decimals
			return ProcessSafeArray<DECIMAL>(psa);
		case VT_BSTR: // SAFEARRAY of strings
		{
			// Handle BSTR arrays separately as they need special memory management
			LONG lBound = 0, uBound = 0;
			if (FAILED(SafeArrayGetLBound(psa, 1, &lBound)) ||
				FAILED(SafeArrayGetUBound(psa, 1, &uBound)))
				return "[]";
			if ((uBound - lBound + 1) <= 0)
				return "[]";

			ostringstream json;
			json << "[";
			bool first = true;
			for (LONG i = lBound; i <= uBound; i++)
			{
				BSTR bstr{};
				if (FAILED(SafeArrayGetElement(psa, &i, &bstr)))
					continue;
				if (!first)
					json << ",";
				json << QuoteBstrJson(bstr);
				if (bstr) SysFreeString(bstr);
				first = false;
			}
			json << "]";
			return json.str();
		}
		case VT_VARIANT: // SAFEARRAY of variants (nested)
		{
			LONG lBound = 0, uBound = 0;
			if (FAILED(SafeArrayGetLBound(psa, 1, &lBound)) ||
				FAILED(SafeArrayGetUBound(psa, 1, &uBound)))
				return "[]";
			if ((uBound - lBound + 1) <= 0)
				return "[]";

			ostringstream json;
			json << "[";
			bool first = true;
			for (LONG i = lBound; i <= uBound; i++)
			{
				VARIANT varElement;
				VariantInit(&varElement);
				if (SUCCEEDED(SafeArrayGetElement(psa, &i, &varElement)))
				{
					if (!first)
						json << ",";

					// Recursively process nested variant with type-aware quoting for JSON output
					string elemJson;
					if (varElement.vt == VT_NULL || varElement.vt == VT_EMPTY)
					{
						elemJson = "null";
					}
					else if (varElement.vt == VT_BSTR)
					{
						elemJson = QuoteBstrJson(varElement.bstrVal);
					}
					else if (varElement.vt == VT_DATE)
					{
						string dateStr;
						if (TryFormatDateIso8601(varElement.date, dateStr))
						{
							elemJson = "\"" + dateStr + "\"";
						}
						else
						{
							elemJson = "null";
						}
					}
					else if (varElement.vt == VT_ERROR)
					{
						elemJson = "\"" + ErrorCodeHexString(varElement.scode) + "\"";
					}
					else
					{
						elemJson = VariantToString(varElement);
						if (elemJson.empty())
							elemJson = "null";
					}

					json << elemJson;
					first = false;
				}
				VariantClear(&varElement);
			}
			json << "]";
			return json.str();
		}
		default:
			// Unsupported SAFEARRAY type: return empty JSON array to preserve array typing
			return "[]";
		}
	}

	// Handle non-array types
	switch (vtType)
	{
	case VT_NULL:
	case VT_EMPTY:
		// Return an empty string for empty and null variants.
		return "";

	case VT_BSTR: // VARENUM(8), string value
	{
		// Convert the BSTR (COM string type) to a standard C++ UTF-8 string.
		string val = WideToUtf8(vt.bstrVal);
		// Return string as is.
		return val;
	}
	case VT_I1:
		// Convert signed char to int and return the numerical representation.
		return format("{}", static_cast<int>(vt.cVal));
	case VT_UI1: // VARENUM(17) as integer type
		// Convert unsigned char to unsigned int for numeric output.
		return format("{}", static_cast<unsigned int>(vt.bVal));
	case VT_I2:
		// Output the 16-bit signed integer.
		return format("{}", vt.iVal);
	case VT_UI2:
		// Output the 16-bit unsigned integer.
		return format("{}", vt.uiVal);
	case VT_I4: // VARENUM(3)
		// Output the 32-bit signed integer.
		return format("{}", vt.lVal);
	case VT_UI4:
		// Output the 32-bit unsigned integer.
		return format("{}", vt.ulVal);
	case VT_INT:
		// Output the signed integer (platform-dependent size).
		return format("{}", vt.intVal);
	case VT_UINT:
		// Output the unsigned integer.
		return format("{}", vt.uintVal);
	case VT_I8:
		// Output the 64-bit signed integer.
		return format("{}", vt.llVal);
	case VT_UI8:
		// Output the 64-bit unsigned integer.
		return format("{}", vt.ullVal);
	case VT_R4:
	{
		// Output the float value (culture-invariant); non-finite -> null
		double dv = static_cast<double>(vt.fltVal);
		bool notFinite = (dv != dv) || ((dv - dv) != (dv - dv));
		if (notFinite) return "null";
		return format("{:.9g}", dv);
	}
	case VT_R8:
	{
		// Output the double value (culture-invariant); non-finite -> null
		double dv = vt.dblVal;
		bool notFinite = (dv != dv) || ((dv - dv) != (dv - dv));
		if (notFinite) return "null";
		return format("{:.17g}", dv);
	}
	case VT_BOOL: // VARENUM(11)
		// Convert the boolean value to "true" or "false".
		return vt.boolVal ? "true" : "false";
	case VT_DATE:
	{
		// Convert DATE to ISO 8601 string; DATE has no time zone. Return empty string on failure (callers decide on null/quoting)
		string dateStr;
		if (TryFormatDateIso8601(vt.date, dateStr))
		{
			return dateStr;
		}
		else
		{
			return "";
		}
	}
	case VT_CY: // Currency type
	{
		// Convert currency to double representation
		double currencyValue = 0.0;
		if (SUCCEEDED(VarR8FromCy(vt.cyVal, &currencyValue)))
		{
			return format("{:.17g}", currencyValue); // culture-invariant
		}
		return "";
	}
	case VT_DECIMAL: // Decimal type
	{
		// Convert decimal to double representation
		double decimalValue = 0.0;
		if (SUCCEEDED(VarR8FromDec(&vt.decVal, &decimalValue)))
		{
			return format("{:.17g}", decimalValue); // culture-invariant
		}
		return "";
	}
	case VT_ERROR: // Error code
	{
		// Output error code as hex string without quotes; callers add quotes when needed
		return ErrorCodeHexString(vt.scode);
	}
	case VT_DISPATCH: // IDispatch pointer
		// For COM objects, return a placeholder
		return "\"[IDispatch Object]\"";
	case VT_UNKNOWN: // IUnknown pointer
		// For COM objects, return a placeholder
		return "\"[IUnknown Object]\"";
	case VT_VARIANT: // Variant pointer (should not happen in normal cases)
		// For safety, handle variant pointers
		if (vt.pvarVal)
		{
			return VariantToString(*vt.pvarVal);
		}
		return "";
	default:
		// Handle BYREF types by dereferencing
		if (vtType & VT_BYREF)
		{
			VARTYPE baseType = vtType & ~VT_BYREF;
			if (baseType == VT_VARIANT && vt.pvarVal)
			{
				return VariantToString(*vt.pvarVal);
			}
			// For other BYREF types, create a new variant with the dereferenced value
			VARIANT tempVar;
			VariantInit(&tempVar);
			if (SUCCEEDED(VariantCopyInd(&tempVar, &vt)))
			{
				string result = VariantToString(tempVar);
				VariantClear(&tempVar);
				return result;
			}
		}
		// Return an empty string literal to indicate no output for unsupported types.
		return "\"\"";
	}
}

// =============================
// Firewall Management
// ==============================

// WMI namespace and class constants for firewall operations
static constexpr const wchar_t* HWS_WMI_NS_STANDARDCIMV2 = L"root\\StandardCimv2";
static constexpr const wchar_t* HWS_WMI_FIREWALL_RULE = L"MSFT_NetFirewallRule";

// NetSecurity enums
enum class NetSecurityEnabled : unsigned short
{
	True = 1,
	False = 2
};

enum class NetSecurityProfile : unsigned short
{
	Any = 0,
	Public = 4,
	Private = 2,
	Domain = 1,
	NotApplicable = 65535
};

enum class NetSecurityDirection : unsigned short
{
	Inbound = 1,
	Outbound = 2
};

enum class NetSecurityAction : unsigned short
{
	NotConfigured = 0,
	Allow = 2,
	Block = 4
};

enum class NetSecurityEdgeTraversal : unsigned short
{
	Block = 0,
	Allow = 1,
	DeferToUser = 2,
	DeferToApp = 3
};

enum class NetSecurityPrimaryStatus : unsigned short
{
	Unknown = 0,
	OK = 1,
	Inactive = 2,
	Error = 3
};

enum class NetSecurityPolicyStoreType : unsigned short
{
	None = 0,
	Local = 1,
	GroupPolicy = 2,
	Dynamic = 3,
	Generated = 4,
	Hardcoded = 5,
	MDM = 6,
	HostFirewallLocal = 8,
	HostFirewallGroupPolicy = 9,
	HostFirewallDynamic = 10,
	HostFirewallMDM = 11
};

// Bitflag-style enums
enum class NetSecurityDynamicTransport : unsigned int
{
	Any = 0,
	ProximityApps = 1,
	ProximitySharing = 2,
	WifiDirectPrinting = 4,
	WifiDirectDisplay = 8,
	WifiDirectDevices = 16
};

enum class NetSecurityInterfaceType : unsigned int
{
	Any = 0,
	Wired = 1,
	Wireless = 2,
	RemoteAccess = 4
};

static wstring Utf8ToWide(string_view s)
{
	if (s.empty()) return wstring();
	int sizeNeeded = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0);
	if (sizeNeeded <= 0) return wstring();
	wstring result(static_cast<size_t>(sizeNeeded), L'\0');
	int written = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), result.data(), sizeNeeded);
	if (written <= 0) return wstring();
	return result;
}

/// <summary>
/// Downloads content from a URL and parses it into a vector of IP address strings
/// by splitting on newlines and filtering out comments and empty lines.
/// </summary>
/// <param name="url">The URL to download from (must be a valid HTTP/HTTPS URL)</param>
/// <param name="ipList">Reference to vector that will be populated with IP addresses</param>
/// <returns>True if download and parsing succeeded, false otherwise</returns>
[[nodiscard]] static bool DownloadIPList(const wchar_t* url, vector<wstring>& ipList)
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
		wcerr << L"WinHttpSetTimeouts warning: " << makeWin32ErrorMessage(L"WinHttpSetTimeouts", err) << endl;
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
			wcerr << L"WinHttpSetOption(WINHTTP_OPTION_DECOMPRESSION) warning: "
				<< makeWin32ErrorMessage(L"WinHttpSetOption(WINHTTP_OPTION_DECOMPRESSION)", err) << endl;
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

static bool EqualsOrdinalIgnoreCase(const wchar_t* a, const wchar_t* b)
{
	if (a == b) return true;
	if (!a || !b) return false;
	return ::CompareStringOrdinal(a, -1, b, -1, TRUE) == CSTR_EQUAL;
}

/// <summary>
/// Helper function to create a SAFEARRAY of BSTR from a vector of wide strings.
/// This is used to pass string arrays to WMI methods (like RemoteAddress arrays).
/// </summary>
/// <param name="values">Vector of wide strings to convert</param>
/// <param name="ppsa">Pointer to receive the created SAFEARRAY</param>
/// <returns>HRESULT indicating success or failure</returns>
[[nodiscard]] static HRESULT CreateSafeArrayOfBSTR(const vector<wstring>& values, SAFEARRAY** ppsa)
{
	if (!ppsa) return E_POINTER;
	*ppsa = nullptr;

	// Set up SAFEARRAY bounds
	SAFEARRAYBOUND sab{};
	sab.lLbound = 0;
	sab.cElements = static_cast<ULONG>(values.size());

	// Create SAFEARRAY for BSTR elements
	SAFEARRAY* psa = SafeArrayCreate(VT_BSTR, 1, &sab);
	if (psa == nullptr)
	{
		return E_OUTOFMEMORY;
	}

	// Populate the SAFEARRAY with BSTR elements
	for (LONG i = 0; i < static_cast<LONG>(values.size()); i++)
	{
		BSTR b = SysAllocString(values[i].c_str());
		if (!b)
		{
			SafeArrayDestroy(psa);
			return E_OUTOFMEMORY;
		}
		HRESULT hr = SafeArrayPutElement(psa, &i, b);
		SysFreeString(b);  // SafeArrayPutElement makes a copy
		if (FAILED(hr))
		{
			SafeArrayDestroy(psa);
			return hr;
		}
	}

	*ppsa = psa;
	return S_OK;
}

/// <summary>
/// Helper function to create IWbemContext and set a string named value on it.
/// This is used to set WMI operation context parameters like PolicyStore.
/// </summary>
/// <param name="ppCtx">Pointer to receive the created IWbemContext</param>
/// <param name="name">Name of the context parameter</param>
/// <param name="value">Value of the context parameter</param>
/// <returns>HRESULT indicating success or failure</returns>
[[nodiscard]] static HRESULT CreateContextAndSetString(IWbemContext** ppCtx, const wchar_t* name, const wchar_t* value)
{
	if (!ppCtx || !name || !value) return E_INVALIDARG;
	*ppCtx = nullptr;

	// Create WMI context object
	IWbemContext* pCtx = nullptr;
	HRESULT hr = CoCreateInstance(CLSID_WbemContext, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemContext, reinterpret_cast<void**>(&pCtx));
	if (FAILED(hr))
	{
		return hr;
	}

	// Set the named value on the context
	VARIANT v;
	VariantInit(&v);
	v.vt = VT_BSTR;
	v.bstrVal = SysAllocString(value);
	if (!v.bstrVal)
	{
		pCtx->Release();
		return E_OUTOFMEMORY;
	}

	hr = pCtx->SetValue(_bstr_t(name), 0, &v);
	VariantClear(&v);

	if (FAILED(hr))
	{
		pCtx->Release();
		return hr;
	}

	*ppCtx = pCtx;
	return S_OK;
}

/// <summary>
/// Helper function to set an array of BSTR strings on IWbemContext.
/// This is used to set address arrays in the WMI context for firewall operations.
/// </summary>
/// <param name="pCtx">The WMI context object</param>
/// <param name="name">Name of the context parameter</param>
/// <param name="psa">SAFEARRAY containing the string values</param>
/// <returns>HRESULT indicating success or failure</returns>
[[nodiscard]] static HRESULT ContextSetStringArray(IWbemContext* pCtx, const wchar_t* name, SAFEARRAY* psa)
{
	if (!pCtx || !name || !psa) return E_INVALIDARG;

	VARIANT v;
	VariantInit(&v);
	v.vt = VT_ARRAY | VT_BSTR;
	v.parray = psa;

	// IWbemContext copies the VARIANT value internally. Caller retains ownership of psa and can destroy it.
	HRESULT hr = pCtx->SetValue(_bstr_t(name), 0, &v);
	return hr;
}

/// <summary>
/// Connects to a WMI namespace with proper COM/security handling.
/// Accepts both "too late" security initialization variants for compatibility.
/// </summary>
/// <param name="wmiNamespace">WMI namespace to connect to</param>
/// <param name="ppLoc">Pointer to receive the IWbemLocator interface</param>
/// <param name="ppSvc">Pointer to receive the IWbemServices interface</param>
/// <param name="didInitCOM">Reference to bool indicating if COM was initialized</param>
/// <returns>True if connection succeeded, false otherwise</returns>
[[nodiscard]] static bool ConnectToWmiNamespace(const wchar_t* wmiNamespace, IWbemLocator** ppLoc, IWbemServices** ppSvc, bool& didInitCOM)
{
	if (!ppLoc || !ppSvc || !wmiNamespace) return false;
	*ppLoc = nullptr;
	*ppSvc = nullptr;
	didInitCOM = false;

	HRESULT hres = S_OK;

	// Initialize COM if not in DLL mode
	if (!g_skipCOMInit)
	{
		hres = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
		if (hres == RPC_E_CHANGED_MODE)
		{
			hres = S_OK;  // COM already initialized with different threading model
		}
		if (FAILED(hres))
		{
			SetLastErrorMsg(L"Failed to initialize COM library.");
			return false;
		}
		didInitCOM = true;

		// Initialize COM security - accept both "security already initialized" error codes
		hres = CoInitializeSecurity(
			nullptr,
			-1,
			nullptr,
			nullptr,
			RPC_C_AUTHN_LEVEL_DEFAULT,
			RPC_C_IMP_LEVEL_IMPERSONATE,
			nullptr,
			EOAC_NONE,
			nullptr
		);
		if (hres == 0x80010109 || hres == 0x80010119)  // Both "too late" variants
		{
			hres = S_OK;
		}
		if (FAILED(hres))
		{
			SetLastErrorMsg(L"Failed to initialize security.");
			if (didInitCOM) CoUninitialize();
			return false;
		}
	}

	// Create WMI locator object
	IWbemLocator* pLoc = nullptr;
	hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, reinterpret_cast<LPVOID*>(&pLoc));
	if (FAILED(hres) || !pLoc)
	{
		SetLastErrorMsg(L"Failed to create IWbemLocator object.");
		if (!g_skipCOMInit && didInitCOM) CoUninitialize();
		return false;
	}

	// Connect to WMI namespace
	IWbemServices* pSvc = nullptr;
	hres = pLoc->ConnectServer(
		_bstr_t(wmiNamespace),
		nullptr, nullptr, nullptr, 0,
		nullptr, nullptr, &pSvc
	);
	if (FAILED(hres) || !pSvc)
	{
		SetLastErrorMsg(wstring(L"Could not connect to namespace: ") + wmiNamespace);
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM) CoUninitialize();
		return false;
	}

	// Set proxy blanket for authentication
	hres = CoSetProxyBlanket(
		pSvc,
		RPC_C_AUTHN_WINNT,
		RPC_C_AUTHZ_NONE,
		nullptr,
		RPC_C_AUTHN_LEVEL_CALL,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		nullptr,
		EOAC_NONE
	);
	if (FAILED(hres))
	{
		SetLastErrorMsg(L"Could not set proxy blanket.");
		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM) CoUninitialize();
		return false;
	}

	*ppLoc = pLoc;
	*ppSvc = pSvc;
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
[[nodiscard]] static bool DeleteFirewallRulesInPolicyStore(IWbemServices* pSvc, const wchar_t* displayName)
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
				HRESULT hrDel = pSvc->DeleteInstance(vPath.bstrVal, 0, pCtx, nullptr);
				if (FAILED(hrDel))
				{
					ok = false;  // Mark as failed but continue deleting other matches
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

/// <summary>
/// Creates a single firewall rule (inbound or outbound) in PolicyStore=localhost 
/// with the provided RemoteAddress array.
/// </summary>
/// <param name="pSvc">WMI services interface</param>
/// <param name="displayName">Display name for the new firewall rule</param>
/// <param name="inbound">True for inbound rule, false for outbound rule</param>
/// <param name="remoteIps">Vector of IP addresses/ranges to block</param>
/// <returns>True if rule creation succeeded, false otherwise</returns>
[[nodiscard]] static bool CreateFirewallRuleInPolicyStore(IWbemServices* pSvc, const wchar_t* displayName, bool inbound, const vector<wstring>& remoteIps)
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
	hr = pSvc->PutInstance(pInst, 0, pCtx, nullptr);
	if (FAILED(hr))
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

// Function that configures WMI preferences via a specified WMI method on any WMI Class/Namespace.
//
// The following types have been detected from the raw results of WMI queries:
// - VARENUM(8): corresponds to string (BSTR).
// - VARENUM(11): corresponds to boolean (VT_BOOL).
// - VARENUM(3) and VARENUM(17): correspond to integer types (VT_I4).
// - VARENUM(8200): corresponds to a SAFEARRAY of strings, so support for vector<wstring>.
// - VARENUM(8209): corresponds to a SAFEARRAY of integers, so support for vector<int>.
//
// This function sets the VARIANT value based on template parameter T, then executes the specified WMI method.
template <typename T>
[[nodiscard]] bool ManageWmiPreference(const wchar_t* wmiNamespace, const wchar_t* wmiClassName, const wchar_t* customMethodName, const wchar_t* preferenceName, T preferenceValue)
{
	// Compile-time check ensuring that only permitted types are accepted.
	static_assert(
		is_same<T, bool>::value ||
		is_same<T, int>::value ||
		is_convertible<T, wstring>::value ||
		is_same<T, vector<wstring>>::value ||
		is_same<T, vector<int>>::value,
		"ManageWmiPreference supports only bool, int, string, vector<string>, and vector<int> types."
		);

	// Clear the global error message at the beginning.
	ClearLastErrorMsg();

	// Variable to store the result of COM function calls.
	HRESULT hres = S_OK;

	// Flag to indicate if this function performed COM initialization.
	bool didInitCOM = false;

	// In command line mode, we need to initialize COM and COM security.
	// When used as a DLL (g_skipCOMInit is true), those are assumed to have been performed already.
	if (!g_skipCOMInit)
	{
		// Initialize COM library for multithreaded use.
		hres = CoInitializeEx(0, COINIT_MULTITHREADED);

		// Check if COM is already initialized in a different model (RPC_E_CHANGED_MODE = 0x80010106)
		if (hres == RPC_E_CHANGED_MODE)
		{
			hres = S_OK;
		}
		if (FAILED(hres))
		{
			// Output the error details for COM initialization failure.
			wcerr << L"Failed to initialize COM library. Error code = 0x"
				<< hex << hres << L" - " << _com_error(hres).ErrorMessage() << endl;
			SetLastErrorMsg(wstring(L"Failed to initialize COM library. Error code = 0x") + to_wstring(hres));
			return false;
		}
		didInitCOM = true;

		// Initialize general COM security settings.
		hres = CoInitializeSecurity(
			NULL,                           // Let COM choose the authentication service.
			-1,                             // COM negotiates the service.
			NULL,                           // No custom authentication services.
			NULL,                           // Reserved parameter.
			RPC_C_AUTHN_LEVEL_DEFAULT,      // Default authentication level for proxies.
			RPC_C_IMP_LEVEL_IMPERSONATE,    // Default impersonation level for proxies.
			NULL,                           // No authentication information.
			EOAC_NONE,                      // No additional capabilities.
			NULL                            // Reserved parameter.
		);
		// Check if security is already initialized (error 0x80010109 or 0x80010119)
		if (hres == 0x80010109 || hres == 0x80010119)
		{
			hres = S_OK;
		}
		if (FAILED(hres))
		{
			// Log error details for security initialization failure.
			wcerr << L"Failed to initialize security. Error code = 0x"
				<< hex << hres << L" - " << _com_error(hres).ErrorMessage() << endl;
			SetLastErrorMsg(wstring(L"Failed to initialize security. Error code = 0x") + to_wstring(hres));
			if (didInitCOM) CoUninitialize();
			return false;
		}
	}

	// Pointer for the WMI locator interface.
	IWbemLocator* pLoc = nullptr;
	// Create the WMI locator instance.
	hres = CoCreateInstance(
		CLSID_WbemLocator,              // CLSID for the WMI locator.
		0,                              // Not used.
		CLSCTX_INPROC_SERVER,           // Specify in-proc server context.
		IID_IWbemLocator,               // Interface ID for IWbemLocator.
		reinterpret_cast<LPVOID*>(&pLoc) // Address of pointer to receive the interface.
	);
	if (FAILED(hres))
	{
		// Log the error if creating the IWbemLocator instance fails.
		wcerr << L"Failed to create IWbemLocator object. Error code = 0x"
			<< hex << hres << L" - " << _com_error(hres).ErrorMessage() << endl;
		SetLastErrorMsg(wstring(L"Failed to create IWbemLocator object. Error code = 0x") + to_wstring(hres));
		if (!g_skipCOMInit && didInitCOM)
			CoUninitialize();
		return false;
	}

	// Declare a pointer for the IWbemServices interface.
	IWbemServices* pSvc = nullptr;
	// Connect to the specified WMI namespace.
	hres = pLoc->ConnectServer(
		_bstr_t(wmiNamespace),          // Specify the target WMI namespace
		NULL,       // User name.
		NULL,       // User password.
		0,          // Locale.
		NULL,       // Security flags.
		0,          // Authority.
		0,          // Context object.
		&pSvc       // Receive the IWbemServices proxy.
	);
	if (FAILED(hres))
	{
		// Log the error details if connection to the WMI namespace fails.
		wcerr << L"Could not connect to " << wmiNamespace << L" namespace. Error code = 0x"
			<< hex << hres << L" - " << _com_error(hres).ErrorMessage() << endl;
		SetLastErrorMsg(wstring(L"Could not connect to ") + wmiNamespace + L" namespace. Error code = 0x" + to_wstring(hres));
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM)
			CoUninitialize();
		return false;
	}

	// Set security levels on the IWbemServices proxy.
	hres = CoSetProxyBlanket(
		pSvc,                           // The proxy on which to set security.
		RPC_C_AUTHN_WINNT,              // NTLM authentication.
		RPC_C_AUTHZ_NONE,               // No specific authorization.
		NULL,                           // No principal name.
		RPC_C_AUTHN_LEVEL_CALL,         // Authentication level for each call.
		RPC_C_IMP_LEVEL_IMPERSONATE,    // Impersonation level.
		NULL,                           // No additional authentication info.
		EOAC_NONE                       // No extra capabilities.
	);
	if (FAILED(hres))
	{
		// Log error if setting the proxy's security fails.
		wcerr << L"Could not set proxy blanket. Error code = 0x"
			<< hex << hres << L" - " << _com_error(hres).ErrorMessage() << endl;
		SetLastErrorMsg(wstring(L"Could not set proxy blanket. Error code = 0x") + to_wstring(hres));
		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM)
			CoUninitialize();
		return false;
	}

	// Allocate a BSTR for the class name
	BSTR className = SysAllocString(wmiClassName);
	// Declare a pointer for the WMI class object.
	IWbemClassObject* pClass = nullptr;
	// Retrieve the WMI class object.
	hres = pSvc->GetObject(className, 0, NULL, &pClass, NULL);
	if (FAILED(hres))
	{
		// Log error if retrieving the class object fails.
		wcerr << L"Failed to get " << wmiClassName << L" object. Error code = 0x"
			<< hex << hres << L" - " << _com_error(hres).ErrorMessage() << endl;
		SetLastErrorMsg(wstring(L"Failed to get ") + wmiClassName + L" object. Error code = 0x" + to_wstring(hres));
		SysFreeString(className);
		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM)
			CoUninitialize();
		return false;
	}

	// Create a BSTR for the method name using the provided customMethodName.
	BSTR methodName = SysAllocString(customMethodName);
	// Declare a pointer for the input parameters definition.
	IWbemClassObject* pInParamsDefinition = nullptr;
	// Retrieve the method definition from the class object.
	hres = pClass->GetMethod(methodName, 0, &pInParamsDefinition, NULL);
	if (FAILED(hres))
	{
		// Log error if method definition retrieval fails.
		wcerr << L"Failed to get method definition for " << customMethodName
			<< L". Error code = 0x" << hex << hres
			<< L" - " << _com_error(hres).ErrorMessage() << endl;
		SetLastErrorMsg(wstring(L"Failed to get method definition for ") + customMethodName + L". Error code = 0x" + to_wstring(hres));
		SysFreeString(methodName);
		SysFreeString(className);
		pClass->Release();
		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM)
			CoUninitialize();
		return false;
	}

	// Declare a pointer for the instance of the method input parameters.
	IWbemClassObject* pInParams = nullptr;

	// Create a new instance of the method parameters.
	hres = pInParamsDefinition->SpawnInstance(0, &pInParams);

	if (FAILED(hres))
	{
		// Log error if spawning the method parameters instance fails.
		wcerr << L"Failed to spawn instance for method parameters. Error code = 0x"
			<< hex << hres << L" - " << _com_error(hres).ErrorMessage() << endl;
		SetLastErrorMsg(wstring(L"Failed to spawn instance for method parameters. Error code = 0x") + to_wstring(hres));
		SysFreeString(methodName);
		SysFreeString(className);
		pInParamsDefinition->Release();
		pClass->Release();
		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM)
			CoUninitialize();
		return false;
	}

	// Declare a VARIANT to hold the input parameter.
	VARIANT varParam;
	// Initialize the VARIANT to a safe empty state.
	VariantInit(&varParam);
	if constexpr (is_same<T, bool>::value)
	{
		// Set the VARIANT type as boolean.
		varParam.vt = VT_BOOL;
		varParam.boolVal = (preferenceValue) ? VARIANT_TRUE : VARIANT_FALSE;
	}
	else if constexpr (is_same<T, int>::value)
	{
		// Set the VARIANT type as a 32-bit integer.
		varParam.vt = VT_I4;
		varParam.lVal = preferenceValue;
	}
	else if constexpr (is_convertible<T, wstring>::value &&
		!is_same<T, vector<wstring>>::value)
	{
		// Set the VARIANT type to BSTR for string conversion.
		varParam.vt = VT_BSTR;
		// Convert the input to a wstring.
		wstring strVal = preferenceValue;
		// Allocate a BSTR from the wide string.
		varParam.bstrVal = SysAllocString(strVal.c_str());
		if (varParam.bstrVal == nullptr)
		{
			// Clean up and fail fast on allocation failure.
			wcerr << L"Failed to allocate BSTR for string parameter." << endl;
			SetLastErrorMsg(L"Failed to allocate BSTR for string parameter.");
			pInParams->Release();
			SysFreeString(methodName);
			SysFreeString(className);
			pInParamsDefinition->Release();
			pClass->Release();
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM)
				CoUninitialize();
			return false;
		}
	}
	else if constexpr (is_same<T, vector<wstring>>::value)
	{
		// Set the VARIANT type as an array of BSTR.
		varParam.vt = VT_ARRAY | VT_BSTR;

		// Get a reference to the vector of wide strings.
		const vector<wstring>& strArray = preferenceValue;

		SAFEARRAY* psa = nullptr;
		HRESULT hrSa = CreateSafeArrayOfBSTR(strArray, &psa);
		if (FAILED(hrSa) || psa == nullptr)
		{
			// Log error if SAFEARRAY creation fails.
			wcerr << L"Failed to create SAFEARRAY for string array." << endl;
			SetLastErrorMsg(L"Failed to create SAFEARRAY for string array.");
			VariantClear(&varParam);
			pInParams->Release();
			SysFreeString(methodName);
			SysFreeString(className);
			pInParamsDefinition->Release();
			pClass->Release();
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM)
				CoUninitialize();
			return false;
		}

		// Assign the SAFEARRAY pointer in the VARIANT.
		varParam.parray = psa;
	}
	else if constexpr (is_same<T, vector<int>>::value)
	{
		// Set the VARIANT type as an array of 32-bit integers.
		varParam.vt = VT_ARRAY | VT_I4;
		// Get a reference to the vector of integers.
		const vector<int>& intArray = preferenceValue;
		// Declare a SAFEARRAYBOUND structure for the array bounds.
		SAFEARRAYBOUND sabound{};
		// Set the lower bound of the SAFEARRAY to 0.
		sabound.lLbound = 0;
		// Set the number of elements equal to the vector size.
		sabound.cElements = static_cast<ULONG>(intArray.size());
		// Allocate a SAFEARRAY for the integer array.
		SAFEARRAY* psa = SafeArrayCreate(VT_I4, 1, &sabound);
		if (psa == nullptr)
		{
			// Log error if the SAFEARRAY creation for int array fails.
			wcerr << L"Failed to create SAFEARRAY for int array." << endl;
			SetLastErrorMsg(L"Failed to create SAFEARRAY for int array.");
			VariantClear(&varParam);
			pInParams->Release();
			SysFreeString(methodName);
			SysFreeString(className);
			pInParamsDefinition->Release();
			pClass->Release();
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM)
				CoUninitialize();
			return false;
		}
		// Populate the SAFEARRAY with integer elements from the vector.
		for (LONG i = 0; i < static_cast<LONG>(intArray.size()); i++)
		{
			int element = intArray[i];
			hres = SafeArrayPutElement(psa, &i, &element);
			if (FAILED(hres))
			{
				// Log error if putting an integer element in the SAFEARRAY fails.
				wcerr << L"Failed to put element in SAFEARRAY for int array. Error code = 0x"
					<< hex << hres << L" - " << _com_error(hres).ErrorMessage() << endl;
				SetLastErrorMsg(wstring(L"Failed to put element in SAFEARRAY for int array. Error code = 0x") + to_wstring(hres));
				SafeArrayDestroy(psa);
				VariantClear(&varParam);
				pInParams->Release();
				SysFreeString(methodName);
				SysFreeString(className);
				pInParamsDefinition->Release();
				pClass->Release();
				pSvc->Release();
				pLoc->Release();
				if (!g_skipCOMInit && didInitCOM)
					CoUninitialize();
				return false;
			}
		}
		// Set the SAFEARRAY pointer in the VARIANT.
		varParam.parray = psa;
	}

	// Bind the VARIANT value to the corresponding input parameter name in the WMI method call.
	hres = pInParams->Put(_bstr_t(preferenceName), 0, &varParam, 0);
	if (FAILED(hres))
	{
		// Log error if setting the input parameter fails.
		wcerr << L"Failed to set parameter " << preferenceName
			<< L". Error code = 0x" << hex << hres
			<< L" - " << _com_error(hres).ErrorMessage() << endl;
		SetLastErrorMsg(wstring(L"Failed to set parameter ") + preferenceName + L". Error code = 0x" + to_wstring(hres));
		VariantClear(&varParam);
		pInParams->Release();
		SysFreeString(methodName);
		SysFreeString(className);
		pInParamsDefinition->Release();
		pClass->Release();
		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM)
			CoUninitialize();
		return false;
	}

	// Log the value being set based on the type.
	if constexpr (is_same<T, bool>::value)
		wcout << L"Setting " << preferenceName << L" to: " << varParam.boolVal << endl;
	else if constexpr (is_same<T, int>::value)
		wcout << L"Setting " << preferenceName << L" to: " << varParam.lVal << endl;
	else if constexpr (is_convertible<T, wstring>::value &&
		!is_same<T, vector<wstring>>::value)
		wcout << L"Setting " << preferenceName << L" to: " << varParam.bstrVal << endl;
	else if constexpr (is_same<T, vector<wstring>>::value)
		wcout << L"Setting " << preferenceName << L" to a string array of size: "
		<< preferenceValue.size() << endl;
	else if constexpr (is_same<T, vector<int>>::value)
		wcout << L"Setting " << preferenceName << L" to an int array of size: "
		<< preferenceValue.size() << endl;

	// Clear the VARIANT now that it has been bound.
	VariantClear(&varParam);

	// A pointer for the method output parameters.
	IWbemClassObject* pOutParams = nullptr;
	// Execute the specified WMI method using the class and method names.
	hres = pSvc->ExecMethod(className, methodName, 0, NULL, pInParams, &pOutParams, NULL);
	if (FAILED(hres))
	{
		// Log error if method execution fails.
		wcerr << L"ExecMethod for " << customMethodName
			<< L" failed. Error code = 0x" << hex << hres
			<< L" - " << _com_error(hres).ErrorMessage() << endl;
		SetLastErrorMsg(wstring(L"ExecMethod for ") + customMethodName + L" failed. Error code = 0x" + to_wstring(hres));
		pInParams->Release();
		SysFreeString(methodName);
		SysFreeString(className);
		pInParamsDefinition->Release();
		pClass->Release();
		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM)
			CoUninitialize();
		return false;
	}

	// Check the method's return value (if provided).
	if (pOutParams != nullptr)
	{
		// Declare a VARIANT to hold the method's return value.
		VARIANT varRet;
		// Initialize the VARIANT.
		VariantInit(&varRet);
		// Retrieve the "ReturnValue" property from the output parameters.
		hres = pOutParams->Get(_bstr_t(L"ReturnValue"), 0, &varRet, NULL, 0);
		if (SUCCEEDED(hres))
		{
			// Log the integer return value.
			wcout << L"Method " << customMethodName
				<< L" returned: " << varRet.intVal << endl;
		}
		else
		{
			// Log that the method executed but no return value was provided.
			wcout << L"Method " << customMethodName
				<< L" executed, but no return value provided. Error code = 0x"
				<< hex << hres
				<< L" - " << _com_error(hres).ErrorMessage() << endl;
		}
		// Clear the VARIANT holding the return value.
		VariantClear(&varRet);
		// Release the output parameters object.
		pOutParams->Release();
	}
	else
	{
		// Log that the method executed successfully without output parameters.
		wcout << L"Method " << customMethodName
			<< L" executed successfully, but no return parameters were provided." << endl;
	}

	// Cleanup: Release the method input parameters.
	pInParams->Release();
	// Free the BSTR allocated for the method name.
	SysFreeString(methodName);
	// Free the BSTR allocated for the class name.
	SysFreeString(className);
	// Release the input parameters definition.
	pInParamsDefinition->Release();
	// Release the WMI class object.
	pClass->Release();
	// Release the IWbemServices pointer.
	pSvc->Release();
	// Release the IWbemLocator pointer.
	pLoc->Release();

	// Uninitialize COM only if we performed the initialization (i.e. in non-DLL mode).
	if (!g_skipCOMInit && didInitCOM)
		CoUninitialize();
	// Return success.
	return true;
}

// Function for getting WMI results based on a property name, namespace, and class name.
// This function queries WMI for the specified namespace and class, and outputs the specified property value in valid JSON format.
[[nodiscard]] static bool GetWmiValue(const wchar_t* wmiNamespace, const wchar_t* wmiClassName, const wchar_t* preferenceName)
{
	// Clear the global error message at the beginning.
	ClearLastErrorMsg();

	// Variable to store the result of COM function calls.
	HRESULT hres = S_OK;

	// Flag to indicate if this function performed COM initialization.
	bool didInitCOM = false;

	if (!g_skipCOMInit)
	{
		// Initialize COM for a multithreaded apartment.
		hres = CoInitializeEx(0, COINIT_MULTITHREADED);

		// Check if COM is already initialized in a different model (RPC_E_CHANGED_MODE = 0x80010106)
		if (hres == RPC_E_CHANGED_MODE)
		{
			hres = S_OK;
		}
		if (FAILED(hres))
		{
			SetLastErrorMsg(wstring(L"Failed to initialize COM library. Error code = 0x") + to_wstring(hres));
			return false;
		}
		didInitCOM = true;
		// Initialize COM security settings.
		hres = CoInitializeSecurity(
			nullptr,
			-1,
			nullptr,
			nullptr,
			RPC_C_AUTHN_LEVEL_DEFAULT,
			RPC_C_IMP_LEVEL_IMPERSONATE,
			nullptr,
			EOAC_NONE,
			nullptr
		);
		// Check if security is already initialized (error 0x80010109 or 0x80010119)
		if (hres == 0x80010109 || hres == 0x80010119)
		{
			hres = S_OK;
		}
		if (FAILED(hres))
		{
			SetLastErrorMsg(wstring(L"Failed to initialize security. Error code = 0x") + to_wstring(hres));
			if (!g_skipCOMInit && didInitCOM)
				CoUninitialize();
			return false;
		}
	}

	// Pointer for the IWbemLocator interface.
	IWbemLocator* pLoc = nullptr;
	// Create the WMI locator instance.
	hres = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator,
		reinterpret_cast<LPVOID*>(&pLoc)
	);
	if (FAILED(hres))
	{
		SetLastErrorMsg(wstring(L"Failed to create IWbemLocator object. Error code = 0x") + to_wstring(hres));
		if (!g_skipCOMInit && didInitCOM)
			CoUninitialize();
		return false;
	}

	// Pointer for the IWbemServices interface.
	IWbemServices* pSvc = nullptr;
	// Connect to the specified WMI namespace.
	hres = pLoc->ConnectServer(
		_bstr_t(wmiNamespace),
		NULL,
		NULL,
		0,
		0,
		nullptr,
		0,
		&pSvc
	);
	if (FAILED(hres))
	{
		SetLastErrorMsg(wstring(L"Could not connect to ") + wmiNamespace + L" namespace. Error code = 0x" + to_wstring(hres));
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM)
			CoUninitialize();
		return false;
	}

	// Set the proxy blanket on the IWbemServices interface.
	hres = CoSetProxyBlanket(
		pSvc,
		RPC_C_AUTHN_WINNT,
		RPC_C_AUTHZ_NONE,
		nullptr,
		RPC_C_AUTHN_LEVEL_CALL,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		nullptr,
		EOAC_NONE
	);
	if (FAILED(hres))
	{
		SetLastErrorMsg(wstring(L"Could not set proxy blanket. Error code = 0x") + to_wstring(hres));
		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM)
			CoUninitialize();
		return false;
	}

	// The WQL query
	wstring wqlQuery = L"SELECT * FROM " + wstring(wmiClassName);

	// Declare an enumerator pointer to iterate WMI objects.
	IEnumWbemClassObject* pEnumerator = nullptr;
	// Execute the WQL query to retrieve all instances of the specified class.
	hres = pSvc->ExecQuery(
		bstr_t(L"WQL"),
		bstr_t(wqlQuery.c_str()),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		nullptr,
		&pEnumerator
	);
	if (FAILED(hres))
	{
		SetLastErrorMsg(wstring(L"ExecQuery failed for ") + wmiClassName + L". Error code = 0x" + to_wstring(hres));
		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM)
			CoUninitialize();
		return false;
	}

	// Declare a pointer for each WMI class object retrieved.
	IWbemClassObject* pclsObj = nullptr;
	// Variable to store the number of objects returned.
	ULONG uReturn = 0;
	// Collect JSON tokens for each instance value to handle multi-instance results.
	vector<string> tokens;

	// Iterate over the query results.
	while (pEnumerator)
	{
		// Get the next WMI object with an infinite timeout.
		hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (0 == uReturn)
			break;
		// Declare a VARIANT to hold the property value.
		VARIANT vtProp;
		// Initialize the VARIANT.
		VariantInit(&vtProp);
		// Retrieve the value of the desired property.
		hres = pclsObj->Get(_bstr_t(preferenceName), 0, &vtProp, nullptr, 0);
		if (SUCCEEDED(hres))
		{
			// Convert the property value to a JSON formatted string token and collect it.
			string token;

			// Resolve to an effective (dereferenced) VARIANT so quoting is based on the actual type.
			VARIANT eff;
			VariantInit(&eff);
			bool haveEff = CopyEffectiveVariant(vtProp, eff);

			const VARIANT& v = haveEff ? eff : vtProp;

			if (v.vt == VT_NULL || v.vt == VT_EMPTY)
			{
				token = "null";
			}
			else if (v.vt == VT_BSTR)
			{
				token = QuoteBstrJson(v.bstrVal);
			}
			else if (v.vt == VT_DATE)
			{
				string dateStr;
				if (TryFormatDateIso8601(v.date, dateStr))
				{
					token = "\"" + dateStr + "\"";
				}
				else
				{
					token = "null";
				}
			}
			else if (v.vt == VT_ERROR)
			{
				token = "\"" + ErrorCodeHexString(v.scode) + "\"";
			}
			else
			{
				token = VariantToString(v);
				if (token.empty())
					token = "null";
			}

			tokens.push_back(token);

			VariantClear(&eff);
		}
		// Clear the VARIANT after use.
		VariantClear(&vtProp);
		// Release the current WMI object.
		pclsObj->Release();
	}

	// Release the enumerator.
	pEnumerator->Release();
	// Release the IWbemServices pointer.
	pSvc->Release();
	// Release the IWbemLocator pointer.
	pLoc->Release();
	// Uninitialize COM only if we performed the initialization.
	if (!g_skipCOMInit && didInitCOM)
		CoUninitialize();

	// Output results as a single JSON token if exactly one, else as a JSON array.
	if (tokens.empty())
	{
		SetLastErrorMsg(L"No data was returned for the requested WMI property.");
		return false;
	}

	if (tokens.size() == 1)
	{
		cout << tokens[0];
	}
	else
	{
		cout << "[";
		for (size_t i = 0; i < tokens.size(); ++i)
		{
			if (i != 0) cout << ",";
			cout << tokens[i];
		}
		cout << "]";
	}
	// Return the success flag.
	return true;
}

// Function for getting all WMI properties for a given namespace and class, formatted as a complete JSON object.
// This function queries WMI for all properties in the specified class and outputs them as a JSON object with property names.
[[nodiscard]] static bool GetAllWmiProperties(const wchar_t* wmiNamespace, const wchar_t* wmiClassName)
{
	// Clear the global error message at the beginning.
	ClearLastErrorMsg();

	// Variable to store the result of COM function calls.
	HRESULT hres = S_OK;

	// Flag to indicate if this function performed COM initialization.
	bool didInitCOM = false;

	if (!g_skipCOMInit)
	{
		// Initialize COM for a multithreaded apartment.
		hres = CoInitializeEx(0, COINIT_MULTITHREADED);

		// Check if COM is already initialized in a different model (RPC_E_CHANGED_MODE = 0x80010106)
		if (hres == RPC_E_CHANGED_MODE)
		{
			hres = S_OK;
		}
		if (FAILED(hres))
		{
			SetLastErrorMsg(wstring(L"Failed to initialize COM library. Error code = 0x") + to_wstring(hres));
			return false;
		}
		didInitCOM = true;
		// Initialize COM security settings.
		hres = CoInitializeSecurity(
			nullptr,
			-1,
			nullptr,
			nullptr,
			RPC_C_AUTHN_LEVEL_DEFAULT,
			RPC_C_IMP_LEVEL_IMPERSONATE,
			nullptr,
			EOAC_NONE,
			nullptr
		);
		// Check if security is already initialized (error 0x80010109 or 0x80010119)
		if (hres == 0x80010109 || hres == 0x80010119)
		{
			hres = S_OK;
		}
		if (FAILED(hres))
		{
			SetLastErrorMsg(wstring(L"Failed to initialize security. Error code = 0x") + to_wstring(hres));
			if (!g_skipCOMInit && didInitCOM)
				CoUninitialize();
			return false;
		}
	}

	// Pointer for the IWbemLocator interface.
	IWbemLocator* pLoc = nullptr;
	// Create the WMI locator instance.
	hres = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator,
		reinterpret_cast<LPVOID*>(&pLoc)
	);
	if (FAILED(hres))
	{
		SetLastErrorMsg(wstring(L"Failed to create IWbemLocator object. Error code = 0x") + to_wstring(hres));
		if (!g_skipCOMInit && didInitCOM)
			CoUninitialize();
		return false;
	}

	// Pointer for the IWbemServices interface.
	IWbemServices* pSvc = nullptr;
	// Connect to the specified WMI namespace.
	hres = pLoc->ConnectServer(
		_bstr_t(wmiNamespace),
		NULL,
		NULL,
		0,
		0,
		nullptr,
		0,
		&pSvc
	);
	if (FAILED(hres))
	{
		SetLastErrorMsg(wstring(L"Could not connect to ") + wmiNamespace + L" namespace. Error code = 0x" + to_wstring(hres));
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM)
			CoUninitialize();
		return false;
	}

	// Set the proxy blanket on the IWbemServices interface.
	hres = CoSetProxyBlanket(
		pSvc,
		RPC_C_AUTHN_WINNT,
		RPC_C_AUTHZ_NONE,
		nullptr,
		RPC_C_AUTHN_LEVEL_CALL,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		nullptr,
		EOAC_NONE
	);
	if (FAILED(hres))
	{
		SetLastErrorMsg(wstring(L"Could not set proxy blanket. Error code = 0x") + to_wstring(hres));
		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM)
			CoUninitialize();
		return false;
	}

	// The WQL query to retrieve all properties
	wstring wqlQuery = L"SELECT * FROM " + wstring(wmiClassName);

	// Declare an enumerator pointer to iterate WMI objects.
	IEnumWbemClassObject* pEnumerator = nullptr;
	// Execute the WQL query to retrieve all instances of the specified class.
	hres = pSvc->ExecQuery(
		bstr_t(L"WQL"),
		bstr_t(wqlQuery.c_str()),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		nullptr,
		&pEnumerator
	);
	if (FAILED(hres))
	{
		SetLastErrorMsg(wstring(L"ExecQuery failed for ") + wmiClassName + L". Error code = 0x" + to_wstring(hres));
		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM)
			CoUninitialize();
		return false;
	}

	// Declare a pointer for each WMI class object retrieved.
	IWbemClassObject* pclsObj = nullptr;
	// Variable to store the number of objects returned.
	ULONG uReturn = 0;
	// Flag to track if any properties were retrieved successfully.
	bool success = false;

	// Output a JSON array of instances (each instance is a JSON object).
	cout << "[";            // Begin JSON array
	bool firstInstance = true;

	// Iterate over the query results (in case there are more than 1 instances of the class? just to be safe.).
	while (pEnumerator)
	{
		// Get the next WMI object with an infinite timeout.
		hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (0 == uReturn)
			break;

		// Comma separator between instance objects in the array.
		if (!firstInstance)
		{
			cout << ",";
		}
		firstInstance = false;

		// Begin property enumeration to iterate through all properties
		hres = pclsObj->BeginEnumeration(WBEM_FLAG_NONSYSTEM_ONLY);
		if (FAILED(hres))
		{
			pclsObj->Release();
			continue;
		}

		// Start the JSON object output
		cout << "{";
		bool firstProperty = true;

		// Loop through all properties using Next()
		while (true)
		{
			BSTR propertyName = nullptr;
			VARIANT propertyValue;
			CIMTYPE propertyType = 0;
			LONG propertyFlavor = 0;

			// Initialize the variant for the property value
			VariantInit(&propertyValue);

			// Get the next property
			hres = pclsObj->Next(0, &propertyName, &propertyValue, &propertyType, &propertyFlavor);

			// Break if no more properties or if there's an error
			if (hres == WBEM_S_NO_MORE_DATA || FAILED(hres) || !propertyName)
			{
				if (propertyName)
					SysFreeString(propertyName);
				VariantClear(&propertyValue);
				break;
			}

			// Convert property name from BSTR to string for JSON output
			string propNameStr = BstrToUtf8(propertyName);

			// Add comma separator if this is not the first property
			if (!firstProperty)
			{
				cout << ",";
			}

			// Output the property name and value in JSON format
			cout << "\"" << escapeJSON(propNameStr) << "\": ";

			// Resolve to an effective (dereferenced) VARIANT so quoting is based on the actual type.
			VARIANT effVar;
			VariantInit(&effVar);
			bool haveEff = CopyEffectiveVariant(propertyValue, effVar);
			const VARIANT& v = haveEff ? effVar : propertyValue;

			// Convert the property value to JSON string representation
			string propertyValueJson = VariantToString(v);

			// Handle different value types for proper JSON formatting
			if (v.vt == VT_BSTR)
			{
				// String values need to be quoted and escaped
				cout << QuoteBstrJson(v.bstrVal);
			}
			else if (v.vt == VT_DATE)
			{
				// Dates are formatted as strings by VariantToString; quote for valid JSON
				if (!propertyValueJson.empty())
					cout << "\"" << escapeJSON(propertyValueJson) << "\"";
				else
					cout << "null";
			}
			else if (v.vt == VT_ERROR)
			{
				// Error codes like 0x80004005 -> quote as string for valid JSON
				cout << "\"" << ErrorCodeHexString(v.scode) << "\"";
			}
			else if (v.vt == VT_NULL || v.vt == VT_EMPTY)
			{
				// Null values
				cout << "null";
			}
			else if (propertyValueJson.empty())
			{
				// Empty values as null
				cout << "null";
			}
			else
			{
				// Numeric, boolean, and array values (already properly formatted by VariantToString)
				cout << propertyValueJson;
			}

			// Clean up for this iteration
			SysFreeString(propertyName);
			VariantClear(&effVar);
			VariantClear(&propertyValue);

			firstProperty = false;
			success = true;
		}

		// End the JSON object
		cout << "}";

		// End property enumeration
		pclsObj->EndEnumeration();

		// Release the current WMI object
		pclsObj->Release();

		// For most WMI classes like Win32_DeviceGuard, there's typically only one instance
		// But we should NOT break here, so that we can include all instances in the JSON array for other namespaces like "root\standardcimv2 MSFT_NetFirewallRule"
	}

	// Close the JSON array output
	cout << "]";

	// Release the enumerator.
	pEnumerator->Release();
	// Release the IWbemServices pointer.
	pSvc->Release();
	// Release the IWbemLocator pointer.
	pLoc->Release();
	// Uninitialize COM only if we performed the initialization.
	if (!g_skipCOMInit && didInitCOM)
		CoUninitialize();

	if (!success)
	{
		SetLastErrorMsg(L"No instances or properties were returned for the requested WMI class.");
	}

	// Return the success flag.
	return success;
}

// --- DLL Exported Functions for C# via DllImport/LibraryImport ---
// These exported wrapper functions allow C# code to call the functionality directly.

// Exported function for bool preference
extern "C" __declspec(dllexport) bool __stdcall ManageWmiPreferenceBool(const wchar_t* wmiNamespace, const wchar_t* wmiClassName, const wchar_t* customMethodName, const wchar_t* preferenceName, bool preferenceValue)
{
	// Call the template function specialized for bool.
	return ManageWmiPreference(wmiNamespace, wmiClassName, customMethodName, preferenceName, preferenceValue);
}

// Exported function for int preference
extern "C" __declspec(dllexport) bool __stdcall ManageWmiPreferenceInt(const wchar_t* wmiNamespace, const wchar_t* wmiClassName, const wchar_t* customMethodName, const wchar_t* preferenceName, int preferenceValue)
{
	// Call the template function specialized for int.
	return ManageWmiPreference(wmiNamespace, wmiClassName, customMethodName, preferenceName, preferenceValue);
}

// Exported function for string preference
extern "C" __declspec(dllexport) bool __stdcall ManageWmiPreferenceString(
	const wchar_t* wmiNamespace,
	const wchar_t* wmiClassName,
	const wchar_t* customMethodName,
	const wchar_t* preferenceName,
	const wchar_t* preferenceValue)
{
	// Validate pointers to prevent undefined behavior
	if (preferenceValue == nullptr)
	{
		SetLastErrorMsg(L"preferenceValue is null.");
		return false;
	}

	// Convert the const wchar_t* to wstring and call the template function.
	return ManageWmiPreference(wmiNamespace, wmiClassName, customMethodName, preferenceName, wstring(preferenceValue));
}

// Exported function for string array preference
extern "C" __declspec(dllexport) bool __stdcall ManageWmiPreferenceStringArray(
	const wchar_t* wmiNamespace,
	const wchar_t* wmiClassName,
	const wchar_t* customMethodName,
	const wchar_t* preferenceName,
	const wchar_t** preferenceArray,
	int arraySize)
{
	// Validate array parameters
	if (arraySize < 0)
	{
		SetLastErrorMsg(L"arraySize is negative.");
		return false;
	}
	if (arraySize > 0 && preferenceArray == nullptr)
	{
		SetLastErrorMsg(L"preferenceArray is null but arraySize > 0.");
		return false;
	}

	// A vector to hold the string array.
	vector<wstring> vec;

	// Pre-allocate capacity to avoid reallocation churn during push_back.
	if (arraySize > 0)
	{
		vec.reserve(static_cast<size_t>(arraySize));
	}

	// Loop over the array of wchar_t* to build the vector.
	for (int i = 0; i < arraySize; i++)
	{
		const wchar_t* p = preferenceArray[i];
		if (p == nullptr)
		{
			// Skip null entries to avoid crashes
			continue;
		}

		// Trim whitespace, skip empty
		wstring s(p);
		size_t first = s.find_first_not_of(L" \t\r\n");
		if (first == wstring::npos)
			continue;
		size_t last = s.find_last_not_of(L" \t\r\n");
		wstring trimmed = s.substr(first, last - first + 1);
		if (trimmed.empty())
			continue;

		vec.push_back(trimmed);
	}

	// Call the template function specialized for vector<string>.
	return ManageWmiPreference(wmiNamespace, wmiClassName, customMethodName, preferenceName, vec);
}

// Exported function for int array preference
extern "C" __declspec(dllexport) bool __stdcall ManageWmiPreferenceIntArray(
	const wchar_t* wmiNamespace,
	const wchar_t* wmiClassName,
	const wchar_t* customMethodName,
	const wchar_t* preferenceName,
	const int* preferenceArray,
	int arraySize)
{
	// Validate array parameters
	if (arraySize < 0)
	{
		SetLastErrorMsg(L"arraySize is negative.");
		return false;
	}
	if (arraySize > 0 && preferenceArray == nullptr)
	{
		SetLastErrorMsg(L"preferenceArray is null but arraySize > 0.");
		return false;
	}

	// Create a vector to hold the integer array.
	vector<int> vec;

	// Pre-allocate capacity to avoid reallocation churn during push_back.
	if (arraySize > 0)
	{
		vec.reserve(static_cast<size_t>(arraySize));
	}

	// Loop over the array of integers to build the vector.
	for (int i = 0; i < arraySize; i++)
	{
		vec.push_back(preferenceArray[i]);
	}

	// Call the template function specialized for vector<int>.
	return ManageWmiPreference(wmiNamespace, wmiClassName, customMethodName, preferenceName, vec);
}

// Exported function for getting WMI results from any specified namespace and class.
// This function allows external callers (e.g. from C#) to query any WMI namespace and class.
extern "C" __declspec(dllexport) bool __stdcall GetWmiData(const wchar_t* wmiNamespace, const wchar_t* wmiClassName, const wchar_t* preferenceName)
{
	return GetWmiValue(wmiNamespace, wmiClassName, preferenceName);
}

// Exported function for getting all WMI properties from any specified namespace and class.
// This function allows external callers (e.g. from C#) to query all properties in a WMI class.
extern "C" __declspec(dllexport) bool __stdcall GetAllWmiData(const wchar_t* wmiNamespace, const wchar_t* wmiClassName)
{
	return GetAllWmiProperties(wmiNamespace, wmiClassName);
}

// --- End of DLL Exported Functions ---


// For command line support.
// This wmain checks if command line arguments are provided and calls corresponding functions.
// If "get" is specified, it retrieves a property value.
// Otherwise, it uses ManageWmiPreference to set a value.
// Comments below explain expected command line usage.
int wmain(int argc, wchar_t* argv[])
{
	if (argc >= 2 && wstring(argv[1]) == L"get")
	{
		// Handles both "get all properties" (4 args) and "get specific property" (5 args) cases
		if (argc != 4 && argc != 5)
		{
			// Print proper usage if incorrect arguments are provided.
			wcerr << L"Usage:" << endl;
			wcerr << L"  Get all properties: ComManager.exe get <namespace> <className>" << endl;
			wcerr << L"  Get specific property: ComManager.exe get <namespace> <className> <preferenceName>" << endl;
			wcerr << L"  Example (all): ComManager.exe get root\\Microsoft\\Windows\\DeviceGuard Win32_DeviceGuard" << endl;
			wcerr << L"  Example (specific): ComManager.exe get root\\Microsoft\\Windows\\DeviceGuard Win32_DeviceGuard RequiredSecurityProperties" << endl;
			return 1;
		}

		// Get namespace and class name from command line arguments (always present)
		const wchar_t* wmiNamespace = argv[2];
		const wchar_t* wmiClassName = argv[3];
		const wchar_t* preferenceName = nullptr;

		// Get preference name if provided
		if (argc == 5)
		{
			preferenceName = argv[4];
		}

		// Verify that the required arguments are not empty or only whitespace.
		for (int i = 2; i < argc; i++)
		{
			wstring arg(argv[i]);
			if (arg.find_first_not_of(L" \t\n\r") == wstring::npos)
			{
				wcerr << L"Error: Command line argument " << i
					<< L" is empty or whitespace." << endl;
				return 1;
			}
		}

		bool isSuccessful = false;

		if (preferenceName != nullptr)
		{
			// Retrieve specific property using the existing function
			isSuccessful = GetWmiValue(wmiNamespace, wmiClassName, preferenceName);
		}
		else
		{
			// Retrieve all properties using the new function
			isSuccessful = GetAllWmiProperties(wmiNamespace, wmiClassName);
		}

		if (!isSuccessful)
		{
			const wchar_t* err = GetLastErrorMessage();
			if (err != nullptr && *err != L'\0')
			{
				wcerr << L"Failed to retrieve WMI data. Error: " << err << endl;
			}
			else
			{
				wcerr << L"Failed to retrieve WMI data." << endl;
			}
		}

		// Return 0 on success, or 1 on failure.
		return isSuccessful ? 0 : 1;
	}

	// Command for firewall functionality
	if (argc >= 2 && wstring(argv[1]) == L"firewall")
	{
		if (argc != 5)
		{
			wcerr << L"Usage:" << endl;
			wcerr << L"  ComManager.exe firewall <displayName> <downloadURL> <true/false>" << endl;
			wcerr << L"  Examples:" << endl;
			wcerr << L"    ComManager.exe firewall \"Block NK IPs\" \"https://raw.githubusercontent.com/blabla/ips.txt\" true" << endl;
			wcerr << L"    ComManager.exe firewall \"Block NK IPs\" \"\" false" << endl;
			return 1;
		}

		const wchar_t* displayName = argv[2];
		const wchar_t* downloadURL = argv[3];
		wstring boolStr = argv[4];
		bool toAdd = (EqualsOrdinalIgnoreCase(boolStr.c_str(), L"true") || EqualsOrdinalIgnoreCase(boolStr.c_str(), L"1"));

		// Validate arguments
		if (!displayName || *displayName == L'\0')
		{
			wcerr << L"Error: DisplayName cannot be empty." << endl;
			return 1;
		}

		// When toAdd is true, URL must be provided and non-empty
		if (toAdd && (!downloadURL || *downloadURL == L'\0'))
		{
			wcerr << L"Error: Download URL must be provided when adding rules." << endl;
			return 1;
		}

		// When toAdd is false, URL can be empty (we pass nullptr in that case)
		const wchar_t* urlToUse = (toAdd && downloadURL && *downloadURL != L'\0') ? downloadURL : nullptr;

		// Call the enhanced firewall function
		bool result = FW_BlockIPAddressListsInGroupPolicy(displayName, urlToUse, toAdd);

		if (result)
		{
			if (toAdd)
			{
				wcout << L"Successfully created firewall rules for: " << displayName << endl;
			}
			else
			{
				wcout << L"Successfully removed firewall rules for: " << displayName << endl;
			}
		}
		else
		{
			wcerr << L"Failed to manage firewall rules. Error: " << GetLastErrorMessage() << endl;
		}

		return result ? 0 : 1;
	}

	// Command line usage for setting WMI preferences
	// For bool, int, and string, there must be exactly 7 arguments.
	// For stringarray and intarray, there must be at least 7 arguments.
	// argv[1]: Function type ("bool", "int", "string", "stringarray", or "intarray")
	// argv[2]: WMI namespace
	// argv[3]: WMI class name
	// argv[4]: customMethodName
	// argv[5]: preferenceName
	// argv[6...]: value(s)
	if (argc < 7)
	{
		// Print usage instructions if not enough arguments are provided.
		wcerr << L"Usage:" << endl;
		wcerr << L"  For getting data:" << endl;
		wcerr << L"    Get all properties: ComManager.exe get <namespace> <className>" << endl;
		wcerr << L"    Get specific property: ComManager.exe get <namespace> <className> <preferenceName>" << endl;
		wcerr << L"    Example (all): ComManager.exe get root\\Microsoft\\Windows\\DeviceGuard Win32_DeviceGuard" << endl;
		wcerr << L"    Example (specific): ComManager.exe get root\\Microsoft\\Windows\\DeviceGuard Win32_DeviceGuard RequiredSecurityProperties" << endl;
		wcerr << L"  For firewall management:" << endl;
		wcerr << L"    ComManager.exe firewall <displayName> <downloadURL> <true/false>" << endl;
		wcerr << L"  For setting preferences (generic WMI):" << endl;
		wcerr << L"    ComManager.exe <bool|int|string> <namespace> <className> <customMethodName> <preferenceName> <value>" << endl;
		wcerr << L"    ComManager.exe <stringarray|intarray> <namespace> <className> <customMethodName> <preferenceName> <value1> [value2] ..." << endl;
		wcerr << L"    Example: ComManager.exe bool root\\Microsoft\\Windows\\Defender MSFT_MpPreference Set BruteForceProtectionLocalNetworkBlocking true" << endl;
		return 1;
	}

	// Verify that the first 6 command line arguments are not empty or only whitespace.
	for (int i = 1; i < 7; i++)
	{
		wstring arg(argv[i]);
		if (arg.find_first_not_of(L" \t\n\r") == wstring::npos)
		{
			wcerr << L"Error: Command line argument " << i
				<< L" is empty or whitespace." << endl;
			wcerr << L"Usage:" << endl;
			wcerr << L"  For getting data:" << endl;
			wcerr << L"    Get all properties: ComManager.exe get <namespace> <className>" << endl;
			wcerr << L"    Get specific property: ComManager.exe get <namespace> <className> <preferenceName>" << endl;
			wcerr << L"    Example (all): ComManager.exe get root\\Microsoft\\Windows\\DeviceGuard Win32_DeviceGuard" << endl;
			wcerr << L"    Example (specific): ComManager.exe get root\\Microsoft\\Windows\\DeviceGuard Win32_DeviceGuard RequiredSecurityProperties" << endl;
			wcerr << L"  For firewall management:" << endl;
			wcerr << L"    ComManager.exe firewall <displayName> <downloadURL> <true/false>" << endl;
			wcerr << L"  For setting preferences (generic WMI):" << endl;
			wcerr << L"    ComManager.exe <bool|int|string> <namespace> <className> <customMethodName> <preferenceName> <value>" << endl;
			wcerr << L"    ComManager.exe <stringarray|intarray> <namespace> <className> <customMethodName> <preferenceName> <value1> [value2] ..." << endl;
			wcerr << L"    Example: ComManager.exe bool root\\Microsoft\\Windows\\Defender MSFT_MpPreference Set BruteForceProtectionLocalNetworkBlocking true" << endl;
			return 1;
		}
	}

	// Read the function type (e.g., bool, int, etc.) from the command line.
	wstring funcType = argv[1];
	// Read the WMI namespace from the command line.
	wstring wmiNamespace = argv[2];
	// Read the WMI class name from the command line.
	wstring wmiClassName = argv[3];
	// Read the custom method name for the WMI call.
	wstring customMethodName = argv[4];
	// Read the preference name to be set or retrieved.
	wstring preferenceName = argv[5];

	// Initialize a flag for operation success.
	bool isSuccessful = false;

	if (funcType == L"bool")
	{
		if (argc != 7)
		{
			// Print usage details for bool if incorrect number of arguments are provided.
			wcerr << L"Usage: ComManager.exe bool <namespace> <className> <customMethodName> <preferenceName> <true/false>" << endl;
			return 1;
		}
		// Read the boolean value as a string.
		wstring value = argv[6];
		bool boolValue = false;
		// Compare the input with "true" or "1", case-insensitively, to determine the boolean value.
		if (EqualsOrdinalIgnoreCase(value.c_str(), L"true") || EqualsOrdinalIgnoreCase(value.c_str(), L"1")) boolValue = true;

		// Call the function specialized for bool and store the success status.
		isSuccessful = ManageWmiPreference(wmiNamespace.c_str(), wmiClassName.c_str(), customMethodName.c_str(), preferenceName.c_str(), boolValue);
	}
	else if (funcType == L"int")
	{
		if (argc != 7)
		{
			// Print usage details for int if the argument count is incorrect.
			wcerr << L"Usage: ComManager.exe int <namespace> <className> <customMethodName> <preferenceName> <integer value>" << endl;
			return 1;
		}
		// Convert the sixth argument from a wide string to an integer.
		int intValue = _wtoi(argv[6]);
		// Call the function specialized for int.
		isSuccessful = ManageWmiPreference(wmiNamespace.c_str(), wmiClassName.c_str(), customMethodName.c_str(), preferenceName.c_str(), intValue);
	}
	else if (funcType == L"string")
	{
		if (argc != 7)
		{
			// Print usage details for string if the argument count is incorrect.
			wcerr << L"Usage: ComManager.exe string <namespace> <className> <customMethodName> <preferenceName> <string value>" << endl;
			return 1;
		}
		// Call the function specialized for string.
		isSuccessful = ManageWmiPreference(wmiNamespace.c_str(), wmiClassName.c_str(), customMethodName.c_str(), preferenceName.c_str(), wstring(argv[6]));
	}
	else if (funcType == L"stringarray")
	{
		if (argc < 7)
		{
			// Print usage details for string array if there are not enough arguments.
			wcerr << L"Usage: ComManager.exe stringarray <namespace> <className> <customMethodName> <preferenceName> <value1> [value2] ..." << endl;
			return 1;
		}
		// Create a vector to hold the string array from the command line.
		vector<wstring> vec;
		for (int i = 6; i < argc; i++)
		{
			vec.push_back(argv[i]);
		}
		// Call the function specialized for vector<string>.
		isSuccessful = ManageWmiPreference(wmiNamespace.c_str(), wmiClassName.c_str(), customMethodName.c_str(), preferenceName.c_str(), vec);
	}
	else if (funcType == L"intarray")
	{
		if (argc < 7)
		{
			// Print usage details for integer array if there are not enough arguments.
			wcerr << L"Usage: ComManager.exe intarray <namespace> <className> <customMethodName> <preferenceName> <value1> [value2] ..." << endl;
			return 1;
		}
		// Create a vector to hold the integer array from the command line.
		vector<int> vec;
		for (int i = 6; i < argc; i++)
		{
			vec.push_back(_wtoi(argv[i]));
		}
		// Call the function specialized for vector<int>.
		isSuccessful = ManageWmiPreference(wmiNamespace.c_str(), wmiClassName.c_str(), customMethodName.c_str(), preferenceName.c_str(), vec);
	}
	else
	{
		// Notify the user about valid function types.
		wcerr << L"Invalid function type. Use one of: bool, int, string, stringarray, intarray, firewall." << endl;
		return 1;
	}

	// Output a success message if the operation succeeded.
	if (isSuccessful)
		wcout << L"Preference was set successfully via command line." << endl;
	else
		wcerr << L"Failed to set preference via command line." << endl;

	// Exit the program with a success or failure code.
	return isSuccessful ? 0 : 1;

	/* Example usage:
		// Usage for a boolean property with generic WMI.
		if (ManageWmiPreference(L"ROOT\\Microsoft\\Windows\\Defender", L"MSFT_MpPreference", L"Set", L"BruteForceProtectionLocalNetworkBlocking", true))
		{
			wcout << L"Boolean preference was set successfully." << endl;
		}
		else
		{
			wcout << L"Failed to set boolean preference." << endl;
		}

		// Usage for an integer property with generic WMI.
		if (ManageWmiPreference(L"ROOT\\Microsoft\\Windows\\Defender", L"MSFT_MpPreference", L"Set", L"SchedulerRandomizationTime", 42))
		{
			wcout << L"Integer preference was set successfully." << endl;
		}
		else
		{
			wcout << L"Failed to set integer preference." << endl;
		}

		// Usage for a string property with generic WMI.
		if (ManageWmiPreference(L"ROOT\\Microsoft\\Windows\\Defender", L"MSFT_MpPreference", L"Set", L"SomeStringProperty", L"ExampleValue"))
		{
			wcout << L"String preference was set successfully." << endl;
		}
		else
		{
			wcout << L"Failed to set string preference." << endl;
		}

		// Usage for an integer array property with generic WMI.
		vector<int> intArray = { 0, 1, 1, 1, 1, 6, 1 };
		if (ManageWmiPreference(L"ROOT\\Microsoft\\Windows\\Defender", L"MSFT_MpPreference", L"Set", L"SomeIntArrayProperty", intArray))
		{
			wcout << L"Integer array preference was set successfully." << endl;
		}
		else
		{
			wcout << L"Failed to set integer array preference." << endl;
		}

		// Usage for a string array property with generic WMI.
		vector<wstring> stringArray = { L"Sum", L"Big", L"Program" };
		if (ManageWmiPreference(L"ROOT\\Microsoft\\Windows\\Defender", L"MSFT_MpPreference", L"Add", L"AttackSurfaceReductionOnlyExclusions", stringArray))
		{
			wcout << L"String array preference was set successfully." << endl;
		}
		else
		{
			wcout << L"Failed to set string array preference." << endl;
		}

		// Usage for a custom WMI namespace and class.
		if (ManageWmiPreference(L"ROOT\\cimv2\\mdm\\dmmap", L"MDM_Policy_Config01_DeviceGuard02", L"Set", L"RequirePlatformSecurityFeatures", 1))
		{
			wcout << L"Custom WMI preference was set successfully." << endl;
		}
		else
		{
			wcout << L"Failed to set custom WMI preference." << endl;
		}

		// Usage examples for firewall functionality
		// Usage for blocking IP addresses from a downloaded list
		if (FW_BlockIPAddressListsInGroupPolicy(L"Block NK IPs", L"https://raw.githubusercontent.com/blabla/nk-ips.txt", true))
		{
			wcout << L"Firewall rules for blocking NK IPs were created successfully." << endl;
		}
		else
		{
			wcout << L"Failed to create firewall rules for blocking NK IPs." << endl;
		}

		// Usage for removing previously created firewall rules
		if (FW_BlockIPAddressListsInGroupPolicy(L"Block NK IPs", nullptr, false))
		{
			wcout << L"Firewall rules for blocking NK IPs were removed successfully." << endl;
		}
		else
		{
			wcout << L"Failed to remove firewall rules for blocking NK IPs." << endl;
		}

		// Usage for blocking IP addresses from a pre-populated array
		const wchar_t* ipAddresses[] = { L"1.2.3.4", L"5.6.7.8", L"192.168.1.0/24" };
		if (FW_BlockIpListInGpo(L"Block Custom IPs", ipAddresses, 3, true))
		{
			wcout << L"Firewall rules for blocking custom IPs were created successfully." << endl;
		}
		else
		{
			wcout << L"Failed to create firewall rules for blocking custom IPs." << endl;
		}
	*/
}
