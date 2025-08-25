#include "StringUtilities.h"
#include <string>
#include <vector>
#include <format>
#include <comdef.h>
#include <cwchar>
#include <array>

using namespace std;

// Helper function to escape a string's control characters for JSON output.
string escapeJSON(string_view s)
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
string WideToUtf8(const wchar_t* s)
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

string BstrToUtf8(BSTR s)
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
bool TryFormatDateIso8601(DATE date, string& outIso8601)
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
string QuoteBstrJson(BSTR s)
{
	if (!s) return "\"\"";
	string utf8 = BstrToUtf8(s);
	return "\"" + escapeJSON(utf8) + "\"";
}

// Format an SCODE as unsigned hex with "0x" prefix (lowercase hex), without quotes.
string ErrorCodeHexString(SCODE sc)
{
	return format("0x{:x}", static_cast<unsigned long>(sc));
}

// copy an "effective" variant by resolving VT_BYREF and VT_VARIANT wrappers.
// - 'out' must be VariantInit'd by the caller.
// - Returns true if 'out' received a valid copy, else false.
bool CopyEffectiveVariant(const VARIANT& in, VARIANT& out)
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

// VariantToString converts a VARIANT to its JSON string representation.
// For JSON output, proper types are used:
// - Strings are output directly.
// - Numbers and booleans are output directly.
// - VT_NULL and VT_EMPTY return null.
// - When the variant type is a SAFEARRAY (for strings or integers) and the array has no members,
//   it returns an empty string (i.e. nothing is output).
string VariantToString(const VARIANT& vt)
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

wstring Utf8ToWide(string_view s)
{
	if (s.empty()) return wstring();
	int sizeNeeded = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0);
	if (sizeNeeded <= 0) return wstring();
	wstring result(static_cast<size_t>(sizeNeeded), L'\0');
	int written = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), result.data(), sizeNeeded);
	if (written <= 0) return wstring();
	return result;
}

bool EqualsOrdinalIgnoreCase(const wchar_t* a, const wchar_t* b)
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
[[nodiscard]] HRESULT CreateSafeArrayOfBSTR(const vector<wstring>& values, SAFEARRAY** ppsa)
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
/// Helper function to set an array of BSTR strings on IWbemContext.
/// This is used to set address arrays in the WMI context for firewall operations.
/// </summary>
/// <param name="pCtx">The WMI context object</param>
/// <param name="name">Name of the context parameter</param>
/// <param name="psa">SAFEARRAY containing the string values</param>
/// <returns>HRESULT indicating success or failure</returns>
[[nodiscard]] HRESULT ContextSetStringArray(IWbemContext* pCtx, const wchar_t* name, SAFEARRAY* psa)
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
/// Helper function to create IWbemContext and set a string named value on it.
/// This is used to set WMI operation context parameters like PolicyStore.
/// </summary>
/// <param name="ppCtx">Pointer to receive the created IWbemContext</param>
/// <param name="name">Name of the context parameter</param>
/// <param name="value">Value of the context parameter</param>
/// <returns>HRESULT indicating success or failure</returns>
[[nodiscard]] HRESULT CreateContextAndSetString(IWbemContext** ppCtx, const wchar_t* name, const wchar_t* value)
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
