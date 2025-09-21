#pragma once
#include <string>
#include <string_view>
#include <format>
#include <windows.h>
#include <sstream>
#include <type_traits>
#include <vector>
#include <iostream>
#include <Wbemidl.h>
#include <array>

using namespace std;

string escapeJSON(string_view s);
string WideToUtf8(const wchar_t* s);
string BstrToUtf8(BSTR s);
bool TryFormatDateIso8601(DATE date, string& outIso8601);
string QuoteBstrJson(BSTR s);
string ErrorCodeHexString(SCODE sc);
bool CopyEffectiveVariant(const VARIANT& in, VARIANT& out);
string VariantToString(const VARIANT& vt);
wstring Utf8ToWide(string_view s);
bool EqualsOrdinalIgnoreCase(const wchar_t* a, const wchar_t* b);
[[nodiscard]] HRESULT CreateSafeArrayOfBSTR(const vector<wstring>& values, SAFEARRAY** ppsa);
[[nodiscard]] HRESULT ContextSetStringArray(IWbemContext* pCtx, const wchar_t* name, SAFEARRAY* psa);
[[nodiscard]] HRESULT CreateContextAndSetString(IWbemContext** ppCtx, const wchar_t* name, const wchar_t* value);

// Helper function to process SAFEARRAY of different types and return JSON array string.
template<typename T>
string ProcessSafeArray(SAFEARRAY* psa)
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
