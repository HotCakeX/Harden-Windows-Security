#include <string>
#include <comdef.h>
#include <Wbemidl.h>
#include <windows.h>
#include <mutex>
#include <winhttp.h>
#include "Globals.h"
#include "Firewall/FirewallManager.h"
#include "StringUtilities.h"
#include "ComHelpers.h"

/// <summary>
/// Connects to a WMI namespace with proper COM/security handling.
/// Accepts both "too late" security initialization variants for compatibility.
/// </summary>
/// <param name="wmiNamespace">WMI namespace to connect to</param>
/// <param name="ppLoc">Pointer to receive the IWbemLocator interface</param>
/// <param name="ppSvc">Pointer to receive the IWbemServices interface</param>
/// <param name="didInitCOM">Reference to bool indicating if COM was initialized</param>
/// <returns>True if connection succeeded, false otherwise</returns>
[[nodiscard]] bool ConnectToWmiNamespace(const wchar_t* wmiNamespace, IWbemLocator** ppLoc, IWbemServices** ppSvc, bool& didInitCOM)
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

// Function for getting WMI results based on a property name, namespace, and class name.
// This function queries WMI for the specified namespace and class, and outputs the specified property value in valid JSON format.
[[nodiscard]] bool GetWmiValue(const wchar_t* wmiNamespace, const wchar_t* wmiClassName, const wchar_t* preferenceName)
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
[[nodiscard]] bool GetAllWmiProperties(const wchar_t* wmiNamespace, const wchar_t* wmiClassName)
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

// Function to check if a given property exists on a WMI class in a namespace.
// - Returns true if the property exists.
// - Returns false if the property doesn't exist.
// - Returns false and sets the last error message when namespace or class is invalid (or on other failures).
[[nodiscard]] bool DoesWmiPropertyExist(const wchar_t* wmiNamespace, const wchar_t* wmiClassName, const wchar_t* propertyName)
{
	// Clear last error to differentiate "false due to not found" vs real errors.
	ClearLastErrorMsg();

	// Basic validation.
	if (!wmiNamespace || !wmiClassName || !propertyName)
	{
		SetLastErrorMsg(L"Namespace, class name, and property name must not be null.");
		return false;
	}

	// Reuse the common connection helper to handle COM/security and connect to the namespace.
	IWbemLocator* pLoc = nullptr;
	IWbemServices* pSvc = nullptr;
	bool didInitCOM = false;
	if (!ConnectToWmiNamespace(wmiNamespace, &pLoc, &pSvc, didInitCOM))
	{
		// Error is already set by ConnectToWmiNamespace.
		return false;
	}

	// Get the class definition.
	IWbemClassObject* pClass = nullptr;
	HRESULT hr = pSvc->GetObject(_bstr_t(wmiClassName), 0, nullptr, &pClass, nullptr);
	if (FAILED(hr) || !pClass)
	{
		SetLastErrorMsg(wstring(L"Failed to get ") + wmiClassName + L" object. Error code = 0x" + to_wstring(hr));
		if (pSvc) pSvc->Release();
		if (pLoc) pLoc->Release();
		if (!g_skipCOMInit && didInitCOM) CoUninitialize();
		return false;
	}

	// Probe the property existence on the class object.
	VARIANT vt{};
	VariantInit(&vt);
	CIMTYPE cim = 0;
	LONG flavor = 0;
	hr = pClass->Get(_bstr_t(propertyName), 0, &vt, &cim, &flavor);

	// Cleanup.
	VariantClear(&vt);
	pClass->Release();
	pSvc->Release();
	pLoc->Release();
	if (!g_skipCOMInit && didInitCOM) CoUninitialize();

	// Property missing: return false without setting an error.
	if (hr == WBEM_E_NOT_FOUND)
	{
		return false;
	}

	// Treat other failure while probing property as error.
	if (FAILED(hr))
	{
		SetLastErrorMsg(wstring(L"Failed to probe property '") + propertyName + L"' on class " + wmiClassName + L". Error code = 0x" + to_wstring(hr));
		return false;
	}

	// Found the property.
	return true;
}

// Execute a parameterless WMI method on a class or instances automatically.
// - Detects the "Static" qualifier on the method:
//   - If static: invokes ExecMethod on the class.
//   - If instance method: enumerates instances and invokes ExecMethod on each instance (__RELPATH).
// Returns true on success (all calls succeed), false on failure (and sets last error).
[[nodiscard]] bool ExecuteWmiClassMethodNoParams(const wchar_t* wmiNamespace, const wchar_t* wmiClassName, const wchar_t* customMethodName)
{
	// Clear last error message first.
	ClearLastErrorMsg();

	// Basic validation
	if (!wmiNamespace || !wmiClassName || !customMethodName)
	{
		SetLastErrorMsg(L"Namespace, class name, and method name must not be null.");
		return false;
	}

	// Connect to the namespace (handles COM init/security internally).
	IWbemLocator* pLoc = nullptr;
	IWbemServices* pSvc = nullptr;
	bool didInitCOM = false;
	if (!ConnectToWmiNamespace(wmiNamespace, &pLoc, &pSvc, didInitCOM) || !pSvc)
	{
		if (pLoc) pLoc->Release();
		if (pSvc) pSvc->Release();
		return false; // error already set
	}

	// Retrieve the class object.
	IWbemClassObject* pClass = nullptr;
	HRESULT hr = pSvc->GetObject(_bstr_t(wmiClassName), 0, nullptr, &pClass, nullptr);
	if (FAILED(hr) || !pClass)
	{
		SetLastErrorMsg(wstring(L"Failed to get ") + wmiClassName + L" object. Error code = 0x" + to_wstring(hr));
		if (pSvc) pSvc->Release();
		if (pLoc) pLoc->Release();
		if (!g_skipCOMInit && didInitCOM) CoUninitialize();
		return false;
	}

	// Determine if method is Static via its qualifier set
	bool isStatic = false;
	{
		IWbemQualifierSet* pMethQuals = nullptr;
		HRESULT hrQ = pClass->GetMethodQualifierSet(_bstr_t(customMethodName), &pMethQuals);
		if (SUCCEEDED(hrQ) && pMethQuals)
		{
			VARIANT v; VariantInit(&v);
			// If "Static" qualifier exists and is VARIANT_TRUE -> static method
			if (SUCCEEDED(pMethQuals->Get(_bstr_t(L"Static"), 0, &v, nullptr)) && v.vt == VT_BOOL)
			{
				isStatic = (v.boolVal == VARIANT_TRUE);
			}
			VariantClear(&v);
			pMethQuals->Release();
		}
		// If qualifier set isn't available, we'll still try to execute; failures will be reported normally.
	}

	// Retrieve method parameter definitions (so we can spawn InParams if defined)
	IWbemClassObject* pInDef = nullptr;
	IWbemClassObject* pOutDef = nullptr;
	hr = pClass->GetMethod(_bstr_t(customMethodName), 0, &pInDef, &pOutDef);
	if (FAILED(hr))
	{
		SetLastErrorMsg(wstring(L"Failed to get method definition for ") + customMethodName + L". Error code = 0x" + to_wstring(hr));
		if (pOutDef) pOutDef->Release();
		pClass->Release();
		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM) CoUninitialize();
		return false;
	}

	// Prepare (possibly empty) InParams if definition exists
	IWbemClassObject* pIn = nullptr;
	if (pInDef)
	{
		hr = pInDef->SpawnInstance(0, &pIn);
		if (FAILED(hr))
		{
			SetLastErrorMsg(wstring(L"Failed to spawn instance for method parameters. Error code = 0x") + to_wstring(hr));
			if (pOutDef) pOutDef->Release();
			if (pInDef) pInDef->Release();
			pClass->Release();
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}
	}

	bool overallOk = false;

	if (isStatic)
	{
		// Static method: call on class path
		IWbemClassObject* pOut = nullptr;
		hr = pSvc->ExecMethod(_bstr_t(wmiClassName), _bstr_t(customMethodName), 0, nullptr, pIn, &pOut, nullptr);

		if (FAILED(hr) || !pOut)
		{
			SetLastErrorMsg(wstring(L"ExecMethod for ") + customMethodName + L" failed. Error code = 0x" + to_wstring(hr));
			if (pOut) pOut->Release();
			if (pIn) pIn->Release();
			if (pOutDef) pOutDef->Release();
			if (pInDef) pInDef->Release();
			pClass->Release();
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		// Log ReturnValue if present
		VARIANT vRet; VariantInit(&vRet);
		HRESULT hrRet = pOut->Get(_bstr_t(L"ReturnValue"), 0, &vRet, nullptr, nullptr);
		if (SUCCEEDED(hrRet))
		{
			if (vRet.vt == VT_I4 || vRet.vt == VT_UI4)
			{
				LogOut(L"Method ", customMethodName, L" returned: ", (vRet.vt == VT_I4 ? vRet.intVal : static_cast<int>(vRet.ulVal)));
			}
			else
			{
				LogOut(L"Method ", customMethodName, L" executed; ReturnValue present with non-integer type.");
			}
		}
		else
		{
			LogOut(L"Method ", customMethodName, L" executed, but no return value provided.");
		}
		VariantClear(&vRet);
		pOut->Release();

		overallOk = true;
	}
	else
	{
		// Instance method: enumerate instances and call for each instance path
		wstringstream wql;
		wql << L"SELECT __RELPATH FROM " << wmiClassName;

		IEnumWbemClassObject* pEnum = nullptr;
		hr = pSvc->ExecQuery(
			_bstr_t(L"WQL"),
			_bstr_t(wql.str().c_str()),
			WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
			nullptr,
			&pEnum);

		if (FAILED(hr) || !pEnum)
		{
			SetLastErrorMsg(wstring(L"ExecQuery failed for ") + wmiClassName + L". Error code = 0x" + to_wstring(hr));
			if (pEnum) pEnum->Release();
			if (pIn) pIn->Release();
			if (pOutDef) pOutDef->Release();
			if (pInDef) pInDef->Release();
			pClass->Release();
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		size_t total = 0;
		size_t successCount = 0;
		size_t failCount = 0;

		for (;;)
		{
			IWbemClassObject* pInst = nullptr;
			ULONG uRet = 0;
			HRESULT hrNext = pEnum->Next(WBEM_INFINITE, 1, &pInst, &uRet);
			if (hrNext != S_OK || uRet == 0 || !pInst)
				break;

			++total;

			// Get instance path (prefer __RELPATH; fallback to __PATH if needed)
			wstring instPath;
			{
				VARIANT v; VariantInit(&v);
				if (SUCCEEDED(pInst->Get(_bstr_t(L"__RELPATH"), 0, &v, nullptr, nullptr)) && v.vt == VT_BSTR && v.bstrVal)
				{
					instPath.assign(v.bstrVal, SysStringLen(v.bstrVal));
				}
				VariantClear(&v);
			}
			if (instPath.empty())
			{
				VARIANT v; VariantInit(&v);
				if (SUCCEEDED(pInst->Get(_bstr_t(L"__PATH"), 0, &v, nullptr, nullptr)) && v.vt == VT_BSTR && v.bstrVal)
				{
					instPath.assign(v.bstrVal, SysStringLen(v.bstrVal));
				}
				VariantClear(&v);
			}

			pInst->Release();

			if (instPath.empty())
			{
				++failCount;
				continue;
			}

			IWbemClassObject* pOut = nullptr;
			HRESULT hrCall = pSvc->ExecMethod(_bstr_t(instPath.c_str()), _bstr_t(customMethodName), 0, nullptr, pIn, &pOut, nullptr);
			if (FAILED(hrCall) || !pOut)
			{
				++failCount;
			}
			else
			{
				// Log ReturnValue (if present) for each instance
				VARIANT vRet; VariantInit(&vRet);
				HRESULT hrRet = pOut->Get(_bstr_t(L"ReturnValue"), 0, &vRet, nullptr, nullptr);
				if (SUCCEEDED(hrRet))
				{
					if (vRet.vt == VT_I4 || vRet.vt == VT_UI4)
					{
						LogOut(L"Method ", customMethodName, L" on instance ", instPath.c_str(), L" returned: ",
							(vRet.vt == VT_I4 ? vRet.intVal : static_cast<int>(vRet.ulVal)));
					}
					else
					{
						LogOut(L"Method ", customMethodName, L" on instance ", instPath.c_str(),
							L" executed; ReturnValue present with non-integer type.");
					}
				}
				else
				{
					LogOut(L"Method ", customMethodName, L" on instance ", instPath.c_str(), L" executed, but no return value provided.");
				}
				VariantClear(&vRet);
				pOut->Release();

				++successCount;
			}
		}

		pEnum->Release();

		if (total == 0)
		{
			SetLastErrorMsg(L"No instances were found for the specified class to execute the instance method.");
			if (pIn) pIn->Release();
			if (pOutDef) pOutDef->Release();
			if (pInDef) pInDef->Release();
			pClass->Release();
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		if (failCount == 0)
		{
			overallOk = true;
		}
		else
		{
			wstringstream ss;
			ss << L"Method execution completed with failures. Succeeded: " << successCount << L", Failed: " << failCount << L".";
			SetLastErrorMsg(ss.str());
			overallOk = false;
		}
	}

	// Cleanup common objects
	if (pIn) pIn->Release();
	if (pOutDef) pOutDef->Release();
	if (pInDef) pInDef->Release();
	pClass->Release();
	pSvc->Release();
	pLoc->Release();
	if (!g_skipCOMInit && didInitCOM) CoUninitialize();

	return overallOk;
}
