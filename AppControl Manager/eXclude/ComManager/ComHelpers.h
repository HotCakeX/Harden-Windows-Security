#pragma once
#include <string>
#include <comdef.h>
#include <ctime>
#include <winhttp.h>
#include <iostream>
#include <iomanip>
#include "Globals.h"

[[nodiscard]] bool ExecuteWmiClassMethodNoParams(const wchar_t* wmiNamespace, const wchar_t* wmiClassName, const wchar_t* customMethodName);
[[nodiscard]] bool ConnectToWmiNamespace(const wchar_t* wmiNamespace, IWbemLocator** ppLoc, IWbemServices** ppSvc, bool& didInitCOM);
[[nodiscard]] bool GetWmiValue(const wchar_t* wmiNamespace, const wchar_t* wmiClassName, const wchar_t* preferenceName);
[[nodiscard]] bool GetAllWmiProperties(const wchar_t* wmiNamespace, const wchar_t* wmiClassName);
[[nodiscard]] bool DoesWmiPropertyExist(const wchar_t* wmiNamespace, const wchar_t* wmiClassName, const wchar_t* propertyName);
extern "C" __declspec(dllexport) bool __stdcall ManageWmiPreferenceInt(const wchar_t* wmiNamespace, const wchar_t* wmiClassName, const wchar_t* customMethodName, const wchar_t* preferenceName, int preferenceValue);
extern "C" __declspec(dllexport) bool __stdcall ManageWmiPreferenceBool(const wchar_t* wmiNamespace, const wchar_t* wmiClassName, const wchar_t* customMethodName, const wchar_t* preferenceName, bool preferenceValue);
extern "C" __declspec(dllexport) bool __stdcall ManageWmiPreferenceString(const wchar_t* wmiNamespace, const wchar_t* wmiClassName, const wchar_t* customMethodName, const wchar_t* preferenceName, const wchar_t* preferenceValue);
extern "C" __declspec(dllexport) bool __stdcall ManageWmiPreferenceStringArray(const wchar_t* wmiNamespace, const wchar_t* wmiClassName, const wchar_t* customMethodName, const wchar_t* preferenceName, const wchar_t** preferenceArray, int arraySize);
extern "C" __declspec(dllexport) bool __stdcall ManageWmiPreferenceIntArray(const wchar_t* wmiNamespace, const wchar_t* wmiClassName, const wchar_t* customMethodName, const wchar_t* preferenceName, const int* preferenceArray, int arraySize);
extern "C" __declspec(dllexport) bool __stdcall GetWmiData(const wchar_t* wmiNamespace, const wchar_t* wmiClassName, const wchar_t* preferenceName);
extern "C" __declspec(dllexport) bool __stdcall GetAllWmiData(const wchar_t* wmiNamespace, const wchar_t* wmiClassName);

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
			LogErr(L"Failed to initialize COM library. Error code = 0x", hex, hres, L" - ", _com_error(hres).ErrorMessage());
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
			LogErr(L"Failed to initialize security. Error code = 0x", hex, hres, L" - ", _com_error(hres).ErrorMessage());
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
		LogErr(L"Failed to create IWbemLocator object. Error code = 0x", hex, hres, L" - ", _com_error(hres).ErrorMessage());
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
		LogErr(L"Could not connect to ", wmiNamespace, L" namespace. Error code = 0x", hex, hres, L" - ", _com_error(hres).ErrorMessage());
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
		LogErr(L"Could not set proxy blanket. Error code = 0x", hex, hres, L" - ", _com_error(hres).ErrorMessage());
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
		LogErr(L"Failed to get ", wmiClassName, L" object. Error code = 0x", hex, hres, L" - ", _com_error(hres).ErrorMessage());
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
		LogErr(L"Failed to get method definition for ", customMethodName,
			L". Error code = 0x", hex, hres,
			L" - ", _com_error(hres).ErrorMessage());
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
		LogErr(L"Failed to spawn instance for method parameters. Error code = 0x", hex, hres, L" - ", _com_error(hres).ErrorMessage());
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
			LogErr(L"Failed to allocate BSTR for string parameter.");
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
			LogErr(L"Failed to create SAFEARRAY for string array.");
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
			LogErr(L"Failed to create SAFEARRAY for int array.");
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
				LogErr(L"Failed to put element in SAFEARRAY for int array. Error code = 0x", hex, hres, L" - ", _com_error(hres).ErrorMessage());
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
		LogErr(L"Failed to set parameter ", preferenceName,
			L". Error code = 0x", hex, hres,
			L" - ", _com_error(hres).ErrorMessage());
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
		LogOut(L"Setting ", preferenceName, L" to: ", varParam.boolVal);
	else if constexpr (is_same<T, int>::value)
		LogOut(L"Setting ", preferenceName, L" to: ", varParam.lVal);
	else if constexpr (is_convertible<T, wstring>::value &&
		!is_same<T, vector<wstring>>::value)
		LogOut(L"Setting ", preferenceName, L" to: ", varParam.bstrVal);
	else if constexpr (is_same<T, vector<wstring>>::value)
		LogOut(L"Setting ", preferenceName, L" to a string array of size: ",
			preferenceValue.size());
	else if constexpr (is_same<T, vector<int>>::value)
		LogOut(L"Setting ", preferenceName, L" to an int array of size: ",
			preferenceValue.size());

	// Clear the VARIANT now that it has been bound.
	VariantClear(&varParam);

	// A pointer for the method output parameters.
	IWbemClassObject* pOutParams = nullptr;
	// Execute the specified WMI method using the class and method names.
	hres = pSvc->ExecMethod(className, methodName, 0, NULL, pInParams, &pOutParams, NULL);
	if (FAILED(hres))
	{
		// Log error if method execution fails.
		LogErr(L"ExecMethod for ", customMethodName,
			L" failed. Error code = 0x", hex, hres,
			L" - ", _com_error(hres).ErrorMessage());
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
			LogOut(L"Method ", customMethodName,
				L" returned: ", varRet.intVal);
		}
		else
		{
			// Log that the method executed but no return value was provided.
			LogOut(L"Method ", customMethodName,
				L" executed, but no return value provided. Error code = 0x",
				hex, hres,
				L" - ", _com_error(hres).ErrorMessage());
		}
		// Clear the VARIANT holding the return value.
		VariantClear(&varRet);
		// Release the output parameters object.
		pOutParams->Release();
	}
	else
	{
		// Log that the method executed successfully without output parameters.
		LogOut(L"Method ", customMethodName,
			L" executed successfully, but no return parameters were provided.");
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