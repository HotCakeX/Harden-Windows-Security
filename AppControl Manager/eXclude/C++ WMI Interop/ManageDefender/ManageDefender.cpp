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

#pragma comment(lib, "wbemuuid.lib")

// Bring the std namespace into scope to avoid prefixing with std::.
// std (aka Standard Library is C++ equivalent of System; namespace in C#)
// std::wcout is used for normal output(typically goes to stdout)
// std::wcerr is used for error output (goes to stderr).
using namespace std;

// Global variable and mutex for storing the last error message.
static std::wstring g_lastErrorMsg;
static std::mutex g_errorMutex;

// Global flag to indicate if the code is running as a library (DLL mode).
// When set to true, COM initialization and security are skipped because they are assumed to be already initialized.
// In packaged WinUI3 apps, Com and Com Security are already initialized so we cannot reinitialize them otherwise we'd get errors.
static bool g_skipCOMInit = false;

// Exported function to allow setting the DLL mode from external callers (e.g. C# via DllImport).
extern "C" __declspec(dllexport) void __stdcall SetDllMode(bool skipInit)
{
	g_skipCOMInit = skipInit;
}

// Helper: Set the global error message (thread-safe)
static void SetLastErrorMsg(const std::wstring& msg)
{
	std::lock_guard<std::mutex> lock(g_errorMutex);
	g_lastErrorMsg = msg;
}

// Helper: Clear the global error message.
static void ClearLastErrorMsg()
{
	std::lock_guard<std::mutex> lock(g_errorMutex);
	g_lastErrorMsg.clear();
}

// Exported function to retrieve the last error message.
// This function returns a pointer to a wide string representing the last error.
// Note: The pointer is valid until the next call to any function in this DLL.
extern "C" __declspec(dllexport) const wchar_t* __stdcall GetLastErrorMessage()
{
	std::lock_guard<std::mutex> lock(g_errorMutex);
	return g_lastErrorMsg.c_str();
}

// Helper function to escape a string for JSON output.
// It escapes characters like \, ", control characters.
static string escapeJSON(const string& s) {
	// Initialize an empty string to accumulate the escaped output.
	string result;
	// Iterate over each character in the input string.
	for (char c : s) {
		switch (c) {
		case '\\': result.append("\\\\"); break;  // Escape backslash.
		case '\"': result.append("\\\""); break;  // Escape double quote.
		case '\b': result.append("\\b"); break;   // Escape backspace.
		case '\f': result.append("\\f"); break;   // Escape form feed.
		case '\n': result.append("\\n"); break;   // Escape newline.
		case '\r': result.append("\\r"); break;   // Escape carriage return.
		case '\t': result.append("\\t"); break;   // Escape tab.
		default:
			result.push_back(c); // Append the character as is.
		}
	}
	// Return the fully escaped JSON string.
	return result;
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
	// Create a string stream to convert numeric values to a string.
	ostringstream oss;
	switch (vt.vt)
	{
	case VT_NULL:
	case VT_EMPTY:
		// Return an empty string for empty and null variants.
		return "";

	case VT_BSTR: // VARENUM(8), string value
	{
		// Convert the BSTR (COM string type) to a standard C++ string.
		string val = string(_bstr_t(vt.bstrVal));
		// Return string as is.
		return val;
	}
	case VT_I1:
		// Convert signed char to int and send it to the stream.
		oss << static_cast<int>(vt.cVal);
		// Return the numerical string representation.
		return oss.str();
	case VT_UI1: // VARENUM(17) as integer type
		// Convert unsigned char to unsigned int for numeric output.
		oss << static_cast<unsigned int>(vt.bVal);
		return oss.str();
	case VT_I2:
		// Output the 16-bit signed integer to the stream.
		oss << vt.iVal;
		return oss.str();
	case VT_UI2:
		// Output the 16-bit unsigned integer to the stream.
		oss << vt.uiVal;
		return oss.str();
	case VT_I4: // VARENUM(3)
		// Output the 32-bit signed integer to the stream.
		oss << vt.lVal;
		return oss.str();
	case VT_UI4:
		// Output the 32-bit unsigned integer to the stream.
		oss << vt.ulVal;
		return oss.str();
	case VT_INT:
		// Output the signed integer (platform-dependent size) to the stream.
		oss << vt.intVal;
		return oss.str();
	case VT_UINT:
		// Output the unsigned integer to the stream.
		oss << vt.uintVal;
		return oss.str();
	case VT_I8:
		// Output the 64-bit signed integer to the stream.
		oss << vt.llVal;
		return oss.str();
	case VT_UI8:
		// Output the 64-bit unsigned integer to the stream.
		oss << vt.ullVal;
		return oss.str();
	case VT_R4:
		// Output the float value to the stream.
		oss << vt.fltVal;
		return oss.str();
	case VT_R8:
		// Output the double value to the stream.
		oss << vt.dblVal;
		return oss.str();
	case VT_BOOL: // VARENUM(11)
		// Convert the boolean value to "true" or "false".
		return vt.boolVal ? "true" : "false";
	case VT_DATE:
	{
		// Declare a SYSTEMTIME structure to hold the conversion result.
		SYSTEMTIME st;
		// Convert the VARIANT date to SYSTEMTIME.
		if (VariantTimeToSystemTime(vt.date, &st))
		{
			// Format the date/time using std::format.
			string dateStr = std::format("{:02d}/{:02d}/{:04d} {:02d}:{:02d}:{:02d}",
				st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute, st.wSecond);
			// Return the formatted date string.
			return dateStr;
		}
		else
		{
			// Return an empty string on conversion failure.
			return "";
		}
	}
	case (VT_ARRAY | VT_BSTR): // SAFEARRAY of strings (VARENUM 8200)
	{
		// Retrieve the pointer to the SAFEARRAY.
		SAFEARRAY* psa = vt.parray;
		// Declare variables to hold the lower and upper bounds.
		LONG lBound = 0, uBound = 0;
		// Get array boundaries from the SAFEARRAY.
		if (FAILED(SafeArrayGetLBound(psa, 1, &lBound)) ||
			FAILED(SafeArrayGetUBound(psa, 1, &uBound)))
			return "";
		// Return an empty string if the array has no members.
		if ((uBound - lBound + 1) <= 0)
			return "";
		// Prepare a stream to build the JSON array string.
		ostringstream json;
		// Start the JSON array.
		json << "[";
		// Boolean flag to handle comma separation between elements.
		bool first = true;
		// Iterate through the array elements.
		for (LONG i = lBound; i <= uBound; i++)
		{
			// Declare a variable to store the BSTR element.
			BSTR bstr;
			// Retrieve the element; continue to next iteration if retrieval fails.
			if (FAILED(SafeArrayGetElement(psa, &i, &bstr)))
				continue;
			// Insert a comma if this is not the first element.
			if (!first)
				json << ",";
			// Convert the obtained BSTR to a std::wstring.
			wstring wstr = bstr ? wstring(bstr) : L"";
			// Free the BSTR after conversion.
			SysFreeString(bstr);
			// Convert the wide string to a narrow string.
			string narrow = string(_bstr_t(wstr.c_str()));
			// Append the escaped string enclosed in quotes.
			json << "\"" << escapeJSON(narrow) << "\"";
			// Update the flag after processing the first element.
			first = false;
		}
		// End the JSON array.
		json << "]";
		// Return the complete JSON array string.
		return json.str();
	}
	case 8209: // SAFEARRAY of integers (VARENUM 8209)
	{
		// Retrieve the pointer to the SAFEARRAY containing integers.
		SAFEARRAY* psa = vt.parray;
		// Declare variables for the lower and upper array bounds.
		LONG lBound = 0, uBound = 0;
		// Get the array boundaries from the SAFEARRAY.
		if (FAILED(SafeArrayGetLBound(psa, 1, &lBound)) ||
			FAILED(SafeArrayGetUBound(psa, 1, &uBound)))
			return "";
		// Return an empty string if the array has no members.
		if ((uBound - lBound + 1) <= 0)
			return "";
		// Create a stream to build the JSON output for the integer array.
		ostringstream intStream;
		// Begin the JSON array.
		intStream << "[";
		// Boolean flag to manage comma placement between array elements.
		bool first = true;
		// Iterate over each element in the integer array.
		for (LONG i = lBound; i <= uBound; i++)
		{
			// Variable to hold the integer value.
			int value = 0;
			// Retrieve the element; if successful, process it.
			if (SUCCEEDED(SafeArrayGetElement(psa, &i, &value)))
			{
				// Insert a comma if this is not the first element.
				if (!first)
					intStream << ",";
				// Insert the integer value into the stream.
				intStream << value;
				// Update the flag after processing the first element.
				first = false;
			}
		}
		// End the JSON array.
		intStream << "]";
		// Return the resulting JSON formatted string.
		return intStream.str();
	}
	default:
		// Return an empty string literal to indicate no output for unsupported types.
		return "\"\"";
	}
}

// Template function that configures a Defender preference via a specified WMI method on the MSFT_MpPreference class.
// Supported types: bool, int, string (std::wstring or types convertible to std::wstring),
//                  string array (std::vector<std::wstring>), and integer array (std::vector<int>).
//
// The following types have been detected from the raw results of the Get method on the MSFT_MpPreference class:
// - VARENUM(8): corresponds to string (BSTR).
// - VARENUM(11): corresponds to boolean (VT_BOOL).
// - VARENUM(3) and VARENUM(17): correspond to integer types (VT_I4).
// - VARENUM(8200): corresponds to a SAFEARRAY of strings, so support for std::vector<std::wstring>.
// - VARENUM(8209): corresponds to a SAFEARRAY of integers, so support for std::vector<int>.
//
// This function sets the VARIANT value based on template parameter T, then executes the specified WMI method.
template <typename T>
bool ManageMpPreference(const wchar_t* customMethodName, const wchar_t* preferenceName, T preferenceValue)
{
	// Compile-time check ensuring that only permitted types are accepted.
	static_assert(
		std::is_same<T, bool>::value ||
		std::is_same<T, int>::value ||
		std::is_convertible<T, std::wstring>::value ||
		std::is_same<T, std::vector<std::wstring>>::value ||
		std::is_same<T, std::vector<int>>::value,
		"ManageMpPreference supports only bool, int, string, vector<string>, and vector<int> types."
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
		if (hres == 0x80010106)
		{
			hres = S_OK;
		}
		if (FAILED(hres))
		{
			// Output the error details for COM initialization failure.
			std::wcerr << L"Failed to initialize COM library. Error code = 0x"
				<< hex << hres << L" - " << _com_error(hres).ErrorMessage() << endl;
			SetLastErrorMsg(std::wstring(L"Failed to initialize COM library. Error code = 0x") + std::to_wstring(hres));
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
		// Check if security is already initialized (error 0x80010109)
		if (hres == 0x80010109)
		{
			hres = S_OK;
		}
		if (FAILED(hres))
		{
			// Log error details for security initialization failure.
			std::wcerr << L"Failed to initialize security. Error code = 0x"
				<< hex << hres << L" - " << _com_error(hres).ErrorMessage() << endl;
			SetLastErrorMsg(std::wstring(L"Failed to initialize security. Error code = 0x") + std::to_wstring(hres));
			CoUninitialize();
			return false;
		}
	}

	// Declare a pointer for the WMI locator interface.
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
		std::wcerr << L"Failed to create IWbemLocator object. Error code = 0x"
			<< hex << hres << L" - " << _com_error(hres).ErrorMessage() << endl;
		SetLastErrorMsg(std::wstring(L"Failed to create IWbemLocator object. Error code = 0x") + std::to_wstring(hres));
		if (!g_skipCOMInit && didInitCOM)
			CoUninitialize();
		return false;
	}

	// Declare a pointer for the IWbemServices interface.
	IWbemServices* pSvc = nullptr;
	// Connect to the WMI namespace for Windows Defender.
	hres = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\Microsoft\\Windows\\Defender"), // Specify the target WMI namespace.
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
		std::wcerr << L"Could not connect to ROOT\\Microsoft\\Windows\\Defender namespace. Error code = 0x"
			<< hex << hres << L" - " << _com_error(hres).ErrorMessage() << endl;
		SetLastErrorMsg(std::wstring(L"Could not connect to ROOT\\Microsoft\\Windows\\Defender namespace. Error code = 0x") + std::to_wstring(hres));
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
		std::wcerr << L"Could not set proxy blanket for Defender. Error code = 0x"
			<< hex << hres << L" - " << _com_error(hres).ErrorMessage() << endl;
		SetLastErrorMsg(std::wstring(L"Could not set proxy blanket for Defender. Error code = 0x") + std::to_wstring(hres));
		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM)
			CoUninitialize();
		return false;
	}

	// Allocate a BSTR for the class name "MSFT_MpPreference".
	BSTR className = SysAllocString(L"MSFT_MpPreference");
	// Declare a pointer for the WMI class object.
	IWbemClassObject* pClass = nullptr;
	// Retrieve the WMI class object.
	hres = pSvc->GetObject(className, 0, NULL, &pClass, NULL);
	if (FAILED(hres))
	{
		// Log error if retrieving the class object fails.
		std::wcerr << L"Failed to get MSFT_MpPreference object. Error code = 0x"
			<< hex << hres << L" - " << _com_error(hres).ErrorMessage() << endl;
		SetLastErrorMsg(std::wstring(L"Failed to get MSFT_MpPreference object. Error code = 0x") + std::to_wstring(hres));
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
		std::wcerr << L"Failed to get method definition for " << customMethodName
			<< L". Error code = 0x" << hex << hres
			<< L" - " << _com_error(hres).ErrorMessage() << endl;
		SetLastErrorMsg(std::wstring(L"Failed to get method definition for ") + customMethodName + L". Error code = 0x" + std::to_wstring(hres));
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
		std::wcerr << L"Failed to spawn instance for method parameters. Error code = 0x"
			<< hex << hres << L" - " << _com_error(hres).ErrorMessage() << endl;
		SetLastErrorMsg(std::wstring(L"Failed to spawn instance for method parameters. Error code = 0x") + std::to_wstring(hres));
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
	if constexpr (std::is_same<T, bool>::value)
	{
		// Set the VARIANT type as boolean.
		varParam.vt = VT_BOOL;
		varParam.boolVal = (preferenceValue) ? VARIANT_TRUE : VARIANT_FALSE;
	}
	else if constexpr (std::is_same<T, int>::value)
	{
		// Set the VARIANT type as a 32-bit integer.
		varParam.vt = VT_I4;
		varParam.lVal = preferenceValue;
	}
	else if constexpr (std::is_convertible<T, std::wstring>::value &&
		!std::is_same<T, std::vector<std::wstring>>::value)
	{
		// Set the VARIANT type to BSTR for string conversion.
		varParam.vt = VT_BSTR;
		// Convert the input to a std::wstring.
		std::wstring strVal = preferenceValue;
		// Allocate a BSTR from the wide string.
		varParam.bstrVal = SysAllocString(strVal.c_str());
	}
	else if constexpr (std::is_same<T, std::vector<std::wstring>>::value)
	{
		// Set the VARIANT type as an array of BSTR.
		varParam.vt = VT_ARRAY | VT_BSTR;
		// Get a reference to the vector of wide strings.
		const std::vector<std::wstring>& strArray = preferenceValue;
		// Declare a SAFEARRAYBOUND structure to specify array bounds.
		SAFEARRAYBOUND sabound{};
		// Set the lower bound of the SAFEARRAY to 0.
		sabound.lLbound = 0;
		// Set the number of elements equal to the vector size.
		sabound.cElements = static_cast<ULONG>(strArray.size());
		// Allocate a SAFEARRAY to hold the BSTR elements.
		SAFEARRAY* psa = SafeArrayCreate(VT_BSTR, 1, &sabound);
		if (psa == nullptr)
		{
			// Log error if SAFEARRAY creation fails.
			std::wcerr << L"Failed to create SAFEARRAY for string array." << endl;
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
		// Populate the SAFEARRAY with each string from the vector.
		for (LONG i = 0; i < static_cast<LONG>(strArray.size()); i++)
		{
			// Convert each vector element into a BSTR.
			BSTR bstrElement = SysAllocString(strArray[i].c_str());
			hres = SafeArrayPutElement(psa, &i, bstrElement);
			SysFreeString(bstrElement);
			if (FAILED(hres))
			{
				// Log error if inserting the element into the SAFEARRAY fails.
				std::wcerr << L"Failed to put element in SAFEARRAY. Error code = 0x"
					<< hex << hres << L" - " << _com_error(hres).ErrorMessage() << endl;
				SetLastErrorMsg(std::wstring(L"Failed to put element in SAFEARRAY. Error code = 0x") + std::to_wstring(hres));
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
	else if constexpr (std::is_same<T, std::vector<int>>::value)
	{
		// Set the VARIANT type as an array of 32-bit integers.
		varParam.vt = VT_ARRAY | VT_I4;
		// Get a reference to the vector of integers.
		const std::vector<int>& intArray = preferenceValue;
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
			std::wcerr << L"Failed to create SAFEARRAY for int array." << endl;
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
				std::wcerr << L"Failed to put element in SAFEARRAY for int array. Error code = 0x"
					<< hex << hres << L" - " << _com_error(hres).ErrorMessage() << endl;
				SetLastErrorMsg(std::wstring(L"Failed to put element in SAFEARRAY for int array. Error code = 0x") + std::to_wstring(hres));
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
		std::wcerr << L"Failed to set parameter " << preferenceName
			<< L". Error code = 0x" << hex << hres
			<< L" - " << _com_error(hres).ErrorMessage() << endl;
		SetLastErrorMsg(std::wstring(L"Failed to set parameter ") + preferenceName + L". Error code = 0x" + std::to_wstring(hres));
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
	if constexpr (std::is_same<T, bool>::value)
		std::wcout << L"Setting " << preferenceName << L" to: " << varParam.boolVal << endl;
	else if constexpr (std::is_same<T, int>::value)
		std::wcout << L"Setting " << preferenceName << L" to: " << varParam.lVal << endl;
	else if constexpr (std::is_convertible<T, std::wstring>::value &&
		!std::is_same<T, std::vector<std::wstring>>::value)
		std::wcout << L"Setting " << preferenceName << L" to: " << varParam.bstrVal << endl;
	else if constexpr (std::is_same<T, std::vector<std::wstring>>::value)
		std::wcout << L"Setting " << preferenceName << L" to a string array of size: "
		<< preferenceValue.size() << endl;
	else if constexpr (std::is_same<T, std::vector<int>>::value)
		std::wcout << L"Setting " << preferenceName << L" to an int array of size: "
		<< preferenceValue.size() << endl;

	// Clear the VARIANT now that it has been bound.
	VariantClear(&varParam);

	// Declare a pointer for the method output parameters.
	IWbemClassObject* pOutParams = nullptr;
	// Execute the specified WMI method using the class and method names.
	hres = pSvc->ExecMethod(className, methodName, 0, NULL, pInParams, &pOutParams, NULL);
	if (FAILED(hres))
	{
		// Log error if method execution fails.
		std::wcerr << L"ExecMethod for " << customMethodName
			<< L" failed. Error code = 0x" << hex << hres
			<< L" - " << _com_error(hres).ErrorMessage() << endl;
		SetLastErrorMsg(std::wstring(L"ExecMethod for ") + customMethodName + L" failed. Error code = 0x" + std::to_wstring(hres));
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
			std::wcout << L"Method " << customMethodName
				<< L" returned: " << varRet.intVal << endl;
		}
		else
		{
			// Log that the method executed but no return value was provided.
			std::wcout << L"Method " << customMethodName
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
		std::wcout << L"Method " << customMethodName
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

// Function for getting WMI results based on a property name and source.
// sourceId: 0 = MSFT_MpPreference, 1 = MSFT_MpComputerStatus
// This function queries WMI for the specified class and outputs the specified property value in valid JSON format.
static bool GetWmiValue(int sourceId, const wchar_t* preferenceName)
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
		if (hres == 0x80010106)
		{
			hres = S_OK;
		}
		if (FAILED(hres))
		{
			SetLastErrorMsg(std::wstring(L"Failed to initialize COM library. Error code = 0x") + std::to_wstring(hres));
			CoUninitialize();
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
		if (FAILED(hres))
		{
			SetLastErrorMsg(std::wstring(L"Failed to initialize security. Error code = 0x") + std::to_wstring(hres));
			if (!g_skipCOMInit && didInitCOM)
				CoUninitialize();
			return false;
		}
	}

	// Declare a pointer for the IWbemLocator interface.
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
		SetLastErrorMsg(std::wstring(L"Failed to create IWbemLocator object. Error code = 0x") + std::to_wstring(hres));
		if (!g_skipCOMInit && didInitCOM)
			CoUninitialize();
		return false;
	}

	// Declare a pointer for the IWbemServices interface.
	IWbemServices* pSvc = nullptr;
	// Connect to the WMI namespace for Windows Defender.
	hres = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\Microsoft\\Windows\\Defender"),
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
		SetLastErrorMsg(std::wstring(L"Could not connect to ROOT\\Microsoft\\Windows\\Defender namespace. Error code = 0x") + std::to_wstring(hres));
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
		SetLastErrorMsg(std::wstring(L"Could not set proxy blanket for Defender. Error code = 0x") + std::to_wstring(hres));
		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM)
			CoUninitialize();
		return false;
	}

	// Determine the WMI class name based on sourceId
	std::wstring wmiClassName;
	switch (sourceId)
	{
	case 0:
		wmiClassName = L"MSFT_MpPreference";
		break;
	case 1:
		wmiClassName = L"MSFT_MpComputerStatus";
		break;
	default:
		SetLastErrorMsg(L"Invalid source ID. Supported values: 0 (MSFT_MpPreference), 1 (MSFT_MpComputerStatus)");
		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM)
			CoUninitialize();
		return false;
	}

	// Construct the WQL query
	std::wstring wqlQuery = L"SELECT * FROM " + wmiClassName;

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
		SetLastErrorMsg(std::wstring(L"ExecQuery failed for ") + wmiClassName + L". Error code = 0x" + std::to_wstring(hres));
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
	// Flag to track if the property retrieval was successful.
	bool success = false;

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
			// Convert the property value to a JSON formatted string and output it.
			cout << VariantToString(vtProp);
			// Mark success if at least one property is retrieved.
			success = true;
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
	// Return the success flag.
	return success;
}

// Function for getting MSFT_MpPreference results based on a property name.
// This function queries WMI for MSFT_MpPreference and outputs the specified property value in valid JSON format.
static bool GetMpPreferenceValue(const wchar_t* preferenceName)
{
	return GetWmiValue(0, preferenceName);
}

// Function for getting MSFT_MpComputerStatus results based on a property name.
// This function queries WMI for MSFT_MpComputerStatus and outputs the specified property value in valid JSON format.
static bool GetMpComputerStatusValue(const wchar_t* preferenceName)
{
	return GetWmiValue(1, preferenceName);
}

// --- DLL Exported Functions for C# via DllImport/LibraryImport ---
// These exported wrapper functions allow C# code to call the functionality directly.

// Exported function for bool preference.
extern "C" __declspec(dllexport) bool __stdcall ManageMpPreferenceBool(const wchar_t* customMethodName, const wchar_t* preferenceName, bool preferenceValue)
{
	// Call the template function specialized for bool.
	return ManageMpPreference(customMethodName, preferenceName, preferenceValue);
}

// Exported function for int preference.
extern "C" __declspec(dllexport) bool __stdcall ManageMpPreferenceInt(const wchar_t* customMethodName, const wchar_t* preferenceName, int preferenceValue)
{
	// Call the template function specialized for int.
	return ManageMpPreference(customMethodName, preferenceName, preferenceValue);
}

// Exported function for string preference.
extern "C" __declspec(dllexport) bool __stdcall ManageMpPreferenceString(const wchar_t* customMethodName, const wchar_t* preferenceName, const wchar_t* preferenceValue)
{
	// Convert the const wchar_t* to std::wstring and call the template function.
	return ManageMpPreference(customMethodName, preferenceName, std::wstring(preferenceValue));
}

// Exported function for string array preference.
extern "C" __declspec(dllexport) bool __stdcall ManageMpPreferenceStringArray(const wchar_t* customMethodName, const wchar_t* preferenceName, const wchar_t** preferenceArray, int arraySize)
{
	// Create a vector to hold the string array.
	std::vector<std::wstring> vec;
	// Loop over the array of wchar_t* to build the vector.
	for (int i = 0; i < arraySize; i++)
	{
		vec.push_back(preferenceArray[i]);
	}
	// Call the template function specialized for vector<string>.
	return ManageMpPreference(customMethodName, preferenceName, vec);
}

// Exported function for int array preference.s
extern "C" __declspec(dllexport) bool __stdcall ManageMpPreferenceIntArray(const wchar_t* customMethodName, const wchar_t* preferenceName, const int* preferenceArray, int arraySize)
{
	// Create a vector to hold the integer array.
	std::vector<int> vec;
	// Loop over the array of integers to build the vector.
	for (int i = 0; i < arraySize; i++)
	{
		vec.push_back(preferenceArray[i]);
	}
	// Call the template function specialized for vector<int>.
	return ManageMpPreference(customMethodName, preferenceName, vec);
}

// Exported function for getting MSFT_MpPreference results.
// This function wraps the GetMpPreferenceValue function, allowing external callers (e.g. from C#) to retrieve the preference value.
extern "C" __declspec(dllexport) bool __stdcall GetMpPreference(const wchar_t* preferenceName)
{
	return GetMpPreferenceValue(preferenceName);
}

// Exported function for getting MSFT_MpComputerStatus results.
// This function wraps the GetMpComputerStatusValue function, allowing external callers (e.g. from C#) to retrieve the computer status value.
extern "C" __declspec(dllexport) bool __stdcall GetMpComputerStatus(const wchar_t* preferenceName)
{
	return GetMpComputerStatusValue(preferenceName);
}

// Exported function for getting WMI results from any supported source.
// sourceId: 0 = MSFT_MpPreference, 1 = MSFT_MpComputerStatus
extern "C" __declspec(dllexport) bool __stdcall GetWmiData(int sourceId, const wchar_t* preferenceName)
{
	return GetWmiValue(sourceId, preferenceName);
}

// --- End of DLL Exported Functions ---


// For command line support.
// This wmain checks if command line arguments are provided and calls corresponding functions.
// If "get" is specified, it retrieves a property value.
// Otherwise, it uses ManageMpPreference to set a value.
// Comments below explain expected command line usage.
int wmain(int argc, wchar_t* argv[])
{
	// command line option added for getting WMI results.
	// Usage: program.exe get <sourceId> <preferenceName>
	// sourceId: 0 = MSFT_MpPreference, 1 = MSFT_MpComputerStatus
	if (argc >= 2 && std::wstring(argv[1]) == L"get")
	{
		if (argc != 4)
		{
			// Print proper usage if incorrect arguments are provided.
			std::wcerr << L"Usage: program.exe get <sourceId> <preferenceName>" << std::endl;
			std::wcerr << L"  sourceId: 0 = MSFT_MpPreference, 1 = MSFT_MpComputerStatus" << std::endl;
			return 1;
		}

		// Parse the source ID
		int sourceId = _wtoi(argv[2]);
		if (sourceId < 0 || sourceId > 1)
		{
			std::wcerr << L"Error: Invalid sourceId. Supported values: 0 (MSFT_MpPreference), 1 (MSFT_MpComputerStatus)" << std::endl;
			return 1;
		}

		// Retrieve the value by source and name.
		bool isSuccessful = GetWmiValue(sourceId, argv[3]);
		// Return 0 on success, or 1 on failure.
		return isSuccessful ? 0 : 1;
	}

	// Command line usage for setting preferences (only works with MSFT_MpPreference cuz MSFT_MpComputerStatus doesn't have a Set method.):
	// For bool, int, and string, there must be exactly 5 arguments.
	// For stringarray and intarray, there must be at least 5 arguments.
	// argv[1]: Function type ("bool", "int", "string", "stringarray", or "intarray")
	// argv[2]: customMethodName
	// argv[3]: preferenceName
	// argv[4...]: value(s)
	if (argc < 5)
	{
		// Print usage instructions if not enough arguments are provided.
		std::wcerr << L"Usage:" << std::endl;
		std::wcerr << L"  For getting data:" << std::endl;
		std::wcerr << L"    program.exe get <sourceId> <preferenceName>" << std::endl;
		std::wcerr << L"    sourceId: 0 = MSFT_MpPreference, 1 = MSFT_MpComputerStatus" << std::endl;
		std::wcerr << L"  For setting preferences (MSFT_MpPreference only):" << std::endl;
		std::wcerr << L"    program.exe <bool|int|string> <customMethodName> <preferenceName> <value>" << std::endl;
		std::wcerr << L"    program.exe <stringarray|intarray> <customMethodName> <preferenceName> <value1> [value2] ..." << std::endl;
		return 1;
	}

	// Verify that the first 4 command line arguments are not empty or only whitespace.
	for (int i = 1; i < 5; i++)
	{
		std::wstring arg(argv[i]);
		if (arg.find_first_not_of(L" \t\n\r") == std::wstring::npos)
		{
			std::wcerr << L"Error: Command line argument " << i
				<< L" is empty or whitespace." << std::endl;
			std::wcerr << L"Usage:" << std::endl;
			std::wcerr << L"  For getting data:" << std::endl;
			std::wcerr << L"    program.exe get <sourceId> <preferenceName>" << std::endl;
			std::wcerr << L"    sourceId: 0 = MSFT_MpPreference, 1 = MSFT_MpComputerStatus" << std::endl;
			std::wcerr << L"  For setting preferences (MSFT_MpPreference only):" << std::endl;
			std::wcerr << L"    program.exe <bool|int|string> <customMethodName> <preferenceName> <value>" << std::endl;
			std::wcerr << L"    program.exe <stringarray|intarray> <customMethodName> <preferenceName> <value1> [value2] ..." << std::endl;
			return 1;
		}
	}

	// Read the function type (e.g., bool, int, etc.) from the command line.
	std::wstring funcType = argv[1];
	// Read the custom method name for the WMI call.
	std::wstring customMethodName = argv[2];
	// Read the preference name to be set or retrieved.
	std::wstring preferenceName = argv[3];

	// Initialize a flag for operation success.
	bool isSuccessful = false;

	if (funcType == L"bool")
	{
		if (argc != 5)
		{
			// Print usage details for bool if incorrect number of arguments are provided.
			std::wcerr << L"Usage: program.exe bool <customMethodName> <preferenceName> <true/false>" << std::endl;
			return 1;
		}
		// Read the boolean value as a string.
		std::wstring value = argv[4];
		bool boolValue = false;
		// Compare the input with "true" or "1", case-insensitively, to determine the boolean value.
		if (_wcsicmp(value.c_str(), L"true") == 0 || _wcsicmp(value.c_str(), L"1") == 0)
			boolValue = true;
		// Call the function specialized for bool and store the success status.
		isSuccessful = ManageMpPreference(customMethodName.c_str(), preferenceName.c_str(), boolValue);
	}
	else if (funcType == L"int")
	{
		if (argc != 5)
		{
			// Print usage details for int if the argument count is incorrect.
			std::wcerr << L"Usage: program.exe int <customMethodName> <preferenceName> <integer value>" << std::endl;
			return 1;
		}
		// Convert the fourth argument from a wide string to an integer.
		int intValue = _wtoi(argv[4]);
		// Call the function specialized for int.
		isSuccessful = ManageMpPreference(customMethodName.c_str(), preferenceName.c_str(), intValue);
	}
	else if (funcType == L"string")
	{
		if (argc != 5)
		{
			// Print usage details for string if the argument count is incorrect.
			std::wcerr << L"Usage: program.exe string <customMethodName> <preferenceName> <string value>" << std::endl;
			return 1;
		}
		// Call the function specialized for string.
		isSuccessful = ManageMpPreference(customMethodName.c_str(), preferenceName.c_str(), std::wstring(argv[4]));
	}
	else if (funcType == L"stringarray")
	{
		if (argc < 5)
		{
			// Print usage details for string array if there are not enough arguments.
			std::wcerr << L"Usage: program.exe stringarray <customMethodName> <preferenceName> <value1> [value2] ..." << std::endl;
			return 1;
		}
		// Create a vector to hold the string array from the command line.
		std::vector<std::wstring> vec;
		for (int i = 4; i < argc; i++)
		{
			vec.push_back(argv[i]);
		}
		// Call the function specialized for vector<string>.
		isSuccessful = ManageMpPreference(customMethodName.c_str(), preferenceName.c_str(), vec);
	}
	else if (funcType == L"intarray")
	{
		if (argc < 5)
		{
			// Print usage details for integer array if there are not enough arguments.
			std::wcerr << L"Usage: program.exe intarray <customMethodName> <preferenceName> <value1> [value2] ..." << std::endl;
			return 1;
		}
		// Create a vector to hold the integer array from the command line.
		std::vector<int> vec;
		for (int i = 4; i < argc; i++)
		{
			vec.push_back(_wtoi(argv[i]));
		}
		// Call the function specialized for vector<int>.
		isSuccessful = ManageMpPreference(customMethodName.c_str(), preferenceName.c_str(), vec);
	}
	else
	{
		// Notify the user about valid function types.
		std::wcerr << L"Invalid function type. Use one of: bool, int, string, stringarray, intarray." << std::endl;
		return 1;
	}

	// Output a success message if the operation succeeded.
	if (isSuccessful)
		std::wcout << L"Preference was set successfully via command line." << std::endl;
	else
		std::wcerr << L"Failed to set preference via command line." << std::endl;

	// Exit the program with a success or failure code.
	return isSuccessful ? 0 : 1;

	/* Example usage:
		// Usage for a boolean property.
		if (ManageMpPreference(L"Set", L"BruteForceProtectionLocalNetworkBlocking", true))
		{
			wcout << L"Boolean preference was set successfully." << endl;
		}
		else
		{
			wcout << L"Failed to set boolean preference." << endl;
		}

		// Usage for an integer property.
		if (ManageMpPreference(L"Set", L"SchedulerRandomizationTime", 42))
		{
			wcout << L"Integer preference was set successfully." << endl;
		}
		else
		{
			wcout << L"Failed to set integer preference." << endl;
		}

		// Usage for a string property.
		if (ManageMpPreference(L"Set", L"SomeStringProperty", L"ExampleValue"))
		{
			wcout << L"String preference was set successfully." << endl;
		}
		else
		{
			wcout << L"Failed to set string preference." << endl;
		}

		// Usage for an integer array property.
		std::vector<int> intArray = { 0, 1, 1, 1, 1, 6, 1 };
		if (ManageMpPreference(L"Set", L"SomeIntArrayProperty", intArray))
		{
			wcout << L"Integer array preference was set successfully." << endl;
		}
		else
		{
			wcout << L"Failed to set integer array preference." << endl;
		}

		// Usage for a string array property.
		std::vector<std::wstring> stringArray = { L"Some", L"Big", L"Program" };
		if (ManageMpPreference(L"Add", L"AttackSurfaceReductionOnlyExclusions", stringArray))
		{
			wcout << L"String array preference was set successfully." << endl;
		}
		else
		{
			wcout << L"Failed to set string array preference." << endl;
		}
	*/
}

/*

To use it as a Library in C# WinUI3 Packaged App


// Import the function to set DLL mode. When set to true,
// the native library will skip COM initialization/security,
// since these are already done in a packaged WinUI3 app.
[DllImport("DefenderPrefDLL.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
static extern void SetDllMode(bool skipInit);

// Importing the exported function for bool preference
[DllImport("DefenderPrefDLL.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
static extern bool ManageMpPreferenceBool(string customMethodName, string preferenceName, bool preferenceValue);

// Importing the exported function for int preference
[DllImport("DefenderPrefDLL.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
static extern bool ManageMpPreferenceInt(string customMethodName, string preferenceName, int preferenceValue);

// Importing the exported function for string preference
[DllImport("DefenderPrefDLL.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
static extern bool ManageMpPreferenceString(string customMethodName, string preferenceName, string preferenceValue);

// Importing the exported function for string array preference
[DllImport("DefenderPrefDLL.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
static extern bool ManageMpPreferenceStringArray(string customMethodName, string preferenceName, [In] string[] preferenceArray, int arraySize);

// Importing the exported function for int array preference
[DllImport("DefenderPrefDLL.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
static extern bool ManageMpPreferenceIntArray(string customMethodName, string preferenceName, [In] int[] preferenceArray, int arraySize);

// Import the exported function to get the last error message.
[DllImport("DefenderPrefDLL.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
static extern IntPtr GetLastErrorMessage();

// Importing the exported function for getting MSFT_MpPreference results
[DllImport("DefenderPrefDLL.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
static extern bool GetMpPreference(string preferenceName);

// Importing the exported function for getting MSFT_MpComputerStatus results
[DllImport("DefenderPrefDLL.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
static extern bool GetMpComputerStatus(string preferenceName);

// Importing the exported function for getting WMI results from any supported source
[DllImport("DefenderPrefDLL.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
static extern bool GetWmiData(int sourceId, string preferenceName);

// Tell the DLL to skip COM initialization.
SetDllMode(true);

// Example: Setting a boolean preference using MSFT_MpPreference
bool boolResult = ManageMpPreferenceBool("Set", "BruteForceProtectionLocalNetworkBlocking", true);

if (!boolResult)
{
	string? error = Marshal.PtrToStringUni(GetLastErrorMessage());
	Console.WriteLine("Error setting Boolean preference: " + error);
}
else
{
	Console.WriteLine("Boolean preference set successfully.");
}

// Example: Getting data from MSFT_MpPreference (sourceId = 0)
bool mpPrefResult = GetWmiData(0, "AntivirusEnabled");
if (!mpPrefResult)
{
	string? error = Marshal.PtrToStringUni(GetLastErrorMessage());
	Console.WriteLine("Error getting MSFT_MpPreference data: " + error);
}

// Example: Getting data from MSFT_MpComputerStatus (sourceId = 1)
bool mpStatusResult = GetWmiData(1, "AMServiceEnabled");
if (!mpStatusResult)
{
	string? error = Marshal.PtrToStringUni(GetLastErrorMessage());
	Console.WriteLine("Error getting MSFT_MpComputerStatus data: " + error);
}

// Alternative methods for getting specific data sources:
// For MSFT_MpPreference only
bool prefResult = GetMpPreference("AntivirusEnabled");

// For MSFT_MpComputerStatus only
bool statusResult = GetMpComputerStatus("AMServiceEnabled");

*/
