#include "Globals.h"
#include "Firewall/FirewallManager.h"
#include "StringUtilities.h"
#include "ComHelpers.h"
#include "BitLocker/BitLockerManager.h"
#include "BitLocker/BitLockerRemoveKeyProtector.h"
#include "BitLocker/BitLockerEnableKeyProtectors.h"
#include "BitLocker/BitLockerEnableAutoUnlock.h"
#include "BitLocker/BitLockerEnable.h"
#include "BitLocker/BitLockerDisable.h"

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "winhttp.lib")

// Bringing the std namespace into scope to avoid prefixing with std::
// std (aka Standard Library is C++ equivalent of System; namespace in C#)
// wcout is used for normal output(typically goes to stdout)
// wcerr is used for error output (goes to stderr).
using namespace std;

using namespace BitLocker;
using namespace Firewall;

// Exported function to allow setting the DLL mode from external callers (e.g. C# via DllImport).
extern "C" __declspec(dllexport) void __stdcall SetDllMode(bool skipInit)
{
	g_skipCOMInit = skipInit;
}

// Exported function to retrieve the last error message using a pointer to its wide string representation.
// The pointer is valid until the next call to any function in this DLL.
extern "C" __declspec(dllexport) const wchar_t* __stdcall GetLastErrorMessage()
{
	lock_guard<mutex> lock(g_errorMutex);
	return g_lastErrorMsg.c_str();
}

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

		return isSuccessful ? 0 : 1;
	}
	else if (argc >= 2 && wstring(argv[1]) == L"firewall")
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

	// Command for BitLocker management.
	//   ComManager.exe bitlocker addpass C: MyPassPhrase123
	//   ComManager.exe bitlocker addrecovery C: - (auto-generate recovery password)
	//   ComManager.exe bitlocker addrecovery C: 111111-111111-111111-111111-111111-111111-111111-111111
	//   ComManager.exe bitlocker addtpm C:
	//   ComManager.exe bitlocker addtpm+pin C: 123456
	//   ComManager.exe bitlocker addtpm+startup C: D:\\Keys
	//   ComManager.exe bitlocker addtpm+pin+startup C: D:\\Keys 123456
	//   ComManager.exe bitlocker addstartupkey C: D:\\Keys
	//   ComManager.exe bitlocker addsid C: S-1-5-21-1234567890-123456789-123456789-1001 false
	//   ComManager.exe bitlocker removekp C: {KeyProtectorID} true
	//   ComManager.exe bitlocker enablekps C:
	//   ComManager.exe bitlocker enableautounlock C:   (Enable Auto-Unlock on a non-OS volume)
	//   ComManager.exe bitlocker enableos <DriveLetter> <normal|enhanced> <PIN> <StartupKeyPathOrDash> <FreePlusUsedSpace true/false> <AllowDowngrade true/false>
	//   ComManager.exe bitlocker enablefixed <DriveLetter> <FreePlusUsedSpace true/false>
	//   ComManager.exe bitlocker enableremovable <DriveLetter> <Password> <FreePlusUsedSpace true/false>
	//   ComManager.exe bitlocker disable <DriveLetter>   (Start decryption of a volume)
	else if (argc >= 2 && wstring(argv[1]) == L"bitlocker")
	{
		if (argc < 3)
		{
			wcerr << L"Usage:" << endl;
			wcerr << L"  ComManager.exe bitlocker <action> [parameters]" << endl;
			wcerr << L"  Actions:" << endl;
			wcerr << L"    addpass <DriveLetter> <PassPhrase>" << endl;
			wcerr << L"    addrecovery <DriveLetter> <RecoveryPasswordOrDashForAuto>" << endl;
			wcerr << L"    addtpm <DriveLetter>" << endl;
			wcerr << L"    addtpm+pin <DriveLetter> <PIN>" << endl;
			wcerr << L"    addtpm+startup <DriveLetter> <StartupKeyPath>" << endl;
			wcerr << L"    addtpm+pin+startup <DriveLetter> <StartupKeyPath> <PIN>" << endl;
			wcerr << L"    addstartupkey <DriveLetter> <StartupKeyPath>" << endl;
			wcerr << L"    addsid <DriveLetter> <SID> <ServiceAccount true/false>" << endl;
			wcerr << L"    removekp <DriveLetter> <KeyProtectorID> <NoErrorIfBound true/false>" << endl;
			wcerr << L"    enablekps <DriveLetter>            (Enable/Resume key protectors on a volume)" << endl;
			wcerr << L"    enableautounlock <DriveLetter>     (Enable Auto-Unlock on a non-OS volume)" << endl;
			wcerr << L"    enableos <DriveLetter> <normal|enhanced> <PIN> <StartupKeyPathOrDash> <FreePlusUsedSpace true/false> <AllowDowngrade true/false>" << endl;
			wcerr << L"    enablefixed <DriveLetter> <FreePlusUsedSpace true/false>" << endl;
			wcerr << L"    enableremovable <DriveLetter> <Password> <FreePlusUsedSpace true/false>" << endl;
			wcerr << L"    disable <DriveLetter>              (Start decryption of a volume)" << endl;
			wcerr << L"    info <DriveLetter>                (Print JSON info for a single volume, e.g. C: )" << endl;
			wcerr << L"    list [all|nonos|removable]        (List volumes with BitLocker info as JSON array)" << endl;
			return 1;
		}

		wstring action = argv[2];

		auto printErrorAndReturn = []() -> int
			{
				wcerr << L"Invalid arguments for bitlocker action." << endl;
				return 1;
			};

		bool ok = false;

		if (EqualsOrdinalIgnoreCase(action.c_str(), L"addpass"))
		{
			if (argc != 5) return printErrorAndReturn();
			ok = AddPasswordProtector(argv[3], argv[4]);
		}
		else if (EqualsOrdinalIgnoreCase(action.c_str(), L"addrecovery"))
		{
			if (argc != 5) return printErrorAndReturn();
			// If "-" treat it as null (auto-generate)
			const wchar_t* pw = argv[4];
			if (EqualsOrdinalIgnoreCase(pw, L"-")) pw = nullptr;
			ok = AddRecoveryPassword(argv[3], pw);
		}
		else if (EqualsOrdinalIgnoreCase(action.c_str(), L"addtpm"))
		{
			if (argc != 4) return printErrorAndReturn();
			ok = AddTpmProtector(argv[3]);
		}
		else if (EqualsOrdinalIgnoreCase(action.c_str(), L"addtpm+pin"))
		{
			if (argc != 5) return printErrorAndReturn();
			ok = AddTpmAndPinProtector(argv[3], argv[4]);
		}
		else if (EqualsOrdinalIgnoreCase(action.c_str(), L"addtpm+startup"))
		{
			if (argc != 5) return printErrorAndReturn();
			ok = AddTpmAndStartupKeyProtector(argv[3], argv[4]);
		}
		else if (EqualsOrdinalIgnoreCase(action.c_str(), L"addtpm+pin+startup"))
		{
			if (argc != 6) return printErrorAndReturn();
			ok = AddTpmAndPinAndStartupKeyProtector(argv[3], argv[4], argv[5]);
		}
		else if (EqualsOrdinalIgnoreCase(action.c_str(), L"addstartupkey"))
		{
			if (argc != 5) return printErrorAndReturn();
			ok = AddStartupKeyProtector_OR_RecoveryKeyProtector(argv[3], argv[4]);
		}
		else if (EqualsOrdinalIgnoreCase(action.c_str(), L"addsid"))
		{
			if (argc != 6) return printErrorAndReturn();
			bool serviceAccount = (EqualsOrdinalIgnoreCase(argv[5], L"true") || EqualsOrdinalIgnoreCase(argv[5], L"1"));
			ok = AddSidProtector(argv[3], argv[4], serviceAccount);
		}
		else if (EqualsOrdinalIgnoreCase(action.c_str(), L"enableos"))
		{
			// enableos <DriveLetter> <normal|enhanced> <PIN> <StartupKeyPathOrDash> <FreePlusUsedSpace true/false> <AllowDowngrade true/false>
			if (argc != 10) return printErrorAndReturn();
			const wchar_t* driveLetter = argv[3];

			// Encryption type
			OSEncryptionType encType;
			if (EqualsOrdinalIgnoreCase(argv[4], L"normal"))
				encType = OSEncryptionType::Normal;
			else if (EqualsOrdinalIgnoreCase(argv[4], L"enhanced"))
				encType = OSEncryptionType::Enhanced;
			else
			{
				wcerr << L"Encryption type must be normal or enhanced." << endl;
				return 1;
			}

			const wchar_t* pin = argv[5];
			if (EqualsOrdinalIgnoreCase(pin, L"-")) pin = nullptr; // allow explicit dash to mean "no PIN" (will still fail later if required)

			const wchar_t* startupKeyPath = argv[6];
			if (EqualsOrdinalIgnoreCase(startupKeyPath, L"-")) startupKeyPath = nullptr;

			bool freePlusUsed = (EqualsOrdinalIgnoreCase(argv[7], L"true") || EqualsOrdinalIgnoreCase(argv[7], L"1"));
			bool allowDowngrade = (EqualsOrdinalIgnoreCase(argv[8], L"true") || EqualsOrdinalIgnoreCase(argv[8], L"1"));
			bool parsedAllowDowngrade = allowDowngrade; // clarity

			ok = EnableOsDrive(driveLetter, encType, pin, startupKeyPath, freePlusUsed, parsedAllowDowngrade);
		}
		else if (EqualsOrdinalIgnoreCase(action.c_str(), L"enablefixed"))
		{
			// enablefixed <DriveLetter> <FreePlusUsedSpace true/false>
			if (argc != 6) return printErrorAndReturn();
			bool freePlusUsed = (EqualsOrdinalIgnoreCase(argv[5], L"true") || EqualsOrdinalIgnoreCase(argv[5], L"1"));
			ok = EnableFixedDrive(argv[3], freePlusUsed);
		}
		else if (EqualsOrdinalIgnoreCase(action.c_str(), L"enableremovable"))
		{
			// enableremovable <DriveLetter> <Password> <FreePlusUsedSpace true/false>
			if (argc != 7) return printErrorAndReturn();
			const wchar_t* password = argv[4];
			bool freePlusUsed = (EqualsOrdinalIgnoreCase(argv[5], L"true") || EqualsOrdinalIgnoreCase(argv[5], L"1"));
			ok = EnableRemovableDrive(argv[3], password, freePlusUsed);
		}
		else if (EqualsOrdinalIgnoreCase(action.c_str(), L"info"))
		{
			if (argc != 4) return printErrorAndReturn();
			VolumeInfo vi;
			ok = GetVolumeInfo(argv[3], vi) && PrintVolumeInfoJson(vi);
			if (!ok)
			{
				wcerr << L"Failed to retrieve volume info. Error: " << GetLastErrorMessage() << endl;
				return 1;
			}
			wcout << endl;
			return 0;
		}
		else if (EqualsOrdinalIgnoreCase(action.c_str(), L"list"))
		{
			bool onlyNonOS = false;
			bool onlyRemovable = false;
			if (argc == 4)
			{
				if (EqualsOrdinalIgnoreCase(argv[3], L"nonos"))
					onlyNonOS = true;
				else if (EqualsOrdinalIgnoreCase(argv[3], L"removable"))
					onlyRemovable = true;
				else if (!EqualsOrdinalIgnoreCase(argv[3], L"all"))
				{
					wcerr << L"Invalid list option. Use one of: all | nonos | removable" << endl;
					return 1;
				}
			}
			else if (argc != 3)
			{
				return printErrorAndReturn();
			}

			vector<VolumeInfo> vols;
			if (!ListAllVolumes(vols, onlyNonOS, onlyRemovable))
			{
				wcerr << L"Failed to enumerate volumes. Error: " << GetLastErrorMessage() << endl;
				return 1;
			}
			(void)PrintVolumeListJson(vols);
			wcout << endl;
			return 0;
		}
		else if (EqualsOrdinalIgnoreCase(action.c_str(), L"removekp"))
		{
			if (argc != 6) return printErrorAndReturn();
			bool noErrorIfBound = (EqualsOrdinalIgnoreCase(argv[5], L"true") || EqualsOrdinalIgnoreCase(argv[5], L"1"));
			ok = RemoveKeyProtector(argv[3], argv[4], noErrorIfBound);
		}
		else if (EqualsOrdinalIgnoreCase(action.c_str(), L"enablekps"))
		{
			if (argc != 4) return printErrorAndReturn();
			ok = EnableKeyProtectors(argv[3]);
		}
		else if (EqualsOrdinalIgnoreCase(action.c_str(), L"enableautounlock"))
		{
			// Enable Auto-Unlock on a non-OS volume
			if (argc != 4) return printErrorAndReturn();
			ok = EnableAutoUnlock(argv[3]);
		}
		else if (EqualsOrdinalIgnoreCase(action.c_str(), L"disable"))
		{
			// disable <DriveLetter>
			if (argc != 4) return printErrorAndReturn();
			ok = DisableDrive(argv[3]);
		}
		else
		{
			wcerr << L"Invalid bitlocker action specified." << endl;
			return 1;
		}

		if (ok)
		{
			wcout << L"BitLocker operation completed successfully." << endl;
			return 0;
		}
		else
		{
			wcerr << L"BitLocker operation failed. Error: " << GetLastErrorMessage() << endl;
			return 1;
		}
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
