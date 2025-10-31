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
#include "BitLocker/BitLockerSuspend.h"
#include "ScheduledTasks/ScheduledTasks.h"
#include "Virtualization/Virtualization.h"

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "winhttp.lib")

// Bringing the std namespace into scope to avoid prefixing with std::
// std (aka Standard Library is C++ equivalent of System; namespace in C#)
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

// Helper: case-insensitive equality wrapper (keeps consistency / readability)
static inline bool IsEq(const wchar_t* a, const wchar_t* b)
{
	return EqualsOrdinalIgnoreCase(a, b);
}

// Boolean parser
// Accepts only: true/false/1/0 (case-insensitive).
// Returns false on unrecognized token.
static bool TryParseBool(const wchar_t* token, bool& outVal)
{
	if (!token) return false;
	if (IsEq(token, L"true") || IsEq(token, L"1"))
	{
		outVal = true;
		return true;
	}
	if (IsEq(token, L"false") || IsEq(token, L"0"))
	{
		outVal = false;
		return true;
	}
	return false;
}

// Overload for wstring
static bool TryParseBool(const wstring& token, bool& outVal)
{
	return TryParseBool(token.c_str(), outVal);
}

// For command line support.
// First detect the Primary Command. All string comparisons must remain case-insensitive.
// Return code 2 used for all invalid args errors.
int wmain(int argc, wchar_t* argv[])
{
	if (argc < 2)
	{
		// No primary command provided -> syntax error.
		return 2;
	}

	// Primary command candidate (argv[1]).
	wstring primary = argv[1];

	// Primary: ScheduledTasks
	if (EqualsOrdinalIgnoreCase(primary.c_str(), L"scheduledtasks"))
	{
		// We want to hand off processing of the rest of the command line to the
		// ScheduledTasks::RunScheduledTasksCommand function.
		//
		// That function expects its own (argc, argv) pair that looks like a "normal" program invocation
		// where argv[0] is the executable name and argv[1]..argv[n-1] are only the
		// parameters intended for the scheduled tasks subsystem (i.e. it should
		// NOT see the primary command token "scheduledtasks" itself).
		// So effectively we "remove" argv[1] from the view passed to the scheduled
		// tasks handler.

		int newArgc = 1 + (argc - 2 < 0 ? 0 : (argc - 2));

		// A vector to hold the adjusted argument pointer list.
		// We only copy pointers (no deep string copies) because the lifetime of
		// the original argv strings covers the duration of this call (we return
		// immediately after the subcommand finishes). This avoids extra allocations.
		vector<wchar_t*> adjusted;
		adjusted.reserve(static_cast<size_t>(newArgc)); // Reserve exact capacity to avoid reallocations.

		// First element: keep the original program name.
		adjusted.push_back(argv[0]);

		// Append all arguments after the primary command token.
		// That is, skip index 1 ("scheduledtasks") and push argv[2] ... argv[argc-1].
		for (int i = 2; i < argc; ++i)
		{
			adjusted.push_back(argv[i]);
		}
		int rc = ScheduledTasks::RunScheduledTasksCommand(newArgc, adjusted.data());

		// Whatever exit/status code that subcommand returns we propagate directly
		// as the overall process exit code for this primary path.
		return rc;
	}

	// Primary: GetAvailability
	if (EqualsOrdinalIgnoreCase(primary.c_str(), L"getavailability"))
	{
		// Must have exactly 5 arguments.
		if (argc != 5)
		{
			return 2;
		}

		const wchar_t* wmiNamespace = argv[2];
		const wchar_t* wmiClassName = argv[3];
		const wchar_t* propertyName = argv[4];

		// Validate non-empty (not just whitespace).
		auto isBlank = [](const wchar_t* s) -> bool
			{
				if (!s || *s == L'\0') return true;
				wstring tmp(s);
				return tmp.find_first_not_of(L" \t\n\r") == wstring::npos;
			};
		if (isBlank(wmiNamespace) || isBlank(wmiClassName) || isBlank(propertyName))
		{
			return 2;
		}

		// Perform the existence check.
		bool exists = DoesWmiPropertyExist(wmiNamespace, wmiClassName, propertyName);

		// If an error was recorded, return failure (per requirement to error on invalid ns/class).
		const wchar_t* err = GetLastErrorMessage();
		if (!exists && err && *err)
		{
			LogErr(L"Failed to check property availability. Error: ", err);
			return 1;
		}

		// Successful check: print boolean token (lowercase).
		LogOut(exists ? L"true" : L"false");
		return 0;
	}

	// Primary: GET
	if (EqualsOrdinalIgnoreCase(primary.c_str(), L"get"))
	{
		// Accept either 4 or 5 total arguments.
		if (argc != 4 && argc != 5)
		{
			return 2;
		}

		const wchar_t* wmiNamespace = argv[2];
		const wchar_t* wmiClassName = argv[3];
		const wchar_t* propertyName = (argc == 5) ? argv[4] : nullptr;

		// Validate non-empty (not just whitespace)
		auto isBlank = [](const wchar_t* s) -> bool
			{
				if (!s || *s == L'\0') return true;
				wstring tmp(s);
				return tmp.find_first_not_of(L" \t\n\r") == wstring::npos;
			};
		if (isBlank(wmiNamespace) || isBlank(wmiClassName) || (propertyName && isBlank(propertyName)))
		{
			return 2;
		}

		bool ok = false;
		if (propertyName)
			ok = GetWmiValue(wmiNamespace, wmiClassName, propertyName);
		else
			ok = GetAllWmiProperties(wmiNamespace, wmiClassName);

		if (!ok)
		{
			const wchar_t* err = GetLastErrorMessage();
			if (err && *err)
				LogErr(L"Failed to retrieve WMI data. Error: ", err);
			else
				LogErr(L"Failed to retrieve WMI data.");
			return 1;
		}
		return 0;
	}

	// Primary: DO
	if (EqualsOrdinalIgnoreCase(primary.c_str(), L"do"))
	{
		// Exactly 5 arguments expected.
		if (argc != 5)
		{
			return 2;
		}

		const wchar_t* wmiNamespace = argv[2];
		const wchar_t* wmiClassName = argv[3];
		const wchar_t* methodName = argv[4];

		// Validate non-empty (not just whitespace).
		auto isBlank = [](const wchar_t* s) -> bool
			{
				if (!s || *s == L'\0') return true;
				wstring tmp(s);
				return tmp.find_first_not_of(L" \t\n\r") == wstring::npos;
			};
		if (isBlank(wmiNamespace) || isBlank(wmiClassName) || isBlank(methodName))
		{
			return 2;
		}

		const bool ok = ExecuteWmiClassMethodNoParams(wmiNamespace, wmiClassName, methodName);
		if (!ok)
		{
			const wchar_t* err = GetLastErrorMessage();
			if (err && *err)
				LogErr(L"Failed to execute WMI method. Error: ", err);
			else
				LogErr(L"Failed to execute WMI method.");
			return 1;
		}
		return 0;
	}

	// Primary: FIREWALL
	if (EqualsOrdinalIgnoreCase(primary.c_str(), L"firewall"))
	{
		// Must have exactly these parameters.
		if (argc != 5)
		{
			return 2;
		}

		const wchar_t* displayName = argv[2];
		const wchar_t* downloadURL = argv[3];
		const wchar_t* boolToken = argv[4];

		if (!displayName || *displayName == L'\0')
		{
			// Missing mandatory displayName.
			return 2;
		}

		bool toAdd = false;
		if (!TryParseBool(boolToken, toAdd))
		{
			return 2; // invalid boolean token
		}

		// If adding, URL must be non-empty
		if (toAdd)
		{
			if (!downloadURL || *downloadURL == L'\0')
			{
				return 2;
			}
		}

		const wchar_t* urlToUse = (toAdd && downloadURL && *downloadURL != L'\0') ? downloadURL : nullptr;
		bool result = FW_BlockIPAddressListsInGroupPolicy(displayName, urlToUse, toAdd);

		if (!result)
		{
			LogErr(L"Failed to manage firewall rules. Error: ", GetLastErrorMessage());
			return 1;
		}

		if (toAdd)
			LogOut(L"Successfully created firewall rules for: ", displayName);
		else
			LogOut(L"Successfully removed firewall rules for: ", displayName);

		return 0;
	}

	// Primary: BITLOCKER
	if (EqualsOrdinalIgnoreCase(primary.c_str(), L"bitlocker"))
	{
		if (argc < 3)
		{
			return 2;
		}

		wstring action = argv[2];
		bool ok = false;

		// Helper: return syntax error uniformly
		auto syntaxError = []() -> int { return 2; };

		if (IsEq(action.c_str(), L"addpass"))
		{
			if (argc != 5) return syntaxError();
			ok = AddPasswordProtector(argv[3], argv[4]);
		}
		else if (IsEq(action.c_str(), L"addrecovery"))
		{
			if (argc != 5) return syntaxError();
			const wchar_t* pw = argv[4];
			if (IsEq(pw, L"-")) pw = nullptr;
			ok = AddRecoveryPassword(argv[3], pw);
		}
		else if (IsEq(action.c_str(), L"addtpm"))
		{
			if (argc != 4) return syntaxError();
			ok = AddTpmProtector(argv[3]);
		}
		else if (IsEq(action.c_str(), L"addtpm+pin"))
		{
			if (argc != 5) return syntaxError();
			ok = AddTpmAndPinProtector(argv[3], argv[4]);
		}
		else if (IsEq(action.c_str(), L"addtpm+startup"))
		{
			if (argc != 5) return syntaxError();
			ok = AddTpmAndStartupKeyProtector(argv[3], argv[4]);
		}
		else if (IsEq(action.c_str(), L"addtpm+pin+startup"))
		{
			if (argc != 6) return syntaxError();
			ok = AddTpmAndPinAndStartupKeyProtector(argv[3], argv[4], argv[5]);
		}
		else if (IsEq(action.c_str(), L"addstartupkey"))
		{
			if (argc != 5) return syntaxError();
			ok = AddStartupKeyProtector_OR_RecoveryKeyProtector(argv[3], argv[4]);
		}
		else if (IsEq(action.c_str(), L"addsid"))
		{
			if (argc != 6) return syntaxError();
			bool serviceAccount = false;
			if (!TryParseBool(argv[5], serviceAccount))
				return syntaxError();
			ok = AddSidProtector(argv[3], argv[4], serviceAccount);
		}
		else if (IsEq(action.c_str(), L"enableos"))
		{
			// enableos <DriveLetter> <normal|enhanced> <PIN> <StartupKeyPathOrDash> <FreePlusUsedSpace true/false> <AllowDowngrade true/false>
			if (argc != 9) return syntaxError();

			const wchar_t* driveLetter = argv[3];

			OSEncryptionType encType;
			if (IsEq(argv[4], L"normal"))
				encType = OSEncryptionType::Normal;
			else if (IsEq(argv[4], L"enhanced"))
				encType = OSEncryptionType::Enhanced;
			else
			{
				LogErr(L"Encryption type must be normal or enhanced.");
				return 2;
			}

			const wchar_t* pin = argv[5];
			const wchar_t* startupKeyPath = argv[6];
			if (IsEq(startupKeyPath, L"-")) startupKeyPath = nullptr;

			bool freePlusUsed = false;
			bool allowDowngrade = false;
			if (!TryParseBool(argv[7], freePlusUsed) || !TryParseBool(argv[8], allowDowngrade))
				return syntaxError();

			ok = EnableOsDrive(driveLetter, encType, pin, startupKeyPath, freePlusUsed, allowDowngrade);
		}
		else if (IsEq(action.c_str(), L"enablefixed"))
		{
			// enablefixed <DriveLetter> <FreePlusUsedSpace true/false>
			if (argc != 5) return syntaxError();
			bool freePlusUsed = false;
			if (!TryParseBool(argv[4], freePlusUsed))
				return syntaxError();
			ok = EnableFixedDrive(argv[3], freePlusUsed);
		}
		else if (IsEq(action.c_str(), L"enableremovable"))
		{
			// enableremovable <DriveLetter> <Password> <FreePlusUsedSpace true/false>
			if (argc != 6) return syntaxError();
			bool freePlusUsed = false;
			if (!TryParseBool(argv[5], freePlusUsed))
				return syntaxError();
			const wchar_t* password = argv[4];
			ok = EnableRemovableDrive(argv[3], password, freePlusUsed);
		}
		else if (IsEq(action.c_str(), L"info"))
		{
			if (argc != 4) return syntaxError();
			VolumeInfo vi;
			ok = GetVolumeInfo(argv[3], vi) && PrintVolumeInfoJson(vi);
			if (!ok)
			{
				LogErr(L"Failed to retrieve volume info. Error: ", GetLastErrorMessage());
				return 1;
			}
			LogOut(L"");
			return 0;
		}
		else if (IsEq(action.c_str(), L"list"))
		{
			bool onlyNonOS = false;
			bool onlyRemovable = false;

			if (argc == 4)
			{
				if (IsEq(argv[3], L"nonos"))
					onlyNonOS = true;
				else if (IsEq(argv[3], L"removable"))
					onlyRemovable = true;
				else if (!IsEq(argv[3], L"all"))
				{
					return 2;
				}
			}
			else if (argc != 3)
			{
				return 2;
			}

			vector<VolumeInfo> vols;
			if (!ListAllVolumes(vols, onlyNonOS, onlyRemovable))
			{
				LogErr(L"Failed to enumerate volumes. Error: ", GetLastErrorMessage());
				return 1;
			}
			(void)PrintVolumeListJson(vols);
			LogOut(L"");
			return 0;
		}
		else if (IsEq(action.c_str(), L"removekp"))
		{
			if (argc != 6) return syntaxError();
			bool noErrorIfBound = false;
			if (!TryParseBool(argv[5], noErrorIfBound))
				return syntaxError();
			ok = RemoveKeyProtector(argv[3], argv[4], noErrorIfBound);
		}
		else if (IsEq(action.c_str(), L"enablekps"))
		{
			if (argc != 4) return syntaxError();
			ok = EnableKeyProtectors(argv[3]);
		}
		else if (IsEq(action.c_str(), L"enableautounlock"))
		{
			if (argc != 4) return syntaxError();
			ok = EnableAutoUnlock(argv[3]);
		}
		else if (IsEq(action.c_str(), L"disable"))
		{
			if (argc != 4) return syntaxError();
			ok = DisableDrive(argv[3]);
		}
		else if (IsEq(action.c_str(), L"suspend"))
		{
			if (argc != 4 && argc != 5) return syntaxError();
			int rebootCount = -1;
			if (argc == 5 && !IsEq(argv[4], L"-"))
			{
				// Strict numeric validation: ensure all chars are digits
				const wchar_t* rc = argv[4];
				bool allDigits = true;
				for (const wchar_t* p = rc; *p; ++p)
				{
					if (*p < L'0' || *p > L'9')
					{
						allDigits = false;
						break;
					}
				}
				if (!allDigits)
					return syntaxError();

				rebootCount = _wtoi(rc);
				if (rebootCount < 0 || rebootCount > 15)
				{
					LogErr(L"RebootCount must be between 0 and 15, or '-' for default.");
					return 2;
				}
			}
			ok = SuspendKeyProtectors(argv[3], rebootCount);
		}
		else
		{
			// Unknown bitlocker action
			return 2;
		}

		if (ok)
		{
			LogOut(L"BitLocker operation completed successfully.");
			return 0;
		}
		else
		{
			LogErr(L"BitLocker operation failed. Error: ", GetLastErrorMessage());
			return 1;
		}
	}

	// Primary: WMI
	if (EqualsOrdinalIgnoreCase(primary.c_str(), L"wmi"))
	{
		// Must have at least: program wmi type ns class method preference value  => argc >= 8
		if (argc < 8)
		{
			return 2;
		}

		// Verify that the required command line arguments (through preference name) are not empty or only whitespace.
		// Indices validated: 1 (wmi), 2 (type), 3 (namespace), 4 (class), 5 (method), 6 (preference)
		for (int i = 1; i <= 6; i++)
		{
			wstring arg(argv[i]);
			if (arg.find_first_not_of(L" \t\n\r") == wstring::npos)
			{
				return 2;
			}
		}

		wstring funcType = argv[2];
		wstring wmiNamespace = argv[3];
		wstring wmiClassName = argv[4];
		wstring customMethodName = argv[5];
		wstring preferenceName = argv[6];

		bool isSuccessful = false;

		if (IsEq(funcType.c_str(), L"bool"))
		{
			// Expect exactly one value argument.
			if (argc != 8)
			{
				return 2;
			}
			wstring value = argv[7];
			bool boolValue = false;
			if (!TryParseBool(value, boolValue))
			{
				return 2;
			}
			isSuccessful = ManageWmiPreference(wmiNamespace.c_str(), wmiClassName.c_str(), customMethodName.c_str(), preferenceName.c_str(), boolValue);
		}
		else if (IsEq(funcType.c_str(), L"int"))
		{
			if (argc != 8)
			{
				return 2;
			}
			// Strict integer validation
			const wchar_t* intToken = argv[7];
			if (!intToken || *intToken == L'\0') return 2;
			bool allDigits = true;
			const wchar_t* pInt = intToken;
			if (*pInt == L'+' || *pInt == L'-') ++pInt; // allow sign
			if (*pInt == L'\0') allDigits = false;
			for (; *pInt; ++pInt)
			{
				if (*pInt < L'0' || *pInt > L'9')
				{
					allDigits = false;
					break;
				}
			}
			if (!allDigits) return 2;
			int intValue = _wtoi(argv[7]);
			isSuccessful = ManageWmiPreference(wmiNamespace.c_str(), wmiClassName.c_str(), customMethodName.c_str(), preferenceName.c_str(), intValue);
		}
		else if (IsEq(funcType.c_str(), L"string"))
		{
			if (argc != 8)
			{
				return 2;
			}
			isSuccessful = ManageWmiPreference(wmiNamespace.c_str(), wmiClassName.c_str(), customMethodName.c_str(), preferenceName.c_str(), wstring(argv[7]));
		}
		else if (IsEq(funcType.c_str(), L"stringarray"))
		{
			// Need at least one value -> argc >= 8 already guaranteed, so ok
			vector<wstring> vec;
			for (int i = 7; i < argc; i++)
			{
				if (argv[i] && *argv[i] != L'\0')
					vec.push_back(argv[i]);
				else
					return 2; // reject empty tokens explicitly
			}
			if (vec.empty()) return 2;
			isSuccessful = ManageWmiPreference(wmiNamespace.c_str(), wmiClassName.c_str(), customMethodName.c_str(), preferenceName.c_str(), vec);
		}
		else if (IsEq(funcType.c_str(), L"intarray"))
		{
			vector<int> vec;
			for (int i = 7; i < argc; i++)
			{
				const wchar_t* token = argv[i];
				if (!token || *token == L'\0') return 2;
				// Strict integer validation for each token
				const wchar_t* pTok = token;
				if (*pTok == L'+' || *pTok == L'-') ++pTok;
				if (*pTok == L'\0') return 2;
				for (; *pTok; ++pTok)
				{
					if (*pTok < L'0' || *pTok > L'9')
						return 2;
				}
				vec.push_back(_wtoi(token));
			}
			if (vec.empty()) return 2;
			isSuccessful = ManageWmiPreference(wmiNamespace.c_str(), wmiClassName.c_str(), customMethodName.c_str(), preferenceName.c_str(), vec);
		}
		else
		{
			// Invalid type token -> syntax error.
			return 2;
		}

		if (isSuccessful)
		{
			LogOut(L"Preference was set successfully via command line.");
			return 0;
		}
		else
		{
			LogErr(L"Failed to set preference via command line.");
			return 1;
		}
	}

	// Primary: VIRTUALIZATION
	if (EqualsOrdinalIgnoreCase(primary.c_str(), L"virtualization"))
	{
		// Syntax: ComManager.exe virtualization
		if (argc < 3)
		{
			return 2; // invalid args
		}

		wstring sub = argv[2];

		// Require explicit "list" subcommand
		if (EqualsOrdinalIgnoreCase(sub.c_str(), L"list"))
		{
			if (argc != 3)
			{
				return 2;
			}
			if (!Virtualization::PrintVmProcessorExposeVirtualizationExtensionsJson())
			{
				LogErr(L"Failed to enumerate Hyper-V VM processor settings. Error: ", GetLastErrorMessage());
				return 1;
			}
			return 0;
		}

		if (EqualsOrdinalIgnoreCase(sub.c_str(), L"ExposeVirtualizationExtensions"))
		{
			bool hasAll = false;
			bool hasName = false;
			wstring vmName;
			bool enable = false;
			bool hasEnable = false;

			for (int i = 3; i < argc; ++i)
			{
				wstring a = argv[i];

				if (EqualsOrdinalIgnoreCase(a.c_str(), L"--all"))
				{
					if (hasName) return 2; // cannot combine --all and --VMName
					hasAll = true;
					continue;
				}

				if (EqualsOrdinalIgnoreCase(a.c_str(), L"--VMName"))
				{
					if (hasAll) return 2; // cannot combine --all and --VMName
					if (i + 1 >= argc) return 2;
					vmName = argv[++i];
					if (vmName.empty()) return 2;
					hasName = true;
					continue;
				}

				if (EqualsOrdinalIgnoreCase(a.c_str(), L"--enable"))
				{
					if (i + 1 >= argc) return 2;
					bool val = false;
					if (!TryParseBool(argv[i + 1], val)) return 2;
					enable = val;
					hasEnable = true;
					++i;
					continue;
				}

				// Unknown token
				return 2;
			}

			// Validate combination
			if (!hasEnable) return 2;
			if (hasAll == hasName) return 2; // exactly one of them must be set

			bool ok = false;
			if (hasAll)
			{
				ok = Virtualization::SetExposeVirtualizationExtensions_All(enable);
			}
			else
			{
				ok = Virtualization::SetExposeVirtualizationExtensions_ByName(vmName, enable);
			}

			if (!ok)
			{
				LogErr(L"Failed to set ExposeVirtualizationExtensions. Error: ", GetLastErrorMessage());
				return 1;
			}
			return 0;
		}

		// Unknown subcommand
		return 2;
	}

	// If we reached here, the primary command is unrecognized.
	return 2;
}
