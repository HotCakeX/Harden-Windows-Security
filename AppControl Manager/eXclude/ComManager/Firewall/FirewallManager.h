#pragma once
#include <windows.h>
#include "../Globals.h"
#include "../StringUtilities.h"
#include "../ComHelpers.h"

namespace Firewall {

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

	[[nodiscard]] bool DownloadIPList(const wchar_t* url, vector<wstring>& ipList);
	[[nodiscard]] bool DeleteFirewallRulesInPolicyStore(IWbemServices* pSvc, const wchar_t* displayName);
	[[nodiscard]] bool CreateFirewallRuleInPolicyStore(IWbemServices* pSvc, const wchar_t* displayName, bool inbound, const vector<wstring>& remoteIps);
	extern "C" __declspec(dllexport) bool __stdcall FW_BlockIpListInGpo(const wchar_t* displayName, const wchar_t** ipArray, int arraySize, bool toAdd);
	extern "C" __declspec(dllexport) bool __stdcall FW_BlockIPAddressListsInGroupPolicy(const wchar_t* displayName, const wchar_t* listDownloadURL, bool toAdd);

	// Creates a rule in Group="HardenSystemSecurity" in the Local PolicyStore.
	// Performs deduplication based on DisplayName + Direction + Group before creation.
	extern "C" __declspec(dllexport) bool __stdcall FW_AddProgramFirewallRule(
		const wchar_t* displayName,
		const wchar_t* programPath,
		const wchar_t* direction,
		const wchar_t* action,
		const wchar_t* description,
		const wchar_t* policyAppId,       // Optional: can be null or empty
		const wchar_t* packageFamilyName  // Optional: can be null or empty
	);

	// Deletes firewall rules from PolicyStore=localhost by ElementName, with a DisplayName fallback.
	// This targets the same policy store used by the program's firewall rule operations / IP blocking logic.
	// Returns true if deletion succeeded (including "nothing matched"), false otherwise (error set).
	extern "C" __declspec(dllexport) bool __stdcall FW_DeleteFirewallRuleByElementName(const wchar_t* elementName);

	// Returns true if all matching rules are disabled (Enabled != 1) or none exist.
	// Returns false if any matching rule is enabled OR on error.
	extern "C" __declspec(dllexport) bool __stdcall FW_AreMdnsInboundRulesDisabled();

	// enable == true  -> set Enabled=1 (NetSecurityEnabled::True) on all matching rules.
	// enable == false -> set Enabled=2 (NetSecurityEnabled::False) on all matching rules.
	// Returns true if all modifications succeed (or none exist), false otherwise (error set).
	extern "C" __declspec(dllexport) bool __stdcall FW_SetMdnsInboundRulesEnabled(bool enable);

	// Lists firewall rules from the same PolicyStore used by this program (PolicyStore=localhost),
	// filtered down to RuleGroup="HardenSystemSecurity".
	// Output is written to stdout as a JSON array.
	// Returns true on success, false on error (error set).
	extern "C" __declspec(dllexport) bool __stdcall FW_ListProgramFirewallRulesInHardenSystemSecurityGroupJson();

	// Helper to detect transient HRESULTs worth retrying for the PutInstance operation.
	// These are known to occur under provider/RPC load and during short policy/store contention windows.
	bool IsTransientHresult(HRESULT hr);

}
