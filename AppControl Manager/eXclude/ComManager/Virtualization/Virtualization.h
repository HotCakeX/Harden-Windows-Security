#include <vector>
#include <string>

using namespace std;

namespace Virtualization {

	// Represents the selected VM information
	struct VmCpuInfo
	{
		// Msvm_ComputerSystem.ElementName
		wstring vmName;

		// -1 => null (not available), 0 => false, 1 => true
		int exposeVirtualizationExtensions = -1;

		// Version from VSSD (e.g., "12.0"); empty if unavailable.
		wstring version;

		// Virtual machine sub-type (e.g., "Generation2").
		// Best-effort mapping from VSSD.VirtualSystemSubType.
		// May be the raw subtype token if generation cannot be inferred; empty if unavailable.
		wstring virtualMachineSubType;

		// Number of virtual processors. -1 if unavailable.
		long long processorCount = -1;

		// Friendly state derived from Msvm_ComputerSystem.EnabledState (e.g., "Off", "Running", "Paused", etc.).
		// Empty if not resolvable.
		wstring state;

		// VM unique identifier (GUID) from Msvm_ComputerSystem.Name.
		// Empty if unavailable.
		wstring vmId;
	};

	// Enumerates local Hyper-V VMs and retrieves ExposeVirtualizationExtensions for each VM's processor settings.
	// On success:
	//   - Fills outList with one entry per VM.
	//   - Returns true.
	// On failure:
	//   - Returns false and sets the global last error message.
	[[nodiscard]] bool GetVmProcessorExposeVirtualizationExtensions(vector<VmCpuInfo>& outList);

	// Prints a JSON array to stdout with objects.
	// Returns true on success, false on failure (global last error is set).
	[[nodiscard]] bool PrintVmProcessorExposeVirtualizationExtensionsJson();

	// Set ExposeVirtualizationExtensions for a single VM by friendly name (OrdinalIgnoreCase).
	// Requires VM to be Off (EnabledState == 3).
	// Returns true on success; false on failure (sets last error).
	[[nodiscard]] bool SetExposeVirtualizationExtensions_ByName(const wstring& vmName, bool enable);

	// Set ExposeVirtualizationExtensions for all VMs. Requires each VM to be Off.
	// Continues on per-VM errors (logs each).
	// returns true only if all succeeded.
	// On any failure, sets the last error with a summary.
	[[nodiscard]] bool SetExposeVirtualizationExtensions_All(bool enable);
}
