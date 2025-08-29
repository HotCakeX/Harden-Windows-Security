#pragma once
#include <string>

namespace BitLocker {

	// Removes a BitLocker key protector identified by its KeyProtectorID.
	// driveLetter:  Must be in the form L"C:" (two characters, second is colon).
	// keyProtectorId: The VolumeKeyProtectorID returned by BitLocker WMI (GUID-like string).
	// noErrorIfBound: If true and the key protector is bound (FVE_E_VOLUME_BOUND_ALREADY), treat as success and do not set an error.
	// Returns true on success (including benign skip conditions such as "not found" or "unsupported type").
	// Returns false on fatal errors; in that case g_lastErrorMsg is set.
	[[nodiscard]] bool RemoveKeyProtector(const wchar_t* driveLetter, const wchar_t* keyProtectorId, bool noErrorIfBound);

}
