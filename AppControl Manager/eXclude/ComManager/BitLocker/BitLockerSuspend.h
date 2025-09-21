#pragma once
#include <string>

namespace BitLocker {

    // Suspends (disables) the key protectors on a BitLocker volume.
    // driveLetter: Must be in the form L"C:".
    // rebootCount: -1 means use WMI default (omit DisableCount); otherwise 0..15 specifies how many reboots
    // before protection auto‑resumes.
    // Returns true on success, false on failure (g_lastErrorMsg set).
    [[nodiscard]] bool SuspendKeyProtectors(const wchar_t* driveLetter, int rebootCount /* -1 => default */);
}