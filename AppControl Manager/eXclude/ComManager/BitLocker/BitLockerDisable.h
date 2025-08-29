#pragma once
#include <string>

namespace BitLocker {
	[[nodiscard]] bool DisableDrive(const wchar_t* driveLetter);
}
