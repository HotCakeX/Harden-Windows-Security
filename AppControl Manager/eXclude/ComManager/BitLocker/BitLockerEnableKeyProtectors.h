#pragma once
#include <string>

namespace BitLocker {
	[[nodiscard]] bool EnableKeyProtectors(const wchar_t* driveLetter);
}
