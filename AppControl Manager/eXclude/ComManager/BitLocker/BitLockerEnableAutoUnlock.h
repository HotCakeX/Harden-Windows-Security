#pragma once
#include <string>

namespace BitLocker {

	[[nodiscard]] bool EnableAutoUnlock(const wchar_t* driveLetter);
}
