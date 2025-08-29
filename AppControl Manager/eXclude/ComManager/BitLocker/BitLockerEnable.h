#pragma once
#include <string>
#include "BitLockerManager.h"
#include "BitLockerEnableKeyProtectors.h"
#include "BitLockerEnableAutoUnlock.h"
#include "BitLockerRemoveKeyProtector.h"
#include "..\ComHelpers.h"

namespace BitLocker {

	// Encryption types of the OS Drive supported by the Harden System Security App
	enum class OSEncryptionType : unsigned long
	{
		Normal = 0,
		Enhanced = 1
	};

	[[nodiscard]] bool EnableOsDrive(const wchar_t* driveLetter,
		OSEncryptionType type,
		const wchar_t* pin,
		const wchar_t* startupKeyPath,
		bool freePlusUsedSpace,
		bool allowDowngradeEnhancedToNormal);

	[[nodiscard]] bool EnableFixedDrive(const wchar_t* driveLetter, bool freePlusUsedSpace);

	[[nodiscard]] bool EnableRemovableDrive(const wchar_t* driveLetter, const wchar_t* password, bool freePlusUsedSpace);
}
