#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include "../Globals.h"
#include "../StringUtilities.h"
#include "../ComHelpers.h"

namespace NetworkProfiles
{
	// Returns true if every MSFT_NetConnectionProfile has NetworkCategory == 0 (Public) OR no profiles exist.
	// Returns false if any profile has a different NetworkCategory OR if an error occurs.
	extern "C" __declspec(dllexport) bool __stdcall NET_AreAllNetworkLocationsPublic();

	// Parameter 'category' must be 0 or 1.
	// 2 (DomainAuthenticated) is rejected (cannot be set manually; assigned automatically by NLA).
	// Sets NetworkCategory on ALL MSFT_NetConnectionProfile instances to the requested value.
	// Returns true if update succeeded for all profiles (or none found), false if any failure (error set).
	// Uses full instance re-fetch (GetObject) before PutInstance to avoid WBEM_E_INVALID_OBJECT on projected objects.
	extern "C" __declspec(dllexport) bool __stdcall NET_SetAllNetworkLocationsCategory(int category);
}
