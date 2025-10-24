// MIT License
//
// Copyright (c) 2023-Present - Violet Hansen - (aka HotCakeX on GitHub) - Email Address: spynetgirl@outlook.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// See here for more information: https://github.com/HotCakeX/Harden-Windows-Security/blob/main/LICENSE
//

using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using CommonCore.DISM;

namespace DISMService;

internal static class Methods
{
	// Resource for DISM error codes.
	// https://learn.microsoft.com/windows/win32/debug/system-error-codes--1700-3999-

	[UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
	internal static void DismProgressCallbackUnmanaged(uint current, uint total, nint userData) => Program.SendProgressCallback(current, total);

	private static unsafe nint GetDismProgressCallbackPtr() => (nint)(delegate* unmanaged[Stdcall]<uint, uint, nint, void>)&DismProgressCallbackUnmanaged;

	// Exposes a precomputed unmanaged function pointer for DISM
	internal static readonly nint DismProgressCallbackPtr = GetDismProgressCallbackPtr();

	/// <summary>
	/// To store the DISM session for usage by the entire app.
	/// </summary>
	private static IntPtr CurrentDISMSession = IntPtr.Zero;

	/// <summary>
	/// Handle "item not found/not applicable" from DISM/CBS gracefully across all operations.
	/// </summary>
	private const int HRESULT_CBS_E_ITEM_NOT_FOUND = unchecked((int)0x800F080C);

	internal static unsafe bool EnableFeature(string featureName, string[]? sourcePaths = null)
	{
		// Get a new session if one doesn't already exist
		InitDISM();

		Logger.Write($"Attempting to enable feature: {featureName}", LogTypeIntel.Information);

		int hr = NativeMethods.DismGetFeatureInfo(CurrentDISMSession, featureName, null, DismPackageIdentifier.DismPackageNone, out IntPtr featureInfoPtr);
		if (hr != 0 || featureInfoPtr == IntPtr.Zero)
		{
			// If the feature doesn't exist on this system, treat as a no-op success.
			if (hr == HRESULT_CBS_E_ITEM_NOT_FOUND)
			{
				Logger.Write($"Feature '{featureName}' is not available on this system (0x{hr:X8}); skipping enable.", LogTypeIntel.Information);
				return true;
			}

			Logger.Write($"Failed to get feature info for '{featureName}'. Error code: 0x{hr:X8}, HR: {hr}", LogTypeIntel.Error);
			return false;
		}

		try
		{
			DismFeatureInfo featureInfo = *(DismFeatureInfo*)featureInfoPtr;
			if (featureInfo.FeatureState is DismPackageFeatureState.DismStateNotPresent)
			{
				Logger.Write($"Feature '{featureName}' is not present (Disabled with Payload Removed). A valid source path (e.g., sources\\sxs) is required.", LogTypeIntel.Information);
			}
			else if (featureInfo.FeatureState is DismPackageFeatureState.DismStateInstalled)
			{
				Logger.Write($"Feature '{featureName}' is already enabled.", LogTypeIntel.Information);
				return true;
			}
			else if (featureInfo.FeatureState is DismPackageFeatureState.DismStateStaged)
			{
				Logger.Write($"Feature '{featureName}' is disabled but staged. No source path required.", LogTypeIntel.Information);
			}
		}
		finally
		{
			if (featureInfoPtr != IntPtr.Zero)
				_ = NativeMethods.DismDelete(featureInfoPtr);
		}

		IntPtr sourcePathsPtr = IntPtr.Zero;
		uint sourcePathCount = 0;
		IntPtr[]? stringPtrs = null;

		try
		{
			if (sourcePaths != null && sourcePaths.Length > 0)
			{
				sourcePathCount = (uint)sourcePaths.Length;
				stringPtrs = new IntPtr[sourcePathCount];

				for (int i = 0; i < sourcePathCount; i++)
				{
					stringPtrs[i] = Marshal.StringToHGlobalUni(sourcePaths[i]);
				}

				sourcePathsPtr = Marshal.AllocHGlobal(sizeof(nint) * (int)sourcePathCount);
				Marshal.Copy(stringPtrs, 0, sourcePathsPtr, (int)sourcePathCount);
			}

			hr = NativeMethods.DismEnableFeature(
				CurrentDISMSession,
				featureName,
				null,
				DismPackageIdentifier.DismPackageNone,
				true,
				sourcePathsPtr,
				sourcePathCount,
				true,
				IntPtr.Zero,
				DismProgressCallbackPtr,
				IntPtr.Zero);

			if (hr == 0)
			{
				Logger.Write($"Successfully enabled feature: {featureName}. Restart may be required.", LogTypeIntel.Information);
				return true;
			}
			if (hr == 3010)
			{
				Logger.Write($"Successfully enabled feature, Reboot required: {featureName}", LogTypeIntel.Information);
				return true;
			}
			// If the feature is not available on this system, treat as a no-op success.
			if (hr == HRESULT_CBS_E_ITEM_NOT_FOUND)
			{
				Logger.Write($"Feature '{featureName}' is not available on this system (0x{hr:X8}); skipping enable.", LogTypeIntel.Information);
				return true;
			}
			else
			{
				// Error code: 0xC004000D | this is for when we try to enable a feature that requires other dependencies to be enabled/installed first.
				Logger.Write($"Failed to enable feature: {featureName}. Error code: 0x{hr:X8}, HR: {hr}", LogTypeIntel.Error);
				return false;
			}
		}
		finally
		{
			if (stringPtrs != null)
			{
				for (int i = 0; i < sourcePathCount; i++)
				{
					if (stringPtrs[i] != IntPtr.Zero)
					{
						Marshal.FreeHGlobal(stringPtrs[i]);
					}
				}
			}
			if (sourcePathsPtr != IntPtr.Zero)
			{
				Marshal.FreeHGlobal(sourcePathsPtr);
			}

			DestroyDISMSession();
		}
	}

	internal static bool DisableFeature(string featureName)
	{
		try
		{

			// Get a new session if one doesn't already exist
			InitDISM();

			Logger.Write($"Attempting to disable feature: {featureName}", LogTypeIntel.Information);

			int hr = NativeMethods.DismDisableFeature(
				CurrentDISMSession,
				featureName,
				null,
				true,                 // RemovePayload: ensure payload is removed
				IntPtr.Zero,          // CancelEvent
				DismProgressCallbackPtr,
				IntPtr.Zero);         // UserData

			if (hr == 0)
			{
				Logger.Write($"Successfully disabled feature: {featureName}. Restart may be required.", LogTypeIntel.Information);
				return true;
			}
			if (hr == 3010)
			{
				// 3010 == ERROR_SUCCESS_REBOOT_REQUIRED
				Logger.Write($"Successfully disabled feature, Reboot required: {featureName}", LogTypeIntel.Information);
				return true;
			}
			// If the feature does not exist or is not applicable on this system, treat as no-op success.
			if (hr == HRESULT_CBS_E_ITEM_NOT_FOUND)
			{
				Logger.Write($"Feature '{featureName}' is not available on this system (0x{hr:X8}); skipping disable.", LogTypeIntel.Information);
				return true;
			}
			else
			{
				Logger.Write($"Failed to disable feature (payload removal requested): {featureName}. Error code: 0x{hr:X8}, HR: {hr}", LogTypeIntel.Error);
				return false;
			}
		}
		finally
		{
			DestroyDISMSession();
		}
	}

	internal static void InitDISM()
	{
		if (CurrentDISMSession != IntPtr.Zero) return;

		// This is what the DISM API will write to the default file path, doesn't affect the errors from API calls at all.
		int hr = NativeMethods.DismInitialize(DismLogLevel.DismLogErrors, null, null);
		if (hr != 0)
		{
			throw new InvalidOperationException($"Failed to initialize DISM. Error code: 0x{hr:X8}, HR: {hr}");
		}

		hr = NativeMethods.DismOpenSession(Program.OnlineImage, null, null, out IntPtr session);
		if (hr != 0)
		{
			throw new InvalidOperationException($"Failed to open DISM session. Error code: 0x{hr:X8}, HR: {hr}");
		}

		CurrentDISMSession = session;
	}

	internal static unsafe void GetFeatures(List<DISMOutput> ListToAdd)
	{
		// Get a new session if one doesn't already exist
		InitDISM();

		nint getFeaturesHR = NativeMethods.DismGetFeatures(CurrentDISMSession, null, DismPackageIdentifier.DismPackageNone, out IntPtr featureList, out uint featureCount);
		if (getFeaturesHR != 0 || featureList == IntPtr.Zero)
		{
			throw new InvalidOperationException($"DismGetFeatures failed. Error code: 0x{getFeaturesHR:X8}, HR: {getFeaturesHR}");
		}

		try
		{
			Logger.Write("Getting the available features.", LogTypeIntel.Information);

			// Pre-sizing the output list to avoid growth overhead during bulk enumeration
			int targetCapacity = ListToAdd.Count + (int)featureCount;
			if (targetCapacity > ListToAdd.Capacity)
			{
				ListToAdd.Capacity = targetCapacity;
			}

			// Pointer iteration to traverse the native array
			DismFeature* featureBase = (DismFeature*)featureList;
			for (uint i = 0; i < featureCount; i++)
			{
				try
				{
					DismFeature* featurePtr = featureBase + i;
					DismFeature feature = *featurePtr;

					string featureName = PtrToStringUniSafe(feature.FeatureName);
					if (string.IsNullOrEmpty(featureName))
					{
						Logger.Write($"Feature {i + 1}: [Invalid or empty name], State: {feature.State}", LogTypeIntel.Warning);
						continue;
					}

					nint getFeatureInfoHR = NativeMethods.DismGetFeatureInfo(CurrentDISMSession, featureName, null, DismPackageIdentifier.DismPackageNone, out IntPtr stateFeatureInfoPtr);
					DismPackageFeatureState state = feature.State;
					string description = string.Empty;
					if (getFeatureInfoHR == 0 && stateFeatureInfoPtr != IntPtr.Zero)
					{
						try
						{
							DismFeatureInfo featureInfo = *(DismFeatureInfo*)stateFeatureInfoPtr;
							state = featureInfo.FeatureState;
							description = PtrToStringUniSafe(featureInfo.Description);
						}
						finally
						{
							_ = NativeMethods.DismDelete(stateFeatureInfoPtr);
						}
					}

					ListToAdd.Add(new DISMOutput(featureName, state, DISMResultType.Feature, description));
				}
				catch (Exception ex)
				{
					Logger.Write($"Error reading feature {i + 1}: {ex.Message}", LogTypeIntel.Error);
					continue;
				}
			}
		}
		finally
		{
			if (featureList != IntPtr.Zero)
				_ = NativeMethods.DismDelete(featureList);
		}
	}

	/// <summary>
	/// PCWSTR -> string conversion
	/// </summary>
	private static unsafe string PtrToStringUniSafe(IntPtr ptr)
	{
		if (ptr == IntPtr.Zero)
			return string.Empty;

		try
		{
			return new string((char*)ptr);
		}
		catch (AccessViolationException)
		{
			return string.Empty;
		}
		catch (Exception)
		{
			return string.Empty;
		}
	}

	// To remove a capability
	internal static bool RemoveCapability(string capabilityName)
	{
		try
		{

			// Get a new session if one doesn't already exist
			InitDISM();

			Logger.Write($"Attempting to remove capability: {capabilityName}", LogTypeIntel.Information);

			int hr = NativeMethods.DismRemoveCapability(CurrentDISMSession, capabilityName, IntPtr.Zero, DismProgressCallbackPtr, IntPtr.Zero);
			if (hr == 0)
			{
				Logger.Write($"Successfully removed capability: {capabilityName}", LogTypeIntel.Information);
				return true;
			}
			if (hr == 3010)
			{
				Logger.Write($"Successfully removed capability, Reboot required: {capabilityName}", LogTypeIntel.Information);
				return true;
			}
			// If the capability does not exist or is not applicable on this system, treat as no-op success.
			if (hr == HRESULT_CBS_E_ITEM_NOT_FOUND)
			{
				Logger.Write($"Capability '{capabilityName}' is not available on this system (0x{hr:X8}); skipping remove.", LogTypeIntel.Information);
				return true;
			}
			else
			{
				Logger.Write($"Failed to remove capability: {capabilityName}, Error code: 0x{hr:X8}, HR: {hr}", LogTypeIntel.Error);
				return false;
			}
		}
		finally
		{
			DestroyDISMSession();
		}
	}

	// to add a capability
	// e.g.: AddCapability("App.StepsRecorder~~~~0.0.1.0", false, null);
	internal static unsafe bool AddCapability(string capabilityName, bool limitAccess = false, string[]? sourcePaths = null)
	{
		// Get a new session if one doesn't already exist
		InitDISM();

		Logger.Write($"Attempting to add capability: {capabilityName}", LogTypeIntel.Information);

		IntPtr sourcePathsPtr = IntPtr.Zero;
		uint sourcePathCount = 0;
		IntPtr[]? stringPtrs = null;

		try
		{
			if (sourcePaths != null && sourcePaths.Length > 0)
			{
				sourcePathCount = (uint)sourcePaths.Length;
				stringPtrs = new IntPtr[sourcePathCount];

				// Allocating memory for each string and copy it
				for (int i = 0; i < sourcePathCount; i++)
				{
					stringPtrs[i] = Marshal.StringToHGlobalUni(sourcePaths[i]);
				}

				// Allocating memory for the array of pointers
				sourcePathsPtr = Marshal.AllocHGlobal(sizeof(nint) * (int)sourcePathCount);
				Marshal.Copy(stringPtrs, 0, sourcePathsPtr, (int)sourcePathCount);
			}

			int hr = NativeMethods.DismAddCapability(
				CurrentDISMSession,
				capabilityName,
				limitAccess,
				sourcePathsPtr,
				sourcePathCount,
				IntPtr.Zero, // CancelEvent
				DismProgressCallbackPtr,
				IntPtr.Zero  // UserData
			);

			if (hr == 0)
			{
				Logger.Write($"Successfully added capability: {capabilityName}", LogTypeIntel.Information);
				return true;
			}
			if (hr == 3010)
			{
				Logger.Write($"Successfully added capability, Reboot required: {capabilityName}", LogTypeIntel.Information);
				return true;
			}
			// If the capability does not exist or is not applicable on this system, treat as no-op success.
			if (hr == HRESULT_CBS_E_ITEM_NOT_FOUND)
			{
				Logger.Write($"Capability '{capabilityName}' is not available on this system (0x{hr:X8}); skipping add.", LogTypeIntel.Information);
				return true;
			}
			else
			{
				Logger.Write($"Failed to add capability: {capabilityName}, Error code: 0x{hr:X8}, HR: {hr}", LogTypeIntel.Error);
				return false;
			}
		}
		finally
		{
			// Free allocated memory for SourcePaths
			if (stringPtrs != null)
			{
				for (int i = 0; i < sourcePathCount; i++)
				{
					if (stringPtrs[i] != IntPtr.Zero)
					{
						Marshal.FreeHGlobal(stringPtrs[i]);
					}
				}
			}
			if (sourcePathsPtr != IntPtr.Zero)
			{
				Marshal.FreeHGlobal(sourcePathsPtr);
			}

			DestroyDISMSession();
		}
	}

	internal static unsafe void GetCapabilities(List<DISMOutput> ListToAdd)
	{
		// Get a new session if one doesn't already exist
		InitDISM();

		int hr = NativeMethods.DismGetCapabilities(CurrentDISMSession, out nint capabilityPtr, out uint count);
		if (hr != 0)
		{
			throw new InvalidOperationException($"Failed to get capabilities. Error code: {hr}");
		}

		try
		{
			// Validate count to prevent processing invalid data
			if (capabilityPtr == IntPtr.Zero || count == 0 || count > 10000)
			{
				throw new InvalidOperationException("No capabilities found or count is invalid.");
			}

			Logger.Write($"Found {count} Windows capabilities:", LogTypeIntel.Information);

			// Pre-sizing the output list to avoid growth overhead during bulk enumeration
			int targetCapacity = ListToAdd.Count + (int)count;
			if (targetCapacity > ListToAdd.Capacity)
			{
				ListToAdd.Capacity = targetCapacity;
			}

			// Pointer iteration to traverse the native array
			int processedCount = 0;
			DismCapability* capBase = (DismCapability*)capabilityPtr;

			for (uint i = 0; i < count; i++)
			{
				DismCapability* capPtr = capBase + i;
				DismCapability capability = *capPtr;

				// Convert name and skip if empty/invalid
				string name = PtrToStringUniSafe(capability.Name);
				if (string.IsNullOrEmpty(name))
				{
					continue;
				}

				DismPackageFeatureState state = capability.State;
				string description = string.Empty;

				// This increases the retrieval time by over 2 minutes!
				// It's because the DismCapability, doesn't give us the description like the DismFeatureInfo does, so we have to get DismGetCapabilityInfo for each capability.
				// The reason commands like "Get-WindowsOptionalFeature -online" are fast is because they use the APIs that return structs with only 2 properties.
				/*
				nint getCapabilityInfoHR = NativeMethods.DismGetCapabilityInfo(CurrentDISMSession, name, out IntPtr capabilityInfoPtr);
				if (getCapabilityInfoHR == 0 && capabilityInfoPtr != IntPtr.Zero)
				{
					try
					{
						DismCapabilityInfo capabilityInfo = *(DismCapabilityInfo*)capabilityInfoPtr;
						state = capabilityInfo.State;
						description = PtrToStringUniSafe(capabilityInfo.Description);
					}
					finally
					{
						_ = NativeMethods.DismDelete(capabilityInfoPtr);
					}
				}
				*/

				ListToAdd.Add(new DISMOutput(name, state, DISMResultType.Capability, description));

				processedCount++;
			}

			Logger.Write($"Successfully processed {processedCount} capabilities out of {count} total.", LogTypeIntel.Information);
		}
		finally
		{
			// Free the memory allocated for capabilities
			if (capabilityPtr != IntPtr.Zero)
			{
				_ = NativeMethods.DismDelete(capabilityPtr);
			}
		}
	}

	/// <summary>
	/// Gets specific features by name from the DISM session.
	/// This is faster than GetFeatures as it only fetches the requested features instead of iterating through all features.
	/// </summary>
	/// <param name="featureNames">List of feature names to fetch</param>
	internal static unsafe List<DISMOutput> GetSpecificFeatures(string[] featureNames)
	{
		// Get a new session if one doesn't already exist
		InitDISM();

		List<DISMOutput> output = [];

		if (featureNames.Length is 0)
		{
			Logger.Write("No feature names provided.", LogTypeIntel.Warning);
			return output;
		}

		Logger.Write($"Getting {featureNames.Length} specific features.", LogTypeIntel.Information);

		foreach (string featureName in featureNames)
		{
			try
			{
				nint getFeatureInfoHR = NativeMethods.DismGetFeatureInfo(
					CurrentDISMSession,
					featureName,
					null,
					DismPackageIdentifier.DismPackageNone,
					out IntPtr featureInfoPtr);

				if (getFeatureInfoHR != 0 || featureInfoPtr == IntPtr.Zero)
				{
					// Handle missing/removed features quietly as NotAvailableOnSystem
					if ((int)getFeatureInfoHR == HRESULT_CBS_E_ITEM_NOT_FOUND)
					{
						output.Add(new DISMOutput(featureName, DismPackageFeatureState.NotAvailableOnSystem, DISMResultType.Feature, string.Empty));
						Logger.Write($"Feature '{featureName}' is not available on this system (0x{getFeatureInfoHR:X8}); marking as NotAvailableOnSystem.", LogTypeIntel.Information);
						continue;
					}

					// Preserve existing behavior for other failures
					Logger.Write($"Failed to get feature info for '{featureName}'. Error code: 0x{getFeatureInfoHR:X8}, HR: {getFeatureInfoHR}", LogTypeIntel.Warning);
					continue;
				}

				try
				{
					DismFeatureInfo featureInfo = *(DismFeatureInfo*)featureInfoPtr;

					string description = PtrToStringUniSafe(featureInfo.Description);

					output.Add(new DISMOutput(featureName, featureInfo.FeatureState, DISMResultType.Feature, description));
					Logger.Write($"Successfully retrieved feature: {featureName}, State: {featureInfo.FeatureState}", LogTypeIntel.Information);
				}
				finally
				{
					if (featureInfoPtr != IntPtr.Zero)
						_ = NativeMethods.DismDelete(featureInfoPtr);
				}
			}
			catch (Exception ex)
			{
				Logger.Write($"Error retrieving feature '{featureName}': {ex.Message}", LogTypeIntel.Error);
				continue;
			}
		}

		return output;
	}

	/// <summary>
	/// Gets specific capabilities by name from the DISM session.
	/// This is faster than GetCapabilities as it only fetches the requested capabilities instead of iterating through all capabilities.
	/// </summary>
	/// <param name="capabilityNames">List of capability names to fetch</param>
	internal static unsafe List<DISMOutput> GetSpecificCapabilities(string[] capabilityNames)
	{
		// Get a new session if one doesn't already exist
		InitDISM();

		List<DISMOutput> output = [];

		if (capabilityNames.Length is 0)
		{
			Logger.Write("No capability names provided.", LogTypeIntel.Warning);
			return output;
		}

		Logger.Write($"Getting {capabilityNames.Length} specific capabilities.", LogTypeIntel.Information);

		foreach (string capabilityName in capabilityNames)
		{
			try
			{
				nint getCapabilityInfoHR = NativeMethods.DismGetCapabilityInfo(CurrentDISMSession, capabilityName, out IntPtr capabilityInfoPtr);

				// We get HR 3010 in here if we previously removed a capability in the same session.
				if (getCapabilityInfoHR != 0 || capabilityInfoPtr == IntPtr.Zero)
				{
					Logger.Write($"Failed to get capability info for '{capabilityName}'. Error code: 0x{getCapabilityInfoHR:X8}, HR: {getCapabilityInfoHR}", LogTypeIntel.Warning);
					continue;
				}

				try
				{
					DismCapabilityInfo capabilityInfo = *(DismCapabilityInfo*)capabilityInfoPtr;

					string description = PtrToStringUniSafe(capabilityInfo.Description);

					output.Add(new DISMOutput(capabilityName, capabilityInfo.State, DISMResultType.Capability, description));
					Logger.Write($"Successfully retrieved capability: {capabilityName}, State: {capabilityInfo.State}", LogTypeIntel.Information);
				}
				finally
				{
					if (capabilityInfoPtr != IntPtr.Zero)
						_ = NativeMethods.DismDelete(capabilityInfoPtr);
				}
			}
			catch (Exception ex)
			{
				Logger.Write($"Error retrieving capability '{capabilityName}': {ex.Message}", LogTypeIntel.Error);
				continue;
			}
		}

		return output;
	}

	/// <summary>
	/// Gets all of the capabilities and features and returns them in a list.
	/// </summary>
	/// <returns></returns>
	internal static List<DISMOutput> GetAllAvailableResults()
	{
		List<DISMOutput> Output = [];

		GetFeatures(Output);
		GetCapabilities(Output);

		return Output;
	}

	/// <summary>
	/// Shuts down the DISM session.
	/// </summary>
	internal static void DestroyDISMSession()
	{
		try
		{
			nint dismCloseSessionHR = NativeMethods.DismCloseSession(CurrentDISMSession);
			// We get 3010 here too if we added/removed a capability/feature in the session
			if (dismCloseSessionHR == 3010)
			{
				Logger.Write($"Successfully closed the DISM session but reboot is required to finish applying the changed performed in the session.", LogTypeIntel.Information);
			}
			else if (dismCloseSessionHR != 0)
			{
				Logger.Write($"Failed to close DISM session. Error code: 0x{dismCloseSessionHR:X8}, HR: {dismCloseSessionHR}", LogTypeIntel.Error);
			}

			nint dismShutDownHR = NativeMethods.DismShutdown();
			if (dismShutDownHR != 0)
			{
				Logger.Write($"Failed to shutdown DISM. Error code: 0x{dismShutDownHR:X8}, HR: {dismShutDownHR}", LogTypeIntel.Error);
			}
		}
		finally
		{
			// Prevent it from having a now invalid session handle.
			CurrentDISMSession = IntPtr.Zero;
		}
	}

	/// <summary>
	/// Checks whether a feature or capability is enabled or disabled
	/// </summary>
	/// <param name="obj"></param>
	/// <returns></returns>
	internal static bool IsEnabled(DISMOutput? obj)
	{
		if (obj is null)
			return false;

		if (obj.State is DismPackageFeatureState.DismStateNotPresent or
			DismPackageFeatureState.DismStateUninstallPending or
			DismPackageFeatureState.DismStateStaged or
			DismPackageFeatureState.DismStateRemoved)
		{
			return false;
		}

		return true;
	}
}
