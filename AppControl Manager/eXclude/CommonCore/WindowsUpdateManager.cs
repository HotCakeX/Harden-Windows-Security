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
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json.Serialization;
using Microsoft.UI.Xaml;

namespace CommonCore;

// https://learn.microsoft.com/windows/win32/api/_wua/
// https://learn.microsoft.com/windows/win32/api/wuapi/nf-wuapi-iupdatesearcher-search
internal unsafe static partial class WindowsUpdateManager
{
	// WUA COM calls run on a worker thread and COINIT_MULTITHREADED selects the multithreaded apartment for that worker when possible.
	private const uint COINIT_MULTITHREADED = 0x0;

	private const uint CLSCTX_INPROC_SERVER = 0x1;
	private const uint CLSCTX_LOCAL_SERVER = 0x4;
	private const uint CLSCTX_ALL = CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER;

	private const ushort DISPATCH_METHOD = 0x1;
	private const ushort DISPATCH_PROPERTYGET = 0x2;
	private const ushort DISPATCH_PROPERTYPUT = 0x4;

	// Named argument DISPID required by IDispatch property put calls.
	private const int DISPID_PROPERTYPUT = -3;

	// VARIANT type constants returned by COM. VariantHelpers.ToDisplayString converts common WUA return types into UI text.
	private const ushort VT_EMPTY = 0;
	private const ushort VT_I4 = 3;
	private const ushort VT_R8 = 5;
	private const ushort VT_DATE = 7;
	private const ushort VT_BSTR = 8;
	private const ushort VT_DISPATCH = 9;
	private const ushort VT_BOOL = 11;
	private const ushort VT_UNKNOWN = 13;
	private const ushort VT_DECIMAL = 14;
	private const ushort VT_UI4 = 19;
	private const ushort VT_I8 = 20;
	private const ushort VT_UI8 = 21;

	private const int RPC_E_CHANGED_MODE = unchecked((int)0x80010106);

	// IID_NULL is passed to IDispatch methods when no interface ID is required.
	private static readonly Guid IidNull = Guid.Empty;

	// Standard IDispatch IID used when a WUA member returns IUnknown and we need late-bound access.
	private static readonly Guid IidIDispatch = new("00020400-0000-0000-C000-000000000046");

	/// <summary>
	/// Searches for available and applicable Windows updates that are not installed, hidden or not.
	/// Entry point used by the ViewModel of Windows Updates.
	/// </summary>
	/// <returns>The list of available Windows updates with their metadata.</returns>
	internal static List<WindowsUpdateItem> SearchAvailableUpdates() => ExecuteWithUpdateSession(SearchUpdates);

	/// <summary>
	/// Sets the hidden state for the supplied Windows updates.
	/// </summary>
	/// <param name="selectedUpdates">The selected updates.</param>
	/// <param name="isHidden">The desired hidden state.</param>
	/// <returns>Per-update hidden-state operation results.</returns>
	internal static List<HiddenStateChangeResult> SetHiddenStates(IReadOnlyList<WindowsUpdateItem> selectedUpdates, bool isHidden)
	{
		return ExecuteWithUpdateSession(updateSession =>
		{
			return SetHiddenStates(updateSession, selectedUpdates, isHidden);
		});
	}

	// Creates and configures the WUA session, then runs the requested operation inside a COM lifetime boundary.
	private static T ExecuteWithUpdateSession<T>(Func<ComObject, T> operation)
	{
		// Initialize COM for the current thread. In WinUI 3, the thread may already be
		// initialized with a different apartment model. RPC_E_CHANGED_MODE means COM is already initialized
		// on this thread, so we can use the existing apartment and must not call CoUninitialize for it.
		int hr = NativeMethods.CoInitializeEx(IntPtr.Zero, COINIT_MULTITHREADED);

		if (hr < 0 && hr != RPC_E_CHANGED_MODE)
		{
			throw new InvalidOperationException($"CoInitializeEx failed with HRESULT 0x{hr:X8}.");
		}

		// Successful CoInitializeEx calls, including S_FALSE, must be balanced with CoUninitialize.
		// RPC_E_CHANGED_MODE is not a successful initialization by this method, so it must not be balanced here.
		bool requiresUninitialize = hr >= 0;

		try
		{
			// Create the Windows Update Agent session object.
			using ComObject updateSession = ComObject.CreateFromProgId("Microsoft.Update.Session");

			// Identify this caller in Windows Update Agent logging and history metadata.
			updateSession.PutString("ClientApplicationID", "HardenSystemSecurity");

			return operation(updateSession);
		}
		catch (InvalidOperationException)
		{
			throw;
		}
		catch (Exception ex)
		{
			throw new InvalidOperationException("Windows Update operation failed.", ex);
		}
		finally
		{
			if (requiresUninitialize)
			{
				NativeMethods.CoUninitialize();
			}
		}
	}

	// Performs the actual WUA search and reads all returned updates before COM objects are disposed.
	private static List<WindowsUpdateItem> SearchUpdates(ComObject updateSession)
	{
		using ComObject updateSearcher = updateSession.CallDispatch("CreateUpdateSearcher");

		// IsInstalled=0 returns available/applicable updates that are not currently installed.
		// https://learn.microsoft.com/windows/win32/api/wuapi/nf-wuapi-iupdatesearcher-search
		using ComObject searchResult = updateSearcher.CallDispatch("Search", VariantHelpers.FromBstr("IsInstalled=0"));

		using ComObject updateCollection = searchResult.GetDispatch("Updates");

		int count = updateCollection.GetInt32("Count");

		List<WindowsUpdateItem> updates = new(capacity: count);

		// Read all update metadata while each COM update item is still alive.
		for (int index = 0; index < count; index++)
		{
			updateCollection.UseDispatchItem(index, update =>
			{
				updates.Add(ReadUpdateItem(update));
			});
		}

		return updates;
	}

	// Converts one live WUA update COM object into the immutable model consumed by the UI and JSON export.
	private static WindowsUpdateItem ReadUpdateItem(ComObject update)
	{
		// Core identifying properties.
		string title = update.GetString("Title");
		bool isHidden = update.GetBoolean("IsHidden");
		string updateId = string.Empty;
		int revisionNumber = 0;

		// Identity can be unavailable on unusual update objects, so keep this non-fatal.
		try
		{
			using ComObject identity = update.GetDispatch("Identity");

			updateId = identity.GetString("UpdateID");
			revisionNumber = identity.GetInt32("RevisionNumber");
		}
		catch (InvalidOperationException)
		{
			updateId = "Unavailable";
			revisionNumber = 0;
		}

		// Gather optional metadata. Missing properties are converted to "Unavailable".
		// WUA properties vary by update type and WUA interface version.
		return new WindowsUpdateItem(
			title,
			isHidden,
			updateId,
			revisionNumber,
			GetOptionalDisplay(update, "Description"),
			GetOptionalDisplay(update, "Type"),
			GetOptionalDisplay(update, "MsrcSeverity"),
			GetOptionalDisplay(update, "SupportUrl"),
			GetOptionalDisplay(update, "IsInstalled"),
			GetOptionalDisplay(update, "IsDownloaded"),
			GetOptionalDisplay(update, "IsMandatory"),
			GetOptionalDisplay(update, "IsBeta"),
			GetOptionalDisplay(update, "CanRequireSource"),
			GetOptionalDisplay(update, "AutoSelectOnWebSites"),
			GetOptionalDisplay(update, "BrowseOnly"),
			GetOptionalDisplay(update, "EulaAccepted"),
			GetOptionalDisplay(update, "HandlerID"),
			GetOptionalDisplay(update, "DeploymentAction"),
			GetOptionalDisplay(update, "DownloadPriority"),
			GetOptionalDisplay(update, "MinDownloadSize"),
			GetOptionalDisplay(update, "MaxDownloadSize"),
			GetOptionalDisplay(update, "Deadline"),
			GetOptionalDisplay(update, "LastDeploymentChangeTime"),
			GetStringCollectionDisplay(update, "KBArticleIDs"),
			GetStringCollectionDisplay(update, "SecurityBulletinIDs"),
			GetStringCollectionDisplay(update, "SupersededUpdateIDs"),
			GetStringCollectionDisplay(update, "Languages"),
			GetStringCollectionDisplay(update, "MoreInfoUrls"),
			GetCategoryCollection(update),
			GetBundledUpdatesDisplay(update),
			GetDownloadContents(update),
			GetBehaviorDetails(update, "InstallationBehavior"),
			GetBehaviorDetails(update, "UninstallationBehavior"),
			GetOptionalDisplay(update, "RebootRequired"),
			GetOptionalDisplay(update, "IsUninstallable"),
			GetOptionalDisplay(update, "ReleaseNotes"),
			GetOptionalDisplay(update, "UninstallationNotes"),
			GetStringCollectionDisplay(update, "UninstallationSteps"),
			GetOptionalDisplay(update, "RecommendedCpuSpeed"),
			GetOptionalDisplay(update, "RecommendedMemory"),
			GetOptionalDisplay(update, "RecommendedHardDiskSpace"),
			GetOptionalDisplay(update, "EulaText"),
			GetDriverDetails(update),
			GetOptionalDisplay(update, "AutoDownload"),
			GetOptionalDisplay(update, "AutoSelection"));
	}

	// Re-searches for fresh COM update objects, matches selected items by UpdateID and RevisionNumber, then changes IsHidden.
	private static List<HiddenStateChangeResult> SetHiddenStates(ComObject updateSession, IReadOnlyList<WindowsUpdateItem> selectedUpdates, bool isHidden)
	{
		List<HiddenStateChangeResult> results = new(capacity: selectedUpdates.Count);

		if (selectedUpdates.Count == 0)
		{
			return results;
		}

		Dictionary<string, WindowsUpdateItem> selectedByKey = new(StringComparer.OrdinalIgnoreCase);

		// Index selected updates by UpdateID and RevisionNumber to avoid depending on display order.
		for (int index = 0; index < selectedUpdates.Count; index++)
		{
			WindowsUpdateItem selectedUpdate = selectedUpdates[index];
			selectedByKey[GetUpdateKey(selectedUpdate.UpdateId, selectedUpdate.RevisionNumber)] = selectedUpdate;
		}

		using ComObject updateSearcher = updateSession.CallDispatch("CreateUpdateSearcher");

		// Search again and modify fresh update COM objects. This keeps searched items disposable
		// and avoids retaining COM objects in the displayed model.
		using ComObject searchResult = updateSearcher.CallDispatch("Search", VariantHelpers.FromBstr("IsInstalled=0"));

		using ComObject updateCollection = searchResult.GetDispatch("Updates");

		int count = updateCollection.GetInt32("Count");

		for (int index = 0; index < count; index++)
		{
			updateCollection.UseDispatchItem(index, update =>
			{
				using ComObject identity = update.GetDispatch("Identity");

				string updateId = identity.GetString("UpdateID");
				int revisionNumber = identity.GetInt32("RevisionNumber");
				string key = GetUpdateKey(updateId, revisionNumber);

				if (!selectedByKey.TryGetValue(key, out WindowsUpdateItem? selectedUpdate))
				{
					return;
				}

				try
				{
					update.PutBoolean("IsHidden", isHidden);
					results.Add(new HiddenStateChangeResult(selectedUpdate.Title, true, string.Empty));
				}
				catch (InvalidOperationException ex)
				{
					results.Add(new HiddenStateChangeResult(selectedUpdate.Title, false, ex.Message));
				}

				_ = selectedByKey.Remove(key);
			});
		}

		// Report anything selected but not found in the fresh COM search result.
		foreach (WindowsUpdateItem missingUpdate in selectedByKey.Values)
		{
			string message = $"The selected update could not be found again. UpdateID: {missingUpdate.UpdateId}, Revision: {missingUpdate.RevisionNumber.ToString(CultureInfo.InvariantCulture)}.";
			results.Add(new HiddenStateChangeResult(missingUpdate.Title, false, message));
		}

		return results;
	}

	private static string GetUpdateKey(string updateId, int revisionNumber) => $"{updateId}|{revisionNumber.ToString(CultureInfo.InvariantCulture)}";

	/// <summary>
	/// Reads a property through IDispatch and converts it to text. Unsupported or absent properties become "Unavailable".
	/// </summary>
	private static string GetOptionalDisplay(ComObject source, string propertyName)
	{
		try
		{
			return source.GetDisplay(propertyName);
		}
		catch (InvalidOperationException)
		{
			return "Unavailable";
		}
	}

	/// <summary>
	/// Reads WUA string collections such as KBArticleIDs, SecurityBulletinIDs, MoreInfoUrls, and UninstallationSteps.
	/// </summary>
	private static string GetStringCollectionDisplay(ComObject update, string propertyName)
	{
		try
		{
			using ComObject collection = update.GetDispatch(propertyName);

			int count = collection.GetInt32("Count");

			if (count == 0)
			{
				return "None";
			}

			List<string> values = new(capacity: count);

			for (int index = 0; index < count; index++)
			{
				values.Add(collection.GetString("Item", VariantHelpers.FromInt32(index)));
			}

			return string.Join(", ", values);
		}
		catch (InvalidOperationException)
		{
			return "Unavailable";
		}
	}

	/// <summary>
	/// Reads update category objects as structured data.
	/// </summary>
	private static WindowsUpdateCollection<WindowsUpdateCategory> GetCategoryCollection(ComObject update)
	{
		try
		{
			using ComObject collection = update.GetDispatch("Categories");
			int count = collection.GetInt32("Count");
			if (count == 0)
			{
				return WindowsUpdateCollection<WindowsUpdateCategory>.None();
			}
			List<WindowsUpdateCategory> values = new(capacity: count);
			for (int index = 0; index < count; index++)
			{
				WindowsUpdateCategory categoryItem = collection.UseDispatchItem(index, category =>
				{
					string name = GetOptionalDisplay(category, "Name");
					string categoryId = GetOptionalDisplay(category, "CategoryID");
					string typeId = GetOptionalDisplay(category, "TypeID");
					return new WindowsUpdateCategory(name, categoryId, typeId);
				});
				values.Add(categoryItem);
			}
			return WindowsUpdateCollection<WindowsUpdateCategory>.FromItems(values);
		}
		catch (InvalidOperationException)
		{
			return WindowsUpdateCollection<WindowsUpdateCategory>.Unavailable();
		}
	}

	/// <summary>
	/// Reads titles of bundled child updates, if the update object contains any.
	/// </summary>
	private static string GetBundledUpdatesDisplay(ComObject update)
	{
		try
		{
			using ComObject collection = update.GetDispatch("BundledUpdates");

			int count = collection.GetInt32("Count");

			if (count == 0)
			{
				return "None";
			}

			List<string> values = new(capacity: count);

			for (int index = 0; index < count; index++)
			{
				string bundledUpdateTitle = collection.UseDispatchItem(index, bundledUpdate =>
				{
					return bundledUpdate.GetString("Title");
				});

				values.Add(bundledUpdateTitle);
			}

			return string.Join("; ", values);
		}
		catch (InvalidOperationException)
		{
			return "Unavailable";
		}
	}

	/// <summary>
	/// Reads download content records as structured FileName and DownloadUrl pairs.
	/// </summary>
	private static WindowsUpdateCollection<WindowsUpdateDownloadContent> GetDownloadContents(ComObject update)
	{
		try
		{
			using ComObject collection = update.GetDispatch("DownloadContents");
			int count = collection.GetInt32("Count");
			if (count == 0)
			{
				return WindowsUpdateCollection<WindowsUpdateDownloadContent>.None();
			}
			List<WindowsUpdateDownloadContent> values = new(capacity: count);
			for (int index = 0; index < count; index++)
			{
				WindowsUpdateDownloadContent contentItem = collection.UseDispatchItem(index, content =>
				{
					string downloadUrl = GetOptionalDisplay(content, "DownloadUrl");
					string fileName = GetOptionalDisplay(content, "FileName");
					return new WindowsUpdateDownloadContent(fileName, downloadUrl);
				});
				values.Add(contentItem);
			}
			return WindowsUpdateCollection<WindowsUpdateDownloadContent>.FromItems(values);
		}
		catch (InvalidOperationException)
		{
			return WindowsUpdateCollection<WindowsUpdateDownloadContent>.Unavailable();
		}
	}
	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/wuapi/ne-wuapi-installationimpact
	/// https://learn.microsoft.com/windows/win32/api/wuapi/ne-wuapi-installationrebootbehavior
	/// </summary>
	private static WindowsUpdateBehaviorDetails GetBehaviorDetails(ComObject update, string propertyName)
	{
		try
		{
			using ComObject behavior = update.GetDispatch(propertyName);
			string canRequestUserInput = GetOptionalDisplay(behavior, "CanRequestUserInput");
			string impact = GetOptionalDisplay(behavior, "Impact");
			string rebootBehavior = GetOptionalDisplay(behavior, "RebootBehavior");
			string requiresNetworkConnectivity = GetOptionalDisplay(behavior, "RequiresNetworkConnectivity");
			return WindowsUpdateBehaviorDetails.Available(canRequestUserInput, impact, rebootBehavior, requiresNetworkConnectivity);
		}
		catch (InvalidOperationException)
		{
			return WindowsUpdateBehaviorDetails.Unavailable();
		}
	}
	/// <summary>
	/// Reads driver-specific Windows Update metadata when the COM object exposes it.
	/// Non-driver update objects normally return "Unavailable" for these fields.
	/// https://learn.microsoft.com/windows/win32/api/wuapi/nn-wuapi-iwindowsdriverupdate
	/// </summary>
	/// <param name="update">The update COM object</param>
	/// <returns>driver metadata</returns>
	private static WindowsUpdateDriverDetails GetDriverDetails(ComObject update)
	{
		string deviceProblemNumber = GetOptionalDisplay(update, "DeviceProblemNumber");
		string deviceStatus = GetOptionalDisplay(update, "DeviceStatus");
		string driverClass = GetOptionalDisplay(update, "DriverClass");
		string driverHardwareId = GetOptionalDisplay(update, "DriverHardwareID");
		string driverManufacturer = GetOptionalDisplay(update, "DriverManufacturer");
		string driverModel = GetOptionalDisplay(update, "DriverModel");
		string driverProvider = GetOptionalDisplay(update, "DriverProvider");
		string driverVerDate = GetOptionalDisplay(update, "DriverVerDate");
		return new WindowsUpdateDriverDetails(deviceProblemNumber, deviceStatus, driverClass, driverHardwareId, driverManufacturer, driverModel, driverProvider, driverVerDate);
	}
	/// <summary>
	/// Minimal IDispatch wrapper for WUA COM objects. It caches DISPIDs and releases every COM pointer through Dispose.
	/// </summary>
	private sealed partial class ComObject : IDisposable
	{
		private readonly Dictionary<string, int> _dispIds = new(StringComparer.OrdinalIgnoreCase);
		private IntPtr _dispatch;

		private ComObject(IntPtr dispatch)
		{
			if (dispatch == IntPtr.Zero)
			{
				throw new ArgumentNullException(nameof(dispatch));
			}

			_dispatch = dispatch;
		}

		/// <summary>
		/// Creates a COM object from a ProgID and requests IDispatch for late-bound access.
		/// </summary>
		internal static ComObject CreateFromProgId(string progId)
		{
			int hr = NativeMethods.CLSIDFromProgID(progId, out Guid clsid);
			ThrowIfFailed(hr, $"CLSIDFromProgID failed for '{progId}'.");

			Guid iidDispatch = IidIDispatch;

			hr = NativeMethods.CoCreateInstance(in clsid, IntPtr.Zero, CLSCTX_ALL, in iidDispatch, out IntPtr dispatch);
			ThrowIfFailed(hr, $"CoCreateInstance failed for '{progId}'.");

			return new ComObject(dispatch);
		}

		/// <summary>
		/// Invokes a COM method that returns another COM object.
		/// </summary>
		internal ComObject CallDispatch(string methodName) => InvokeForDispatch(methodName, DISPATCH_METHOD, []);

		internal ComObject CallDispatch(string methodName, VARIANT argument)
		{
			try
			{
				ReadOnlySpan<VARIANT> arguments = [argument];

				return InvokeForDispatch(methodName, DISPATCH_METHOD, arguments);
			}
			finally
			{
				VariantHelpers.Clear(ref argument);
			}
		}

		/// <summary>
		/// Reads a COM property that returns another COM object.
		/// </summary>
		internal ComObject GetDispatch(string propertyName) => InvokeForDispatch(propertyName, DISPATCH_PROPERTYGET, []);

		internal ComObject GetDispatch(string propertyName, VARIANT argument)
		{
			try
			{
				ReadOnlySpan<VARIANT> arguments = [argument];

				return InvokeForDispatch(propertyName, DISPATCH_PROPERTYGET, arguments);
			}
			finally
			{
				VariantHelpers.Clear(ref argument);
			}
		}

		/// <summary>
		/// Reads a BSTR property.
		/// </summary>
		internal string GetString(string propertyName)
		{
			VARIANT result = Invoke(propertyName, DISPATCH_PROPERTYGET, [], propertyPut: false);

			try
			{
				if (result.vt != VT_BSTR)
				{
					throw new InvalidOperationException($"Property '{propertyName}' did not return a BSTR. VT={result.vt}.");
				}

				return VariantHelpers.BstrToString(result.bstrVal);
			}
			finally
			{
				VariantHelpers.Clear(ref result);
			}
		}

		internal string GetString(string propertyName, VARIANT argument)
		{
			try
			{
				ReadOnlySpan<VARIANT> arguments = [argument];

				VARIANT result = Invoke(propertyName, DISPATCH_PROPERTYGET, arguments, propertyPut: false);

				try
				{
					if (result.vt != VT_BSTR)
					{
						throw new InvalidOperationException($"Property '{propertyName}' did not return a BSTR. VT={result.vt}.");
					}

					return VariantHelpers.BstrToString(result.bstrVal);
				}
				finally
				{
					VariantHelpers.Clear(ref result);
				}
			}
			finally
			{
				VariantHelpers.Clear(ref argument);
			}
		}

		/// <summary>
		/// Reads a 32-bit integer property.
		/// </summary>
		internal int GetInt32(string propertyName)
		{
			VARIANT result = Invoke(propertyName, DISPATCH_PROPERTYGET, [], propertyPut: false);

			try
			{
				if (result.vt == VT_I4)
				{
					return result.lVal;
				}

				if (result.vt == VT_UI4)
				{
					uint value = unchecked((uint)result.llVal);

					return checked((int)value);
				}

				throw new InvalidOperationException($"Property '{propertyName}' did not return an integer. VT={result.vt}.");
			}
			finally
			{
				VariantHelpers.Clear(ref result);
			}
		}

		/// <summary>
		/// Reads a VARIANT_BOOL property and converts it to a C# Boolean.
		/// </summary>
		internal bool GetBoolean(string propertyName)
		{
			VARIANT result = Invoke(propertyName, DISPATCH_PROPERTYGET, [], propertyPut: false);

			try
			{
				if (result.vt != VT_BOOL)
				{
					throw new InvalidOperationException($"Property '{propertyName}' did not return a VARIANT_BOOL. VT={result.vt}.");
				}

				short value = unchecked((short)result.lVal);

				return value != 0;
			}
			finally
			{
				VariantHelpers.Clear(ref result);
			}
		}

		/// <summary>
		/// Reads a property and converts the returned VARIANT to display text.
		/// </summary>
		internal string GetDisplay(string propertyName)
		{
			VARIANT result = Invoke(propertyName, DISPATCH_PROPERTYGET, [], propertyPut: false);

			try
			{
				return VariantHelpers.ToDisplayString(propertyName, result);
			}
			finally
			{
				VariantHelpers.Clear(ref result);
			}
		}

		/// <summary>
		/// Writes a BSTR property.
		/// </summary>
		internal void PutString(string propertyName, string value)
		{
			VARIANT argument = VariantHelpers.FromBstr(value);

			try
			{
				ReadOnlySpan<VARIANT> arguments = [argument];

				VARIANT result = Invoke(propertyName, DISPATCH_PROPERTYPUT, arguments, propertyPut: true);
				VariantHelpers.Clear(ref result);
			}
			finally
			{
				VariantHelpers.Clear(ref argument);
			}
		}

		/// <summary>
		/// Writes a VARIANT_BOOL property.
		/// </summary>
		internal void PutBoolean(string propertyName, bool value)
		{
			VARIANT argument = VariantHelpers.FromBoolean(value);

			try
			{
				ReadOnlySpan<VARIANT> arguments = [argument];

				VARIANT result = Invoke(propertyName, DISPATCH_PROPERTYPUT, arguments, propertyPut: true);
				VariantHelpers.Clear(ref result);
			}
			finally
			{
				VariantHelpers.Clear(ref argument);
			}
		}

		public void Dispose()
		{
			IntPtr dispatch = _dispatch;

			if (dispatch == IntPtr.Zero)
			{
				return;
			}

			_dispatch = IntPtr.Zero;
			NativeMethods.ReleaseComObject(dispatch);
		}

		/// <summary>
		/// Calls a member expected to return IDispatch or IUnknown and wraps the returned pointer.
		/// </summary>
		private ComObject InvokeForDispatch(string memberName, ushort flags, ReadOnlySpan<VARIANT> arguments)
		{
			VARIANT result = Invoke(memberName, flags, arguments, propertyPut: false);

			if (result.vt == VT_DISPATCH)
			{
				IntPtr dispatch = result.bstrVal;

				if (dispatch == IntPtr.Zero)
				{
					VariantHelpers.Clear(ref result);
					throw new InvalidOperationException($"Member '{memberName}' returned a null COM dispatch object.");
				}

				result.bstrVal = IntPtr.Zero;
				result.vt = VT_EMPTY;

				return new ComObject(dispatch);
			}

			if (result.vt == VT_UNKNOWN)
			{
				IntPtr unknown = result.bstrVal;

				if (unknown == IntPtr.Zero)
				{
					VariantHelpers.Clear(ref result);
					throw new InvalidOperationException($"Member '{memberName}' returned a null COM unknown object.");
				}

				IntPtr dispatch;

				try
				{
					dispatch = QueryDispatch(unknown);
				}
				finally
				{
					VariantHelpers.Clear(ref result);
				}

				return new ComObject(dispatch);
			}

			VariantHelpers.Clear(ref result);
			throw new InvalidOperationException($"Member '{memberName}' did not return a COM dispatch object. VT={result.vt}.");
		}

		/// <summary>
		/// Central IDispatch.Invoke path. Arguments are reversed because COM automation receives positional arguments in reverse order.
		/// </summary>
		private VARIANT Invoke(string memberName, ushort flags, ReadOnlySpan<VARIANT> arguments, bool propertyPut)
		{
			EnsureNotDisposed();

			int dispId = GetDispId(memberName);
			VARIANT result = default;
			DispatchParams dispatchParams = default;
			ExcepInfo excepInfo = default;
			uint argumentError = 0;
			int namedArgument = DISPID_PROPERTYPUT;
			int argumentCount = arguments.Length;

			Span<VARIANT> reversedArguments = argumentCount == 0 ? [] : stackalloc VARIANT[argumentCount];

			// IDispatch receives positional arguments in reverse order.
			for (int index = 0; index < argumentCount; index++)
			{
				reversedArguments[index] = arguments[argumentCount - 1 - index];
			}

			if (argumentCount > 0)
			{
				dispatchParams.ArgumentCount = unchecked((uint)argumentCount);
			}

			if (propertyPut)
			{
				dispatchParams.NamedArguments = &namedArgument;
				dispatchParams.NamedArgumentCount = 1;
			}

			Guid iidNull = IidNull;

			fixed (VARIANT* reversedArgumentsPointer = reversedArguments)
			{
				if (argumentCount > 0)
				{
					dispatchParams.Arguments = reversedArgumentsPointer;
				}

				IDispatchVtbl* vtbl = *(IDispatchVtbl**)_dispatch;

				int hr = vtbl->Invoke(
					_dispatch,
					dispId,
					&iidNull,
					0,
					flags,
					&dispatchParams,
					&result,
					&excepInfo,
					&argumentError);

				if (hr < 0)
				{
					int exceptionScode = excepInfo.Scode;
					string detail = excepInfo.Description1;

					excepInfo.Clear();
					VariantHelpers.Clear(ref result);

					string hresultDetails = exceptionScode < 0
						? $"IDispatch HRESULT: 0x{hr:X8}. EXCEPINFO scode: 0x{exceptionScode:X8}."
						: $"HRESULT: 0x{hr:X8}.";

					detail = string.IsNullOrWhiteSpace(detail)
						? $"IDispatch.Invoke failed for '{memberName}'. {hresultDetails}"
						: $"IDispatch.Invoke failed for '{memberName}'. {hresultDetails} {detail}";

					throw new InvalidOperationException(detail);
				}

				excepInfo.Clear();

				return result;
			}
		}

		/// <summary>
		/// Resolves and caches a COM member name to its DISPID.
		/// </summary>
		private int GetDispId(string name)
		{
			if (_dispIds.TryGetValue(name, out int cachedDispId))
			{
				return cachedDispId;
			}

			EnsureNotDisposed();

			Guid iidNull = IidNull;

			fixed (char* namePointer = name)
			{
				char** names = stackalloc char*[1];
				names[0] = namePointer;
				int dispId = 0;

				IDispatchVtbl* vtbl = *(IDispatchVtbl**)_dispatch;

				int hr = vtbl->GetIDsOfNames(
					_dispatch,
					&iidNull,
					names,
					1,
					0,
					&dispId);

				ThrowIfFailed(hr, $"IDispatch.GetIDsOfNames failed for '{name}'.");

				_dispIds.Add(name, dispId);

				return dispId;
			}
		}

		/// <summary>
		/// Converts an IUnknown pointer to IDispatch with QueryInterface.
		/// </summary>
		private static IntPtr QueryDispatch(IntPtr unknown)
		{
			if (unknown == IntPtr.Zero)
			{
				throw new InvalidOperationException("IUnknown pointer was null.");
			}

			IUnknownVtbl* vtbl = *(IUnknownVtbl**)unknown;

			Guid iidDispatch = IidIDispatch;
			void* dispatchPointer = null;

			int hr = vtbl->QueryInterface((void*)unknown, &iidDispatch, &dispatchPointer);
			ThrowIfFailed(hr, "QueryInterface for IDispatch failed.");

			IntPtr dispatch = (IntPtr)dispatchPointer;

			if (dispatch == IntPtr.Zero)
			{
				throw new InvalidOperationException("QueryInterface for IDispatch returned a null pointer.");
			}

			return dispatch;
		}

		private void EnsureNotDisposed() => ObjectDisposedException.ThrowIf(_dispatch == IntPtr.Zero, this);

		/// <summary>
		/// Reads an Item(index) object from a COM collection, uses it, and disposes it immediately.
		/// </summary>
		internal void UseDispatchItem(int index, Action<ComObject> action)
		{
			ArgumentNullException.ThrowIfNull(action);

			VARIANT itemIndexVariant = VariantHelpers.FromInt32(index);

			try
			{
				using ComObject item = GetDispatch("Item", itemIndexVariant);
				action(item);
			}
			finally
			{
				VariantHelpers.Clear(ref itemIndexVariant);
			}
		}

		internal T UseDispatchItem<T>(int index, Func<ComObject, T> func)
		{
			ArgumentNullException.ThrowIfNull(func);

			VARIANT itemIndexVariant = VariantHelpers.FromInt32(index);

			try
			{
				using ComObject item = GetDispatch("Item", itemIndexVariant);

				return func(item);
			}
			finally
			{
				VariantHelpers.Clear(ref itemIndexVariant);
			}
		}
	}

	[StructLayout(LayoutKind.Sequential)]
	private struct IDispatchVtbl
	{
		internal delegate* unmanaged[Stdcall]<IntPtr, Guid*, IntPtr*, int> QueryInterface;
		internal delegate* unmanaged[Stdcall]<IntPtr, uint> AddRef;
		internal delegate* unmanaged[Stdcall]<IntPtr, uint> Release;
		internal delegate* unmanaged[Stdcall]<IntPtr, uint*, int> GetTypeInfoCount;
		internal delegate* unmanaged[Stdcall]<IntPtr, uint, uint, IntPtr*, int> GetTypeInfo;
		internal delegate* unmanaged[Stdcall]<IntPtr, Guid*, char**, uint, uint, int*, int> GetIDsOfNames;
		internal delegate* unmanaged[Stdcall]<IntPtr, int, Guid*, uint, ushort, DispatchParams*, VARIANT*, ExcepInfo*, uint*, int> Invoke;
	}

	[StructLayout(LayoutKind.Sequential)]
	private struct DispatchParams
	{
		internal VARIANT* Arguments;
		internal int* NamedArguments;
		internal uint ArgumentCount;
		internal uint NamedArgumentCount;
	}

	// Helpers for creating, reading, formatting, and clearing COM VARIANT values.
	private static class VariantHelpers
	{
		// Builds a VT_I4 VARIANT for indexed COM calls such as collection.Item(index).
		internal static VARIANT FromInt32(int value) => new()
		{
			vt = VT_I4,
			lVal = value
		};

		// Builds a VARIANT_BOOL. COM uses -1 for true and 0 for false.
		internal static VARIANT FromBoolean(bool value) => new()
		{
			vt = VT_BOOL,
			lVal = value ? -1 : 0
		};

		// Builds a BSTR VARIANT and relies on VariantClear to free it after the COM call.
		internal static VARIANT FromBstr(string value)
		{
			IntPtr bstr = Marshal.StringToBSTR(value);

			if (bstr == IntPtr.Zero)
			{
				throw new InvalidOperationException("StringToBSTR failed.");
			}

			return new VARIANT
			{
				vt = VT_BSTR,
				bstrVal = bstr
			};
		}

		internal static string BstrToString(IntPtr bstr)
		{
			if (bstr == IntPtr.Zero)
			{
				return string.Empty;
			}

			return Marshal.PtrToStringBSTR(bstr) ?? string.Empty;
		}

		// Converts a COM VARIANT into UI text. Integer enum values are mapped by property name below.
		internal static string ToDisplayString(string propertyName, VARIANT value)
		{
			if (TryGetInt32(value, out int intValue))
			{
				return propertyName switch
				{
					"Type" => FormatUpdateType(intValue),
					"DeploymentAction" => FormatDeploymentAction(intValue),
					"DownloadPriority" => FormatDownloadPriority(intValue),
					"AutoDownload" => FormatAutoDownloadMode(intValue),
					"AutoSelection" => FormatAutoSelectionMode(intValue),
					"Impact" => FormatInstallationImpact(intValue),
					"RebootBehavior" => FormatInstallationRebootBehavior(intValue),
					_ => intValue.ToString(CultureInfo.InvariantCulture)
				};
			}

			return value.vt switch
			{
				VT_EMPTY => "None",
				VT_R8 => BitConverter.Int64BitsToDouble(value.llVal).ToString(CultureInfo.InvariantCulture),
				VT_DATE => DateTime.FromOADate(BitConverter.Int64BitsToDouble(value.llVal)).ToString("u", CultureInfo.InvariantCulture),
				VT_BSTR => BstrToString(value.bstrVal),
				VT_BOOL => value.lVal != 0 ? "True" : "False",
				VT_DISPATCH => value.bstrVal == IntPtr.Zero ? "Unavailable" : "COM dispatch object",
				VT_UNKNOWN => value.bstrVal == IntPtr.Zero ? "Unavailable" : "COM unknown object",
				VT_DECIMAL => DecimalToString(value),
				VT_I8 => value.llVal.ToString(CultureInfo.InvariantCulture),
				VT_UI8 => unchecked((ulong)value.llVal).ToString(CultureInfo.InvariantCulture),
				_ => $"Unsupported VARIANT type {value.vt.ToString(CultureInfo.InvariantCulture)}"
			};
		}

		// Handles signed and unsigned 32-bit enum values returned by WUA.
		private static bool TryGetInt32(VARIANT value, out int result)
		{
			if (value.vt == VT_I4)
			{
				result = value.lVal;

				return true;
			}

			if (value.vt == VT_UI4)
			{
				uint unsignedValue = unchecked((uint)value.llVal);

				if (unsignedValue <= int.MaxValue)
				{
					result = unchecked((int)unsignedValue);

					return true;
				}
			}

			result = 0;

			return false;
		}

		// Converts VT_DECIMAL manually because decimal is stored differently from the other VARIANT union fields.
		private static string DecimalToString(VARIANT value)
		{
			byte scale = unchecked((byte)(value.wReserved1 & 0x00FF));
			byte sign = unchecked((byte)((value.wReserved1 & 0xFF00) >> 8));
			int high = unchecked((int)(value.wReserved2 | ((uint)value.wReserved3 << 16)));
			ulong low64 = unchecked((ulong)value.llVal);
			int low = unchecked((int)(low64 & 0xFFFFFFFFUL));
			int middle = unchecked((int)((low64 >> 32) & 0xFFFFFFFFUL));

			decimal decimalValue = new(low, middle, high, (sign & 0x80) != 0, scale);

			return decimalValue.ToString(CultureInfo.InvariantCulture);
		}

		// https://learn.microsoft.com/windows/win32/api/wuapi/ne-wuapi-updatetype
		private static string FormatUpdateType(int value) => value switch
		{
			1 => "Software",
			2 => "Driver",
			_ => $"Unknown Update Type ({value.ToString(CultureInfo.InvariantCulture)})"
		};

		// https://learn.microsoft.com/windows/win32/api/wuapi/ne-wuapi-deploymentaction
		private static string FormatDeploymentAction(int value) => value switch
		{
			0 => "None",
			1 => "Installation",
			2 => "Uninstallation",
			3 => "Detection",
			4 => "Optional Installation",
			_ => $"Unknown Deployment Action ({value.ToString(CultureInfo.InvariantCulture)})"
		};

		// https://learn.microsoft.com/windows/win32/api/wuapi/ne-wuapi-downloadpriority
		private static string FormatDownloadPriority(int value) => value switch
		{
			1 => "Low",
			2 => "Normal",
			3 => "High",
			4 => "Extra High",
			_ => $"Unknown Download Priority ({value.ToString(CultureInfo.InvariantCulture)})"
		};

		// https://learn.microsoft.com/windows/win32/api/wuapi/ne-wuapi-autodownloadmode
		private static string FormatAutoDownloadMode(int value) => value switch
		{
			0 => "Let Windows Update decide",
			1 => "Never auto download",
			2 => "Always auto download",
			_ => $"Unknown Auto Download Mode ({value.ToString(CultureInfo.InvariantCulture)})"
		};

		// https://learn.microsoft.com/windows/win32/api/wuapi/ne-wuapi-autoselectionmode
		private static string FormatAutoSelectionMode(int value) => value switch
		{
			0 => "Let Windows Update decide",
			1 => "Auto select if downloaded",
			2 => "Never auto select",
			3 => "Always auto select",
			_ => $"Unknown Auto Selection Mode ({value.ToString(CultureInfo.InvariantCulture)})"
		};

		// https://learn.microsoft.com/windows/win32/api/wuapi/ne-wuapi-installationimpact
		private static string FormatInstallationImpact(int value) => value switch
		{
			0 => "Normal",
			1 => "Minor",
			2 => "Requires Exclusive Handling",
			_ => $"Unknown Installation Impact ({value.ToString(CultureInfo.InvariantCulture)})"
		};

		// https://learn.microsoft.com/windows/win32/api/wuapi/ne-wuapi-installationrebootbehavior
		private static string FormatInstallationRebootBehavior(int value) => value switch
		{
			0 => "Never Reboots",
			1 => "Always Requires Reboot",
			2 => "Can Request Reboot",
			_ => $"Unknown Installation Reboot Behavior ({value.ToString(CultureInfo.InvariantCulture)})"
		};

		// Frees BSTR and other VARIANT-owned resources by calling VariantClear.
		internal static void Clear(ref VARIANT value)
		{
			if (value.vt == VT_EMPTY)
			{
				return;
			}

			_ = NativeMethods.VariantClear(ref value);
			value = default;
		}
	}

	[StructLayout(LayoutKind.Sequential)]
	private struct ExcepInfo
	{
		internal ushort Code;
		internal ushort Reserved;
		internal IntPtr Source;
		internal IntPtr Description;
		internal IntPtr HelpFile;
		internal uint HelpContext;
		internal IntPtr ReservedPointer;
		internal IntPtr DeferredFillIn;
		internal int Scode;

		internal readonly string Description1 => Description == IntPtr.Zero
			? string.Empty
			: Marshal.PtrToStringBSTR(Description) ?? string.Empty;

		internal void Clear()
		{
			if (Source != IntPtr.Zero)
			{
				NativeMethods.SysFreeString(Source);
				Source = IntPtr.Zero;
			}

			if (Description != IntPtr.Zero)
			{
				NativeMethods.SysFreeString(Description);
				Description = IntPtr.Zero;
			}

			if (HelpFile != IntPtr.Zero)
			{
				NativeMethods.SysFreeString(HelpFile);
				HelpFile = IntPtr.Zero;
			}
		}
	}

	private static void ThrowIfFailed(int hr, string message)
	{
		if (hr < 0)
		{
			throw new InvalidOperationException($"{message} HRESULT: 0x{hr:X8}.");
		}
	}
}

// Immutable display model for each update returned by WUA. COM objects are never stored here.
internal sealed partial class WindowsUpdateItem(
	string title,
	bool isHidden,
	string updateId,
	int revisionNumber,
	string description,
	string type,
	string msrcSeverity,
	string supportUrl,
	string isInstalled,
	string isDownloaded,
	string isMandatory,
	string isBeta,
	string canRequireSource,
	string autoSelectOnWebSites,
	string browseOnly,
	string eulaAccepted,
	string handlerId,
	string deploymentAction,
	string downloadPriority,
	string minDownloadSize,
	string maxDownloadSize,
	string deadline,
	string lastDeploymentChangeTime,
	string kbArticleIds,
	string securityBulletinIds,
	string supersededUpdateIds,
	string languages,
	string moreInfoUrls,
	WindowsUpdateCollection<WindowsUpdateCategory> categories,
	string bundledUpdates,
	WindowsUpdateCollection<WindowsUpdateDownloadContent> downloadContents,
	WindowsUpdateBehaviorDetails installationBehavior,
	WindowsUpdateBehaviorDetails uninstallationBehavior,
	string requiresReboot,
	string isUninstallable,
	string releaseNotes,
	string uninstallationNotes,
	string uninstallationSteps,
	string recommendedCpuSpeed,
	string recommendedMemory,
	string recommendedHardDiskSpace,
	string eulaText,
	WindowsUpdateDriverDetails driverDetails,
	string autoDownload,
	string autoSelection)
{
	public string Title => title;
	public bool IsHidden => isHidden;
	public string UpdateId => updateId;
	public int RevisionNumber => revisionNumber;
	public string Description => description;
	public string Type => type;
	public string MsrcSeverity => msrcSeverity;
	public string SupportUrl => supportUrl;
	public string IsInstalled => isInstalled;
	public string IsDownloaded => isDownloaded;
	public string IsMandatory => isMandatory;
	public string IsBeta => isBeta;
	public string CanRequireSource => canRequireSource;
	public string AutoSelectOnWebSites => autoSelectOnWebSites;
	public string BrowseOnly => browseOnly;
	public string EulaAccepted => eulaAccepted;
	public string HandlerId => handlerId;
	public string DeploymentAction => deploymentAction;
	public string DownloadPriority => downloadPriority;
	[JsonIgnore]
	public string MinDownloadSize => minDownloadSize;
	[JsonIgnore]
	public string MaxDownloadSize => maxDownloadSize;
	public string Deadline => deadline;
	public string LastDeploymentChangeTime => WindowsUpdateDisplayFormatter.FormatDateTimeDisplay(lastDeploymentChangeTime);
	public string KbArticleIds => kbArticleIds;
	public string SecurityBulletinIds => securityBulletinIds;
	public string SupersededUpdateIds => supersededUpdateIds;
	public string Languages => languages;
	public string MoreInfoUrls => moreInfoUrls;
	public WindowsUpdateCollection<WindowsUpdateCategory> Categories => categories;
	public string BundledUpdates => bundledUpdates;
	public WindowsUpdateCollection<WindowsUpdateDownloadContent> DownloadContents => downloadContents;
	public WindowsUpdateBehaviorDetails InstallationBehavior => installationBehavior;
	public WindowsUpdateBehaviorDetails UninstallationBehavior => uninstallationBehavior;
	public string RequiresReboot => requiresReboot;
	public string IsUninstallable => isUninstallable;
	public string ReleaseNotes => releaseNotes;
	public string UninstallationNotes => uninstallationNotes;
	public string UninstallationSteps => uninstallationSteps;
	public string RecommendedCpuSpeed => recommendedCpuSpeed;
	public string RecommendedMemory => recommendedMemory;
	public string RecommendedHardDiskSpace => recommendedHardDiskSpace;
	public string EulaText => eulaText;
	public WindowsUpdateDriverDetails DriverDetails => driverDetails;
	public string AutoDownload => autoDownload;
	public string AutoSelection => autoSelection;

	[JsonIgnore]
	public string RevisionNumberDisplay => revisionNumber.ToString(CultureInfo.InvariantCulture);

	[JsonIgnore]
	public string IsHiddenDisplay => isHidden ? "True" : "False";

	[JsonIgnore]
	public string HiddenStateGlyph => isHidden ? "\uED1A" : "\uE890";

	[JsonIgnore]
	public string HiddenStateText => isHidden ? "Hidden" : "Visible";

	[JsonIgnore]
	/// <summary>
	/// Sort key intentionally uses the raw Windows Update date string.
	/// The UI display formatting should not affect sorting accuracy.
	/// </summary>
	public DateTimeOffset LastDeploymentChangeTimeSortKey => WindowsUpdateDisplayFormatter.ParseDateForSort(lastDeploymentChangeTime);

	[JsonIgnore]
	public string Summary => string.Format(
		CultureInfo.InvariantCulture,
		"{0} | Severity: {1} | KB: {2}",
		type,
		msrcSeverity,
		kbArticleIds);

	[JsonIgnore]
	public string SecurityBulletinIdsDisplay => WindowsUpdateDisplayFormatter.FormatDelimitedList(securityBulletinIds, ',');

	[JsonIgnore]
	public string SupersededUpdateIdsDisplay => WindowsUpdateDisplayFormatter.FormatDelimitedList(supersededUpdateIds, ',');

	[JsonIgnore]
	public string LanguagesDisplay => WindowsUpdateDisplayFormatter.FormatDelimitedList(languages, ',');

	[JsonIgnore]
	public string MoreInfoUrlsDisplay => WindowsUpdateDisplayFormatter.FormatDelimitedList(moreInfoUrls, ',');

	[JsonIgnore]
	public string CategoriesDisplay => WindowsUpdateDisplayFormatter.FormatCategories(categories);

	[JsonIgnore]
	public string BundledUpdatesDisplay => WindowsUpdateDisplayFormatter.FormatDelimitedList(bundledUpdates, ';');

	[JsonIgnore]
	public string DownloadContentsDisplay => WindowsUpdateDisplayFormatter.FormatDownloadContents(downloadContents);

	public string InstallationBehaviorDisplay => WindowsUpdateDisplayFormatter.FormatBehaviorDetails(installationBehavior);

	public string MinDownloadSizeDisplay => WindowsUpdateDisplayFormatter.FormatByteSize(minDownloadSize);

	public string MaxDownloadSizeDisplay => WindowsUpdateDisplayFormatter.FormatByteSize(maxDownloadSize);

	[JsonIgnore]
	public string UninstallationBehaviorDisplay => WindowsUpdateDisplayFormatter.FormatBehaviorDetails(uninstallationBehavior);

	[JsonIgnore]
	public string UninstallationStepsDisplay => WindowsUpdateDisplayFormatter.FormatDelimitedList(uninstallationSteps, ',');

	[JsonIgnore]
	public string DriverDetailsDisplay => WindowsUpdateDisplayFormatter.FormatDriverDetails(driverDetails);

	internal List<WindowsUpdateLink> SupportUrlLinks => field ??= CreateLinksFromDelimitedText(SupportUrl);
	internal Visibility SupportUrlLinksVisibility => SupportUrlLinks.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
	internal Visibility SupportUrlTextVisibility => SupportUrlLinks.Count > 0 ? Visibility.Collapsed : Visibility.Visible;
	internal List<WindowsUpdateLink> HandlerIdLinks => field ??= CreateLinksFromDelimitedText(HandlerId);
	internal Visibility HandlerIdLinksVisibility => HandlerIdLinks.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
	internal Visibility HandlerIdTextVisibility => HandlerIdLinks.Count > 0 ? Visibility.Collapsed : Visibility.Visible;
	internal List<WindowsUpdateLink> MoreInfoUrlLinks { get => field ??= CreateLinksFromDelimitedText(MoreInfoUrls); private set; }
	internal Visibility MoreInfoUrlLinksVisibility => MoreInfoUrlLinks.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
	internal Visibility MoreInfoUrlsTextVisibility => MoreInfoUrlLinks.Count > 0 ? Visibility.Collapsed : Visibility.Visible;

	private static List<WindowsUpdateLink> CreateLinksFromDelimitedText(string value)
	{
		List<WindowsUpdateLink> links = [];

		if (WindowsUpdateDisplayFormatter.IsEmptyDisplayValue(value))
		{
			return links;
		}

		string[] candidates = value.Split(
			[',', ';', '\r', '\n'],
			StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

		for (int index = 0; index < candidates.Length; index++)
		{
			string candidate = candidates[index];

			if (TryCreateHttpLink(candidate, out WindowsUpdateLink? link))
			{
				links.Add(link);
			}
		}

		return links;
	}

	private static bool TryCreateHttpLink(string value, [NotNullWhen(true)] out WindowsUpdateLink? link)
	{
		link = null;

		if (!Uri.TryCreate(value, UriKind.Absolute, out Uri? uri))
		{
			return false;
		}

		if (!string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) &&
			!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
		{
			return false;
		}

		link = new(value, uri);
		return true;
	}
}

// Presentation helpers for the WindowsUpdateItem model.
internal static class WindowsUpdateDisplayFormatter
{
	// Formats byte counts from WUA size properties into KB, MB, or GB.
	internal static string FormatByteSize(string value)
	{
		if (IsEmptyDisplayValue(value))
		{
			return value;
		}

		if (!ulong.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out ulong bytes))
		{
			return value;
		}

		const double KiB = 1024D;
		const double MiB = KiB * 1024D;
		const double GiB = MiB * 1024D;

		if (bytes >= (ulong)GiB)
		{
			return string.Format(
				CultureInfo.InvariantCulture,
				"{0:N2} GB",
				bytes / GiB);
		}

		if (bytes >= (ulong)MiB)
		{
			return string.Format(
				CultureInfo.InvariantCulture,
				"{0:N2} MB",
				bytes / MiB);
		}

		if (bytes >= (ulong)KiB)
		{
			return string.Format(
				CultureInfo.InvariantCulture,
				"{0:N2} KB",
				bytes / KiB);
		}

		if (bytes == 0)
		{
			return "0 KB";
		}

		return string.Format(
			CultureInfo.InvariantCulture,
			"{0:N2} KB",
			bytes / KiB);
	}

	// Normalizes WUA date strings for the UI. Unknown values pass through unchanged.
	internal static string FormatDateTimeDisplay(string value)
	{
		if (IsEmptyDisplayValue(value))
		{
			return value;
		}

		if (TryParseWindowsUpdateDate(value, out DateTimeOffset parsedDate))
		{
			return FormatDateTimeOffsetForDisplay(parsedDate);
		}

		return value;
	}

	// Parses the raw date value for sorting without depending on the formatted display string.
	internal static DateTimeOffset ParseDateForSort(string value)
	{
		if (IsEmptyDisplayValue(value))
		{
			return DateTimeOffset.MinValue;
		}

		return TryParseWindowsUpdateDate(value, out DateTimeOffset parsedDate)
			? parsedDate
			: DateTimeOffset.MinValue;
	}

	// Parses WUA date strings consistently for display and sorting.
	private static bool TryParseWindowsUpdateDate(string value, out DateTimeOffset result)
	{
		if (DateTimeOffset.TryParse(
			value,
			CultureInfo.InvariantCulture,
			DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
			out DateTimeOffset invariantDate))
		{
			result = invariantDate;
			return true;
		}

		if (DateTimeOffset.TryParse(
			value,
			CultureInfo.CurrentCulture,
			DateTimeStyles.AssumeLocal,
			out DateTimeOffset currentCultureDate))
		{
			result = currentCultureDate.ToUniversalTime();
			return true;
		}

		result = DateTimeOffset.MinValue;
		return false;
	}

	// Converts comma or other delimiter separated metadata into one item per line.
	internal static string FormatDelimitedList(string value, char delimiter)
	{
		if (IsEmptyDisplayValue(value))
		{
			return value;
		}

		string[] parts = value.Split(delimiter, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

		if (parts.Length == 0)
		{
			return value;
		}

		return string.Join(Environment.NewLine, parts);
	}

	// Converts text like "Name=value, Other=value" into labeled UI lines.
	internal static string FormatKeyValueList(string value)
	{
		if (IsEmptyDisplayValue(value))
		{
			return value;
		}

		string[] pairs = value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

		if (pairs.Length == 0)
		{
			return value;
		}

		List<string> lines = new(capacity: pairs.Length);

		for (int index = 0; index < pairs.Length; index++)
		{
			string pair = pairs[index];

			int separatorIndex = pair.IndexOf('=', StringComparison.Ordinal);

			if (separatorIndex <= 0 || separatorIndex == pair.Length - 1)
			{
				lines.Add(pair);
				continue;
			}

			string name = pair[..separatorIndex].Trim();
			string displayName = FormatPropertyName(name);
			string displayValue = pair[(separatorIndex + 1)..].Trim();

			lines.Add($"{displayName}: {displayValue}");
		}

		return string.Join(Environment.NewLine, lines);
	}

	// Formats download content records for the UI. Large collections are summarized to avoid rendering many long URLs.
	internal static string FormatDownloadContents(WindowsUpdateCollection<WindowsUpdateDownloadContent> value)
	{
		if (value.Items.Count == 0)
		{
			return value.EmptyDisplayText;
		}

		if (value.Items.Count > 3)
		{
			return string.Format(
				CultureInfo.InvariantCulture,
				"{0} download content item(s). Export to JSON to view full download URLs.",
				value.Items.Count);
		}

		List<string> blocks = new(capacity: value.Items.Count);
		for (int index = 0; index < value.Items.Count; index++)
		{
			WindowsUpdateDownloadContent item = value.Items[index];
			blocks.Add(string.Join(
				Environment.NewLine,
				FormatNamedValue(nameof(WindowsUpdateDownloadContent.FileName), item.FileName),
				FormatNamedValue(nameof(WindowsUpdateDownloadContent.DownloadUrl), item.DownloadUrl)));
		}

		return string.Join(Environment.NewLine + Environment.NewLine, blocks);
	}

	// Formats category records and their metadata as separate blocks without parsing category text.
	internal static string FormatCategories(WindowsUpdateCollection<WindowsUpdateCategory> value)
	{
		if (value.Items.Count == 0)
		{
			return value.EmptyDisplayText;
		}
		List<string> blocks = new(capacity: value.Items.Count);
		for (int index = 0; index < value.Items.Count; index++)
		{
			WindowsUpdateCategory item = value.Items[index];
			blocks.Add(string.Join(
				Environment.NewLine,
				item.Name,
				FormatNamedValue(nameof(WindowsUpdateCategory.CategoryID), item.CategoryID),
				FormatNamedValue(nameof(WindowsUpdateCategory.TypeID), item.TypeID)));
		}
		return string.Join(Environment.NewLine + Environment.NewLine, blocks);
	}
	internal static string FormatBehaviorDetails(WindowsUpdateBehaviorDetails value)
	{
		if (!value.IsAvailable)
		{
			return value.EmptyDisplayText;
		}
		return string.Join(
			Environment.NewLine,
			FormatNamedValue(nameof(WindowsUpdateBehaviorDetails.CanRequestUserInput), value.CanRequestUserInput),
			FormatNamedValue(nameof(WindowsUpdateBehaviorDetails.Impact), value.Impact),
			FormatNamedValue(nameof(WindowsUpdateBehaviorDetails.RebootBehavior), value.RebootBehavior),
			FormatNamedValue(nameof(WindowsUpdateBehaviorDetails.RequiresNetworkConnectivity), value.RequiresNetworkConnectivity));
	}
	internal static string FormatDriverDetails(WindowsUpdateDriverDetails value) => string.Join(
			Environment.NewLine,
			FormatNamedValue(nameof(WindowsUpdateDriverDetails.DeviceProblemNumber), value.DeviceProblemNumber),
			FormatNamedValue(nameof(WindowsUpdateDriverDetails.DeviceStatus), value.DeviceStatus),
			FormatNamedValue(nameof(WindowsUpdateDriverDetails.DriverClass), value.DriverClass),
			FormatNamedValue(nameof(WindowsUpdateDriverDetails.DriverHardwareID), value.DriverHardwareID),
			FormatNamedValue(nameof(WindowsUpdateDriverDetails.DriverManufacturer), value.DriverManufacturer),
			FormatNamedValue(nameof(WindowsUpdateDriverDetails.DriverModel), value.DriverModel),
			FormatNamedValue(nameof(WindowsUpdateDriverDetails.DriverProvider), value.DriverProvider),
			FormatNamedValue(nameof(WindowsUpdateDriverDetails.DriverVerDate), value.DriverVerDate));

	// Formats a property name and value as a single display line.
	private static string FormatNamedValue(string name, string value) => $"{FormatPropertyName(name)}: {value}";

	internal static string FormatPropertyName(string value) => value switch
	{
		"CategoryID" => "Category ID",
		"TypeID" => "Type ID",
		"CanRequestUserInput" => "Can request user input",
		"RebootBehavior" => "Reboot behavior",
		"RequiresNetworkConnectivity" => "Requires network connectivity",
		"DownloadUrl" => "Download URL",
		"FileName" => "File name",
		"DeviceProblemNumber" => "Device problem number",
		"DeviceStatus" => "Device status",
		"DriverClass" => "Driver class",
		"DriverHardwareID" => "Driver hardware ID",
		"DriverManufacturer" => "Driver manufacturer",
		"DriverModel" => "Driver model",
		"DriverProvider" => "Driver provider",
		"DriverVerDate" => "Driver version date",
		_ => SplitPascalCase(value)
	};

	// Fallback label formatter for property names not listed explicitly above.
	internal static string SplitPascalCase(string value)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			return value;
		}

		List<char> chars = new(capacity: value.Length + 8);

		for (int index = 0; index < value.Length; index++)
		{
			char current = value[index];

			if (index > 0 &&
				char.IsUpper(current) &&
				!char.IsWhiteSpace(value[index - 1]) &&
				!char.IsUpper(value[index - 1]))
			{
				chars.Add(' ');
			}

			chars.Add(current);
		}

		return new string(chars.ToArray());
	}

	internal static bool IsEmptyDisplayValue(string value) =>
		 string.IsNullOrWhiteSpace(value) ||
			string.Equals(value, "None", StringComparison.OrdinalIgnoreCase) ||
			string.Equals(value, "Unavailable", StringComparison.OrdinalIgnoreCase);

	private static string FormatDateTimeOffsetForDisplay(DateTimeOffset value)
	{
		DateTime utcDateTime = value.UtcDateTime;

		if (utcDateTime.TimeOfDay == TimeSpan.Zero)
		{
			return utcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
		}

		return utcDateTime.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
	}
}

// Generic wrapper for WUA collections where an empty list can mean either "None" or "Unavailable".
internal sealed class WindowsUpdateCollection<T>(IReadOnlyList<T> items, string emptyDisplayText)
{
	public IReadOnlyList<T> Items => items;
	public string EmptyDisplayText => emptyDisplayText;
	internal static WindowsUpdateCollection<T> None() => new([], "None");
	internal static WindowsUpdateCollection<T> Unavailable() => new([], "Unavailable");
	internal static WindowsUpdateCollection<T> FromItems(IReadOnlyList<T> items) => new(items, "None");
}
// WUA category metadata.
internal sealed class WindowsUpdateCategory(string name, string categoryID, string typeID)
{
	public string Name => name;
	public string CategoryID => categoryID;
	public string TypeID => typeID;
}
// WUA download content metadata.
internal sealed class WindowsUpdateDownloadContent(string fileName, string downloadUrl)
{
	public string FileName => fileName;
	public string DownloadUrl => downloadUrl;
}
// installation behavior metadata.
internal sealed class WindowsUpdateBehaviorDetails(
	bool isAvailable,
	string emptyDisplayText,
	string canRequestUserInput,
	string impact,
	string rebootBehavior,
	string requiresNetworkConnectivity)
{
	public bool IsAvailable => isAvailable;
	public string EmptyDisplayText => emptyDisplayText;
	public string CanRequestUserInput => canRequestUserInput;
	public string Impact => impact;
	public string RebootBehavior => rebootBehavior;
	public string RequiresNetworkConnectivity => requiresNetworkConnectivity;
	internal static WindowsUpdateBehaviorDetails Available(string canRequestUserInput, string impact, string rebootBehavior, string requiresNetworkConnectivity) =>
		new(true, "None", canRequestUserInput, impact, rebootBehavior, requiresNetworkConnectivity);
	internal static WindowsUpdateBehaviorDetails Unavailable() => new(false, "Unavailable", string.Empty, string.Empty, string.Empty, string.Empty);
}
// Driver-specific metadata exposed by IWindowsDriverUpdate-compatible update objects.
internal sealed class WindowsUpdateDriverDetails(
	string deviceProblemNumber,
	string deviceStatus,
	string driverClass,
	string driverHardwareID,
	string driverManufacturer,
	string driverModel,
	string driverProvider,
	string driverVerDate)
{
	public string DeviceProblemNumber => deviceProblemNumber;
	public string DeviceStatus => deviceStatus;
	public string DriverClass => driverClass;
	public string DriverHardwareID => driverHardwareID;
	public string DriverManufacturer => driverManufacturer;
	public string DriverModel => driverModel;
	public string DriverProvider => driverProvider;
	public string DriverVerDate => driverVerDate;
}
// Result model for hiding or unhiding a selected update.
internal sealed class HiddenStateChangeResult(string title, bool succeeded, string message)
{
	internal string Title => title;
	internal bool Succeeded => succeeded;
	internal string Message => message;
}

// Link model used by XAML ItemsControls for support, handler, and more-info URLs.
internal sealed class WindowsUpdateLink(string text, Uri uri)
{
	internal string Text => text;
	internal Uri Uri => uri;
}
