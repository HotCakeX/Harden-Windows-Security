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

using System.Collections.Frozen;
using System.Collections.Generic;
using System.Linq;
using CommonCore.IncrementalCollection;
using CommonCore.IntelGathering;
using Microsoft.UI.Xaml.Controls;

namespace CommonCore.Others;

/// <summary>
/// This class includes methods that are helpers for the custom ListView implementations in this application.
/// </summary>
internal static partial class ListViewHelper
{
	// Pre-computed property getters for high performance.
	// Used for column sorting and column copying (single cell and entire row), for all of the ListViews that display FileIdentity data type.
	internal static readonly Lazy<FrozenDictionary<string, (string Label, Func<FileIdentity, object?> Getter)>> FileIdentityPropertyMappings = new(static () => new Dictionary<string, (string Label, Func<FileIdentity, object?> Getter)>
	{
		{ "Origin", ("Origin", static fi => fi.Origin) },
		{ "SignatureStatus", (Atlas.GetStr("SignatureStatusHeader/Text"), static fi => fi.SignatureStatus) },
		{ "Action", (Atlas.GetStr("ActionHeader/Text"), static fi => fi.Action) },
		{ "EventID", ("Event ID", static fi => fi.EventID) },
		{ "TimeCreated", (Atlas.GetStr("TimeCreatedHeader/Text"), static fi => fi.TimeCreated) },
		{ "ComputerName", (Atlas.GetStr("ComputerNameHeader/Text"), static fi => fi.ComputerName) },
		{ "PolicyGUID", (Atlas.GetStr("PolicyGUIDHeader/Text"), static fi => fi.PolicyGUID) },
		{ "UserWriteable", ("User Writeable", static fi => fi.UserWriteable) },
		{ "ProcessName", ("Process Name", static fi => fi.ProcessName) },
		{ "RequestedSigningLevel", ("Requested Signing Level", static fi => fi.RequestedSigningLevel) },
		{ "ValidatedSigningLevel", ("Validated Signing Level", static fi => fi.ValidatedSigningLevel) },
		{ "Status", ("Status", static fi => fi.Status) },
		{ "USN", ("USN", static fi => fi.USN) },
		{ "PolicyName", (Atlas.GetStr("PolicyNameHeader/Text"), static fi => fi.PolicyName) },
		{ "PolicyID", (Atlas.GetStr("PolicyIDHeader/Text"), static fi => fi.PolicyID) },
		{ "PolicyHash", ("Policy Hash", static fi => fi.PolicyHash) },
		{ "UserID", ("User ID", static fi => fi.UserID) },
		{ "FilePath", (Atlas.GetStr("FilePathHeader/Text"), static fi => fi.FilePath) },
		{ "FileName", (Atlas.GetStr("FileNameHeader/Text"), static fi => fi.FileName) },
		{ "SHA1Hash", (Atlas.GetStr("SHA1HashHeader/Text"), static fi => fi.SHA1Hash) },
		{ "SHA256Hash", (Atlas.GetStr("SHA256HashHeader/Text"), static fi => fi.SHA256Hash) },
		{ "SHA1PageHash", (Atlas.GetStr("SHA1PageHashHeader/Text"), static fi => fi.SHA1PageHash) },
		{ "SHA256PageHash", (Atlas.GetStr("SHA256PageHashHeader/Text"), static fi => fi.SHA256PageHash) },
		{ "SHA1FlatHash", (Atlas.GetStr("SHA1FlatHashHeader/Text"), static fi => fi.SHA1FlatHash) },
		{ "SHA256FlatHash", (Atlas.GetStr("SHA256FlatHashHeader/Text"), static fi => fi.SHA256FlatHash) },
		{ "SISigningScenario", (Atlas.GetStr("SigningScenarioHeader/Text"), static fi => fi.SISigningScenario) },
		{ "OriginalFileName", (Atlas.GetStr("OriginalFileNameHeader/Text"), static fi => fi.OriginalFileName) },
		{ "InternalName", (Atlas.GetStr("InternalNameHeader/Text"), static fi => fi.InternalName) },
		{ "FileDescription", (Atlas.GetStr("FileDescriptionHeader/Text"), static fi => fi.FileDescription) },
		{ "ProductName", (Atlas.GetStr("ProductNameHeader/Text"), static fi => fi.ProductName) },
		{ "FileVersion", (Atlas.GetStr("FileVersionHeader/Text"), static fi => fi.FileVersion) },
		{ "PackageFamilyName", (Atlas.GetStr("PackageFamilyNameHeader/Text"), static fi => fi.PackageFamilyName) },
		{ "FilePublishersToDisplay", (Atlas.GetStr("FilePublishersHeader/Text"), static fi => fi.FilePublishersToDisplay) },
		{ "HasWHQLSigner", (Atlas.GetStr("HasWHQLSignerHeader/Text"), static fi => fi.HasWHQLSigner) },
		{ "IsECCSigned", (Atlas.GetStr("IsECCSignedHeader/Text"), static fi => fi.IsECCSigned) },
		{ "Opus", (Atlas.GetStr("OpusDataHeader/Text"), static fi => fi.Opus) }
		}.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase), System.Threading.LazyThreadSafetyMode.None);

	/// <summary>
	/// Applies the search, date, and property filters to the provided data.
	/// </summary>
	/// <param name="allFileIdentities">
	/// The complete list of FileIdentity objects (unfiltered).
	/// </param>
	/// <param name="filteredCollection">
	/// The ObservableCollection that will be populated with the filtered results.
	/// </param>
	/// <param name="searchText">
	/// The search term.
	/// </param>
	/// <param name="selectedDate">
	/// An optional DateTimeOffset for date filtering. If null, no date filtering is applied.
	/// </param>
	/// <param name="regKey">used to find the ListView in the cache.</param>
	/// <param name="selectedPropertyFilter">
	/// An optional PropertyFilterItem for property-based filtering. If null, no property filtering is applied.
	/// </param>
	/// <param name="propertyFilterValue">
	/// The value to filter by for the selected property. If null or empty, no property filtering is applied.
	/// </param>
	internal static void ApplyFilters(
		List<FileIdentity> allFileIdentities,
		RangedObservableCollection<FileIdentity> filteredCollection,
		string? searchText,
		DateTimeOffset? selectedDate,
		ListViewsRegistry regKey,
		PropertyFilterItem? selectedPropertyFilter = null,
		string? propertyFilterValue = null
		)
	{
		// Get the ListView ScrollViewer info
		ScrollViewer? Sv = GetScrollViewerFromCache(regKey);

		double? savedHorizontal = null;
		if (Sv != null)
		{
			savedHorizontal = Sv.HorizontalOffset;
		}

		bool NoFilter = true;

		// Get the search term from the SearchBox, converting it to lowercase for case-insensitive searching
		string? searchTerm = searchText?.Trim();

		// Start with the full list.
		// This list is used as the base set for filtering to preserve original data
		IEnumerable<FileIdentity> filteredResults = allFileIdentities;

		// If a selectedDate is provided, filter by date.
		// Filter results to include only items where 'TimeCreated' is greater than or equal to the selected date.
		if (selectedDate is not null)
		{
			NoFilter = false;

			filteredResults = filteredResults.Where(item =>
				item.TimeCreated.HasValue && item.TimeCreated.Value.Date >= selectedDate.Value.Date);
		}

		// Filter results further to match the search term across multiple properties, case-insensitively
		if (!string.IsNullOrWhiteSpace(searchTerm))
		{
			NoFilter = false;

			filteredResults = filteredResults.Where(output =>
				(output.FileName is not null && output.FileName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				output.SignatureStatus_String.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
				output.Action_String.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
				(output.OriginalFileName is not null && output.OriginalFileName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.InternalName is not null && output.InternalName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.FileDescription is not null && output.FileDescription.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.ProductName is not null && output.ProductName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.FileVersion_String is not null && output.FileVersion_String.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.PackageFamilyName is not null && output.PackageFamilyName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.FilePath is not null && output.FilePath.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.SHA256FlatHash is not null && output.SHA256FlatHash.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.SHA256Hash is not null && output.SHA256Hash.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.FilePublishersToDisplay is not null && output.FilePublishersToDisplay.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.Opus is not null && output.Opus.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.PolicyName is not null && output.PolicyName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.ComputerName is not null && output.ComputerName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase))
			);
		}

		// Apply property-based filter if specified
		if (selectedPropertyFilter is not null && !string.IsNullOrEmpty(propertyFilterValue))
		{
			NoFilter = false;

			string filterValue = propertyFilterValue.Trim();
			filteredResults = filteredResults.Where(item =>
			{
				object? propertyValue = selectedPropertyFilter.Getter(item);
				return propertyValue is not null &&
					   propertyValue.ToString()?.Contains(filterValue, StringComparison.OrdinalIgnoreCase) == true;
			});
		}

		// Clear the ObservableCollection
		filteredCollection.Clear();

		// If there are no filters then use the original list (AddRange's high performance overload), otherwise add the new filtered results to the ObservableCollection.
		if (NoFilter)
		{
			filteredCollection.AddRange(allFileIdentities);
		}
		else
		{
			filteredCollection.AddRange(filteredResults);
		}

		// restore horizontal scroll position
		_ = Sv?.ChangeView(savedHorizontal, null, null, disableAnimation: false);
	}

	/// <summary>
	/// Creates a collection of PropertyFilterItem objects from FileIdentityPropertyMappings for use in ComboBox binding
	/// </summary>
	/// <returns>List of PropertyFilterItem objects</returns>
	internal static List<PropertyFilterItem> CreatePropertyFilterItems()
	{
		List<PropertyFilterItem> items = new(FileIdentityPropertyMappings.Value.Count);
		foreach (KeyValuePair<string, (string Label, Func<FileIdentity, object?> Getter)> mapping in FileIdentityPropertyMappings.Value)
		{
			items.Add(new PropertyFilterItem(mapping.Key, mapping.Value.Label, mapping.Value.Getter));
		}
		return items;
	}

	/// <summary>
	/// Represents a property that can be used for filtering
	/// </summary>
	internal sealed class PropertyFilterItem(string propertyKey, string displayName, Func<FileIdentity, object?> getter)
	{
		internal string PropertyKey => propertyKey;
		internal string DisplayName => displayName;
		internal Func<FileIdentity, object?> Getter => getter;

		public override string ToString() => DisplayName;
	}
}
