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
using System.Collections.ObjectModel;
using System.Linq;
using AppControlManager.IntelGathering;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.Others;

/// <summary>
/// This class includes methods that are helpers for the custom ListView implementations in this application.
/// </summary>
internal static partial class ListViewHelper
{
	// Pre-computed property getters for high performance.
	// Used for column sorting and column copying (single cell and entire row), for all of the ListViews that display FileIdentity data type.
	internal static readonly FrozenDictionary<string, (string Label, Func<FileIdentity, object?> Getter)> FileIdentityPropertyMappings = new Dictionary<string, (string Label, Func<FileIdentity, object?> Getter)>
	{
		{ "Origin", ("Origin", fi => fi.Origin) },
		{ "SignatureStatus", (GlobalVars.GetStr("SignatureStatusHeader/Text"), fi => fi.SignatureStatus) },
		{ "Action", (GlobalVars.GetStr("ActionHeader/Text"), fi => fi.Action) },
		{ "EventID", ("Event ID", fi => fi.EventID) },
		{ "TimeCreated", (GlobalVars.GetStr("TimeCreatedHeader/Text"), fi => fi.TimeCreated) },
		{ "ComputerName", (GlobalVars.GetStr("ComputerNameHeader/Text"), fi => fi.ComputerName) },
		{ "PolicyGUID", (GlobalVars.GetStr("PolicyGUIDHeader/Text"), fi => fi.PolicyGUID) },
		{ "UserWriteable", ("User Writeable", fi => fi.UserWriteable) },
		{ "ProcessName", ("Process Name", fi => fi.ProcessName) },
		{ "RequestedSigningLevel", ("Requested Signing Level", fi => fi.RequestedSigningLevel) },
		{ "ValidatedSigningLevel", ("Validated Signing Level", fi => fi.ValidatedSigningLevel) },
		{ "Status", ("Status", fi => fi.Status) },
		{ "USN", ("USN", fi => fi.USN) },
		{ "PolicyName", (GlobalVars.GetStr("PolicyNameHeader/Text"), fi => fi.PolicyName) },
		{ "PolicyID", (GlobalVars.GetStr("PolicyIDHeader/Text"), fi => fi.PolicyID) },
		{ "PolicyHash", ("Policy Hash", fi => fi.PolicyHash) },
		{ "UserID", ("User ID", fi => fi.UserID) },
		{ "FilePath", (GlobalVars.GetStr("FilePathHeader/Text"), fi => fi.FilePath) },
		{ "FileName", (GlobalVars.GetStr("FileNameHeader/Text"), fi => fi.FileName) },
		{ "SHA1Hash", (GlobalVars.GetStr("SHA1HashHeader/Text"), fi => fi.SHA1Hash) },
		{ "SHA256Hash", (GlobalVars.GetStr("SHA256HashHeader/Text"), fi => fi.SHA256Hash) },
		{ "SHA1PageHash", (GlobalVars.GetStr("SHA1PageHashHeader/Text"), fi => fi.SHA1PageHash) },
		{ "SHA256PageHash", (GlobalVars.GetStr("SHA256PageHashHeader/Text"), fi => fi.SHA256PageHash) },
		{ "SHA1FlatHash", (GlobalVars.GetStr("SHA1FlatHashHeader/Text"), fi => fi.SHA1FlatHash) },
		{ "SHA256FlatHash", (GlobalVars.GetStr("SHA256FlatHashHeader/Text"), fi => fi.SHA256FlatHash) },
		{ "SISigningScenario", (GlobalVars.GetStr("SigningScenarioHeader/Text"), fi => fi.SISigningScenario) },
		{ "OriginalFileName", (GlobalVars.GetStr("OriginalFileNameHeader/Text"), fi => fi.OriginalFileName) },
		{ "InternalName", (GlobalVars.GetStr("InternalNameHeader/Text"), fi => fi.InternalName) },
		{ "FileDescription", (GlobalVars.GetStr("FileDescriptionHeader/Text"), fi => fi.FileDescription) },
		{ "ProductName", (GlobalVars.GetStr("ProductNameHeader/Text"), fi => fi.ProductName) },
		{ "FileVersion", (GlobalVars.GetStr("FileVersionHeader/Text"), fi => fi.FileVersion) },
		{ "PackageFamilyName", (GlobalVars.GetStr("PackageFamilyNameHeader/Text"), fi => fi.PackageFamilyName) },
		{ "FilePublishersToDisplay", (GlobalVars.GetStr("FilePublishersHeader/Text"), fi => fi.FilePublishersToDisplay) },
		{ "HasWHQLSigner", (GlobalVars.GetStr("HasWHQLSignerHeader/Text"), fi => fi.HasWHQLSigner) },
		{ "IsECCSigned", (GlobalVars.GetStr("IsECCSignedHeader/Text"), fi => fi.IsECCSigned) },
		{ "Opus", (GlobalVars.GetStr("OpusDataHeader/Text"), fi => fi.Opus) }}.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);


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
		IEnumerable<FileIdentity> allFileIdentities,
		ObservableCollection<FileIdentity> filteredCollection,
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

		// Get the search term from the SearchBox, converting it to lowercase for case-insensitive searching
		string? searchTerm = searchText?.Trim();

		// Start with the full list.
		// This list is used as the base set for filtering to preserve original data
		IEnumerable<FileIdentity> filteredResults = allFileIdentities;

		// If a selectedDate is provided, filter by date.
		// Filter results to include only items where 'TimeCreated' is greater than or equal to the selected date.
		if (selectedDate is not null)
		{
			filteredResults = filteredResults.Where(item =>
				item.TimeCreated.HasValue && item.TimeCreated.Value >= selectedDate);
		}

		// Filter results further to match the search term across multiple properties, case-insensitively
		if (!string.IsNullOrWhiteSpace(searchTerm))
		{
			filteredResults = filteredResults.Where(output =>
				(output.FileName is not null && output.FileName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				output.SignatureStatus.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
				output.Action.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
				(output.OriginalFileName is not null && output.OriginalFileName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.InternalName is not null && output.InternalName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.FileDescription is not null && output.FileDescription.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.ProductName is not null && output.ProductName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.FileVersion is not null && output.FileVersion.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
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

		// Add the new filtered results to the ObservableCollection
		foreach (FileIdentity item in filteredResults)
		{
			filteredCollection.Add(item);
		}

		if (Sv != null && savedHorizontal.HasValue)
		{
			// restore horizontal scroll position
			_ = Sv.ChangeView(savedHorizontal, null, null, disableAnimation: false);
		}
	}

	/// <summary>
	/// Creates a collection of PropertyFilterItem objects from FileIdentityPropertyMappings for use in ComboBox binding
	/// </summary>
	/// <returns>ObservableCollection of PropertyFilterItem objects</returns>
	internal static ObservableCollection<PropertyFilterItem> CreatePropertyFilterItems()
	{
		ObservableCollection<PropertyFilterItem> items = [];
		foreach (KeyValuePair<string, (string Label, Func<FileIdentity, object?> Getter)> mapping in FileIdentityPropertyMappings)
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
