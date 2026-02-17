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
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using AppControlManager.CustomUIElements;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using CommonCore.GroupPolicy;
using CommonCore.IncrementalCollection;
using CommonCore.SecurityPolicy;
using CommonCore.ToolKits;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class GroupPolicyEditorVM : ViewModelBase
{

	internal GroupPolicyEditorVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);

		// To adjust the initial width of the columns, giving them nice paddings.
		_ = Dispatcher.TryEnqueue(CalculateColumnWidths);
	}

	/// <summary>
	/// The main InfoBar for this VM.
	/// </summary>
	internal readonly InfoBarSettings MainInfoBar;

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	internal Visibility ProgressBarVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal bool ElementsAreEnabled
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ProgressBarVisibility = field ? Visibility.Collapsed : Visibility.Visible;
			}
		}
	} = true;

	#region ListView

	internal GridLength ColumnWidth1 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth2 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth3 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth4 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth5 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth6 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth7 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth8 { get; set => SP(ref field, value); }

	internal void CalculateColumnWidths()
	{
		// Measure header text widths first.
		double maxWidth1 = ListViewHelper.MeasureText(GlobalVars.GetStr("KeynameHeader/Text"));
		double maxWidth2 = ListViewHelper.MeasureText(GlobalVars.GetStr("ValueNameHeader/Text"));
		double maxWidth3 = ListViewHelper.MeasureText(GlobalVars.GetStr("ValueHeader/Text"));
		double maxWidth4 = ListViewHelper.MeasureText(GlobalVars.GetStr("CategoryHeader/Text"));
		double maxWidth5 = ListViewHelper.MeasureText(GlobalVars.GetStr("SubCategoryHeader/Text"));
		double maxWidth6 = ListViewHelper.MeasureText(GlobalVars.GetStr("PolicyActionHeader/Text"));
		double maxWidth7 = ListViewHelper.MeasureText(GlobalVars.GetStr("FriendlyNameHeader/Text"));
		double maxWidth8 = ListViewHelper.MeasureText(GlobalVars.GetStr("SizeHeader/Text"));

		// Iterate over all items to determine the widest string for each column.
		foreach (RegistryPolicyEntry item in Policies)
		{
			maxWidth1 = ListViewHelper.MeasureText(item.KeyName, maxWidth1);
			maxWidth2 = ListViewHelper.MeasureText(item.ValueName.ToString(), maxWidth2);
			maxWidth3 = ListViewHelper.MeasureText(item.ValueDisplay, maxWidth3);
			maxWidth4 = ListViewHelper.MeasureText(item.Category.ToString(), maxWidth4);
			maxWidth5 = ListViewHelper.MeasureText(item.SubCategory.ToString(), maxWidth5);
			maxWidth6 = ListViewHelper.MeasureText(item.policyAction.ToString(), maxWidth6);
			maxWidth7 = ListViewHelper.MeasureText(item.FriendlyName, maxWidth7);
			maxWidth8 = ListViewHelper.MeasureText(item.Size.ToString(), maxWidth8);
		}

		// Set the column width properties.
		ColumnWidth1 = new(maxWidth1);
		ColumnWidth2 = new(maxWidth2);
		ColumnWidth3 = new(maxWidth3);
		ColumnWidth4 = new(maxWidth4);
		ColumnWidth5 = new(maxWidth5);
		ColumnWidth6 = new(maxWidth6);
		ColumnWidth7 = new(maxWidth7);
		ColumnWidth8 = new(maxWidth8);
	}

	#endregion

	/// <summary>
	/// UI Search box value.
	/// </summary>
	internal string? SearchKeyword
	{
		get; set
		{
			if (SPT(ref field, value))
				SearchBox_TextChanged();
		}
	}

	/// <summary>
	/// Collection of all policies bound to the ListView.
	/// </summary>
	internal readonly RangedObservableCollection<RegistryPolicyEntry> Policies = [];

	/// <summary>
	/// Backing field of all policies.
	/// </summary>
	internal readonly List<RegistryPolicyEntry> AllPolicies = [];

	/// <summary>
	/// Whether the sidebar's pane is open or closed.
	/// </summary>
	internal bool MergeSidebarIsOpen { get; set => SP(ref field, value); }
	internal void OpenSideBar() => MergeSidebarIsOpen = true;
	internal void CloseSideBar() => MergeSidebarIsOpen = false;

	#region Search

	/// <summary>
	/// Event handler for the SearchBox text change
	/// </summary>
	internal void SearchBox_TextChanged()
	{
		string? searchTerm = SearchKeyword?.Trim();

		if (searchTerm is null)
			return;

		// Get the ListView ScrollViewer info
		ScrollViewer? Sv = ListViewHelper.GetScrollViewerFromCache(ListViewHelper.ListViewsRegistry.GroupPolicyEditor);

		double? savedHorizontal = null;
		if (Sv != null)
		{
			savedHorizontal = Sv.HorizontalOffset;
		}

		// Perform a case-insensitive search in all relevant fields
		IEnumerable<RegistryPolicyEntry> filteredResults = AllPolicies.Where(policy =>
			(policy.KeyName is not null && policy.KeyName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(policy.ValueName is not null && policy.ValueName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			policy.ValueDisplay.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
			(policy.Category is not null && (policy.Category?.ToString()?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false)) ||
			(policy.SubCategory is not null && (policy.SubCategory?.ToString()?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false)) ||
			(policy.FriendlyName is not null && policy.FriendlyName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			policy.policyAction.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase)
		);

		Policies.Clear();
		Policies.AddRange(filteredResults);

		CalculateColumnWidths();

		if (Sv != null && savedHorizontal.HasValue)
		{
			// restore horizontal scroll position
			_ = Sv.ChangeView(savedHorizontal, null, null, disableAnimation: false);
		}
	}

	#endregion

	#region Sort

	private ListViewHelper.SortState SortState { get; set; } = new();

	// Used for column sorting and column copying (single cell and entire row), for all ListViews that display RegistryPolicyEntry data type
	private static readonly FrozenDictionary<string, (string Label, Func<RegistryPolicyEntry, object?> Getter)> RegistryPolicyEntryPropertyMappings
		= new Dictionary<string, (string Label, Func<RegistryPolicyEntry, object?> Getter)>
		{
			{ "KeyName",        (GlobalVars.GetStr("KeynameHeader/Text") + ": ",        rpe => rpe.KeyName) },
			{ "ValueName",      (GlobalVars.GetStr("ValueNameHeader/Text") + ": ",      rpe => rpe.ValueName) },
			{ "Value",          (GlobalVars.GetStr("ValueHeader/Text") + ": ",          rpe => rpe.ValueDisplay) },
			{ "Category",       (GlobalVars.GetStr("CategoryHeader/Text") + ": ",       rpe => rpe.Category) },
			{ "SubCategory",    (GlobalVars.GetStr("SubCategoryHeader/Text") + ": ",    rpe => rpe.SubCategory) },
			{ "PolicyAction",   (GlobalVars.GetStr("PolicyActionHeader/Text") + ": ",   rpe => rpe.policyAction) },
			{ "FriendlyName",   (GlobalVars.GetStr("FriendlyNameHeader/Text") + ": ",   rpe => rpe.FriendlyName) },
			{ "Size",           (GlobalVars.GetStr("SizeHeader/Text") + ": ",           rpe => rpe.Size) }
		}.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

	internal void HeaderColumnSortingButton_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is string key)
		{
			// Look up the mapping in the reusable property mappings dictionary.
			if (RegistryPolicyEntryPropertyMappings.TryGetValue(key, out (string Label, Func<RegistryPolicyEntry, object?> Getter) mapping))
			{
				ListViewHelper.SortColumn(
					mapping.Getter,
					SearchKeyword,
					AllPolicies,
					Policies,
					SortState,
					key,
					regKey: ListViewHelper.ListViewsRegistry.GroupPolicyEditor);
			}
		}
	}

	#endregion

	#region Copy

	/// <summary>
	/// Converts the properties of a RegistryPolicyEntry row into a labeled, formatted string for copying to clipboard.
	/// </summary>
	internal void CopySelectedPolicies_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.GroupPolicyEditor);

		if (lv is null) return;

		if (lv.SelectedItems.Count > 0)
		{
			// SelectedItems is an IList, and contains RegistryPolicyEntry
			ListViewHelper.ConvertRowToText(lv.SelectedItems, RegistryPolicyEntryPropertyMappings);
		}
	}

	/// <summary>
	/// Copy a single property of the current selection
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void CopyPolicyProperty_Click(object sender, RoutedEventArgs e)
	{
		MenuFlyoutItem menuItem = (MenuFlyoutItem)sender;
		string key = (string)menuItem.Tag;

		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.GroupPolicyEditor);

		if (lv is null) return;

		if (RegistryPolicyEntryPropertyMappings.TryGetValue(key, out (string Label, Func<RegistryPolicyEntry, object?> Getter) map))
		{
			// TElement = RegistryPolicyEntry, copy just that one property
			ListViewHelper.CopyToClipboard<RegistryPolicyEntry>(ci => map.Getter(ci)?.ToString(), lv);
		}
	}
	#endregion

	#region Edit

	private static readonly string[] Separators = [Environment.NewLine, "\n", "\r"];

	/// <summary>
	/// Opens a dialog to edit the selected policy's value with rigorous validation.
	/// </summary>
	internal async void EditPolicy_Click(object sender, RoutedEventArgs e)
	{
		if (sender is not FrameworkElement { DataContext: RegistryPolicyEntry policy } element)
			return;

		if (string.IsNullOrEmpty(SelectedFile))
		{
			MainInfoBar.WriteWarning("No policy file loaded to save changes to.");
			return;
		}

		try
		{
			StackPanel contentPanel = new() { Spacing = 10 };

			contentPanel.Children.Add(new TextBlock { Text = $"Key: {policy.KeyName}", TextWrapping = TextWrapping.Wrap });
			contentPanel.Children.Add(new TextBlock { Text = $"Value Name: {policy.ValueName}", TextWrapping = TextWrapping.Wrap });
			contentPanel.Children.Add(new TextBlock { Text = $"Type: {policy.Type}" });

			TextBox inputTextBox = new()
			{
				Header = "New Value",
				AcceptsReturn = policy.Type == RegistryValueType.REG_MULTI_SZ,
				TextWrapping = policy.Type == RegistryValueType.REG_MULTI_SZ ? TextWrapping.Wrap : TextWrapping.NoWrap,
				MinWidth = 350,
				MaxHeight = 300,
			};

			// Set attached property
			ScrollViewer.SetVerticalScrollBarVisibility(inputTextBox, ScrollBarVisibility.Auto);

			// Status area: Icon + Text
			StackPanel statusPanel = new() { Orientation = Orientation.Horizontal, Spacing = 8, Margin = new Thickness(0, 5, 0, 0) };
			FontIcon statusIcon = new() { Glyph = "\uE73E", FontSize = 16 }; // Default to Checkmark
			TextBlock statusText = new() { Text = "Valid", FontSize = 12 };
			ProgressRing statusRing = new() { IsIndeterminate = true, Width = 16, Height = 16, Visibility = Visibility.Collapsed };

			statusPanel.Children.Add(statusRing);
			statusPanel.Children.Add(statusIcon);
			statusPanel.Children.Add(statusText);
			contentPanel.Children.Add(inputTextBox);
			contentPanel.Children.Add(statusPanel);

			// Pre-fill current value
			if (policy.ParsedValue != null)
			{
				inputTextBox.Text = policy.Type == RegistryValueType.REG_MULTI_SZ && policy.ParsedValue is string[] strings
					? string.Join(Environment.NewLine, strings)
					: (policy.Type == RegistryValueType.REG_BINARY || policy.Type == RegistryValueType.REG_NONE) && policy.ParsedValue is ReadOnlyMemory<byte> bytes
						? Convert.ToHexString(bytes.Span)
						: policy.ParsedValue.ToString();
			}

			using ContentDialogV2 dialog = new()
			{
				Title = "Edit Policy Value",
				PrimaryButtonText = "Save",
				CloseButtonText = GlobalVars.GetStr("Cancel"),
				DefaultButton = ContentDialogButton.Primary,
				Content = contentPanel,
				IsPrimaryButtonEnabled = true // Initially true, updated by validation logic immediately
			};

			// Validation Logic
			void ValidateInput(string text)
			{
				statusRing.Visibility = Visibility.Visible;
				statusIcon.Visibility = Visibility.Collapsed;
				statusText.Text = "Validating...";
				dialog.IsPrimaryButtonEnabled = false;

				bool isValid = false;
				string message = "";

				try
				{
					switch (policy.Type)
					{
						case RegistryValueType.REG_DWORD:
							if (string.IsNullOrWhiteSpace(text))
							{
								message = "Value cannot be empty.";
							}
							else if (uint.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out _))
							{
								isValid = true;
								message = "Valid 32-bit unsigned integer.";
							}
							else
							{
								message = "Must be a valid 32-bit integer number.";
							}
							break;

						case RegistryValueType.REG_QWORD:
							if (string.IsNullOrWhiteSpace(text))
							{
								message = "Value cannot be empty.";
							}
							else if (ulong.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out _))
							{
								isValid = true;
								message = "Valid 64-bit unsigned integer.";
							}
							else
							{
								message = "Must be a valid 64-bit integer.";
							}
							break;

						case RegistryValueType.REG_BINARY:
						case RegistryValueType.REG_NONE:
							if (string.IsNullOrWhiteSpace(text))
							{
								// Empty binary is valid (0 bytes)
								isValid = true;
								message = "Empty binary data.";
							}
							else
							{
								string cleanHex = text.Replace(" ", string.Empty).Replace("-", string.Empty);
								// Check for hex characters
								if (HexCharactersRegex().IsMatch(cleanHex))
								{
									if (cleanHex.Length % 2 == 0)
									{
										isValid = true;
										message = $"Valid binary data ({cleanHex.Length / 2} bytes).";
									}
									else
									{
										message = "Hex string must have an even number of characters.";
									}
								}
								else
								{
									message = "Contains invalid characters. Only 0-9 and A-F allowed.";
								}
							}
							break;
						case RegistryValueType.REG_DWORD_BIG_ENDIAN:
							break;
						case RegistryValueType.REG_LINK:
							break;
						case RegistryValueType.REG_RESOURCE_LIST:
							break;
						case RegistryValueType.REG_FULL_RESOURCE_DESCRIPTOR:
							break;
						case RegistryValueType.REG_RESOURCE_REQUIREMENTS_LIST:
							break;
						case RegistryValueType.REG_SZ:
						case RegistryValueType.REG_EXPAND_SZ:
						case RegistryValueType.REG_MULTI_SZ:
						default:
							// Strings are generally always valid unless there are specific constraints
							isValid = true;
							message = "Valid string.";
							break;
					}
				}
				catch
				{
					isValid = false;
					message = "Validation error.";
				}

				// Update UI
				statusRing.Visibility = Visibility.Collapsed;
				statusIcon.Visibility = Visibility.Visible;
				dialog.IsPrimaryButtonEnabled = isValid;

				if (isValid)
				{
					statusIcon.Glyph = "\uE73E"; // Checkmark
					statusIcon.Foreground = new SolidColorBrush(Colors.Green);
					statusText.Foreground = new SolidColorBrush(Colors.Green);
					statusText.Text = message;
				}
				else
				{
					statusIcon.Glyph = "\uE783"; // Error badge
					statusIcon.Foreground = new SolidColorBrush(Colors.Red);
					statusText.Foreground = new SolidColorBrush(Colors.Red);
					statusText.Text = message;
				}
			}

			// Event handler for textchanged
			void TextChangedHandler(object sender, TextChangedEventArgs args) =>
				ValidateInput(inputTextBox.Text ?? string.Empty);

			// Hook up event
			inputTextBox.TextChanged += TextChangedHandler;

			// Trigger initial validation
			ValidateInput(inputTextBox.Text ?? string.Empty);

			try
			{
				// Show the dialog and await its result
				ContentDialogResult result = await dialog.ShowAsync();

				// Ensure primary button was selected
				if (result is ContentDialogResult.Primary)
				{
					// Handle potentially null input
					string input = inputTextBox.Text ?? string.Empty;

					// Capture old policy object index in AllPolicies
					int allPoliciesIndex = AllPolicies.IndexOf(policy);
					int policiesIndex = Policies.IndexOf(policy);

					try
					{
						byte[] newData = [];

						switch (policy.Type)
						{
							case RegistryValueType.REG_SZ:
							case RegistryValueType.REG_EXPAND_SZ:
								// Append null terminator
								newData = Encoding.Unicode.GetBytes(input + "\0");
								break;

							case RegistryValueType.REG_DWORD:
								newData = uint.TryParse(input, NumberStyles.Integer, CultureInfo.InvariantCulture, out uint dwordVal)
									? BitConverter.GetBytes(dwordVal)
									: throw new InvalidDataException("Invalid DWORD (32-bit) value.");
								break;

							case RegistryValueType.REG_QWORD:
								newData = ulong.TryParse(input, NumberStyles.Integer, CultureInfo.InvariantCulture, out ulong qwordVal)
									? BitConverter.GetBytes(qwordVal)
									: throw new InvalidDataException("Invalid QWORD (64-bit) value.");
								break;

							case RegistryValueType.REG_MULTI_SZ:
								string[] lines = input.Split(Separators, StringSplitOptions.RemoveEmptyEntries);
								// Join with null separators and double null at end
								string multiString = string.Join("\0", lines) + "\0\0";
								newData = Encoding.Unicode.GetBytes(multiString);
								break;

							case RegistryValueType.REG_BINARY:
							case RegistryValueType.REG_NONE:
								try
								{
									string cleanHex = input.Replace(" ", string.Empty).Replace("-", string.Empty);
									newData = Convert.FromHexString(cleanHex);
								}
								catch
								{
									MainInfoBar.WriteWarning("Invalid Hex string.");
									return;
								}
								break;
							case RegistryValueType.REG_DWORD_BIG_ENDIAN:
								break;
							case RegistryValueType.REG_LINK:
								break;
							case RegistryValueType.REG_RESOURCE_LIST:
								break;
							case RegistryValueType.REG_FULL_RESOURCE_DESCRIPTOR:
								break;
							case RegistryValueType.REG_RESOURCE_REQUIREMENTS_LIST:
								break;
							default:
								newData = Encoding.Unicode.GetBytes(input + "\0");
								break;
						}

						// Creating a new RegistryPolicyEntry with the correct size and updated data.
						RegistryPolicyEntry newEntry = new(
							policy.Source,
							policy.KeyName,
							policy.ValueName,
							policy.Type,
							(uint)newData.Length, // Updated
							newData, // Updated
							policy.Hive,
							policy.ID
						)
						{
							FriendlyName = policy.FriendlyName,
							Category = policy.Category,
							SubCategory = policy.SubCategory,
							policyAction = policy.policyAction,
							URL = policy.URL,
							DefaultRegValue = policy.DefaultRegValue,
							DeviceIntents = policy.DeviceIntents
						};

						// Recompute RegValue from the new data so it reflects the edited value
						newEntry.RegValue = CommonCore.RegistryManager.Manager.BuildRegValueFromParsedValue(newEntry);

						// Update the collections with the new object
						if (allPoliciesIndex >= 0) AllPolicies[allPoliciesIndex] = newEntry;
						if (policiesIndex >= 0) Policies[policiesIndex] = newEntry;

						// Save changes to disk
						await Task.Run(SavePoliciesToFile);

						// Refresh the search filter to update the ListView display based on the potentially changed properties of the edited entry
						SearchBox_TextChanged();

						// Recalculate columns to fit new data width
						CalculateColumnWidths();
					}
					catch
					{
						// Revert changes in memory if save failed
						// Put the old policy object back into the lists
						if (allPoliciesIndex >= 0) AllPolicies[allPoliciesIndex] = policy;
						if (policiesIndex >= 0) Policies[policiesIndex] = policy;
						throw;
					}
				}
			}
			finally
			{
				// Unsubscribe from event handler
				inputTextBox.TextChanged -= TextChangedHandler;
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			MainInfoBar.IsClosable = true;
		}
	}

	/// <summary>
	/// Saves the current list of policies to the selected file and refreshes system policies if applicable.
	/// </summary>
	private void SavePoliciesToFile()
	{
		if (SelectedFile is null) return;

		ElementsAreEnabled = false;
		MainInfoBarIsClosable = false;

		// Make a copy of the original file first
		ReadOnlySpan<byte> originalFileContent = File.ReadAllBytes(SelectedFile);

		try
		{
			string extension = Path.GetExtension(SelectedFile);

			if (string.Equals(extension, ".json", StringComparison.OrdinalIgnoreCase))
			{
				// Ensure RegValue is updated for JSON
				foreach (RegistryPolicyEntry item in AllPolicies)
				{
					if (item.Source == Source.GroupPolicy)
					{
						item.RegValue = CommonCore.RegistryManager.Manager.BuildRegValueFromParsedValue(item);
					}
				}
				RegistryPolicyEntry.Save(SelectedFile, AllPolicies);
			}
			else if (string.Equals(extension, ".pol", StringComparison.OrdinalIgnoreCase))
			{
				RegistryPolicyFile newPolFile = new(
					signature: RegistryPolicyFile.REGISTRY_FILE_SIGNATURE,
					version: RegistryPolicyFile.REGISTRY_FILE_VERSION,
					entries: AllPolicies);

				RegistryPolicyParser.WriteFile(SelectedFile, newPolFile);
			}

			// Check if we need to refresh system policies
			if (string.Equals(SelectedFile, RegistryPolicyParser.LocalPolicyMachineFilePath, StringComparison.OrdinalIgnoreCase) ||
				string.Equals(SelectedFile, RegistryPolicyParser.LocalPolicyUserFilePath, StringComparison.OrdinalIgnoreCase))
			{
				CSEMgr.RegisterCSEGuids();
				MainInfoBar.WriteSuccess("Policy updated and system policies refreshed.");
			}
			else
			{
				MainInfoBar.WriteSuccess("Policy updated and file saved.");
			}
		}
		catch
		{
			// Restore the file's original content if there was an error
			File.WriteAllBytes(SelectedFile, originalFileContent);
			throw;
		}
		finally
		{
			ElementsAreEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

	#endregion

	#region Delete

	/// <summary>
	/// Deletes the selected policies from the currently loaded POL or JSON file and refreshes the UI.
	/// </summary>
	internal async void DeleteSelectedPolicies_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.GroupPolicyEditor);

		if (lv is null || lv.SelectedItems.Count == 0)
		{
			MainInfoBar.WriteWarning("No policies selected for deletion.");
			return;
		}

		if (string.IsNullOrEmpty(SelectedFile) || !File.Exists(SelectedFile))
		{
			MainInfoBar.WriteWarning("No policy file is selected.");
			return;
		}

		string fileExtension = Path.GetExtension(SelectedFile);

		// Determine the file type
		bool isPOLFile = string.Equals(fileExtension, ".pol", StringComparison.OrdinalIgnoreCase);
		bool isJSONFile = string.Equals(fileExtension, ".json", StringComparison.OrdinalIgnoreCase);

		// Check if we have a valid POL or JSON file loaded
		if (!isPOLFile && !isJSONFile)
		{
			MainInfoBar.WriteWarning("No valid POL or JSON file is currently loaded.");
			return;
		}

		try
		{
			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			// Get the selected policies
			List<RegistryPolicyEntry> policiesToDelete = [];
			foreach (object item in lv.SelectedItems)
			{
				if (item is RegistryPolicyEntry policy)
				{
					policiesToDelete.Add(policy);
				}
			}

			if (policiesToDelete.Count == 0)
			{
				MainInfoBar.WriteWarning("No policies selected for deletion.");
				return;
			}

			if (isPOLFile)
			{
				await Task.Run(() =>
				{
					// Remove policies directly from the loaded POL file
					RegistryPolicyParser.RemovePoliciesFromPOLFile(SelectedFile, policiesToDelete);
				});
			}
			else
			{
				// JSON file workflow - remove from backing list and save
				foreach (RegistryPolicyEntry policy in policiesToDelete)
				{
					_ = AllPolicies.Remove(policy);
				}

				await Task.Run(() =>
				{
					// Ensure RegValue is up to date for Group Policy entries before saving
					foreach (RegistryPolicyEntry item in AllPolicies)
					{
						if (item.Source == Source.GroupPolicy)
						{
							item.RegValue = CommonCore.RegistryManager.Manager.BuildRegValueFromParsedValue(item);
						}
					}

					RegistryPolicyEntry.Save(SelectedFile, AllPolicies);
				});
			}

			// Remove policies from UI collections
			foreach (RegistryPolicyEntry policy in policiesToDelete)
			{
				// Remove from the observable collection
				_ = Policies.Remove(policy);

				// For POL files, AllPolicies removal happens here.
				// For JSON files, AllPolicies was already modified above before saving.
				if (isPOLFile)
				{
					_ = AllPolicies.Remove(policy);
				}
			}

			// Update UI
			CalculateColumnWidths();

			string fileType = isPOLFile ? "POL" : "JSON";
			MainInfoBar.WriteSuccess($"Successfully deleted {policiesToDelete.Count} policies from the {fileType} file.");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

	#endregion

	/// <summary>
	/// The main policy file whose data will be displayed in the ListView.
	/// </summary>
	internal string? SelectedFile { get; set => SPT(ref field, value); }

	internal void ClearSelectedFile_Click() => SelectedFile = null;

	/// <summary>
	/// Opens a file picker dialog to select a policy file (JSON or POL).
	/// </summary>
	internal void BrowseForPolicy_Click()
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.JSONAndPOLPickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			SelectedFile = selectedFile;
		}
	}

	/// <summary>
	/// Event handler for the UI process button,
	/// </summary>
	internal async void ProcessSelectedFile()
	{
		try
		{
			await ProcessSelectedFilePrivate();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Parses the selected policy file and displays it data in the ListView.
	/// </summary>
	private async Task ProcessSelectedFilePrivate()
	{
		if (SelectedFile is null)
			return;

		try
		{
			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			AllPolicies.Clear();
			Policies.Clear();

			await Task.Run(async () =>
			{
				string fileExtension = Path.GetExtension(SelectedFile);

				if (string.Equals(fileExtension, ".json", StringComparison.OrdinalIgnoreCase))
				{
					List<RegistryPolicyEntry> policy = RegistryPolicyEntry.Load(SelectedFile);

					// Ensures the JSON file that is loaded has correct "RegValue".
					foreach (RegistryPolicyEntry item in policy)
					{
						if (item.Source == Source.GroupPolicy)
						{
							item.RegValue = CommonCore.RegistryManager.Manager.BuildRegValueFromParsedValue(item);
						}
					}

					// Persist the updated RegValue(s) back to disk
					RegistryPolicyEntry.Save(SelectedFile, policy);

					// Load again
					policy = RegistryPolicyEntry.Load(SelectedFile);

					// Retrieve friendly names
					AdmxAdmlParser.PopulateFriendlyNames(policy);

					await Dispatcher.EnqueueAsync(() =>
					{
						Policies.AddRange(policy);
						AllPolicies.AddRange(policy);
					});
				}
				else if (string.Equals(fileExtension, ".pol", StringComparison.OrdinalIgnoreCase))
				{
					RegistryPolicyFile policy = RegistryPolicyParser.ParseFile(SelectedFile);

					// Retrieve friendly names
					AdmxAdmlParser.PopulateFriendlyNames(policy.Entries);

					await Dispatcher.EnqueueAsync(() =>
					{
						Policies.AddRange(policy.Entries);
						AllPolicies.AddRange(policy.Entries);
					});
				}
				else
				{
					throw new NotSupportedException(string.Format(GlobalVars.GetStr("UnsupportedFileTypeError"), fileExtension));
				}

			});

			CalculateColumnWidths();
			MainInfoBar.WriteSuccess(GlobalVars.GetStr("GroupPolicyDataLoadedSuccess"));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

	/// <summary>
	/// Retrieves and loads the effective Group Policies on the system.
	/// </summary>
	internal async void GetEffectivePolicies_Click()
	{
		try
		{
			SelectedFile = RegistryPolicyParser.LocalPolicyMachineFilePath;

			await ProcessSelectedFilePrivate();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Retrieves and loads the effective Group Policies for the User.
	/// </summary>
	internal async void GetEffectiveUserPolicies_Click()
	{
		try
		{
			SelectedFile = RegistryPolicyParser.LocalPolicyUserFilePath;

			await ProcessSelectedFilePrivate();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Clears all of the data from the UI.
	/// </summary>
	internal void ClearData()
	{
		Policies.Clear();
		AllPolicies.Clear();
		CalculateColumnWidths();
	}

	#region Merge POL files

	internal string? SelectedMainPOLFileForMerge { get; set => SPT(ref field, value); }
	internal void ClearSelectedMainPOLFileForMerge_Click() => SelectedMainPOLFileForMerge = null;

	internal UniqueStringObservableCollection SelectedOtherPOLFilesForMerge = [];
	internal void ClearSelectedOtherPOLFilesForMerge() => SelectedOtherPOLFilesForMerge.Clear();

	internal void BrowseForMainPolFile()
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.POLPickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			SelectedMainPOLFileForMerge = selectedFile;
		}
	}

	internal void PickPOLFiles()
	{
		List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.POLPickerFilter);

		if (selectedFiles.Count > 0)
		{
			foreach (string item in selectedFiles)
			{
				SelectedOtherPOLFilesForMerge.Add(item);
			}
		}
	}

	internal async void StartPOLFilesMergeOperation()
	{
		if (SelectedMainPOLFileForMerge is null || SelectedOtherPOLFilesForMerge.Count == 0)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("SelectMainAndOtherPOLFilesWarning"));
			return;
		}

		try
		{
			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			await Task.Run(() =>
			{
				MergeResult result = RegistryPolicyParser.MergePolicyFilesWithReport(SelectedMainPOLFileForMerge, SelectedOtherPOLFilesForMerge.UniqueItems.ToArray());

				// Log each operation
				foreach (MergeOperation operation in result.Operations)
				{
					Logger.Write(operation.ToString());
				}

				// Log summary statistics
				Logger.Write(GlobalVars.GetStr("MergeSummaryHeader"));
				Logger.Write(string.Format(GlobalVars.GetStr("TotalOperationsLog"), result.Operations.Count));
				Logger.Write(string.Format(GlobalVars.GetStr("AddedEntriesLog"), result.Operations.Count(op => op.OperationType == OperationType.Added)));
				Logger.Write(string.Format(GlobalVars.GetStr("ReplacedEntries"), result.Operations.Count(op => op.OperationType == OperationType.Replaced)));
				Logger.Write(string.Format(GlobalVars.GetStr("TotalEntriesInMergedFileLog"), result.MergedFile.Entries.Count));

				RegistryPolicyFile newPolFile = new(
					signature: RegistryPolicyFile.REGISTRY_FILE_SIGNATURE,
					version: RegistryPolicyFile.REGISTRY_FILE_VERSION,
					entries: result.MergedFile.Entries);

				RegistryPolicyParser.WriteFile(SelectedMainPOLFileForMerge, newPolFile);
			});

			MainInfoBar.WriteSuccess(GlobalVars.GetStr("POLFilesMergedSuccess"));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

	#endregion

	#region Convert POL to JSON

	internal UniqueStringObservableCollection SelectedPOLFilesForConversionToJSON = [];
	internal void ClearSelectedPOLFilesForConversionToJSON() => SelectedPOLFilesForConversionToJSON.Clear();

	internal string? OutputDirForJsonFilesAfterConversion { get; set => SP(ref field, value); }
	internal void ClearOutputDirForJsonFilesAfterConversion_Click() => OutputDirForJsonFilesAfterConversion = null;

	internal void PickPOLFilesForJSONConversion()
	{
		List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.POLPickerFilter);

		if (selectedFiles.Count > 0)
		{
			foreach (string item in selectedFiles)
			{
				SelectedPOLFilesForConversionToJSON.Add(item);
			}
		}
	}

	internal void PickADirectory()
	{
		string? dir = FileDialogHelper.ShowDirectoryPickerDialog();

		if (!string.IsNullOrEmpty(dir))
		{
			OutputDirForJsonFilesAfterConversion = dir;
		}
	}

	internal async void ConvertPOLToJSON()
	{
		if (SelectedPOLFilesForConversionToJSON.Count == 0)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("SelectAtLeastOnePOLFileWarning"));
			return;
		}

		try
		{
			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			await Task.Run(() =>
			{
				foreach (string item in SelectedPOLFilesForConversionToJSON)
				{
					RegistryPolicyFile policy = RegistryPolicyParser.ParseFile(item);

					// Retrieve friendly names
					AdmxAdmlParser.PopulateFriendlyNames(policy.Entries);

					string? saveLoc = OutputDirForJsonFilesAfterConversion is null
						? Path.Combine(
							Path.GetDirectoryName(item) ?? GlobalVars.SystemDrive,
							Path.GetFileNameWithoutExtension(item) + ".json")
						: Path.Combine(
							OutputDirForJsonFilesAfterConversion,
							Path.GetFileNameWithoutExtension(item) + ".json");

					// Populate RegValue for Group Policy entries at save time so the generated JSON includes it.
					foreach (RegistryPolicyEntry entry in policy.Entries)
					{
						if (entry.Source == Source.GroupPolicy)
						{
							entry.RegValue = CommonCore.RegistryManager.Manager.BuildRegValueFromParsedValue(entry);
						}
					}

					RegistryPolicyEntry.Save(saveLoc, policy.Entries);

					MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("POLFilesConvertedToJSONSuccess"), saveLoc));
				}
			});
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

	#endregion

	#region Convert JSON to POL

	internal string? OutputDirForPOLFilesAfterConversion { get; set => SP(ref field, value); }
	internal void ClearOutputDirForPOLFilesAfterConversion_Click() => OutputDirForPOLFilesAfterConversion = null;

	internal UniqueStringObservableCollection SelectedJSONFilesForConversionToPol = [];
	internal void ClearSelectedJSONFilesForConversionToPol() => SelectedJSONFilesForConversionToPol.Clear();

	internal void PickADirectoryForJSONToPOLConversion()
	{
		string? dir = FileDialogHelper.ShowDirectoryPickerDialog();

		if (!string.IsNullOrEmpty(dir))
		{
			OutputDirForPOLFilesAfterConversion = dir;
		}
	}

	internal void PickJSONFilesForPOLConversion()
	{
		List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.JSONPickerFilter);

		if (selectedFiles.Count > 0)
		{
			foreach (string item in selectedFiles)
			{
				SelectedJSONFilesForConversionToPol.Add(item);
			}
		}
	}

	internal async void ConvertJSONToPol()
	{
		if (SelectedJSONFilesForConversionToPol.Count == 0)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("SelectAtLeastOneJSONFileWarning"));
			return;
		}

		try
		{
			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			await Task.Run(() =>
			{
				foreach (string item in SelectedJSONFilesForConversionToPol)
				{
					List<RegistryPolicyEntry> policies = RegistryPolicyEntry.Load(item);

					RegistryPolicyFile newPolicyFile = new(
							signature: RegistryPolicyFile.REGISTRY_FILE_SIGNATURE,
							version: RegistryPolicyFile.REGISTRY_FILE_VERSION,
							entries: policies);

					string? saveLoc = OutputDirForPOLFilesAfterConversion is null
						? Path.Combine(
							Path.GetDirectoryName(item) ?? GlobalVars.SystemDrive,
							Path.GetFileNameWithoutExtension(item) + ".pol")
						: Path.Combine(
							OutputDirForPOLFilesAfterConversion,
							Path.GetFileNameWithoutExtension(item) + ".pol");
					RegistryPolicyParser.WriteFile(saveLoc, newPolicyFile);

					MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("JSONFileConvertedToPOLSuccess"), saveLoc));
				}
			});
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

	#endregion

	#region Convert Security INF to JSON

	internal UniqueStringObservableCollection SelectedSecurityINFFilesForConversionToJSON = [];
	internal void ClearSelectedSecurityINFFilesForConversionToJSON() => SelectedSecurityINFFilesForConversionToJSON.Clear();

	internal string? OutputDirForSecurityINFToJSONConversion { get; set => SP(ref field, value); }
	internal void ClearOutputDirForSecurityINFToJSONConversion_Click() => OutputDirForSecurityINFToJSONConversion = null;

	internal void PickSecurityINFFilesForJSONConversion()
	{
		List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.SecurityINFPickerFilter);

		if (selectedFiles.Count > 0)
		{
			foreach (string item in selectedFiles)
			{
				SelectedSecurityINFFilesForConversionToJSON.Add(item);
			}
		}
	}

	internal void PickADirectoryForSecurityINFToJSON()
	{
		string? dir = FileDialogHelper.ShowDirectoryPickerDialog();

		if (!string.IsNullOrEmpty(dir))
		{
			OutputDirForSecurityINFToJSONConversion = dir;
		}
	}

	internal async void ConvertSecurityINFToJSON()
	{
		if (SelectedSecurityINFFilesForConversionToJSON.Count == 0)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("SelectAtLeastOneSecurityINFFileWarning"));
			return;
		}

		try
		{
			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			await Task.Run(() =>
			{
				foreach (string item in SelectedSecurityINFFilesForConversionToJSON)
				{
					List<RegistryPolicyEntry> policies = SecurityINFParser.ParseSecurityINFFile(item);

					string? saveLoc = OutputDirForSecurityINFToJSONConversion is null
						? Path.Combine(
							Path.GetDirectoryName(item) ?? GlobalVars.SystemDrive,
							Path.GetFileNameWithoutExtension(item) + ".json")
						: Path.Combine(
							OutputDirForSecurityINFToJSONConversion,
							Path.GetFileNameWithoutExtension(item) + ".json");
					RegistryPolicyEntry.Save(saveLoc, policies);

					MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("SecurityINFFileConvertedToJSONSuccess"), saveLoc));
				}
			});
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

	#endregion

	#region Retrive System Security Policy

	internal async void RetrieveSystemSecurityPolicy()
	{
		try
		{
			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			string? saveLocation = FileDialogHelper.ShowSaveFileDialog(
					"Security Reports|*.txt",
					"SecurityPolicy_Report.txt");

			if (saveLocation is null)
				return;

			await DataDump.DumpSystemSecurityPoliciesData(saveLocation);

			MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("SecurityPolicyReportSavedSuccess"), saveLocation));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

	#endregion

	/// <summary>
	/// Method used to open the Group Policy Editor with the selected policy file.
	/// </summary>
	/// <param name="filePath"></param>
	/// <returns></returns>
	internal async Task OpenInGroupPolicyEditor(string? filePath)
	{
		if (filePath is null)
			return;
		try
		{
			SelectedFile = filePath;

			ViewModelProvider.NavigationService.Navigate(typeof(Pages.GroupPolicyEditor));

			await ProcessSelectedFilePrivate();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	[GeneratedRegex("^[0-9A-Fa-f]*$")]
	private static partial Regex HexCharactersRegex();
}
