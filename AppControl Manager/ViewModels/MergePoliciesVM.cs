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

using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using AppControlManager.Others;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.ViewModels;

internal sealed partial class MergePoliciesVM : ViewModelBase
{

	internal bool IsElevated => App.IsElevated;

	#region UI-Bound Properties

	internal HashSet<string> OtherPolicies
	{
		get; set => SP(ref field, value);
	} = [];

	internal string? OtherPoliciesString { get; set => SP(ref field, value); }

	internal bool ShouldDeploy { get; set => SP(ref field, value); }

	internal bool ShouldDeployToggleState = App.IsElevated;

	internal string? MainPolicy { get; set => SP(ref field, value); }

	internal bool MergeButtonState
	{
		get; set => SP(ref field, value);
	} = true;

	internal bool PolicyMergerInfoBarIsOpen { get; set => SP(ref field, value); }

	internal string? PolicyMergerInfoBarMessage { get; set => SP(ref field, value); }

	internal Visibility MergeProgressRingVisibility
	{
		get; set => SP(ref field, value);
	} = Visibility.Collapsed;

	internal InfoBarSeverity PolicyMergerInfoBarSeverity { get; set => SP(ref field, value); }

	internal bool PolicyMergerInfoBarIsClosable { get; set => SP(ref field, value); }

	#endregion


	/// <summary>
	/// Event handler for the main Merge button
	/// </summary>
	internal async void MergeButton_Click()
	{

		if (string.IsNullOrWhiteSpace(MainPolicy))
		{
			PolicyMergerInfoBarIsOpen = true;
			PolicyMergerInfoBarMessage = GlobalVars.Rizz.GetString("MergePolicies_SelectMainPolicySubtitle");
			PolicyMergerInfoBarIsClosable = true;
			PolicyMergerInfoBarSeverity = InfoBarSeverity.Warning;
			return;
		}

		if (OtherPolicies.Count is 0)
		{
			PolicyMergerInfoBarIsOpen = true;
			PolicyMergerInfoBarMessage = GlobalVars.Rizz.GetString("MergePolicies_SelectOtherPoliciesSubtitle");
			PolicyMergerInfoBarIsClosable = true;
			PolicyMergerInfoBarSeverity = InfoBarSeverity.Warning;
			return;
		}

		bool errorsOccurred = false;

		try
		{
			MergeButtonState = false;
			MergeProgressRingVisibility = Visibility.Visible;

			PolicyMergerInfoBarIsOpen = true;
			PolicyMergerInfoBarMessage = GlobalVars.Rizz.GetString("MergePolicies_MergingMessage");
			PolicyMergerInfoBarIsClosable = false;
			PolicyMergerInfoBarSeverity = InfoBarSeverity.Informational;

			await Task.Run(() =>
			{

				// Perform the merge operation
				SiPolicy.Merger.Merge(MainPolicy, OtherPolicies);

				// If user chose to deploy the policy after merge
				if (ShouldDeploy)
				{

					_ = Dispatcher.TryEnqueue(() =>
					{
						PolicyMergerInfoBarMessage = GlobalVars.Rizz.GetString("MergePolicies_DeployingMessage");
					});

					string stagingArea = StagingArea.NewStagingArea(GlobalVars.Rizz.GetString("MergePolicies_StagingAreaName")).FullName;

					string CIPPath = Path.Combine(stagingArea, GlobalVars.Rizz.GetString("MergePolicies_MergedPolicyFileName"));

					SiPolicy.Management.ConvertXMLToBinary(MainPolicy, null, CIPPath);

					CiToolHelper.UpdatePolicy(CIPPath);
				}

			});
		}
		catch
		{
			errorsOccurred = true;
			throw;
		}
		finally
		{

			if (errorsOccurred)
			{
				PolicyMergerInfoBarSeverity = InfoBarSeverity.Error;
				PolicyMergerInfoBarMessage = GlobalVars.Rizz.GetString("MergePolicies_ErrorMessage");
			}
			else
			{
				PolicyMergerInfoBarSeverity = InfoBarSeverity.Success;
				PolicyMergerInfoBarMessage = GlobalVars.Rizz.GetString("MergePolicies_SuccessMessage");
			}

			PolicyMergerInfoBarIsClosable = true;

			MergeProgressRingVisibility = Visibility.Collapsed;


			MergeButtonState = true;
		}
	}

	/// <summary>
	/// Handles the click event for the Main Policy Browse button. Opens a file picker dialog to select an XML file and
	/// stores the path.
	/// </summary>
	internal void MainPolicyBrowseButton_Click()
	{

		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			MainPolicy = selectedFile;

			// Add the selected main XML policy file path to the flyout's TextBox
			MainPolicy = selectedFile;
		}
	}

	/// <summary>
	/// Handles the click event for the Other Policies browse button. It opens a file picker dialog to select multiple XML
	/// files and adds unique selections to a display string.
	/// </summary>
	internal void OtherPoliciesBrowseButton_Click()
	{

		List<string>? selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (selectedFiles is { Count: > 0 })
		{
			foreach (string file in selectedFiles)
			{
				// Add the file to the display string only if it's unique
				if (OtherPolicies.Add(file))
				{
					// Append the new file to the TextBox, followed by a newline
					OtherPoliciesString += file + Environment.NewLine;
				}
			}
		}
	}


	/// <summary>
	/// Clears the text box for the main selected policy
	/// </summary>
	internal void MainPolicy_Flyout_ClearButton()
	{
		MainPolicy = null;
	}


	/// <summary>
	/// Clears the textbox for other selected policies
	/// </summary>
	internal void OtherPolicies_Flyout_ClearButton()
	{
		OtherPoliciesString = null;
		OtherPolicies.Clear();
	}

}
