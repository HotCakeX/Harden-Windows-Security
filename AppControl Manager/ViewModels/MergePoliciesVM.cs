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
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using AppControlManager.Others;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.ViewModels;

internal sealed partial class MergePoliciesVM : ViewModelBase
{

	internal MergePoliciesVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => PolicyMergerInfoBarIsOpen, value => PolicyMergerInfoBarIsOpen = value,
			() => PolicyMergerInfoBarMessage, value => PolicyMergerInfoBarMessage = value,
			() => PolicyMergerInfoBarSeverity, value => PolicyMergerInfoBarSeverity = value,
			() => PolicyMergerInfoBarIsClosable, value => PolicyMergerInfoBarIsClosable = value,
			Dispatcher,
			() => PolicyMergerInfoBarTitle, value => PolicyMergerInfoBarTitle = value);
	}

	private readonly InfoBarSettings MainInfoBar;

	#region UI-Bound Properties

	internal readonly UniqueStringObservableCollection OtherPolicies = [];

	internal bool ShouldDeploy { get; set => SP(ref field, value); }

	internal string? MainPolicy { get; set => SP(ref field, value); }

	internal bool MergeButtonState { get; set => SP(ref field, value); } = true;

	internal bool PolicyMergerInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? PolicyMergerInfoBarMessage { get; set => SP(ref field, value); }
	internal string? PolicyMergerInfoBarTitle { get; set => SP(ref field, value); }
	internal InfoBarSeverity PolicyMergerInfoBarSeverity { get; set => SP(ref field, value); }
	internal bool PolicyMergerInfoBarIsClosable { get; set => SP(ref field, value); }

	internal Visibility MergeProgressRingVisibility
	{
		get; set => SP(ref field, value);
	} = Visibility.Collapsed;

	#endregion

	/// <summary>
	/// Event handler for the main Merge button
	/// </summary>
	internal async void MergeButton_Click()
	{

		if (string.IsNullOrWhiteSpace(MainPolicy))
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("MergePolicies_SelectMainPolicySubtitle"));
			return;
		}

		if (OtherPolicies.Count is 0)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("MergePolicies_SelectOtherPoliciesSubtitle"));
			return;
		}

		bool errorsOccurred = false;

		try
		{
			MergeButtonState = false;
			MergeProgressRingVisibility = Visibility.Visible;

			PolicyMergerInfoBarIsClosable = false;

			MainInfoBar.WriteInfo(GlobalVars.GetStr("MergePolicies_MergingMessage"));

			await Task.Run(() =>
			{
				// Perform the merge operation
				SiPolicy.Merger.Merge(MainPolicy, OtherPolicies.UniqueItems.ToList());

				// If user chose to deploy the policy after merge
				if (ShouldDeploy)
				{
					MainInfoBar.WriteInfo(GlobalVars.GetStr("MergePolicies_DeployingMessage"));

					string stagingArea = StagingArea.NewStagingArea(GlobalVars.GetStr("MergePolicies_StagingAreaName")).FullName;

					string CIPPath = Path.Combine(stagingArea, GlobalVars.GetStr("MergePolicies_MergedPolicyFileName"));

					SiPolicy.Management.ConvertXMLToBinary(MainPolicy, null, CIPPath);

					CiToolHelper.UpdatePolicy(CIPPath);
				}
			});
		}
		catch (Exception ex)
		{
			errorsOccurred = true;
			MainInfoBar.WriteError(ex, GlobalVars.GetStr("MergePolicies_ErrorMessage"));
		}
		finally
		{
			if (!errorsOccurred)
			{
				MainInfoBar.WriteSuccess(GlobalVars.GetStr("MergePolicies_SuccessMessage"));
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
		}
	}

	/// <summary>
	/// Handles the click event for the Other Policies browse button. It opens a file picker dialog to select multiple XML
	/// files and adds unique selections to a display string.
	/// </summary>
	internal void OtherPoliciesBrowseButton_Click()
	{
		List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (selectedFiles.Count > 0)
		{
			foreach (string file in selectedFiles)
			{
				OtherPolicies.Add(file);
			}
		}
	}

	/// <summary>
	/// Clears the text box for the main selected policy
	/// </summary>
	internal void MainPolicy_Flyout_ClearButton() => MainPolicy = null;

	/// <summary>
	/// Clears the textbox for other selected policies
	/// </summary>
	internal void OtherPolicies_Flyout_ClearButton() => OtherPolicies.Clear();

}
