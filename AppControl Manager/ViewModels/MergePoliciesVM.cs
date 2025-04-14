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

#pragma warning disable CA1812 // an internal class that is apparently never instantiated
// It's handled by Dependency Injection so this warning is a false-positive.
internal sealed partial class MergePoliciesVM : ViewModelBase
{

#pragma warning disable CA1822 // Mark members as static
	internal bool IsElevated => App.IsElevated;
#pragma warning restore CA1822


	#region UI-Bound Properties

	private HashSet<string> _otherPolicies = [];
	internal HashSet<string> OtherPolicies
	{
		get => _otherPolicies;
		set => SetProperty(_otherPolicies, value, newValue => _otherPolicies = newValue);
	}

	private string? _OtherPoliciesString;
	internal string? OtherPoliciesString
	{
		get => _OtherPoliciesString;
		set => SetProperty(_OtherPoliciesString, value, newValue => _OtherPoliciesString = newValue);
	}

	private bool _shouldDeploy;
	internal bool ShouldDeploy
	{
		get => _shouldDeploy;
		set => SetProperty(_shouldDeploy, value, newValue => _shouldDeploy = newValue);
	}

	internal bool ShouldDeployToggleState = App.IsElevated;

	private string? _mainPolicy;
	internal string? MainPolicy
	{
		get => _mainPolicy;
		set => SetProperty(_mainPolicy, value, newValue => _mainPolicy = newValue);
	}

	private bool _MergeButtonState = true;
	internal bool MergeButtonState
	{
		get => _MergeButtonState;
		set => SetProperty(_MergeButtonState, value, newValue => _MergeButtonState = newValue);
	}

	private bool _MergeButtonTeachingTipIsOpen;
	internal bool MergeButtonTeachingTipIsOpen
	{
		get => _MergeButtonTeachingTipIsOpen;
		set => SetProperty(_MergeButtonTeachingTipIsOpen, value, newValue => _MergeButtonTeachingTipIsOpen = newValue);
	}

	private string? _MergeButtonTeachingTipTitle;
	internal string? MergeButtonTeachingTipTitle
	{
		get => _MergeButtonTeachingTipTitle;
		set => SetProperty(_MergeButtonTeachingTipTitle, value, newValue => _MergeButtonTeachingTipTitle = newValue);
	}

	private string? _MergeButtonTeachingTipSubTitle;
	internal string? MergeButtonTeachingTipSubTitle
	{
		get => _MergeButtonTeachingTipSubTitle;
		set => SetProperty(_MergeButtonTeachingTipSubTitle, value, newValue => _MergeButtonTeachingTipSubTitle = newValue);
	}

	private bool _PolicyMergerInfoBarIsOpen;
	internal bool PolicyMergerInfoBarIsOpen
	{
		get => _PolicyMergerInfoBarIsOpen;
		set => SetProperty(_PolicyMergerInfoBarIsOpen, value, newValue => _PolicyMergerInfoBarIsOpen = newValue);
	}

	private string? _PolicyMergerInfoBarMessage;
	internal string? PolicyMergerInfoBarMessage
	{
		get => _PolicyMergerInfoBarMessage;
		set => SetProperty(_PolicyMergerInfoBarMessage, value, newValue => _PolicyMergerInfoBarMessage = newValue);
	}

	private Visibility _MergeProgressRingVisibility = Visibility.Collapsed;
	internal Visibility MergeProgressRingVisibility
	{
		get => _MergeProgressRingVisibility;
		set => SetProperty(_MergeProgressRingVisibility, value, newValue => _MergeProgressRingVisibility = newValue);
	}

	private InfoBarSeverity _PolicyMergerInfoBarSeverity;
	internal InfoBarSeverity PolicyMergerInfoBarSeverity
	{
		get => _PolicyMergerInfoBarSeverity;
		set => SetProperty(_PolicyMergerInfoBarSeverity, value, newValue => _PolicyMergerInfoBarSeverity = newValue);
	}

	private bool _PolicyMergerInfoBarIsClosable;
	internal bool PolicyMergerInfoBarIsClosable
	{
		get => _PolicyMergerInfoBarIsClosable;
		set => SetProperty(_PolicyMergerInfoBarIsClosable, value, newValue => _PolicyMergerInfoBarIsClosable = newValue);
	}

	#endregion


	/// <summary>
	/// Event handler for the main Merge button
	/// </summary>
	internal async void MergeButton_Click()
	{

		// Close the teaching tip if it's open when user presses the button
		// it will be opened again if necessary
		MergeButtonTeachingTipIsOpen = false;

		if (string.IsNullOrWhiteSpace(MainPolicy))
		{
			MergeButtonTeachingTipIsOpen = true;
			MergeButtonTeachingTipTitle = GlobalVars.Rizz.GetString("MergePolicies_SelectMainPolicyXML");
			MergeButtonTeachingTipSubTitle = GlobalVars.Rizz.GetString("MergePolicies_SelectMainPolicySubtitle");
			return;
		}

		if (OtherPolicies.Count is 0)
		{
			MergeButtonTeachingTipIsOpen = true;
			MergeButtonTeachingTipTitle = GlobalVars.Rizz.GetString("MergePolicies_SelectOtherPolicies");
			MergeButtonTeachingTipSubTitle = GlobalVars.Rizz.GetString("MergePolicies_SelectOtherPoliciesSubtitle");
			return;
		}


		bool errorsOccurred = false;

		try
		{

			PolicyMergerInfoBarIsClosable = false;

			MergeButtonState = false;

			PolicyMergerInfoBarIsOpen = true;

			PolicyMergerInfoBarMessage = GlobalVars.Rizz.GetString("MergePolicies_MergingMessage");

			MergeProgressRingVisibility = Visibility.Visible;

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

					PolicyToCIPConverter.Convert(MainPolicy, CIPPath);

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
