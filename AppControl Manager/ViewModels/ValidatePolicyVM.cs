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

using System.IO;
using System.Threading.Tasks;
using System.Xml;
using AppControlManager.Main;
using AppControlManager.Others;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.ViewModels;

internal sealed partial class ValidatePolicyVM : ViewModelBase
{
	internal ValidatePolicyVM() => MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher,
			() => MainInfoBarTitle, value => MainInfoBarTitle = value);


	private readonly InfoBarSettings MainInfoBar;

	#region UI-Bound Properties

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal string? MainInfoBarTitle { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); }
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	internal bool ElementsAreEnabled
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ProgressRingVisibility = field ? Visibility.Collapsed : Visibility.Visible;
				MainInfoBarIsClosable = field;
				// Re-evaluate refresh button state when elements are re-enabled
				OnPropertyChanged(nameof(RefreshButtonEnabled));
			}
		}
	} = true;

	internal Visibility ProgressRingVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	/// <summary>
	/// The path of the currently selected policy file
	/// </summary>
	internal string? SelectedPolicyPath
	{
		get; set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(RefreshButtonEnabled));
			}
		}
	}

	/// <summary>
	/// Only enable refresh if elements are enabled and we have a valid path
	/// </summary>
	internal bool RefreshButtonEnabled => ElementsAreEnabled && !string.IsNullOrWhiteSpace(SelectedPolicyPath);

	// Level 2
	internal bool Level2Test
	{
		get; set
		{
			if (SP(ref field, value))
			{
				if (!field)
				{
					Level3Test = false;
					Level4Test = false;
				}
			}
		}
	} = true;

	// Level 3
	internal bool Level3Test
	{
		get; set
		{
			if (SP(ref field, value))
			{
				if (field)
				{
					Level2Test = true;
				}
				else
				{
					Level4Test = false;
				}
			}
		}
	} = true;

	// Level 4
	internal bool Level4Test
	{
		get; set
		{
			if (SP(ref field, value))
			{
				if (field)
				{
					Level2Test = true;
					Level3Test = true;
				}
			}
		}
	} = true;

	#endregion

	/// <summary>
	/// Opens the file picker to select a policy, then validates it.
	/// </summary>
	internal async void BrowseAndValidate()
	{
		SelectedPolicyPath = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);
		if (SelectedPolicyPath is null) return;
		await ValidateLogic();
	}

	/// <summary>
	/// Re-runs validation on the currently selected policy.
	/// </summary>
	internal async void RefreshValidation() => await ValidateLogic();

	/// <summary>
	/// Clears the selected policy path from the UI.
	/// </summary>
	internal void ClearSelectedPolicy() => SelectedPolicyPath = null;

	/// <summary>
	/// Core logic to validate the XML policy file.
	/// </summary>
	private async Task ValidateLogic()
	{
		string? stagingArea = null;

		try
		{
			ElementsAreEnabled = false;

			if (string.IsNullOrWhiteSpace(SelectedPolicyPath) && !File.Exists(SelectedPolicyPath))
			{
				SelectedPolicyPath = null;
				MainInfoBar.WriteWarning(GlobalVars.GetStr("SelectAppControlPolicyFirstMessage"));
				return;
			}

			MainInfoBar.WriteInfo(GlobalVars.GetStr("Validating"), GlobalVars.GetStr("CurrentStatusInfoBar/Title"));

			double CIPSize = 0;
			bool IsValid = false;

			await Task.Run(() =>
			{
				// Throws if the policy is invalid.
				CiPolicyTest.TestCiPolicy(SelectedPolicyPath);

				IsValid = true;

				if (IsValid && Level2Test)
				{
					SiPolicy.SiPolicy temp = SiPolicy.CustomDeserialization.DeserializeSiPolicy(SelectedPolicyPath, null);

					if (Level3Test)
					{
						XmlDocument xmlObj = SiPolicy.CustomSerialization.CreateXmlFromSiPolicy(temp);

						if (!App.IsElevated)
						{
							string tempDir = Path.GetTempPath();
							string randomFolderName = Path.GetRandomFileName();
							string fullPath = Path.Combine(tempDir, randomFolderName);

							stagingArea = Directory.CreateDirectory(fullPath).FullName;
						}
						else
						{
							stagingArea = StagingArea.NewStagingArea("Level4Validation").FullName;
						}

						string tempPolicyCIPPath = Path.Combine(stagingArea, $"test.cip");
						string tempPolicyXMLPath = Path.Combine(stagingArea, $"test.xml");

						xmlObj.Save(tempPolicyXMLPath);

						if (Level4Test)
						{
							SiPolicy.Management.ConvertXMLToBinary(tempPolicyXMLPath, null, tempPolicyCIPPath);

							FileInfo fileInfo = new(tempPolicyCIPPath);

							CIPSize = Math.Round(fileInfo.Length / 1024.0, 2);
						}
					}
				}
			});

			if (IsValid)
			{
				string msg = GlobalVars.GetStr("IsValid") + SelectedPolicyPath;

				if (Level4Test)
				{
					msg += $"\n{GlobalVars.GetStr("CIPFileSize")}: {CIPSize} KB";

					if (CIPSize < 350)
					{
						msg += $"\n{GlobalVars.GetStr("SuitableForIntuneDeployment")}";
					}
					else
					{
						msg += $"\n{GlobalVars.GetStr("ReduceSizeForIntuneDeployment")}";
					}
				}

				MainInfoBar.WriteSuccess(msg, GlobalVars.GetStr("Valid"));
			}
			else
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("IsNotValid") + SelectedPolicyPath, GlobalVars.GetStr("Invalid"));
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex, null, GlobalVars.GetStr("Invalid"));
		}
		finally
		{
			ElementsAreEnabled = true;
			MainInfoBarIsClosable = true;

			if (Directory.Exists(stagingArea))
			{
				try
				{
					Directory.Delete(stagingArea, true);
				}
				catch { }
			}
		}
	}
}
