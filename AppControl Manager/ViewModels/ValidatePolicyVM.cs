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
using System.IO;
using System.Threading.Tasks;
using System.Xml;
using AppControlManager.Main;
using AppControlManager.Others;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.ViewModels;

#pragma warning disable CA1812

internal sealed partial class ValidatePolicyVM : ViewModelBase
{

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
			}
		}
	} = true;

	internal Visibility ProgressRingVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	// Level 2
	internal bool Level2Test
	{
		get; set
		{
			if (SP(ref field, value))
			{
				// אם כיבינו את רמת 2 ⇒ ממטירים את 3 ו־4
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
					// אם הדלקנו רמת 3 ⇒ נבטיח שרמת 2 דולקת
					Level2Test = true;
				}
				else
				{
					// אם כיבינו רמת 3 ⇒ נבטיח שרמת 4 כבוייה
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
					// אם הדלקנו רמת 4 ⇒ נדאג שגם 2 וגם 3 דלוקים
					Level2Test = true;
					Level3Test = true;
				}
				// אם כיבינו רמת 4 ⇒ אין פעולות נוספות
			}
		}
	} = true;


	#endregion

	/// <summary>
	/// Validates an App Control XML policy file by allowing the user to select a file and checking its validity.
	/// </summary>
	internal async void ValidateXML()
	{
		string? stagingArea = null;

		try
		{
			MainInfoBarMessage = GlobalVars.Rizz.GetString("BrowseForAppControlPolicy");
			MainInfoBarSeverity = InfoBarSeverity.Informational;
			MainInfoBarIsOpen = true;
			MainInfoBarTitle = GlobalVars.Rizz.GetString("CurrentStatusInfoBar/Title");

			ElementsAreEnabled = false;

			double CIPSize = 0;

			string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

			bool IsValid = false;

			MainInfoBarMessage = GlobalVars.Rizz.GetString("Validating");

			if (!string.IsNullOrEmpty(selectedFile))
			{
				await Task.Run(() =>
				{
					IsValid = CiPolicyTest.TestCiPolicy(selectedFile);

					if (IsValid && Level2Test)
					{
						SiPolicy.SiPolicy temp = SiPolicy.CustomDeserialization.DeserializeSiPolicy(selectedFile, null);

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
								PolicyToCIPConverter.Convert(tempPolicyXMLPath, tempPolicyCIPPath);

								FileInfo fileInfo = new(tempPolicyCIPPath);

								CIPSize = Math.Round(fileInfo.Length / 1024.0, 2);
							}
						}
					}
				});
			}
			else
			{
				MainInfoBarIsOpen = false;
				return;
			}

			if (IsValid)
			{
				MainInfoBarMessage = GlobalVars.Rizz.GetString("IsValid") + selectedFile;
				MainInfoBarSeverity = InfoBarSeverity.Success;
				MainInfoBarTitle = GlobalVars.Rizz.GetString("Valid");

				if (Level4Test)
				{
					MainInfoBarMessage += $"\n{GlobalVars.Rizz.GetString("CIPFileSize")}: {CIPSize} KB";

					if (CIPSize < 350)
					{
						MainInfoBarMessage += $"\n{GlobalVars.Rizz.GetString("SuitableForIntuneDeployment")}";
					}
					else
					{
						MainInfoBarMessage += $"\n{GlobalVars.Rizz.GetString("ReduceSizeForIntuneDeployment")}";
					}
				}
			}
			else
			{
				MainInfoBarMessage = GlobalVars.Rizz.GetString("IsNotValid") + selectedFile;
				MainInfoBarSeverity = InfoBarSeverity.Warning;
				MainInfoBarTitle = GlobalVars.Rizz.GetString("Invalid");
			}
		}
		catch (Exception ex)
		{
			MainInfoBarMessage = ex.Message;
			MainInfoBarSeverity = InfoBarSeverity.Error;
			MainInfoBarTitle = GlobalVars.Rizz.GetString("Invalid");
		}
		finally
		{
			ElementsAreEnabled = true;

			if (Directory.Exists(stagingArea))
			{
				Directory.Delete(stagingArea, true);
			}
		}
	}
}
