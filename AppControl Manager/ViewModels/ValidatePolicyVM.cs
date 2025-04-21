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
using System.Threading.Tasks;
using AppControlManager.Main;
using AppControlManager.Others;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.ViewModels;

#pragma warning disable CA1812

internal sealed partial class ValidatePolicyVM : ViewModelBase
{

	#region UI-Bound Properties

	internal bool MainInfoBarIsOpen
	{
		get; set => SetProperty(ref field, value);
	}

	internal string? MainInfoBarMessage
	{
		get; set => SetProperty(ref field, value);
	}

	internal string? MainInfoBarTitle
	{
		get; set => SetProperty(ref field, value);
	}

	internal InfoBarSeverity MainInfoBarSeverity
	{
		get; set => SetProperty(ref field, value);
	}

	internal bool MainInfoBarIsClosable
	{
		get; set => SetProperty(ref field, value);
	}

	internal bool ElementsAreEnabled
	{
		get; set => SetProperty(ref field, value);
	} = true;

	#endregion


	/// <summary>
	/// Validates an App Control XML policy file by allowing the user to select a file and checking its validity.
	/// </summary>
	internal async void ValidateXML()
	{

		try
		{
			MainInfoBarMessage = "Browse for an App Control XML policy file";
			MainInfoBarSeverity = InfoBarSeverity.Informational;
			MainInfoBarIsOpen = true;
			MainInfoBarIsClosable = false;
			MainInfoBarTitle = "Status";

			ElementsAreEnabled = false;

			string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

			bool isValid = false;

			if (!string.IsNullOrEmpty(selectedFile))
			{
				await Task.Run(() =>
				{
					isValid = CiPolicyTest.TestCiPolicy(selectedFile);
				});
			}
			else
			{
				MainInfoBarIsOpen = false;
				return;
			}

			if (isValid)
			{
				MainInfoBarMessage = $"The selected policy file '{selectedFile}' is valid.";
				MainInfoBarSeverity = InfoBarSeverity.Success;
				MainInfoBarTitle = "Valid";
			}
			else
			{
				MainInfoBarMessage = $"The selected policy file '{selectedFile}' is not valid.";
				MainInfoBarSeverity = InfoBarSeverity.Warning;
				MainInfoBarTitle = "Invalid";
			}
		}
		catch (Exception ex)
		{
			MainInfoBarMessage = ex.Message;
			MainInfoBarSeverity = InfoBarSeverity.Error;
			MainInfoBarTitle = "Invalid";
		}
		finally
		{
			MainInfoBarIsClosable = true;
			ElementsAreEnabled = true;
		}
	}

}
