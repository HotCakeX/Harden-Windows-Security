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

using System.Globalization;
using System.Threading.Tasks;
using AppControlManager.Main;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.ViewModels;

internal sealed partial class GetSecurePolicySettingsVM : ViewModelBase
{
	internal GetSecurePolicySettingsVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);
	}

	private readonly InfoBarSettings MainInfoBar;

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	internal string? Provider { get; set => SP(ref field, value); }
	internal string? Key { get; set => SP(ref field, value); }
	internal string? ValueName { get; set => SP(ref field, value); }
	internal string? Value { get; set => SP(ref field, value); }
	internal string? ValueType { get; set => SP(ref field, value); }
	internal string? ValueSize { get; set => SP(ref field, value); }
	internal string? Status { get; set => SP(ref field, value); }
	internal string? StatusCode { get; set => SP(ref field, value); }

	/// <summary>
	/// Event handler for the Fetch button
	/// </summary>
	internal async void InvokeButton_Click()
	{
		try
		{
			MainInfoBarIsClosable = false;

			// Check if all fields are filled
			if (string.IsNullOrWhiteSpace(Provider) || string.IsNullOrWhiteSpace(Key) || string.IsNullOrWhiteSpace(ValueName))
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("GetSecurePolicySettings_FillAllFields"),
					GlobalVars.GetStr("GetSecurePolicySettings_InputRequired"));
				return;
			}

			// Call the Invoke method
			SecurePolicySetting result = await Task.Run(() => GetCIPolicySetting.Invoke(Provider, Key, ValueName));

			if (result.StatusCode is not 0)
			{
				MainInfoBar.WriteInfo(GlobalVars.GetStr("GetSecurePolicySettings_NoPolicyMessage"),
					GlobalVars.GetStr("GetSecurePolicySettings_PolicyNotFound"));
			}
			else
			{
				MainInfoBar.WriteSuccess(GlobalVars.GetStr("GetSecurePolicySettings_PolicyFoundMessage"),
					GlobalVars.GetStr("GetSecurePolicySettings_PolicyFound"));
			}

			// Populate result fields
			Value = result.Value?.ToString();
			ValueType = result.ValueType.ToString();
			ValueSize = result.ValueSize.ToString(CultureInfo.InvariantCulture);
			Status = result.Status.ToString();
			StatusCode = result.StatusCode.ToString(CultureInfo.InvariantCulture);
		}
		finally
		{
			MainInfoBarIsClosable = true;
		}
	}
}
