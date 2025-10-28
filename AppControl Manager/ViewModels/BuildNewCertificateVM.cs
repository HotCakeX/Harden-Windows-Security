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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using AppControlManager.Others;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.ViewModels;

internal sealed partial class BuildNewCertificateVM : ViewModelBase
{

	internal BuildNewCertificateVM()
	{
		MainInfoBar = new InfoBarSettings(
		() => StatusInfoBarIsOpen, value => StatusInfoBarIsOpen = value,
		() => StatusInfoBarMessage, value => StatusInfoBarMessage = value,
		() => StatusInfoBarSeverity, value => StatusInfoBarSeverity = value,
		() => StatusInfoBarIsClosable, value => StatusInfoBarIsClosable = value,
		Dispatcher,
		() => StatusInfoBarTitle, value => StatusInfoBarTitle = value);
	}

	private readonly InfoBarSettings MainInfoBar;

	/// <summary>
	/// To save the generated certificate's thumb print
	/// </summary>
	internal string? generatedCertThumbPrint { get; set => SP(ref field, value); }

	internal InfoBarSeverity StatusInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool StatusInfoBarIsOpen { get; set => SP(ref field, value); }
	internal bool StatusInfoBarIsClosable { get; set => SP(ref field, value); } = true;
	internal string? StatusInfoBarMessage { get; set => SP(ref field, value); }
	internal string? StatusInfoBarTitle { get; set => SP(ref field, value); }

	/// <summary>
	/// Gets or sets the visibility state of the progress ring.
	/// </summary>
	internal Visibility ProgressRingVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	/// <summary>
	/// Gets or sets the visibility of the "Copy to Clipboard" button in the information bar.
	/// </summary>
	internal Visibility CopyInfoBarToClipboardButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	/// <summary>
	/// Enables/Disables the UI elements during an ongoing operation.
	/// </summary>
	internal bool ElementsAreEnabled
	{
		get; set
		{
			if (SP(ref field, value))
			{
				StatusInfoBarIsClosable = field;
				ProgressRingVisibility = field ? Visibility.Collapsed : Visibility.Visible;
			}
		}
	} = true;

	private enum HashAlgorithm
	{
		SHA2_256 = 0,
		SHA2_384 = 1,
		SHA2_512 = 2,
		SHA3_256 = 3,
		SHA3_384 = 4,
		SHA3_512 = 5
	}

	private readonly Dictionary<HashAlgorithm, HashAlgorithmName> AlgoCorrelation = new() {
		{ HashAlgorithm.SHA2_256, HashAlgorithmName.SHA256 },
		{ HashAlgorithm.SHA2_384, HashAlgorithmName.SHA384 },
		{ HashAlgorithm.SHA2_512, HashAlgorithmName.SHA512 },
		{ HashAlgorithm.SHA3_256, HashAlgorithmName.SHA3_256 },
		{ HashAlgorithm.SHA3_384, HashAlgorithmName.SHA3_384 },
		{ HashAlgorithm.SHA3_512, HashAlgorithmName.SHA3_512 }
	};

	internal string? CommonName { get; set => SPT(ref field, value); }
	internal string? Password { get; set => SPT(ref field, value); }
	internal string KeySizeComboBoxSelectedItem { get; set => SP(ref field, value); } = "4096";
	internal double Validity { get; set => SP(ref field, value); } = 100;
	internal int SelectedHashAlgorithm
	{
		get; set
		{
			if (SP(ref field, value))
			{
				if (field > 2)
				{
					MainInfoBar.WriteWarning(GlobalVars.GetStr("AlgoNotSupportedByCIWarning"));
				}
				else
				{
					StatusInfoBarIsOpen = false;
				}
			}
		}
	} = 2;

	/// <summary>
	/// Event handler for the main build button
	/// </summary>
	internal async void BuildCertificateButton_Click()
	{
		CopyInfoBarToClipboardButtonVisibility = Visibility.Collapsed;

		if (string.IsNullOrEmpty(CommonName) || string.IsNullOrEmpty(Password))
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("ProvideCNOrPassErrorMsg"),
				GlobalVars.GetStr("ProvideCNOrPassErrorTitle"));
			return;
		}

		// Track whether errors occurred
		bool ErrorsOccurred = false;

		try
		{
			generatedCertThumbPrint = null;

			ElementsAreEnabled = false;

			MainInfoBar.WriteInfo(GlobalVars.GetStr("BuildingCertificate"),
				GlobalVars.GetStr("ProcessingTitle"));

			await Task.Run(() =>
			{
				X509Certificate2 generatedCert = CertificateGenerator.BuildAppControlCertificate(
					 CommonName,
					 Password,
					 (int)Validity,
					 int.Parse(KeySizeComboBoxSelectedItem),
					 AlgoCorrelation[(HashAlgorithm)SelectedHashAlgorithm]
					 );

				generatedCertThumbPrint = generatedCert.Thumbprint;
			});
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex, GlobalVars.GetStr("CertificateBuildError"),
				GlobalVars.GetStr("ErrorTitle"));
			ErrorsOccurred = true;
		}

		finally
		{
			ElementsAreEnabled = true;

			if (!ErrorsOccurred)
			{
				MainInfoBar.WriteSuccess(GlobalVars.GetStr("CertificateBuildSuccess") + generatedCertThumbPrint + "'",
					GlobalVars.GetStr("SuccessText"));

				CopyInfoBarToClipboardButtonVisibility = Visibility.Visible;
			}
		}
	}

	/// <summary>
	/// Copies the thumbprint of the generated certificate to the clipboard.
	/// </summary>
	internal void CopyInfoBarToClipboardButton_Click() => ClipboardManagement.CopyText(generatedCertThumbPrint);
}
