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
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using AppControlManager.Others;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.ViewModels;

#pragma warning disable CA1812
internal sealed partial class BuildNewCertificateVM : ViewModelBase
{
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

	internal string? CommonName { get; set => SP(ref field, value); }
	internal string? Password { get; set => SP(ref field, value); }
	internal string KeySizeComboBoxSelectedItem { get; set => SP(ref field, value); } = "4096";
	internal double Validity { get; set => SP(ref field, value); } = 100;

	/// <summary>
	/// Event handler for the main build button
	/// </summary>
	internal async void BuildCertificateButton_Click()
	{
		StatusInfoBarIsOpen = true;
		CopyInfoBarToClipboardButtonVisibility = Visibility.Collapsed;

		if (string.IsNullOrEmpty(CommonName) || string.IsNullOrEmpty(Password))
		{
			StatusInfoBarSeverity = InfoBarSeverity.Warning;
			StatusInfoBarMessage = GlobalVars.Rizz.GetString("ProvideCNOrPassErrorMsg");
			StatusInfoBarTitle = GlobalVars.Rizz.GetString("ProvideCNOrPassErrorTitle");
			return;
		}

		// Track whether errors occurred
		bool ErrorsOccurred = false;

		try
		{
			StatusInfoBarSeverity = InfoBarSeverity.Informational;

			generatedCertThumbPrint = null;

			ElementsAreEnabled = false;

			StatusInfoBarTitle = GlobalVars.Rizz.GetString("ProcessingTitle");
			StatusInfoBarMessage = GlobalVars.Rizz.GetString("BuildingCertificate");

			await Task.Run(() =>
			{
				X509Certificate2 generatedCert = CertificateGenerator.BuildAppControlCertificate(
					 CommonName,
					 Password,
					 (int)Validity,
					 int.Parse(KeySizeComboBoxSelectedItem)
					 );

				generatedCertThumbPrint = generatedCert.Thumbprint;
			});
		}
		catch (Exception ex)
		{
			StatusInfoBarTitle = GlobalVars.Rizz.GetString("ErrorTitle");
			StatusInfoBarMessage = GlobalVars.Rizz.GetString("CertificateBuildError") + " : " + ex.Message;
			StatusInfoBarSeverity = InfoBarSeverity.Error;

			ErrorsOccurred = true;

			Logger.Write(ErrorWriter.FormatException(ex));
		}

		finally
		{
			ElementsAreEnabled = true;

			if (!ErrorsOccurred)
			{
				StatusInfoBarTitle = GlobalVars.Rizz.GetString("SuccessTitle");
				StatusInfoBarMessage = GlobalVars.Rizz.GetString("CertificateBuildSuccess") + generatedCertThumbPrint + "'";

				StatusInfoBarSeverity = InfoBarSeverity.Success;

				CopyInfoBarToClipboardButtonVisibility = Visibility.Visible;
			}
		}
	}

	/// <summary>
	/// Copies the thumbprint of the generated certificate to the clipboard.
	/// </summary>
	internal void CopyInfoBarToClipboardButton_Click()
	{
		ClipboardManagement.CopyText(generatedCertThumbPrint);
	}
}
