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

using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using AppControlManager.Others;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Windows.ApplicationModel.DataTransfer;

namespace AppControlManager.Pages;

/// <summary>
/// BuildNewCertificate is a page for generating a new certificate. It manages user input, validates fields, and handles
/// the certificate creation process.
/// </summary>
internal sealed partial class BuildNewCertificate : Page
{
#pragma warning disable CA1822
	private AppSettings.Main AppSettings { get; } = App.AppHost.Services.GetRequiredService<AppSettings.Main>();
#pragma warning restore CA1822

	// To save the generated certificate's thumb print
	private string? generatedCertThumbPrint;

	/// <summary>
	/// Initializes a new instance of the BuildNewCertificate class. Sets the navigation cache mode and checks field
	/// contents.
	/// </summary>
	internal BuildNewCertificate()
	{
		this.InitializeComponent();

		this.NavigationCacheMode = NavigationCacheMode.Required;

		CheckFieldContents();
	}

	/// <summary>
	/// Handle the open/close style of the ComboBox via SettingsCard touch/click event
	/// </summary>
	private void KeySizeSettingsCard_Click()
	{
		KeySizeComboBox.IsDropDownOpen = !KeySizeComboBox.IsDropDownOpen;
	}

	/// <summary>
	/// Method to ensure all the required fields are filled with content before the build button will be enabled
	/// </summary>
	private void CheckFieldContents()
	{
		if (string.IsNullOrWhiteSpace(CommonNameTextBox.Text) || string.IsNullOrWhiteSpace(PFXEncryptionPasswordBox.Password))
		{
			BuildCertificateButton.IsEnabled = false;
		}
		else
		{
			BuildCertificateButton.IsEnabled = true;
		}
	}

	/// <summary>
	/// Event handler for the main build button
	/// </summary>
	private async void BuildCertificateButton_Click()
	{
		// Track whether errors occurred
		bool ErrorsOccurred = false;

		try
		{

			ProgressRing.Visibility = Visibility.Visible;
			StatusInfoBar.Severity = InfoBarSeverity.Informational;

			CopyInfoBarToClipboardButton.Visibility = Visibility.Collapsed;

			generatedCertThumbPrint = null;

			string keySize = (string)KeySizeComboBox.SelectedItem;
			string commonName = CommonNameTextBox.Text;
			double validity = ValidityNumberBox.Value;
			string password = PFXEncryptionPasswordBox.Password;

			KeySizeComboBox.IsEnabled = false;
			CommonNameTextBox.IsEnabled = false;
			ValidityNumberBox.IsEnabled = false;
			PFXEncryptionPasswordBox.IsEnabled = false;
			BuildCertificateButton.IsEnabled = false;
			KeySizeSettingsCard.IsEnabled = false;

			StatusInfoBar.Title = GlobalVars.Rizz.GetString("ProcessingTitle");
			StatusInfoBar.Message = GlobalVars.Rizz.GetString("BuildingCertificate");
			StatusInfoBar.Visibility = Visibility.Visible;
			StatusInfoBar.IsOpen = true;
			StatusInfoBar.IsClosable = false;

			await Task.Run(() =>
			{
				X509Certificate2 generatedCert = CertificateGenerator.BuildAppControlCertificate(
					 commonName,
					 password,
					 (int)validity,
					 int.Parse(keySize)
					 );

				generatedCertThumbPrint = generatedCert.Thumbprint;
			});
		}
		catch
		{
			StatusInfoBar.Title = GlobalVars.Rizz.GetString("ErrorTitle");
			StatusInfoBar.Message = GlobalVars.Rizz.GetString("CertificateBuildError");
			StatusInfoBar.Severity = InfoBarSeverity.Error;

			ErrorsOccurred = true;

			throw;
		}

		finally
		{
			ProgressRing.Visibility = Visibility.Collapsed;

			KeySizeComboBox.IsEnabled = true;
			CommonNameTextBox.IsEnabled = true;
			ValidityNumberBox.IsEnabled = true;
			PFXEncryptionPasswordBox.IsEnabled = true;
			BuildCertificateButton.IsEnabled = true;
			KeySizeSettingsCard.IsEnabled = true;
			StatusInfoBar.IsClosable = true;

			if (!ErrorsOccurred)
			{
				StatusInfoBar.Title = GlobalVars.Rizz.GetString("SuccessTitle");
				StatusInfoBar.Message = GlobalVars.Rizz.GetString("CertificateBuildSuccess") + generatedCertThumbPrint + "'";

				StatusInfoBar.Severity = InfoBarSeverity.Success;

				CopyInfoBarToClipboardButton.Visibility = Visibility.Visible;
			}
		}
	}


	private void CopyInfoBarToClipboardButton_Click()
	{
		// Create a new data package
		DataPackage dataPackage = new();

		// Set the string to the data package
		dataPackage.SetText(generatedCertThumbPrint);

		// Set the clipboard content
		Clipboard.SetContent(dataPackage);
	}
}
