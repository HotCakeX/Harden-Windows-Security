using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Windows.ApplicationModel.DataTransfer;

namespace AppControlManager.Pages;


public sealed partial class BuildNewCertificate : Page
{

	// To save the generated certificate's thumb print
	private string? generatedCertThumbPrint;

	public BuildNewCertificate()
	{
		this.InitializeComponent();

		this.NavigationCacheMode = NavigationCacheMode.Required;

		CheckFieldContents();
	}


	/// <summary>
	/// Handle the open/close style of the ComboBox via SettingsCard touch/click event
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void KeySizeSettingsCard_Click(object sender, RoutedEventArgs e)
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
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void BuildCertificateButton_Click(object sender, RoutedEventArgs e)
	{
		// Track whether errors occurred
		bool ErrorsOccurred = false;

		try
		{

			ProgressRing.Visibility = Visibility.Visible;
			StatusInfoBar.Severity = InfoBarSeverity.Informational;

			CopyInfoBarToClipboardButton.Visibility = Visibility.Collapsed;

			generatedCertThumbPrint = null;

			string keySize = ((ComboBoxItem)KeySizeComboBox.SelectedValue).Content.ToString()!;
			string commonName = CommonNameTextBox.Text;
			double validity = ValidityNumberBox.Value;
			string password = PFXEncryptionPasswordBox.Password;

			KeySizeComboBox.IsEnabled = false;
			CommonNameTextBox.IsEnabled = false;
			ValidityNumberBox.IsEnabled = false;
			PFXEncryptionPasswordBox.IsEnabled = false;
			BuildCertificateButton.IsEnabled = false;
			KeySizeSettingsCard.IsEnabled = false;

			StatusInfoBar.Title = "Processing";
			StatusInfoBar.Message = "Building the certificate...";
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
			StatusInfoBar.Title = "Error";
			StatusInfoBar.Message = "Errors occurred while building the certificate";
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
				StatusInfoBar.Title = "Success";
				StatusInfoBar.Message = $"Successfully generated the certificate with the selected details. The certificate's thumbprint is: '{generatedCertThumbPrint}'";

				StatusInfoBar.Severity = InfoBarSeverity.Success;

				CopyInfoBarToClipboardButton.Visibility = Visibility.Visible;
			}
		}
	}



	private void CommonNameTextBox_TextChanged(object sender, TextChangedEventArgs e)
	{
		CheckFieldContents();
	}

	private void PFXEncryptionPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
	{
		CheckFieldContents();
	}


	private void CopyInfoBarToClipboardButton_Click(object sender, RoutedEventArgs e)
	{
		// Create a new data package
		DataPackage dataPackage = new();

		// Set the string to the data package
		dataPackage.SetText(generatedCertThumbPrint);

		// Set the clipboard content
		Clipboard.SetContent(dataPackage);
	}
}
