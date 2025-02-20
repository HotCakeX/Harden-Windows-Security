using System;
using System.Threading.Tasks;
using AppControlManager.Main;
using AppControlManager.Others;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

public sealed partial class ValidatePolicy : Page
{
	public ValidatePolicy()
	{
		this.InitializeComponent();

		this.NavigationCacheMode = NavigationCacheMode.Enabled;
	}

	private async void BrowseForXMLSettingsCard_Click(object sender, RoutedEventArgs e)
	{
		await ValidateXML();
	}

	private async void BrowseForXMLButton_Click(object sender, RoutedEventArgs e)
	{
		await ValidateXML();
	}

	private async Task ValidateXML()
	{

		try
		{
			MainInfoBar.Message = "Browse for an App Control XML policy file";
			MainInfoBar.Severity = InfoBarSeverity.Informational;
			MainInfoBar.IsOpen = true;
			MainInfoBar.IsClosable = false;
			MainInfoBar.Title = "Status";

			BrowseForXMLSettingsCard.IsEnabled = false;
			BrowseForXMLButton.IsEnabled = false;

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
				MainInfoBar.IsOpen = false;
				return;
			}

			if (isValid)
			{
				MainInfoBar.Message = $"The selected policy file '{selectedFile}' is valid.";
				MainInfoBar.Severity = InfoBarSeverity.Success;
				MainInfoBar.Title = "Valid";
			}
			else
			{
				MainInfoBar.Message = $"The selected policy file '{selectedFile}' is not valid.";
				MainInfoBar.Severity = InfoBarSeverity.Warning;
				MainInfoBar.Title = "Invalid";
			}

		}
		catch (Exception ex)
		{
			MainInfoBar.Message = ex.Message;
			MainInfoBar.Severity = InfoBarSeverity.Error;
			MainInfoBar.Title = "Invalid";
		}
		finally
		{
			MainInfoBar.IsClosable = true;
			BrowseForXMLSettingsCard.IsEnabled = true;
			BrowseForXMLButton.IsEnabled = true;
		}
	}

}
