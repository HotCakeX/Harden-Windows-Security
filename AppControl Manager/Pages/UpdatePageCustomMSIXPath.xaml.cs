using System.IO;
using AppControlManager.Others;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

public sealed partial class UpdatePageCustomMSIXPath : Page
{
	public UpdatePageCustomMSIXPath()
	{
		this.InitializeComponent();

		// Set the initial state of things
		SetConfirmToggleSwitchState();

		this.NavigationCacheMode = NavigationCacheMode.Enabled;
	}


	private void BrowseForCustomMSIXPathButton_Click(object sender, RoutedEventArgs e)
	{
		// Offer file picker to select MSIX file path
		string? MSIXPath = FileDialogHelper.ShowFilePickerDialog("MSIXBundle file|*.msixbundle");

		// If user has selected a path and the file name is valid
		if (!string.IsNullOrWhiteSpace(MSIXPath))
		{
			// Update the path variable on the main update page
			UpdatePage.Instance.customMSIXBundlePath = MSIXPath;

			// Enable the confirmation settings card
			ConfirmUseOfCustomMSIXPathSettingsCard.IsEnabled = true;
		}
		else
		{
			ConfirmUseOfCustomMSIXPathSettingsCard.IsEnabled = false;
			ConfirmUseOfCustomMSIXPath.IsOn = false;

			// Revert the update button's text back to the default value
			GlobalVars.updateButtonTextOnTheUpdatePage = "Check for update";
		}
	}


	private void ConfirmUseOfCustomMSIXPath_Click(object sender, RoutedEventArgs e)
	{
		ConfirmUseOfCustomMSIXPath.IsOn = !ConfirmUseOfCustomMSIXPath.IsOn;

		UpdatePage.Instance.useCustomMSIXBundlePath = ConfirmUseOfCustomMSIXPath.IsOn;

		SetConfirmToggleSwitchState();
	}


	/// <summary>
	/// Set the initial state of the toggle switch based on whether a custom MSIX file path is selected or not
	/// </summary>
	private void SetConfirmToggleSwitchState()
	{

		if (!string.IsNullOrEmpty(UpdatePage.Instance.customMSIXBundlePath))
		{
			ConfirmUseOfCustomMSIXPathSettingsCard.IsEnabled = true;

			if (ConfirmUseOfCustomMSIXPath.IsOn)
			{
				// Update the Update button's text content to reflect the selected MSIX file name
				GlobalVars.updateButtonTextOnTheUpdatePage = $"Install {Path.GetFileName(UpdatePage.Instance.customMSIXBundlePath)}";
			}
			else
			{
				// Revert the update button's text back to the default value
				GlobalVars.updateButtonTextOnTheUpdatePage = "Check for update";
			}
		}
		else
		{
			ConfirmUseOfCustomMSIXPathSettingsCard.IsEnabled = false;
			ConfirmUseOfCustomMSIXPath.IsOn = false;

			// Revert the update button's text back to the default value
			GlobalVars.updateButtonTextOnTheUpdatePage = "Check for update";
		}
	}
}
