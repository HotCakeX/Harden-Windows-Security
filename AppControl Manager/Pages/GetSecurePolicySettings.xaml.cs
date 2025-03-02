using System.Globalization;
using AppControlManager.Main;
using AppControlManager.Others;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

public sealed partial class GetSecurePolicySettings : Page
{
	public GetSecurePolicySettings()
	{
		this.InitializeComponent();

		// Make sure navigating to/from this page maintains its state
		this.NavigationCacheMode = NavigationCacheMode.Required;
	}

	// Event handler for the Fetch button
	private void InvokeButton_Click(object sender, RoutedEventArgs e)
	{
		// Retrieve input values
		string provider = ProviderTextBox.Text;
		string key = KeyTextBox.Text;
		string valueName = ValueNameTextBox.Text;

		// Check if all fields are filled
		if (string.IsNullOrWhiteSpace(provider) || string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(valueName))
		{
			InfoBar.Message = GlobalVars.Rizz.GetString("GetSecurePolicySettings_FillAllFields");
			InfoBar.Severity = InfoBarSeverity.Warning;
			InfoBar.Title = GlobalVars.Rizz.GetString("GetSecurePolicySettings_InputRequired");
			InfoBar.IsOpen = true;
			return;
		}

		// Call the Invoke method
		SecurePolicySetting result = GetCIPolicySetting.Invoke(provider, key, valueName);

		if (result.StatusCode is not 0)
		{
			InfoBar.Message = GlobalVars.Rizz.GetString("GetSecurePolicySettings_NoPolicyMessage");
			InfoBar.Severity = InfoBarSeverity.Informational;
			InfoBar.Title = GlobalVars.Rizz.GetString("GetSecurePolicySettings_PolicyNotFound");
			InfoBar.IsOpen = true;
		}
		else
		{
			InfoBar.Message = GlobalVars.Rizz.GetString("GetSecurePolicySettings_PolicyFoundMessage");
			InfoBar.Severity = InfoBarSeverity.Success;
			InfoBar.Title = GlobalVars.Rizz.GetString("GetSecurePolicySettings_PolicyFound");
			InfoBar.IsOpen = true;
		}

		// Populate result fields
		ValueTextBox.Text = result.Value?.ToString();
		ValueTypeTextBox.Text = result.ValueType.ToString();
		ValueSizeTextBox.Text = result.ValueSize.ToString(CultureInfo.InvariantCulture);
		StatusTextBox.Text = result.Status.ToString();
		StatusCodeTextBox.Text = result.StatusCode.ToString(CultureInfo.InvariantCulture);
	}
}
