using HardenSystemSecurity.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.CustomUIElements.HomePageStageContents;

internal sealed partial class Item4 : UserControl
{
	internal Item4()
	{
		InitializeComponent();
	}

	private void Button_Click(object sender, RoutedEventArgs e)
	{
		ViewModelProvider.NavigationService.Navigate(typeof(HardenSystemSecurity.Pages.AuditPolicies), null);
	}
}
