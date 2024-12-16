using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.Pages;

public sealed partial class CodeIntegrityInfo : Page
{
	public CodeIntegrityInfo()
	{
		this.InitializeComponent();

		this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Enabled;
	}

	private void RetrieveCodeIntegrityInfo_Click(object sender, RoutedEventArgs e)
	{
		// Get the system code integrity information
		CodeIntegrity.SystemCodeIntegrityInfo codeIntegrityInfoResult = CodeIntegrity.DetailsRetrieval.Get();

		// Bind the CodeIntegrityDetails (List<CodeIntegrityOption>) to the ListView
		CodeIntegrityInfoListView.ItemsSource = codeIntegrityInfoResult.CodeIntegrityDetails;
	}
}
