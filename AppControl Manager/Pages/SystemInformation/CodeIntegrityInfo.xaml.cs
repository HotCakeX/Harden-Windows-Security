using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

public sealed partial class CodeIntegrityInfo : Page
{
	public CodeIntegrityInfo()
	{
		this.InitializeComponent();

		this.NavigationCacheMode = NavigationCacheMode.Enabled;
	}


	/// <summary>
	/// Local method to convert numbers to their actual string values
	/// </summary>
	/// <param name="status"></param>
	/// <returns></returns>
	private static string? GetPolicyStatus(uint? status) => status switch
	{
		1 => "Audit Mode",
		1 => "Audit mode",
		2 => "Enforced Mode",
		_ => null
	};


	/// <summary>
	/// Event handler for the retrieve code integrity information button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void RetrieveCodeIntegrityInfo_Click(object sender, RoutedEventArgs e)
	{
		// Get the system code integrity information
		CodeIntegrity.SystemCodeIntegrityInfo codeIntegrityInfoResult = CodeIntegrity.DetailsRetrieval.Get();

		// Bind the CodeIntegrityDetails (List<CodeIntegrityOption>) to the ListView
		CodeIntegrityInfoListView.ItemsSource = codeIntegrityInfoResult.CodeIntegrityDetails;

		// Get the Application Control Status
		DeviceGuardStatus? DGStatus = DeviceGuardInfo.GetDeviceGuardStatus();

		UMCI.Text = GetPolicyStatus(DGStatus?.UsermodeCodeIntegrityPolicyEnforcementStatus);
		KMCI.Text = GetPolicyStatus(DGStatus?.CodeIntegrityPolicyEnforcementStatus);

	}
}
