using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using AppControlManager.MicrosoftGraph;
using AppControlManager.ViewModels;

namespace AppControlManager.CustomUIElements;

internal sealed partial class GraphAuthPanel : UserControl
{
	private AppSettings.Main AppSettings => App.Settings;

	public IGraphAuthHost Host
	{
		get { return (IGraphAuthHost)GetValue(HostProperty); }
		set { SetValue(HostProperty, value); }
	}

	internal static readonly DependencyProperty HostProperty =
		DependencyProperty.Register(
			nameof(Host),
			typeof(IGraphAuthHost),
			typeof(GraphAuthPanel),
			new PropertyMetadata(null));

	internal ViewModelForMSGraph GraphVM => ViewModelProvider.ViewModelForMSGraph;

	internal GraphAuthPanel()
	{
		InitializeComponent();
	}
}
