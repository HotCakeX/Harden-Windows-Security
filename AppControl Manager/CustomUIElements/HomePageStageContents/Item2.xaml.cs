using System;
using AppControlManager.Others;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.System;

namespace AppControlManager.CustomUIElements.HomePageStageContents;

internal sealed partial class Item2 : UserControl
{
	internal Item2()
	{
		InitializeComponent();
	}

	private static readonly Uri uri = new("https://apps.microsoft.com/detail/9P7GGFL7DX57");

	private async void Button_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			bool launched = await Launcher.LaunchUriAsync(uri);

			if (!launched)
			{
				Logger.Write($"Failed opening: '{uri}'");
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}
}
