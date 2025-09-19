using System;
using AppControlManager.Others;
using Microsoft.UI.Xaml.Controls;
using Windows.System;
using Microsoft.UI.Xaml;

namespace AppControlManager.CustomUIElements.HomePageStageContents;

internal sealed partial class Item1 : UserControl
{
	internal Item1()
	{
		InitializeComponent();
	}

	private static readonly Uri uri = new("https://github.com/HotCakeX/Harden-Windows-Security/releases");

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
