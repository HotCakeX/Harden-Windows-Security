using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace HardenWindowsSecurity;

internal static class DialogMsgHelper
{

	/// <summary>
	/// Display a Dialog box window using WPF elements.
	/// </summary>
	/// <param name="Message"></param>
	/// <param name="Title"></param>
	internal static void Show(string Message, string? Title = "An Error Occurred")
	{
		// Needs to be on the UI thread
		Application.Current.Dispatcher.Invoke(() =>
		{
			// Create a custom dialog window
			Window dialogWindow = new()
			{
				Title = Title,
				Width = 450,
				Height = 350,
				WindowStartupLocation = WindowStartupLocation.CenterScreen,
				ResizeMode = ResizeMode.NoResize,
				Owner = Application.Current.MainWindow, // Associate the dialog with the main Window

				// Enable this when the time is right
				// ThemeMode = ThemeMode.System

				WindowStyle = WindowStyle.None,  // Hides the title bar

				Background = new LinearGradientBrush(
				Color.FromRgb(15, 32, 39),
				Color.FromRgb(32, 58, 67),
				45),

				BorderThickness = new Thickness(1),
				BorderBrush = new LinearGradientBrush(
				Color.FromRgb(255, 105, 180),
				Color.FromRgb(255, 20, 147),
				90)
			};

			StackPanel stackPanel = new() { Margin = new Thickness(20) };

			TextBlock errorMessage = new()
			{
				Text = Message,
				Margin = new Thickness(0, 0, 0, 20),
				TextWrapping = TextWrapping.Wrap,
				Foreground = Brushes.White,
				FontSize = 14,
				HorizontalAlignment = HorizontalAlignment.Center,
				TextAlignment = TextAlignment.Center,
				FontWeight = FontWeights.SemiBold
			};

			Button okButton = new()
			{
				Content = "OK",
				Width = 120,
				Margin = new Thickness(10),
				FontSize = 12,
				Height = 50
			};

			okButton.Click += (sender, args) =>
			{
				dialogWindow.Close();
			};

			StackPanel buttonPanel = new() { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Center };
			_ = buttonPanel.Children.Add(okButton);

			_ = stackPanel.Children.Add(errorMessage);
			_ = stackPanel.Children.Add(buttonPanel);

			dialogWindow.Content = stackPanel;
			_ = dialogWindow.ShowDialog();
		});
	}
}
