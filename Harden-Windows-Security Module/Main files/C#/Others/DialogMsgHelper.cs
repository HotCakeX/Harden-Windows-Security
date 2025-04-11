// MIT License
//
// Copyright (c) 2023-Present - Violet Hansen - (aka HotCakeX on GitHub) - Email Address: spynetgirl@outlook.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// See here for more information: https://github.com/HotCakeX/Harden-Windows-Security/blob/main/LICENSE
//

using System.Windows;
using System.Windows.Controls;

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
				Owner = Application.Current.MainWindow, // Associate the dialog with the main Window
				ThemeMode = ThemeMode.System
			};

			StackPanel stackPanel = new() { Margin = new Thickness(20) };

			TextBlock errorMessage = new()
			{
				Text = Message,
				Margin = new Thickness(0, 0, 0, 20),
				TextWrapping = TextWrapping.Wrap,
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
