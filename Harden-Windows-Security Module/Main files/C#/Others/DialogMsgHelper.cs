using System.Threading;
using System.Windows;
using System.Windows.Controls;

#nullable enable

namespace HardenWindowsSecurity
{
    internal static class DialogMsgHelper
    {

        /// <summary>
        /// Display a Dialog box window using WPF elements.
        /// </summary>
        /// <param name="Message"></param>
        /// <param name="Title"></param>
        public static void Show(string Message, string? Title = "An Error Occurred")
        {
            Thread thread = new(() =>
            {

                // Create a custom error window
                Window errorWindow = new()
                {
                    Title = Title,
                    Width = 450,
                    Height = 300,
                    WindowStartupLocation = WindowStartupLocation.CenterScreen,
                    ResizeMode = ResizeMode.NoResize

                    // Enable this when the time is right
                    // ThemeMode = ThemeMode.System
                };

                StackPanel stackPanel = new() { Margin = new Thickness(20) };

                TextBlock errorMessage = new()
                {
                    Text = Message,
                    Margin = new Thickness(0, 0, 0, 20),
                    TextWrapping = TextWrapping.Wrap,
                    FontSize = 14,
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
                    errorWindow.Close();
                };

                StackPanel buttonPanel = new() { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Center };
                _ = buttonPanel.Children.Add(okButton);

                _ = stackPanel.Children.Add(errorMessage);
                _ = stackPanel.Children.Add(buttonPanel);

                errorWindow.Content = stackPanel;
                _ = errorWindow.ShowDialog();

            });

            // Required since we're displaying GUI elements
            thread.SetApartmentState(ApartmentState.STA);
            thread.Start();
        }
    }
}
