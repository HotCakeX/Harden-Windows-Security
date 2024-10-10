using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Media;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace WDACConfig.Pages
{
    public sealed partial class Logs : Page
    {
        // Brush to store the log text color (default set to CornflowerBlue, must be the one set in XAML too for consistency)
        private SolidColorBrush logTextBrush = new(Colors.CornflowerBlue);

        // Brush to store the highlight text color (default set to Yellow, must be the one set in XAML too for consistency)
        private SolidColorBrush highlightTextBrush = new(Colors.Yellow);

        public Logs()
        {
            this.InitializeComponent();

            // Load log files when the page is initialized
            LoadLogFiles();

            // Handle TextChanged event for real-time search
            SearchTextBox.TextChanged += SearchTextBox_TextChanged;

            // Subscribe to the Loaded event for initializing color pickers
            this.Loaded += Logs_Loaded;
        }

        // Initialize color picker event handlers once the page is loaded
        private void Logs_Loaded(object sender, RoutedEventArgs e)
        {
            // Subscribe to color picker changes for log text color
            TextColorPicker.ColorPicker.ColorChanged += TextColorPicker_ColorChanged;

            // Subscribe to color picker changes for highlight color
            HighlightColorPicker.ColorPicker.ColorChanged += HighlightColorPicker_ColorChanged;
        }

        // Handler for when the log text color picker changes
        private void TextColorPicker_ColorChanged(Microsoft.UI.Xaml.Controls.ColorPicker sender, Microsoft.UI.Xaml.Controls.ColorChangedEventArgs args)
        {
            // Change the log text color based on user selection
            logTextBrush = new SolidColorBrush(args.NewColor);

            // Apply the new color to the TextBlock displaying the log content
            LogContentTextBox.Foreground = logTextBrush;
        }

        // Handler for when the highlight color picker changes
        private void HighlightColorPicker_ColorChanged(Microsoft.UI.Xaml.Controls.ColorPicker sender, Microsoft.UI.Xaml.Controls.ColorChangedEventArgs args)
        {
            // Change the highlight text color based on user selection
            highlightTextBrush = new SolidColorBrush(args.NewColor);

            // Update the highlight color immediately if there's an active search
            if (!string.IsNullOrWhiteSpace(SearchTextBox.Text))
            {
                // Call the highlight method again with the new color asynchronously
                _ = HighlightTextAsync(LogContentTextBox.Text, SearchTextBox.Text.Trim());
            }
        }

        private void LoadLogFiles()
        {
            // Get all log files matching the syntax and sort them by creation time
            var logFiles = Directory.GetFiles(Logger.LogsDirectory, "WDACConfig_AppLogs_*.txt")
                .Select(f => new FileInfo(f))
                .Where(f => f.Length <= 409600) // Filter files that are 400KB or smaller to prevent UI from freezing. ItemsRepeater element should be used for virtualized content display.
                .OrderByDescending(f => f.CreationTime)
                .ToList();

            // Clear existing items and add sorted files to the ComboBox
            LogFileComboBox.Items.Clear();
            foreach (var logFile in logFiles)
            {
                LogFileComboBox.Items.Add(logFile.FullName);
            }

            // Select the first item if any files were found
            if (logFiles.Count > 0)
            {
                LogFileComboBox.SelectedIndex = 0;
                _ = DisplayLogContentAsync(logFiles[0].FullName);
            }
        }


        private void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            // Refresh the list of log files
            LoadLogFiles();
        }

        private async void LogFileComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (LogFileComboBox.SelectedItem != null)
            {
                // Get the selected file path
                string? selectedFile = LogFileComboBox.SelectedItem.ToString();

                if (selectedFile is not null)
                {
                    // Display the content of the selected log file asynchronously
                    await DisplayLogContentAsync(selectedFile);
                }
            }
        }

        private async Task DisplayLogContentAsync(string filePath)
        {
            if (File.Exists(filePath))
            {
                // Read and display the log file content asynchronously
                string fileContent = await Task.Run(() => File.ReadAllText(filePath));

                // Set the text in the UI thread to avoid cross-thread exceptions
                LogContentTextBox.Text = fileContent;

                // Apply the current text color when loading new content
                LogContentTextBox.Foreground = logTextBrush;
            }
        }

        // Event handler for real-time search in the SearchTextBox
        private async void SearchTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            // Get the updated text from the search box
            string searchText = SearchTextBox.Text.Trim();

            // If the search text is not empty, highlight the text in the log content asynchronously
            if (!string.IsNullOrWhiteSpace(searchText) && !string.IsNullOrEmpty(LogContentTextBox.Text))
            {
                await HighlightTextAsync(LogContentTextBox.Text, searchText);
            }
            else
            {
                // Reset to the original content if the search box is empty
                await HighlightTextAsync(LogContentTextBox.Text, string.Empty);
            }
        }

        private async Task HighlightTextAsync(string content, string searchText)
        {
            // Perform text highlighting asynchronously to avoid UI blocking
            await Task.Run(() =>
            {
                // Get index of the first occurrence of the search text
                int index = content.IndexOf(searchText, System.StringComparison.OrdinalIgnoreCase);

                // Clear the current text and apply a new format with highlighting
                _ = LogContentTextBox.DispatcherQueue.TryEnqueue(() =>
                 {
                     LogContentTextBox.Inlines.Clear();

                     if (index < 0 || string.IsNullOrWhiteSpace(searchText))
                     {
                         // Reset to the original content if no match is found or search text is empty
                         LogContentTextBox.Text = content;
                     }
                     else
                     {
                         // Loop through the text and highlight all occurrences
                         int lastIndex = 0;
                         while (index >= 0)
                         {
                             // Add unhighlighted text before the search term
                             if (index > lastIndex)
                             {
                                 LogContentTextBox.Inlines.Add(new Run { Text = content.Substring(lastIndex, index - lastIndex) });
                             }

                             // Add highlighted text for the search term
                             LogContentTextBox.Inlines.Add(new Run
                             {
                                 Text = content.Substring(index, searchText.Length),
                                 Foreground = highlightTextBrush, // Apply the updated highlight color
                                 FontStyle = Windows.UI.Text.FontStyle.Italic
                             });

                             // Move past this match and look for the next
                             lastIndex = index + searchText.Length;
                             index = content.IndexOf(searchText, lastIndex, System.StringComparison.OrdinalIgnoreCase);
                         }

                         // Add the remaining text if any
                         if (lastIndex < content.Length)
                         {
                             LogContentTextBox.Inlines.Add(new Run { Text = content.Substring(lastIndex) });
                         }
                     }
                 });
            });
        }
    }
}
