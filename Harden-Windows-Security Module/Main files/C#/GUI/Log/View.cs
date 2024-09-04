using System.IO;
using System.Windows.Markup;

namespace HardenWindowsSecurity
{
    public partial class GUIMain
    {

        // Partial class definition for handling navigation and view models
        public partial class NavigationVM : ViewModelBase
        {

            // Method to handle the Logs view, including loading
            private void Logs(object obj)
            {

                // Check if the view is already cached
                if (_viewCache.TryGetValue("LogsView", out var cachedView))
                {
                    CurrentView = cachedView;
                    return;
                }

                // Defining the path to the XAML XML file
                if (HardenWindowsSecurity.GlobalVars.path == null)
                {
                    throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
                }

                // Construct the file path for the Logs view XAML
                string xamlPath = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "XAML", "Logs.xaml");

                // Read the XAML content from the file
                string xamlContent = File.ReadAllText(xamlPath);

                // Parse the XAML content to create a UserControl
                HardenWindowsSecurity.GUILogs.View = (System.Windows.Controls.UserControl)XamlReader.Parse(xamlContent);

                // Set the DataContext for Protect view
                HardenWindowsSecurity.GUILogs.View.DataContext = new LogsVM();

                // Find the Parent Grid
                HardenWindowsSecurity.GUILogs.ParentGrid = (System.Windows.Controls.Grid)HardenWindowsSecurity.GUILogs.View.FindName("ParentGrid");

                HardenWindowsSecurity.GUILogs.MainLoggerTextBox = HardenWindowsSecurity.GUILogs.ParentGrid.FindName("MainLoggerTextBox") as System.Windows.Controls.TextBox;
                HardenWindowsSecurity.GUILogs.scrollerForOutputTextBox = HardenWindowsSecurity.GUILogs.ParentGrid.FindName("ScrollerForOutputTextBox") as System.Windows.Controls.ScrollViewer;

                // Cache the view before setting it as the CurrentView
                _viewCache["LogsView"] = HardenWindowsSecurity.GUILogs.View;

                // Set the CurrentView to the Protect view
                CurrentView = HardenWindowsSecurity.GUILogs.View;
            }
        }
    }
}
