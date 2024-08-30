using System;
using System.IO;
using System.Collections;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Markup;
using System.Xml;
using System.Windows.Media.Imaging;
using System.Linq;
using System.Windows.Forms;
using System.Collections.Concurrent;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Effects;
using System.Windows.Threading;
using System.Runtime.CompilerServices;
using System.Diagnostics;
using System.ComponentModel;
using System.Threading;
using System.Windows.Automation;
using System.Windows.Controls.Ribbon;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Forms.Integration;
using System.Windows.Ink;
using System.Windows.Media.Animation;
using System.Windows.Media.Media3D;
using System.Windows.Media.TextFormatting;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Shell;
using System.Threading.Tasks;
using System.Text;
using System.Reflection.PortableExecutable;

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

                // Find the DataGrid
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
