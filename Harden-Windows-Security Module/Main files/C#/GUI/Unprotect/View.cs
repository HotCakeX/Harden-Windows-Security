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

            // Method to handle the Unprotect view, including loading
            private void Unprotect(object obj)
            {

                // Check if the view is already cached
                if (_viewCache.TryGetValue("UnprotectView", out var cachedView))
                {
                    CurrentView = cachedView;
                    return;
                }

                // Defining the path to the XAML XML file
                if (HardenWindowsSecurity.GlobalVars.path == null)
                {
                    throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
                }

                // Construct the file path for the Unprotect view XAML
                string xamlPath = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "XAML", "Unprotect.xaml");

                // Read the XAML content from the file
                string xamlContent = File.ReadAllText(xamlPath);

                // Parse the XAML content to create a UserControl
                HardenWindowsSecurity.GUIUnprotect.View = (System.Windows.Controls.UserControl)XamlReader.Parse(xamlContent);

                // Find the Parent Grid
                HardenWindowsSecurity.GUIUnprotect.ParentGrid = (System.Windows.Controls.Grid)HardenWindowsSecurity.GUIUnprotect.View.FindName("ParentGrid");


                // Cache the view before setting it as the CurrentView
                _viewCache["UnprotectView"] = HardenWindowsSecurity.GUIUnprotect.View;

                // Set the CurrentView to the Protect view
                CurrentView = HardenWindowsSecurity.GUIUnprotect.View;
            }
        }
    }
}
