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
using System.Runtime.CompilerServices;
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
using System.Text;

#nullable enable

namespace HardenWindowsSecurity
{
    public partial class GUIMain
    {
        // The following are XAML GUI Elements
        public static string? xamlPath;

        // Main window instance
        public static System.Windows.Window? mainGUIWindow;

        // Application instance
        public static System.Windows.Application? app;

        // Sidebar menu Grid in the main Window
        public static System.Windows.Controls.Grid? SidebarGrid;

        // The main progress bar for the entire GUI
        public static System.Windows.Controls.ProgressBar? mainProgressBar;
    }
}
