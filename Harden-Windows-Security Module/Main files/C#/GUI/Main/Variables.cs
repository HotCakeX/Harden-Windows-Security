using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace HardenWindowsSecurity;

    /// <summary>
    /// The following are XAML GUI Elements
    /// </summary>
    public partial class GUIMain
    {
        // Define the path to the main Window XAML file
        public static readonly string xamlPath = Path.Combine(GlobalVars.path!, "Resources", "XAML", "Main.xaml");

        // Main window instance
        public static Window? mainGUIWindow;

        // Application instance
        // Create and initialize the application - the WPF GUI uses the App context
        public readonly static Application app = new();

        // Sidebar menu Grid in the main Window
        public static Grid? SidebarGrid;

        // The main progress bar for the entire GUI
        public static ProgressBar? mainProgressBar;

        // The Inner border of the entire GUI
        public static RadialGradientBrush? InnerBorderBackground;

        // The slider at the bottom left that controls the background image opacity
        public static Slider? BackgroundSlider;
    }
