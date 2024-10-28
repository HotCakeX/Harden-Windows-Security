using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

#nullable enable

namespace HardenWindowsSecurity
{
    public partial class GUIMain
    {
        // The following are XAML GUI Elements
        public static string? xamlPath;

        // Main window instance
        public static Window? mainGUIWindow;

        // Application instance
        public static Application? app;

        // Sidebar menu Grid in the main Window
        public static Grid? SidebarGrid;

        // The main progress bar for the entire GUI
        public static ProgressBar? mainProgressBar;

        // The Inner border of the entire GUI
        public static RadialGradientBrush? InnerBorderBackground;

        // The slider at the bottom left that controls the background image opacity
        public static Slider? BackgroundSlider;
    }
}
