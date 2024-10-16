using System.Windows.Controls;

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
        public static Grid? SidebarGrid;

        // The main progress bar for the entire GUI
        public static System.Windows.Controls.ProgressBar? mainProgressBar;

        // The Inner border of the entire GUI
        public static System.Windows.Media.RadialGradientBrush? InnerBorderBackground;

        // The slider at the bottom left that controls the background image opacity
        public static System.Windows.Controls.Slider? BackgroundSlider;
    }
}
