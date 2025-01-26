using System.IO;
using System.Windows;
using System.Windows.Controls;

namespace HardenWindowsSecurity;

/// <summary>
/// The following are XAML GUI Elements
/// </summary>
public partial class GUIMain
{
	// Define the path to the main Window XAML file
	internal static readonly string xamlPath = Path.Combine(GlobalVars.path, "Resources", "XAML", "Main.xaml");

	// Main window instance
	public static Window? mainGUIWindow;

	// Application instance
	// Create and initialize the application - the WPF GUI uses the App context
	public static readonly Application app = new();

	// The main progress bar for the entire GUI
	internal static ProgressBar? mainProgressBar;
}
