using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Microsoft.Win32;

#nullable disable

namespace HardenWindowsSecurity;

public partial class GUIMain
{
	// ViewModelBase class
	// Base class for ViewModel that implements INotifyPropertyChanged to notify the UI of property changes
	public class ViewModelBase : INotifyPropertyChanged
	{
		// Event that is triggered when a property value changes
		public event PropertyChangedEventHandler PropertyChanged;

		// Method to raise the PropertyChanged event
		// The CallerMemberName attribute allows the method to automatically use the name of the calling property
		public void OnPropertyChanged([CallerMemberName] string propName = null)
		{
			// Invoke the PropertyChanged event if there are any subscribers
			PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propName));
		}
	}


	/// <summary>
	/// Implementation of ICommand to handle command execution and checking whether a command can execute
	/// </summary>
	/// <param name="execute">Assign the execute delegate</param>
	/// <param name="canExecute">Assign the canExecute delegate (optional)</param>
	public class RelayCommand(Action<object> execute, Func<object, bool> canExecute = null) : ICommand
	{
		// Delegate to define the method that will be executed when the command is invoked
		private readonly Action<object> _execute = execute;

		// Delegate to define the method that determines if the command can execute
		private readonly Func<object, bool> _canExecute = canExecute;

		// Event that is triggered when the ability of the command to execute changes
		public event EventHandler CanExecuteChanged
		{
			// Add event handler to the CommandManager's RequerySuggested event
			add { CommandManager.RequerySuggested += value; }

			// Remove event handler from the CommandManager's RequerySuggested event
			remove { CommandManager.RequerySuggested -= value; }
		}

		// Check if the command can execute
		public bool CanExecute(object parameter) => _canExecute is null || _canExecute(parameter);

		// Execute the command
		public void Execute(object parameter) => _execute(parameter);
	}


	// Uncomment these section when actually need it
	/*

	// PageModel class
	// Model class representing the data for a page
	public class PageModel
	{
		// Property representing the protection count
		public int ProtectCount { get; set; }

		// Property representing the status of the Confirmation
		public string Confirmation { get; set; }
	}

	*/


	// ProtectVM class
	// ViewModel for a specific page that inherits from ViewModelBase
	public class ProtectVM : ViewModelBase
	{
		/*

		// Field to hold the PageModel instance
		private readonly PageModel _pageModel;

		// Property for Some that updates the ProtectCount in PageModel and notifies of property change
		public int SomeInt
		{
			get { return _pageModel.ProtectCount; }
			set { _pageModel.ProtectCount = value; OnPropertyChanged(); }
		}

		// Constructor to initialize the ProtectVM
		public ProtectVM()
		{
			_pageModel = new PageModel(); // Instantiate PageModel
			SomeInt = 123456;           // Set an initial value for SomeInt
		}

		*/
	}

	// ConfirmVM class
	// ViewModel for the Confirm page, currently empty but can be extended with additional properties
	public class ConfirmVM : ViewModelBase
	{
	}


	// NavigationVM class
	// ViewModel for handling navigation between different views, inheriting from ViewModelBase
	public partial class NavigationVM : ViewModelBase
	{
		// Field to hold the current view
		private object _currentView;

		// Property to get or set the current view and notify of changes
		public object CurrentView
		{
			get { return _currentView; }
			set
			{
				_currentView = value; // Set the current view
				OnPropertyChanged(); // Notify any observers that the CurrentView has changed
			}
		}

		// ICommand properties for handling navigation commands
		public ICommand ProtectCommand { get; set; }
		public ICommand ConfirmCommand { get; set; }
		public ICommand ASRRulesCommand { get; set; }
		public ICommand UnprotectCommand { get; set; }
		public ICommand ExclusionsCommand { get; set; }
		public ICommand BitLockerCommand { get; set; }
		public ICommand LogsCommand { get; set; }
		public ICommand OptionalFeaturesCommand { get; set; }
		public ICommand FileReputationCommand { get; set; }

		// Dictionary to cache views by their identifiers
		private readonly Dictionary<string, object> _viewCache = [];

		// Constructor for initializing the NavigationVM
		public NavigationVM()
		{
			// Initialize commands with methods to execute
			ProtectCommand = new RelayCommand(ProtectView); // Command to handle the Protect action
			ConfirmCommand = new RelayCommand(ConfirmView); // Command to handle the Confirm action
			ASRRulesCommand = new RelayCommand(ASRRulesView); // Command to handle the ASRRules action
			UnprotectCommand = new RelayCommand(UnprotectView); // Command to handle the Unprotect action
			ExclusionsCommand = new RelayCommand(ExclusionsView); // Command to handle the Exclusions action
			BitLockerCommand = new RelayCommand(BitLockerView); // Command to handle the BitLocker action
			LogsCommand = new RelayCommand(LogsView); // Command to handle the Logs action
			OptionalFeaturesCommand = new RelayCommand(OptionalFeaturesView); // Command to handle the OptionalFeatures action
			FileReputationCommand = new RelayCommand(FileReputationView); // Command to handle the FileReputation action

			// Load the Logs view initially to make it ready for logs to be written to it
			LogsView(null);

			// Load the Protect view next, it will be set as the default startup page because of "CurrentView = GUIProtectWinSecurity.View;"
			ProtectView(null);
		}
	}

	// Btn class
	// Custom RadioButton control
	public class Btn : RadioButton
	{
		// Static constructor to set default style for Btn
		static Btn()
		{
			// Override the default style key for Btn control
			DefaultStyleKeyProperty.OverrideMetadata(typeof(Btn), new FrameworkPropertyMetadata(typeof(Btn)));
		}
	}


	public static void LoadMainXaml()
	{

		#region Load Resource Dictionaries (First)
		// Define the path to the ResourceDictionaries folder
		string resourceFolder = Path.Combine(GlobalVars.path, "Resources", "XAML", "ResourceDictionaries");

		// Get all of the XAML files in the folder
		string[] resourceFiles = Directory.GetFiles(resourceFolder, "*.xaml");

		// Load resource dictionaries from the ResourceDictionaries folder
		foreach (string file in resourceFiles)
		{
			using FileStream fs = new(file, FileMode.Open, FileAccess.Read);

			// Load the resource dictionary from the XAML file
			ResourceDictionary resourceDict = (ResourceDictionary)XamlReader.Load(fs);

			// Add to application resources to ensure dictionaries are available to the whole application
			app.Resources.MergedDictionaries.Add(resourceDict);
		}
		#endregion

		#region Load Main Window XAML (After Resource dictionaries have been loaded)

		// Load the MainWindow.xaml
		using (FileStream fs = new(xamlPath, FileMode.Open, FileAccess.Read))
		{
			// Load the main window from the XAML file
			mainGUIWindow = (Window)XamlReader.Load(fs);
		}
		#endregion

		// Set the MainWindow for the application
		app.MainWindow = mainGUIWindow;

		#region
		// Caching the icon in memory so that when the GUI is closed in PowerShell module, there wil be no files in the module directory preventing deletion of the module itself
		// "UriKind.Absolute" ensures that the path to the icon file is correctly interpreted as an absolute path.
		Uri iconUri = new(Path.Combine(GlobalVars.path, "Resources", "Media", "ProgramIcon.ico"), UriKind.Absolute);

		// Load the icon into a BitmapImage and cache it in memory
		BitmapImage IconBitmapImage = new();
		IconBitmapImage.BeginInit();
		IconBitmapImage.UriSource = iconUri;
		IconBitmapImage.CacheOption = BitmapCacheOption.OnLoad; // Load the image data into memory
		IconBitmapImage.EndInit();

		// Assign the cached icon to the MainWindow
		mainGUIWindow.Icon = IconBitmapImage;
		#endregion

		// Set the DataContext for the main window
		mainGUIWindow.DataContext = new NavigationVM();

		#region Event handlers For The Main GUI

		// Defining what happens when the GUI window is closed
		mainGUIWindow.Closed += (sender, e) =>
		{
			// Create the footer to the log file
			string endOfLogFile = $"""
**********************
Harden Windows Security operation log end
End time: {DateTime.Now}
**********************
""";

			Logger.LogMessage(endOfLogFile, LogTypeIntel.Information);
		};

		// Exit Event, will work for the GUI when using compiled version of the app or in Visual Studio
		app.Exit += (object s, ExitEventArgs e) =>
		{
			// Revert the changes to the PowerShell console Window Title
			ChangePSConsoleTitle.Set("PowerShell");

			ControlledFolderAccessHandler.Reset();
			Miscellaneous.CleanUp();

			// System.Windows.MessageBox.Show(messageBoxText: "Exiting!", caption: "Exit", button: MessageBoxButton.OK, icon: MessageBoxImage.Information);
		};


		// DispatcherUnhandledException Event is triggered when an unhandled exception occurs in the application
		app.DispatcherUnhandledException += (object s, DispatcherUnhandledExceptionEventArgs e) =>
		{
			// Create a custom error window
			Window errorWindow = new()
			{
				Title = "An Error Occurred",
				Width = 450,
				Height = 300,
				WindowStartupLocation = WindowStartupLocation.CenterScreen,
				ResizeMode = ResizeMode.NoResize
			};

			StackPanel stackPanel = new() { Margin = new Thickness(20) };

			TextBlock errorMessage = new()
			{
				Text = "An error has occurred in the Harden Windows Security App. Please return to the PowerShell window to review the error details. Reporting this issue on GitHub will greatly assist me in addressing and resolving it promptly. Your feedback is invaluable to improving the software. 💚",
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

			Button githubButton = new()
			{
				Content = "Report on GitHub",
				Width = 160,
				Margin = new Thickness(10),
				FontSize = 12,
				Height = 50
			};
			githubButton.Click += (sender, args) =>
			{
				// Open the GitHub issues page
				_ = Process.Start(new ProcessStartInfo
				{
					FileName = "https://github.com/HotCakeX/Harden-Windows-Security/issues",
					UseShellExecute = true // Ensure the link opens in the default browser
				});
				errorWindow.Close();
			};

			StackPanel buttonPanel = new() { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Center };
			_ = buttonPanel.Children.Add(okButton);
			_ = buttonPanel.Children.Add(githubButton);

			_ = stackPanel.Children.Add(errorMessage);
			_ = stackPanel.Children.Add(buttonPanel);

			errorWindow.Content = stackPanel;
			_ = errorWindow.ShowDialog();

			// The error will be terminating the application
			e.Handled = false;
		};


		#endregion

		#region parent border of the Main GUI
		// Find the Border control by name
		Border border = (Border)mainGUIWindow.FindName("OuterMostBorder");

		// Access the ImageBrush from the Border's Background property
		ImageBrush imageBrush = (ImageBrush)border.Background;

		// Set the ImageSource property to the desired image path
		// Load the background image into memory and set it as the ImageSource for the ImageBrush
		BitmapImage BackgroundBitmapImage = new();
		BackgroundBitmapImage.BeginInit();
		BackgroundBitmapImage.UriSource = new Uri(Path.Combine(GlobalVars.path, "Resources", "Media", "background.jpg"));
		BackgroundBitmapImage.CacheOption = BitmapCacheOption.OnLoad; // Load the image data into memory
		BackgroundBitmapImage.EndInit();

		imageBrush.ImageSource = BackgroundBitmapImage;

		#endregion

		#region Inner border of the main GUI
		Border InnerBorder = (Border)mainGUIWindow.FindName("InnerBorder");

		// Finding the gradient brush background of the inner border
		InnerBorderBackground = (RadialGradientBrush)InnerBorder.Background;

		// Finding the bottom left slider
		BackgroundSlider = (Slider)mainGUIWindow.FindName("BackgroundOpacitySlider");

		// Creating event handler for the slider
		BackgroundSlider.ValueChanged += (sender, e) =>
		{
			Slider slider = (Slider)sender;

			// Scale value from 0-100 to 0-1
			double opacityValue = slider.Value / 100.0;

			// Apply the scaled opacity value to the RadialGradientBrush background
			InnerBorderBackground.Opacity = opacityValue;
		};

		#endregion

		// Finding the sidebar Grid
		SidebarGrid = mainGUIWindow.FindName("SidebarGrid") as Grid;

		// Finding the progress bar
		mainProgressBar = (ProgressBar)mainGUIWindow.FindName("MainProgressBar");

		// Finding the button responsible for changing the background image by browsing for image file
		Button BackgroundChangeButton = (Button)mainGUIWindow.FindName("BackgroundChangeButton");

		// event handler for button to open file picker to browse for image files
		BackgroundChangeButton.Click += (sender, e) =>
		{
			try
			{
				// Creating and configuring the OpenFileDialog
				OpenFileDialog openFileDialog = new()
				{
					// Filter for image files
					Filter = "Image Files|*.jpg;*.jpeg;*.png;",
					Title = "Select an Image to set as the Harden Windows Security App's Background"
				};

				// Show the dialog and get the result
				bool? result = openFileDialog.ShowDialog();

				if (result == true)
				{
					// Get the selected file path
					string filePath = openFileDialog.FileName;

					// Create a BitmapImage from the selected file
					BitmapImage bitmapImage = new();
					bitmapImage.BeginInit();
					bitmapImage.UriSource = new Uri(filePath, UriKind.Absolute);
					bitmapImage.EndInit();

					// Set the image as the source for the ImageBrush defined in the Border's Background earlier
					imageBrush.ImageSource = bitmapImage;
				}
			}
			catch
			{
				Logger.LogMessage("An error occurred while trying to change the background image.", LogTypeIntel.Error);
			}
		};

		#region sidebar menu assignments
		// Protect button icon
		Grid ProtectButtonGrid = SidebarGrid.FindName("ProtectButtonGrid") as Grid;
		Image ProtectButtonIcon = ProtectButtonGrid.FindName("ProtectButtonIcon") as Image;
		BitmapImage ProtectButtonImage = new();
		ProtectButtonImage.BeginInit();
		ProtectButtonImage.UriSource = new Uri(Path.Combine(GlobalVars.path, "Resources", "Media", "ProtectMenuButton.png"));
		ProtectButtonImage.CacheOption = BitmapCacheOption.OnLoad; // Load the image data into memory
		ProtectButtonImage.EndInit();
		ProtectButtonIcon.Source = ProtectButtonImage;

		// Confirm button icon
		Grid ConfirmButtonGrid = SidebarGrid.FindName("ConfirmButtonGrid") as Grid;
		Image ConfirmButtonIcon = ConfirmButtonGrid.FindName("ConfirmButtonIcon") as Image;
		BitmapImage ConfirmButtonImage = new();
		ConfirmButtonImage.BeginInit();
		ConfirmButtonImage.UriSource = new Uri(Path.Combine(GlobalVars.path, "Resources", "Media", "ConfirmMenuButton.png"));
		ConfirmButtonImage.CacheOption = BitmapCacheOption.OnLoad; // Load the image data into memory
		ConfirmButtonImage.EndInit();
		ConfirmButtonIcon.Source = ConfirmButtonImage;

		// ASRRules button icon
		Grid ASRRulesButtonGrid = SidebarGrid.FindName("ASRRulesButtonGrid") as Grid;
		Image ASRRulesButtonIcon = ASRRulesButtonGrid.FindName("ASRRulesButtonIcon") as Image;
		BitmapImage ASRRulesButtonImage = new();
		ASRRulesButtonImage.BeginInit();
		ASRRulesButtonImage.UriSource = new Uri(Path.Combine(GlobalVars.path, "Resources", "Media", "ASRRulesMenuButton.png"));
		ASRRulesButtonImage.CacheOption = BitmapCacheOption.OnLoad; // Load the image data into memory
		ASRRulesButtonImage.EndInit();
		ASRRulesButtonIcon.Source = ASRRulesButtonImage;

		// Unprotect button icon
		Grid UnprotectButtonGrid = SidebarGrid.FindName("UnprotectButtonGrid") as Grid;
		Image UnprotectButtonIcon = UnprotectButtonGrid.FindName("UnprotectButtonIcon") as Image;
		BitmapImage UnprotectButtonImage = new();
		UnprotectButtonImage.BeginInit();
		UnprotectButtonImage.UriSource = new Uri(Path.Combine(GlobalVars.path, "Resources", "Media", "UnprotectButton.png"));
		UnprotectButtonImage.CacheOption = BitmapCacheOption.OnLoad; // Load the image data into memory
		UnprotectButtonImage.EndInit();
		UnprotectButtonIcon.Source = UnprotectButtonImage;

		// Exclusions button icon
		Grid ExclusionsButtonGridButtonGrid = SidebarGrid.FindName("ExclusionsButtonGrid") as Grid;
		Image ExclusionsButtonIcon = ExclusionsButtonGridButtonGrid.FindName("ExclusionsButtonIcon") as Image;
		BitmapImage ExclusionsButtonImage = new();
		ExclusionsButtonImage.BeginInit();
		ExclusionsButtonImage.UriSource = new Uri(Path.Combine(GlobalVars.path, "Resources", "Media", "ExclusionMenuButton.png"));
		ExclusionsButtonImage.CacheOption = BitmapCacheOption.OnLoad; // Load the image data into memory
		ExclusionsButtonImage.EndInit();
		ExclusionsButtonIcon.Source = ExclusionsButtonImage;

		// BitLocker button icon
		Grid BitLockerButtonGridButtonGrid = SidebarGrid.FindName("BitLockerButtonGrid") as Grid;
		Image BitLockerButtonIcon = BitLockerButtonGridButtonGrid.FindName("BitLockerButtonIcon") as Image;
		BitmapImage BitLockerButtonImage = new();
		BitLockerButtonImage.BeginInit();
		BitLockerButtonImage.UriSource = new Uri(Path.Combine(GlobalVars.path, "Resources", "Media", "BitLockerMenuButton.png"));
		BitLockerButtonImage.CacheOption = BitmapCacheOption.OnLoad; // Load the image data into memory
		BitLockerButtonImage.EndInit();
		BitLockerButtonIcon.Source = BitLockerButtonImage;

		// Logs button icon
		Grid LogsButtonGrid = SidebarGrid.FindName("LogsButtonGrid") as Grid;
		Image LogsButtonIcon = LogsButtonGrid.FindName("LogsButtonIcon") as Image;
		BitmapImage LogsButtonImage = new();
		LogsButtonImage.BeginInit();
		LogsButtonImage.UriSource = new Uri(Path.Combine(GlobalVars.path, "Resources", "Media", "LogsMenuButton.png"));
		LogsButtonImage.CacheOption = BitmapCacheOption.OnLoad; // Load the image data into memory
		LogsButtonImage.EndInit();
		LogsButtonIcon.Source = LogsButtonImage;

		// OptionalFeatures button icon
		Grid OptionalFeaturesButtonGrid = SidebarGrid.FindName("OptionalFeaturesButtonGrid") as Grid;
		Image OptionalFeaturesButtonIcon = OptionalFeaturesButtonGrid.FindName("OptionalFeaturesButtonIcon") as Image;
		BitmapImage OptionalFeaturesButtonImage = new();
		OptionalFeaturesButtonImage.BeginInit();
		OptionalFeaturesButtonImage.UriSource = new Uri(Path.Combine(GlobalVars.path, "Resources", "Media", "OptionalFeaturesMenuButtonIcon.png"));
		OptionalFeaturesButtonImage.CacheOption = BitmapCacheOption.OnLoad; // Load the image data into memory
		OptionalFeaturesButtonImage.EndInit();
		OptionalFeaturesButtonIcon.Source = OptionalFeaturesButtonImage;

		// FileReputation button icon
		Grid FileReputationButtonGrid = SidebarGrid.FindName("FileReputationButtonGrid") as Grid;
		Image FileReputationButtonIcon = FileReputationButtonGrid.FindName("FileReputationButtonIcon") as Image;
		BitmapImage FileReputationButtonImage = new();
		FileReputationButtonImage.BeginInit();
		FileReputationButtonImage.UriSource = new Uri(Path.Combine(GlobalVars.path, "Resources", "Media", "FileReputationMenuButton.png"));
		FileReputationButtonImage.CacheOption = BitmapCacheOption.OnLoad; // Load the image data into memory
		FileReputationButtonImage.EndInit();
		FileReputationButtonIcon.Source = FileReputationButtonImage;
		#endregion

	}
}
