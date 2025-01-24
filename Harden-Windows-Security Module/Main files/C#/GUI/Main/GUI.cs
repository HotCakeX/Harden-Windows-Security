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
using System.Windows.Media.Imaging;
using System.Windows.Threading;

#nullable disable

namespace HardenWindowsSecurity;

public partial class GUIMain
{
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
		public ICommand AppControlManagerCommand { get; set; }

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
			AppControlManagerCommand = new RelayCommand(AppControlManagerView); // Command to handle the AppControlManager action

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

		// Get all of the XAML files in the folder
		string[] resourceFiles = Directory.GetFiles(Path.Combine(GlobalVars.path, "Resources", "XAML", "ResourceDictionaries"), "*.xaml");

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
				ThemeMode = ThemeMode.System
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

		// Finding the progress bar
		mainProgressBar = (ProgressBar)mainGUIWindow.FindName("MainProgressBar");
	}
}
