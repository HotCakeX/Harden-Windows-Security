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

#nullable disable

namespace HardenWindowsSecurity
{
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

        // RelayCommand class
        // Implementation of ICommand to handle command execution and checking whether a command can execute
        public class RelayCommand : ICommand
        {
            // Delegate to define the method that will be executed when the command is invoked
            private readonly Action<object> _execute;

            // Delegate to define the method that determines if the command can execute
            private readonly Func<object, bool> _canExecute;

            // Event that is triggered when the ability of the command to execute changes
            public event EventHandler CanExecuteChanged
            {
                // Add event handler to the CommandManager's RequerySuggested event
                add { CommandManager.RequerySuggested += value; }

                // Remove event handler from the CommandManager's RequerySuggested event
                remove { CommandManager.RequerySuggested -= value; }
            }

            // Constructor to initialize the RelayCommand with execute and canExecute delegates
            public RelayCommand(Action<object> execute, Func<object, bool> canExecute = null)
            {
                _execute = execute;        // Assign the execute delegate
                _canExecute = canExecute;  // Assign the canExecute delegate (optional)
            }

            // Check if the command can execute
            public bool CanExecute(object parameter) => _canExecute == null || _canExecute(parameter);

            // Execute the command
            public void Execute(object parameter) => _execute(parameter);
        }

        // PageModel class
        // Model class representing the data for a page
        public class PageModel
        {
            // Property representing the protection count
            public int ProtectCount { get; set; }

            // Property representing the status of the Confirmation
            public string Confirmation { get; set; }
        }

        // ProtectVM class
        // ViewModel for a specific page that inherits from ViewModelBase
        public class ProtectVM : ViewModelBase
        {
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
        }

        // ConfirmVM class
        // ViewModel for the Confirm page, currently empty but can be extended with additional properties
        public class ConfirmVM : ViewModelBase
        {
            // Additional properties can be added here for Confirm page content
        }

        public class LogsVM : ViewModelBase
        {

        }

        public class UnprotectCommand : ViewModelBase
        {

        }

        public class ASRRulesCommand : ViewModelBase
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
            public ICommand LogsCommand { get; set; }

            // Dictionary to cache views by their identifiers
            private Dictionary<string, object> _viewCache = new Dictionary<string, object>();

            // Constructor for initializing the NavigationVM
            public NavigationVM()
            {
                // Initialize commands with methods to execute
                ProtectCommand = new RelayCommand(Protect); // Command to handle Protect action
                ConfirmCommand = new RelayCommand(Confirm); // Command to handle Confirm action
                ASRRulesCommand = new RelayCommand(ASRRules); // Command to handle the ASRRules action
                UnprotectCommand = new RelayCommand(Unprotect); // Command to handle the Unprotect action
                LogsCommand = new RelayCommand(Logs); // Command to handle the Log action

                // Load the Logs view initially to make it ready for logs to be written to it
                Logs(null);

                // Load the Protect view next, it will be set as the default startup page
                Protect(null);
            }
        }

        // Btn class
        // Custom RadioButton control
        public class Btn : System.Windows.Controls.RadioButton
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

            // Defining the path to the XAML XML file
            if (HardenWindowsSecurity.GlobalVars.path == null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            // Create and initialize the application - the WPF GUI uses the App context
            GUIMain.app = new System.Windows.Application();

            #region Load Resource Dictionaries (First)
            // Define the path to the ResourceDictionaries folder
            string resourceFolder = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "XAML", "ResourceDictionaries");

            // Get all of the XAML files in the folder
            var resourceFiles = Directory.GetFiles(resourceFolder, "*.xaml");

            // Load resource dictionaries from the ResourceDictionaries folder
            foreach (var file in resourceFiles)
            {
                using (FileStream fs = new FileStream(file, FileMode.Open, FileAccess.Read))
                {
                    // Load the resource dictionary from the XAML file
                    System.Windows.ResourceDictionary resourceDict = (System.Windows.ResourceDictionary)System.Windows.Markup.XamlReader.Load(fs);
                    GUIMain.app.Resources.MergedDictionaries.Add(resourceDict);  // Add to application resources to ensure dictionaries are available to the whole application
                }
            }
            #endregion

            #region Load Main Window XAML (After Resource dictionaries have been loaded)
            // Define the path to the main Window XAML file
            GUIMain.xamlPath = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "XAML", "Main.xaml");

            // Load the MainWindow.xaml
            using (FileStream fs = new FileStream(GUIMain.xamlPath, FileMode.Open, FileAccess.Read))
            {
                // Load the main window from the XAML file
                GUIMain.mainGUIWindow = (System.Windows.Window)System.Windows.Markup.XamlReader.Load(fs);
            }
            #endregion

            // Set the MainWindow for the application
            GUIMain.app.MainWindow = GUIMain.mainGUIWindow;

            // Assigning the icon for the Harden Windows Security GUI
            GUIMain.mainGUIWindow.Icon = new System.Windows.Media.Imaging.BitmapImage(new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Media", "ProgramIcon.ico")));

            // Set the DataContext for the main window
            GUIMain.mainGUIWindow.DataContext = new NavigationVM();

            #region Event handlers For The Main GUI

            // Defining what happens when the GUI window is closed
            GUIMain.mainGUIWindow.Closed += (sender, e) =>
            {
                // Create the footer to the log file
                string endOfLogFile = $"""
**********************
Harden Windows Security operation log end
End time: {DateTime.Now}
**********************
""";

                HardenWindowsSecurity.Logger.LogMessage(endOfLogFile);
            };

            /*
                        // Startup Event
                        GUIMain.app!.Startup += (object s, StartupEventArgs e) =>
                        {
                            // Display a welcome message
                            System.Windows.MessageBox.Show(messageBoxText: "Welcome to the application!", caption: "Startup", button: MessageBoxButton.OK, icon: MessageBoxImage.Information);
                        };

                        // Exit Event
                        GUIMain.app!.Exit += (object s, ExitEventArgs e) =>
                        {
                            System.Windows.MessageBox.Show(messageBoxText: "Exiting!", caption: "Exit", button: MessageBoxButton.OK, icon: MessageBoxImage.Information);
                        };

                        // DispatcherUnhandledException Event is triggered when an unhandled exception occurs in the application
                        GUIMain.app!.DispatcherUnhandledException += (object s, DispatcherUnhandledExceptionEventArgs e) =>
                        {

                            // Display an error message to the user
                            System.Windows.MessageBox.Show(messageBoxText: "An unexpected error occurred.", caption: "Error", button: MessageBoxButton.OK, icon: MessageBoxImage.Error);

                            // Mark the exception as handled
                            e.Handled = true;
                        };
            */

            /*
                        GUIMain.app!.Resources["GlobalStyle"] = new Style(typeof(System.Windows.Controls.Button))
                        {
                            Setters =
                            {
                                new Setter(System.Windows.Controls.Button.BackgroundProperty, System.Windows.Media.Brushes.LightBlue),
                                new Setter(System.Windows.Controls.Button.ForegroundProperty, System.Windows.Media.Brushes.DarkBlue)
                            }
                        };
            */


            // event handler to make the GUI window draggable wherever it's empty
            GUIMain.mainGUIWindow.MouseDown += (sender, e) =>
            {
                // Only allow dragging the window when the left mouse button (also includes touch) is clicked
                if (e.ChangedButton == MouseButton.Left)
                {
                    GUIMain.mainGUIWindow.DragMove();
                }
            };

            #endregion

            #region parent border of the Main GUI
            // Find the Border control by name
            System.Windows.Controls.Border border = (System.Windows.Controls.Border)GUIMain.mainGUIWindow.FindName("OuterMostBorder");

            // Access the ImageBrush from the Border's Background property
            ImageBrush imageBrush = (ImageBrush)border.Background;

            // Set the ImageSource property to the desired image path
            imageBrush.ImageSource = new System.Windows.Media.Imaging.BitmapImage(
                    new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path!, "Resources", "Media", "background.jpg"))
                );
            #endregion

            // Finding the sidebar Grid
            HardenWindowsSecurity.GUIMain.SidebarGrid = GUIMain.mainGUIWindow.FindName("SidebarGrid") as System.Windows.Controls.Grid;

            // Protect button icon
            System.Windows.Controls.Grid ProtectButtonGrid = SidebarGrid.FindName("ProtectButtonGrid") as System.Windows.Controls.Grid;
            System.Windows.Controls.Image ProtectButtonIcon = ProtectButtonGrid.FindName("ProtectButtonIcon") as System.Windows.Controls.Image;
            ProtectButtonIcon.Source = new System.Windows.Media.Imaging.BitmapImage(new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Media", "ProtectMenuButton.png")));

            // Confirm button icon
            System.Windows.Controls.Grid ConfirmButtonGrid = SidebarGrid.FindName("ConfirmButtonGrid") as System.Windows.Controls.Grid;
            System.Windows.Controls.Image ConfirmButtonIcon = ConfirmButtonGrid.FindName("ConfirmButtonIcon") as System.Windows.Controls.Image;
            ConfirmButtonIcon.Source = new System.Windows.Media.Imaging.BitmapImage(new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Media", "ConfirmMenuButton.png")));

            // ASRRules button icon
            System.Windows.Controls.Grid ASRRulesButtonGrid = SidebarGrid.FindName("ASRRulesButtonGrid") as System.Windows.Controls.Grid;
            System.Windows.Controls.Image ASRRulesButtonIcon = ConfirmButtonGrid.FindName("ASRRulesButtonIcon") as System.Windows.Controls.Image;
            ASRRulesButtonIcon.Source = new System.Windows.Media.Imaging.BitmapImage(new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Media", "ASRRulesMenuButton.png")));

            // Unprotect button icon
            System.Windows.Controls.Grid UnprotectButtonGrid = SidebarGrid.FindName("UnprotectButtonGrid") as System.Windows.Controls.Grid;
            System.Windows.Controls.Image UnprotectButtonIcon = ConfirmButtonGrid.FindName("UnprotectButtonIcon") as System.Windows.Controls.Image;
            UnprotectButtonIcon.Source = new System.Windows.Media.Imaging.BitmapImage(new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Media", "UnprotectButton.png")));

            // Logs button icon
            System.Windows.Controls.Grid LogsButtonGrid = SidebarGrid.FindName("LogsButtonGrid") as System.Windows.Controls.Grid;
            System.Windows.Controls.Image LogsButtonIcon = ConfirmButtonGrid.FindName("LogsButtonIcon") as System.Windows.Controls.Image;
            LogsButtonIcon.Source = new System.Windows.Media.Imaging.BitmapImage(new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Media", "LogsMenuButton.png")));

        }
    }
}
