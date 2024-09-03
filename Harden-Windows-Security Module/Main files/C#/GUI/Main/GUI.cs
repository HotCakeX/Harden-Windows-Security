using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Microsoft.Win32;

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

                    // Add to application resources to ensure dictionaries are available to the whole application
                    GUIMain.app.Resources.MergedDictionaries.Add(resourceDict);
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

                HardenWindowsSecurity.Logger.LogMessage(endOfLogFile, LogTypeIntel.Information);
            };

            // Exit Event, will work for the GUI when using compiled version of the app or in Visual Studio
            GUIMain.app!.Exit += (object s, ExitEventArgs e) =>
            {
                HardenWindowsSecurity.ControlledFolderAccessHandler.Reset();
                HardenWindowsSecurity.Miscellaneous.CleanUp();

                // System.Windows.MessageBox.Show(messageBoxText: "Exiting!", caption: "Exit", button: MessageBoxButton.OK, icon: MessageBoxImage.Information);
            };

            /*

           // Startup Event
           GUIMain.app!.Startup += (object s, StartupEventArgs e) =>
           {
               // Display a welcome message
               System.Windows.MessageBox.Show(messageBoxText: "Welcome to the application!", caption: "Startup", button: MessageBoxButton.OK, icon: MessageBoxImage.Information);
           };

           // DispatcherUnhandledException Event is triggered when an unhandled exception occurs in the application
           GUIMain.app!.DispatcherUnhandledException += (object s, DispatcherUnhandledExceptionEventArgs e) =>
           {

               // Display an error message to the user
               System.Windows.MessageBox.Show(messageBoxText: "An unexpected error occurred.", caption: "Error", button: MessageBoxButton.OK, icon: MessageBoxImage.Error);

               // Mark the exception as handled
               e.Handled = true;
           };

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

            #region Inner border of the main GUI
            System.Windows.Controls.Border InnerBorder = (System.Windows.Controls.Border)GUIMain.mainGUIWindow.FindName("InnerBorder");

            // Finding the gradient brush background of the inner border
            GUIMain.InnerBorderBackground = (System.Windows.Media.RadialGradientBrush)InnerBorder.Background;

            // Finding the bottom left slider
            GUIMain.BackgroundSlider = (System.Windows.Controls.Slider)GUIMain.mainGUIWindow.FindName("BackgroundOpacitySlider");

            // Creating event handler for the slider
            GUIMain.BackgroundSlider.ValueChanged += (sender, e) =>
            {
                var slider = (System.Windows.Controls.Slider)sender;

                // Scale value from 0-100 to 0-1
                double opacityValue = slider.Value / 100.0;

                // Apply the scaled opacity value to the RadialGradientBrush background
                GUIMain.InnerBorderBackground.Opacity = opacityValue;
            };

            #endregion

            // Finding the sidebar Grid
            HardenWindowsSecurity.GUIMain.SidebarGrid = GUIMain.mainGUIWindow.FindName("SidebarGrid") as System.Windows.Controls.Grid;

            // Finding the progress bar
            GUIMain.mainProgressBar = (System.Windows.Controls.ProgressBar)GUIMain.mainGUIWindow.FindName("MainProgressBar");

            // Finding the button responsible for changing the background image by browsing for image file
            System.Windows.Controls.Button BackgroundChangeButton = (System.Windows.Controls.Button)GUIMain.mainGUIWindow.FindName("BackgroundChangeButton");

            // event handler for button to open file picker to browse for image files
            BackgroundChangeButton.Click += (sender, e) =>
            {
                try
                {
                    // Creating and configuring the OpenFileDialog
                    OpenFileDialog openFileDialog = new OpenFileDialog();

                    // Filter for image files
                    openFileDialog.Filter = "Image Files|*.jpg;*.jpeg;*.png;";
                    openFileDialog.Title = "Select an Image to set as the Harden Windows Security App's Background";

                    // Show the dialog and get the result
                    bool? result = openFileDialog.ShowDialog();

                    if (result == true)
                    {
                        // Get the selected file path
                        string filePath = openFileDialog.FileName;

                        // Create a BitmapImage from the selected file
                        BitmapImage bitmapImage = new BitmapImage();
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
