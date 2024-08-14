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

#nullable enable

namespace HardenWindowsSecurity
{
    public partial class GUIProtectWinSecurity
    {
        // During offline mode, this is the path that the button for MicrosoftSecurityBaselineZipPath assigns
        public static string MicrosoftSecurityBaselineZipPath = string.Empty;

        // During offline mode, this is the path that the button for Microsoft365AppsSecurityBaselineZipPath assigns
        public static string Microsoft365AppsSecurityBaselineZipPath = string.Empty;

        // During offline mode, this is the path that the button for LGPOZipPath assigns
        public static string LGPOZipPath = string.Empty;

        // List of all the selected categories in a thread safe way
        public static ConcurrentQueue<string> SelectedCategories = new ConcurrentQueue<string>();

        // List of all the selected subcategories in a thread safe way
        public static ConcurrentQueue<string> SelectedSubCategories = new ConcurrentQueue<string>();

        // To store the log messages in a thread safe way that will be displayed on the GUI and stored in the Logs text file
        public static ArrayList Logger = ArrayList.Synchronized(new ArrayList());

        // Initialize a flag to determine whether to write logs or not, set to false by default
        public static bool ShouldWriteLogs = false;


        // Set a flag indicating that the required files for the Offline operation mode have been processed
        // When the execute button was clicked, so it won't run twice
        public static bool StartFileDownloadHasRun = false;


        // The following are XAML GUI Elements
        public static string? xamlPath;
        public static string? xamlContent;
        public static System.Xml.XmlDocument? xamlDocument;
        public static System.Xml.XmlNodeReader? reader;
        // Main window instance
        public static System.Windows.Window? window;
        // Application instance
        public static System.Windows.Application? app;
        public static System.Windows.Controls.Grid? parentGrid;
        public static System.Windows.Controls.Primitives.ToggleButton? mainTabControlToggle;
        public static System.Windows.Controls.ContentControl? mainContentControl;
        public static System.Windows.Style? mainContentControlStyle;
        public static System.Windows.Controls.TextBox? outputTextBlock;
        public static System.Windows.Controls.ScrollViewer? scrollerForOutputTextBlock;


        // Defining the correlation between Categories and which Sub-Categories they activate
        public static System.Collections.Hashtable correlation = new System.Collections.Hashtable(StringComparer.OrdinalIgnoreCase)
            {
                { "MicrosoftSecurityBaselines", new string[] { "SecBaselines_NoOverrides" } },
                { "MicrosoftDefender", new string[] { "MSFTDefender_SAC", "MSFTDefender_NoDiagData", "MSFTDefender_NoScheduledTask", "MSFTDefender_BetaChannels" } },
                { "LockScreen", new string[] { "LockScreen_CtrlAltDel", "LockScreen_NoLastSignedIn" } },
                { "UserAccountControl", new string[] { "UAC_NoFastSwitching", "UAC_OnlyElevateSigned" } },
                { "CountryIPBlocking", new string[] { "CountryIPBlocking_OFAC" } },
                { "DownloadsDefenseMeasures", new string[] { "DangerousScriptHostsBlocking" } },
                { "NonAdminCommands", new string[] { "ClipboardSync" } }
            };

        public static System.Windows.Controls.ListView? categories;
        public static System.Windows.Controls.ListView? subCategories;
        public static System.Windows.Controls.CheckBox? selectAllCategories;
        public static System.Windows.Controls.CheckBox? selectAllSubCategories;
        public static System.Windows.Controls.ProgressBar? mainProgressBar;


        // fields for Log related elements
        public static System.Windows.Controls.TextBox? txtFilePath;
        public static System.Windows.Controls.Button? logPath;
        public static System.Windows.Controls.Primitives.ToggleButton? log;
        public static System.Windows.Controls.Viewbox? loggingViewBox;


        // fields for Offline-Mode related elements
        public static System.Windows.Controls.Grid? grid2;
        public static System.Windows.Controls.Primitives.ToggleButton? enableOfflineMode;
        public static System.Windows.Controls.Button? microsoftSecurityBaselineZipButton;
        public static System.Windows.Controls.TextBox? microsoftSecurityBaselineZipTextBox;
        public static System.Windows.Controls.Button? microsoft365AppsSecurityBaselineZipButton;
        public static System.Windows.Controls.TextBox? microsoft365AppsSecurityBaselineZipTextBox;
        public static System.Windows.Controls.Button? lgpoZipButton;
        public static System.Windows.Controls.TextBox? lgpoZipTextBox;
    }
}

