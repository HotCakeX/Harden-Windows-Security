using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

#nullable enable

namespace HardenWindowsSecurity
{
    public partial class GUIProtectWinSecurity
    {
        // During offline mode, this is the path that the button for MicrosoftSecurityBaselineZipPath assigns
        internal static string MicrosoftSecurityBaselineZipPath = string.Empty;

        // During offline mode, this is the path that the button for Microsoft365AppsSecurityBaselineZipPath assigns
        internal static string Microsoft365AppsSecurityBaselineZipPath = string.Empty;

        // During offline mode, this is the path that the button for LGPOZipPath assigns
        internal static string LGPOZipPath = string.Empty;

        // List of all the selected categories in a thread safe way
        internal static ConcurrentQueue<string> SelectedCategories = new();

        // List of all the selected subcategories in a thread safe way
        internal static ConcurrentQueue<string> SelectedSubCategories = new();

        // Set a flag indicating that the required files for the Offline operation mode have been processed
        // When the execute button was clicked, so it won't run twice
        internal static bool StartFileDownloadHasRun;

        // View for the ProtectWindowsSecurity
        internal static System.Windows.Controls.UserControl? View;

        internal static System.Windows.Controls.Grid? parentGrid;
        internal static System.Windows.Controls.Primitives.ToggleButton? mainTabControlToggle;
        internal static System.Windows.Controls.ContentControl? mainContentControl;
        internal static System.Windows.Style? mainContentControlStyle;

        // Defining the correlation between Categories and which Sub-Categories they activate
        internal static System.Collections.Hashtable correlation = new(StringComparer.OrdinalIgnoreCase)
            {
                { "MicrosoftSecurityBaselines", new string[] { "SecBaselines_NoOverrides" } },
                { "MicrosoftDefender", new string[] { "MSFTDefender_SAC", "MSFTDefender_NoDiagData", "MSFTDefender_NoScheduledTask", "MSFTDefender_BetaChannels" } },
                { "LockScreen", new string[] { "LockScreen_CtrlAltDel", "LockScreen_NoLastSignedIn" } },
                { "UserAccountControl", new string[] { "UAC_NoFastSwitching", "UAC_OnlyElevateSigned" } },
                { "WindowsNetworking", new string[] { "WindowsNetworking_BlockNTLM" } },
                { "MiscellaneousConfigurations", new string[] { "Miscellaneous_ProtectedPrinting" } },
                { "CountryIPBlocking", new string[] { "CountryIPBlocking_OFAC" } },
                { "DownloadsDefenseMeasures", new string[] { "DangerousScriptHostsBlocking" } }
            };

        internal static System.Windows.Controls.ListView? categories;
        internal static System.Windows.Controls.ListView? subCategories;
        internal static System.Windows.Controls.CheckBox? selectAllCategories;
        internal static System.Windows.Controls.CheckBox? selectAllSubCategories;

        // fields for Log related elements
        internal static System.Windows.Controls.TextBox? txtFilePath;
        internal static System.Windows.Controls.Button? logPath;
        internal static System.Windows.Controls.Primitives.ToggleButton? log;
        internal static System.Windows.Controls.Primitives.ToggleButton? EventLogging;

        // fields for Offline-Mode related elements
        internal static System.Windows.Controls.Grid? grid2;
        internal static System.Windows.Controls.Primitives.ToggleButton? enableOfflineMode;
        internal static System.Windows.Controls.Button? microsoftSecurityBaselineZipButton;
        internal static System.Windows.Controls.TextBox? microsoftSecurityBaselineZipTextBox;
        internal static System.Windows.Controls.Button? microsoft365AppsSecurityBaselineZipButton;
        internal static System.Windows.Controls.TextBox? microsoft365AppsSecurityBaselineZipTextBox;
        internal static System.Windows.Controls.Button? lgpoZipButton;
        internal static System.Windows.Controls.TextBox? lgpoZipTextBox;

        // Execute button variables
        internal static System.Windows.Controls.Primitives.ToggleButton? ExecuteButton;
        internal static System.Windows.Controls.Grid? ExecuteButtonGrid;
        internal static System.Windows.Controls.Image? ExecuteButtonImage;


        // Flag to run the event for view load only once to prevent file download multiple times when switching between views etc.
        internal static bool LoadEventHasBeenTriggered;

        internal static System.Windows.Controls.ComboBox? ProtectionPresetComboBox;

        internal static string? SelectedProtectionPreset;

        // Defining the presets configurations for the protection
        internal static System.Collections.Generic.Dictionary<string, System.Collections.Generic.Dictionary<string, List<string>>> PresetsIntel = new(StringComparer.OrdinalIgnoreCase)
        {
            {
            "preset: basic", new System.Collections.Generic.Dictionary<string, List<string>>
        {
            { "Categories", new List<string> { "MicrosoftSecurityBaselines", "Microsoft365AppsSecurityBaselines", "MicrosoftDefender", "DeviceGuard", "OptionalWindowsFeatures" } },
            { "SubCategories", new List<string> {} }
        }
        },
        {
        "preset: recommended", new System.Collections.Generic.Dictionary<string, List<string>>
        {
            { "Categories", new List<string> { "MicrosoftSecurityBaselines", "Microsoft365AppsSecurityBaselines", "MicrosoftDefender", "AttackSurfaceReductionRules", "BitLockerSettings", "DeviceGuard", "TLSSecurity", "LockScreen", "UserAccountControl", "WindowsFirewall", "OptionalWindowsFeatures", "WindowsNetworking", "MiscellaneousConfigurations", "WindowsUpdateConfigurations", "EdgeBrowserConfigurations", "DownloadsDefenseMeasures", "NonAdminCommands" } },
            { "SubCategories", new List<string> { "DangerousScriptHostsBlocking" } }
        }
        },
        {
       "preset: complete", new System.Collections.Generic.Dictionary<string, List<string>>
        {
            { "Categories", new List<string> { "MicrosoftSecurityBaselines", "Microsoft365AppsSecurityBaselines", "MicrosoftDefender", "AttackSurfaceReductionRules", "BitLockerSettings", "DeviceGuard", "TLSSecurity", "LockScreen", "UserAccountControl", "WindowsFirewall", "OptionalWindowsFeatures", "WindowsNetworking", "MiscellaneousConfigurations", "WindowsUpdateConfigurations", "EdgeBrowserConfigurations", "CountryIPBlocking", "DownloadsDefenseMeasures", "NonAdminCommands" } },
            { "SubCategories", new List<string> { "MSFTDefender_SAC", "UAC_OnlyElevateSigned", "CountryIPBlocking_OFAC", "DangerousScriptHostsBlocking" } }
        }
        }
        };

    }
}

