using System;
using System.IO;
using Microsoft.Toolkit.Uwp.Notifications;

#nullable enable

namespace HardenWindowsSecurity
{
    public class NewToastNotification
    {

        // These are the different type of notification types/presets that can be displayed
        public enum ToastNotificationType
        {
            EndOfProtection,
            EndOfConfirmation
        }

        /// <summary>
        /// Displays modern toast notification on Windows
        /// The caller must check for HardenWindowsSecurity.GlobalVars.UseNewNotificationsExp and if it's true then use this method
        /// So that it will only display the notifications if the required DLLs have been loaded in the PowerShell session via Add-Type
        /// That is different than the DLLs being made available to the Add-Type during C# code compilation
        /// </summary>
        /// <param name="Type">The type of the toast notification to use</param>
        public static void Show(ToastNotificationType Type, string? TotalCompliantValues, string? TotalNonCompliantValues)
        {
            // Detect the notification type so we can create the proper notification to be displayed
            switch (Type)
            {

                // Notification to show at the end of applying the hardening measures
                case ToastNotificationType.EndOfProtection:
                    {
                        // Combine paths
                        string Hero = Path.Combine(HardenWindowsSecurity.GlobalVars.path!, "Resources", "Media", "notification (3).png");
                        string Inline = Path.Combine(HardenWindowsSecurity.GlobalVars.path!, "Resources", "Media", "notification (3).png");
                        string LogoOverride = Path.Combine(HardenWindowsSecurity.GlobalVars.path!, "Resources", "Media", "notification (2).png");
                        string DismissButtonImage = Path.Combine(HardenWindowsSecurity.GlobalVars.path!, "Resources", "Media", "notification (1).png");


                        new Microsoft.Toolkit.Uwp.Notifications.ToastContentBuilder()

                        .AddAppLogoOverride(new Uri($"file:///{LogoOverride}"), ToastGenericAppLogoCrop.Circle)

                        .AddText("Protection Completed.")

                        .AddText($"Successfully applied {HardenWindowsSecurity.GUIProtectWinSecurity.SelectedCategories.Count} categories")

                        .AddText("Your computer is now more secure 👏")

                        //   .AddHeroImage(new Uri($"file:///{Hero}"))

                        .AddInlineImage(new Uri($"file:///{Inline}"))


                        /*

                         .AddButton(new ToastButton()
                                        .SetContent("Dismiss")
                                        .AddArgument("action", "dismiss")
                                        .SetImageUri(new Uri($"file:///{DismissButtonImage}")))

                                    .AddButton(new ToastButton()
                                        .SetContent("View Details")
                                        .AddArgument("action", "viewDetails")
                                        .SetImageUri(new Uri("file:///D:/notifications/view_icon.jpg")))

                                    .AddButton(new ToastButton()
                                        .SetContent("Open App")
                                        .AddArgument("action", "openApp")
                                        .SetImageUri(new Uri("file:///D:/notifications/view_icon.jpg")))

                                    .AddButton(new ToastButton()
                                        .SetContent("Open App")
                                        .AddArgument("action", "openApp")
                                        .SetImageUri(new Uri("file:///D:/notifications/view_icon.jpg")))

                                    .AddButton(new ToastButton()
                                        .SetContent("Open App")
                                        .AddArgument("action", "openApp")
                                        .SetImageUri(new Uri("file:///D:/notifications/view_icon.jpg")))
                        */

                        .AddAudio(new Uri("ms-winsoundevent:Notification.SMS"))

                        .AddAttributionText("Brought to you by Harden Windows Security")

                            .AddHeader("54331", "End of Protection", "")

                        .Show();

                        break;
                    }

                // Notification to show for End of compliance checking/Confirmation
                case ToastNotificationType.EndOfConfirmation:
                    {

                        // Combine paths
                        string Hero = Path.Combine(HardenWindowsSecurity.GlobalVars.path!, "Resources", "Media", "notification (3).png");
                        string Inline = Path.Combine(HardenWindowsSecurity.GlobalVars.path!, "Resources", "Media", "notification (3).png");
                        string LogoOverride = Path.Combine(HardenWindowsSecurity.GlobalVars.path!, "Resources", "Media", "3d-glassy-gradient-plastic-twisted-torus.png");
                        string DismissButtonImage = Path.Combine(HardenWindowsSecurity.GlobalVars.path!, "Resources", "Media", "notification (1).png");


                        new Microsoft.Toolkit.Uwp.Notifications.ToastContentBuilder()

                        .AddAppLogoOverride(new Uri($"file:///{LogoOverride}"), ToastGenericAppLogoCrop.Circle)

                        .AddText("Compliance checking completed.")

                        .AddText($"Successfully verified the hardening measures on the current system.")

                        .AddText($"{TotalCompliantValues} Compliant and {TotalNonCompliantValues} Non-Compliant items have been detected.")

                        //   .AddHeroImage(new Uri($"file:///{Hero}"))

                        .AddInlineImage(new Uri($"file:///{Inline}"))

                        .AddAudio(new Uri("ms-winsoundevent:Notification.SMS"))

                        .AddAttributionText("Brought to you by Harden Windows Security")

                           .AddHeader("12345", "End of Confirmation", "Action")

                        .Show();

                        break;
                    }
            }
        }
    }
}
