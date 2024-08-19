using System;
using System.IO;
using Microsoft.Toolkit.Uwp.Notifications;

#nullable enable

namespace HardenWindowsSecurity
{
    public class NewToastNotification
    {
        public static void Show()
        {

            // Combine paths
            string Hero = Path.Combine(HardenWindowsSecurity.GlobalVars.path!, "Resources", "Media", "notification (3).png");
            string Inline = Path.Combine(HardenWindowsSecurity.GlobalVars.path!, "Resources", "Media", "notification (3).png");
            string LogoOverride = Path.Combine(HardenWindowsSecurity.GlobalVars.path!, "Resources", "Media", "dance.gif");
            string DismissButtonImage = Path.Combine(HardenWindowsSecurity.GlobalVars.path!, "Resources", "Media", "bandage-bleed.gif");

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

            //    .AddHeader("6289", "Camping!!", "action=openConversation&id=6289")

            .Show();
        }
    }
}
