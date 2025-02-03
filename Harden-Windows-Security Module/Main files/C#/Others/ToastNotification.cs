using System;
using System.IO;
using Microsoft.Toolkit.Uwp.Notifications;

namespace HardenWindowsSecurity;

internal static class ToastNotification
{

	// These are the different type of notification types/presets that can be displayed
	internal enum Type
	{
		EndOfProtection,
		EndOfConfirmation,
		EndOfASRRules,
		EndOfUnprotection,
		EndOfExclusions,
		EndOfBitLocker
	}

	/// <summary>
	/// Displays modern toast notification on Windows
	/// </summary>
	/// <param name="Type">The type of the toast notification to use</param>
	internal static void Show(Type Type, string? TotalCompliantValues, string? TotalNonCompliantValues, string? UnprotectCategory, string? BitLockerEncryptionTab)
	{

		try
		{

			// Notifications Icon Override for all of the toast notification styles
			string LogoOverride = Path.Combine(GlobalVars.path, "Resources", "Media", "NotificationIconOverride.png");

			// Detect the notification type so we can create the proper notification to be displayed
			switch (Type)
			{

				// Notification to show at the end of applying the hardening measures
				case Type.EndOfProtection:
					{
						// Combine paths
						// string Hero = Path.Combine(GlobalVars.path, "Resources", "Media", "Microsoft Defender.png");
						// string DismissButtonImage = Path.Combine(GlobalVars.path, "Resources", "Media", "notification (1).png");
						string Inline = Path.Combine(GlobalVars.path, "Resources", "Media", "ProtectToastNotificationImage.png");

						new ToastContentBuilder()

						.AddAppLogoOverride(new Uri($"file:///{LogoOverride}"), ToastGenericAppLogoCrop.Circle)

						.AddText("Protection Completed.")

						.AddText($"Successfully applied {GUIProtectWinSecurity.SelectedCategories.Count} categories")

						.AddText("Your computer is now more secure 👏")

						// .AddHeroImage(new Uri($"file:///{Hero}"))

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

						.AddHeader("00001", "End of Protection", "Action")

						.Show();

						break;
					}

				// Notification to show for End of compliance checking/Confirmation
				case Type.EndOfConfirmation:
					{

						// Combine paths
						string Inline = Path.Combine(GlobalVars.path, "Resources", "Media", "ConfirmToastNotificationImage.png");

						new ToastContentBuilder()

						.AddAppLogoOverride(new Uri($"file:///{LogoOverride}"), ToastGenericAppLogoCrop.Circle)

						.AddText("Compliance checking completed.")

						.AddText($"Successfully verified the hardening measures on the current system.")

						.AddText($"{TotalCompliantValues} Compliant and {TotalNonCompliantValues} Non-Compliant items have been detected.")

						// .AddHeroImage(new Uri($"file:///{Hero}"))

						.AddInlineImage(new Uri($"file:///{Inline}"))

						.AddAudio(new Uri("ms-winsoundevent:Notification.SMS"))

						.AddAttributionText("Brought to you by Harden Windows Security")

						.AddHeader("00002", "End of Confirmation", "Action")

						.Show();

						break;
					}
				case Type.EndOfASRRules:
					{

						// Combine paths
						string Hero = Path.Combine(GlobalVars.path, "Resources", "Media", "Attack Surface Reduction Notification Hero Image.png");
						string Inline = Path.Combine(GlobalVars.path, "Resources", "Media", "ASRRulesToastNotificationImage.png");

						new ToastContentBuilder()

						.AddAppLogoOverride(new Uri($"file:///{LogoOverride}"), ToastGenericAppLogoCrop.Circle)

						.AddText("ASR Rules Applied.")

						.AddText($"Successfully applied the Attack Surface Reduction configurations on the system.")

						.AddText($"They were applied using Group Policy..")

						.AddHeroImage(new Uri($"file:///{Hero}"))

						.AddInlineImage(new Uri($"file:///{Inline}"))

						.AddAudio(new Uri("ms-winsoundevent:Notification.SMS"))

						.AddAttributionText("Brought to you by Harden Windows Security")

						.AddHeader("00003", "End of ASR Rules application", "Action")

						.Show();

						break;
					}
				case Type.EndOfUnprotection:
					{
						// Combine paths
						string Inline = Path.Combine(GlobalVars.path, "Resources", "Media", "UnprotectToastNotificationImage.png");

						new ToastContentBuilder()

						.AddAppLogoOverride(new Uri($"file:///{LogoOverride}"), ToastGenericAppLogoCrop.Circle)

						.AddText("Protections have been removed.")

						.AddText($"Successfully removed the {UnprotectCategory} from the system.")

						.AddInlineImage(new Uri($"file:///{Inline}"))

						.AddAudio(new Uri("ms-winsoundevent:Notification.SMS"))

						.AddAttributionText("Brought to you by Harden Windows Security")

						.AddHeader("00004", "End of Unprotection", "Action")

						.Show();

						break;
					}
				case Type.EndOfExclusions:
					{
						// Combine paths
						string Inline = Path.Combine(GlobalVars.path, "Resources", "Media", "UnprotectToastNotificationImage.png");

						new ToastContentBuilder()

						.AddAppLogoOverride(new Uri($"file:///{LogoOverride}"), ToastGenericAppLogoCrop.Circle)

						.AddText("Exclusions Processed.")

						.AddText($"Successfully Processed {(GUIExclusions.selectedFiles!.Length)} file path(s) for exclusions.")

						.AddInlineImage(new Uri($"file:///{Inline}"))

						.AddAudio(new Uri("ms-winsoundevent:Notification.SMS"))

						.AddAttributionText("Brought to you by Harden Windows Security")

						.AddHeader("00004", "End of Exclusions", "Action")

						.Show();

						break;
					}
				case Type.EndOfBitLocker:
					{
						// Combine paths
						string Inline = Path.Combine(GlobalVars.path, "Resources", "Media", "BitLockerToastNotificationImage.png");

						new ToastContentBuilder()

						.AddAppLogoOverride(new Uri($"file:///{LogoOverride}"), ToastGenericAppLogoCrop.Circle)

						.AddText("BitLocker section Completed.")

						.AddText($"{BitLockerEncryptionTab} encryption section completed.")

						.AddInlineImage(new Uri($"file:///{Inline}"))

						.AddAudio(new Uri("ms-winsoundevent:Notification.SMS"))

						.AddAttributionText("Brought to you by Harden Windows Security")

						.AddHeader("00004", "End of BitLocker Encryption", "Action")

						.Show();

						break;
					}

				default:
					break;
			}
		}
		catch (Exception ex)
		{
			Logger.LogMessage($"Couldn't display toast notification: {ex.Message}", LogTypeIntel.Warning);
		}

	}
}
