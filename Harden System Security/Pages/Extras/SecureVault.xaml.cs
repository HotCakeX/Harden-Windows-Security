// MIT License
//
// Copyright (c) 2023-Present - Violet Hansen - (aka HotCakeX on GitHub) - Email Address: spynetgirl@outlook.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// See here for more information: https://github.com/HotCakeX/Harden-Windows-Security/blob/main/LICENSE
//

using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using AppControlManager.CustomUIElements;
using CommonCore.IncrementalCollection;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using Microsoft.UI.Xaml.Navigation;
using Windows.Foundation;
using Windows.UI;
using Windows.UI.Core;
using WinRT;

namespace HardenSystemSecurity.Pages.Extras;

internal sealed partial class SecureVault : Page, CommonCore.UI.IPageHeaderProvider, INPCImplant
{
	#region INPCImplant Implementation
	public event PropertyChangedEventHandler? PropertyChanged;
	public void RaisePropertyChanged(string? propertyName) => PropertyChanged?.Invoke(this, new(propertyName));
	#endregion

	internal SecureVault()
	{
		InitializeComponent();
		NavigationCacheMode = NavigationCacheMode.Disabled;
		refreshTimer = DispatcherQueue.CreateTimer();
		refreshTimer.Interval = TimeSpan.FromMilliseconds(RefreshIntervalMilliseconds);
		refreshTimer.Tick += RefreshTimer_Tick;
		VaultContentPanel.AddHandler(PointerPressedEvent, new PointerEventHandler(VaultContentPanel_PointerPressed), true);
	}

	string CommonCore.UI.IPageHeaderProvider.HeaderTitle => Atlas.GetStr("SecureVaultNavigationViewItem/ToolTipService/ToolTip");
	Uri? CommonCore.UI.IPageHeaderProvider.HeaderGuideUri => new("https://github.com/HotCakeX/Harden-Windows-Security/wiki/Secure-Vault");

	private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	private const string VaultPurpose = "HardenSystemSecurity.TOTP.Vault";
	private const string VaultEncryptionAlgorithm = "AES-256-GCM";
	private const string VaultKdfAlgorithm = "PBKDF2-HMAC-SHA3-512";
	private const string VaultRecordAssociatedDataDomain = "HardenWindowsSecurity.TOTP.Vault.Record.AAD.SHA3-512";
	private const string VaultKeyWrapAssociatedDataDomain = "HardenWindowsSecurity.TOTP.Vault.KeyWrap.AAD.SHA3-512";
	private const string VaultRecordEncryptionKeyDomain = "HardenWindowsSecurity.TOTP.Vault.RecordKey.HKDF-SHA3-512";
	private const string VaultPasswordUnlockFailureMessage = "The vault password is incorrect, or the vault file was modified or corrupted.";
	private const int VaultVersion = 1;
	private const int RefreshIntervalMilliseconds = 1000;
	private static readonly TimeSpan AutoLockAfterOneMinuteDuration = TimeSpan.FromMinutes(1D);
	private const int SaltSizeInBytes = 32;
	private const int VaultIdSizeInBytes = 32;
	private const int AesKeySizeInBytes = 32;
	private const int AesGcmNonceSizeInBytes = 12;
	private const int AesGcmTagSizeInBytes = 16;
	private const int PasswordKdfIterations = 1000000;
	private const int MinimumVaultPasswordLength = 6;
	private const int PasswordStrengthMaximumScore = 6;
	private const int MaxStackAllocatedSecretNormalizationChars = 256;
	private const int CryptProtectMemoryBlockSizeInBytes = 16;
	private const uint CRYPTPROTECTMEMORY_SAME_PROCESS = 0U;
	private const double LockedContentOpacityValue = 0.10D;
	private const int LongVaultHoldDurationMilliseconds = 5000;
	private const int ShortVaultHoldDurationMilliseconds = 3000;
	private const double VaultLocationFlyoutWidth = 600D;
	private const double VaultLocationTextBoxWidth = 500D;
	private const double DestructiveHoldButtonSize = 144D;
	private const double DestructiveHoldRingSize = 168D;
	private const double DestructiveHoldRingRadius = 76D;
	private static readonly Color DestructiveHoldGreen = Color.FromArgb(255, 18, 160, 78);
	private static readonly Color DestructiveHoldLime = Color.FromArgb(255, 84, 214, 96);
	private static readonly Color DestructiveHoldYellow = Color.FromArgb(255, 245, 208, 66);
	private static readonly Color DestructiveHoldOrange = Color.FromArgb(255, 245, 128, 32);
	private static readonly Color DestructiveHoldPink = Color.FromArgb(255, 236, 72, 153);
	private static readonly Color DestructiveHoldRed = Color.FromArgb(255, 220, 38, 38);
	private static readonly Color DestructiveHoldDarkRed = Color.FromArgb(255, 96, 16, 16);
	private static readonly Color DestructiveHoldBlack = Color.FromArgb(255, 0, 0, 0);
	private static readonly Color PasswordStrengthNeutralColor = Color.FromArgb(255, 148, 163, 184);
	private static readonly Color PasswordStrengthWeakColor = Color.FromArgb(255, 220, 38, 38);
	private static readonly Color PasswordStrengthFairColor = Color.FromArgb(255, 245, 128, 32);
	private static readonly Color PasswordStrengthGoodColor = Color.FromArgb(255, 245, 208, 66);
	private static readonly Color PasswordStrengthStrongColor = Color.FromArgb(255, 18, 160, 78);
	private static readonly Color PasswordStrengthVeryStrongColor = Color.FromArgb(255, 5, 150, 105);
	private static readonly Color PasswordStrengthExcellentColor = Color.FromArgb(255, 2, 132, 199);
	private readonly DispatcherQueueTimer? refreshTimer;
	// Stores the vault data key protected in-place with CryptProtectMemory and only accessible to the current process while the vault remains unlocked.
	// The key is only unprotected for the shortest possible duration immediately around cryptographic operations that require it.
	private byte[]? currentVaultDataKey;
	private DateTimeOffset? lastVaultInteractionUtc;
	internal readonly InfoBarSettings MainInfoBar = new();
	internal readonly InfoBarSettings LockedInfoBar = new();

	// Backing list of the tokens
	internal readonly List<TotpTokenItem> Tokens = [];

	// Collection bound to the ListView's ItemsSource.
	internal readonly RangedObservableCollection<TotpTokenItem> FilteredTokens = [];

	/// <summary>
	/// Refreshes the page UI each time the page is loaded into the visual tree.
	/// One-time page instance setup is performed in the constructor to avoid stacking subscriptions.
	/// </summary>
	private void Loaded_Handler()
	{
		RaiseVaultStateProperties();
		WriteLockedStateGuidance();
		_ = DispatcherQueue.TryEnqueue(FocusPrimaryVaultInput);
	}

	private bool HasPasteInputText
	{
		get; set
		{
			if (this.SP(ref field, value))
			{
				RaisePropertyChanged(nameof(IsAddButtonEnabled));
				RaisePropertyChanged(nameof(IsCurrentTotpInputAddEnabled));
				RecordVaultInteraction();
			}
		}
	}

	private bool IsManualTotpEntryMode
	{
		get; set
		{
			if (this.SP(ref field, value))
			{
				if (value)
				{
					_ = (PasteInputTextBox?.Text = string.Empty);
				}
				else
				{
					ClearManualTotpEntryInputs();
				}
				RaisePropertyChanged(nameof(IsAddButtonEnabled));
				RaisePropertyChanged(nameof(IsCurrentTotpInputAddEnabled));
				RecordVaultInteraction();
			}
		}
	}

	private bool HasManualSecretInput
	{
		get; set
		{
			if (this.SP(ref field, value))
			{
				RaisePropertyChanged(nameof(IsCurrentTotpInputAddEnabled));
				RecordVaultInteraction();
			}
		}
	}

	private string ManualWebsiteText
	{
		get; set
		{
			if (this.SP(ref field, value))
			{
				RaisePropertyChanged(nameof(IsCurrentTotpInputAddEnabled));
				RecordVaultInteraction();
			}
		}
	} = string.Empty;

	private string ManualAccountText
	{
		get; set
		{
			if (this.SP(ref field, value))
				RecordVaultInteraction();
		}
	} = string.Empty;

	private string ManualIssuerText
	{
		get; set
		{
			if (this.SP(ref field, value))
				RecordVaultInteraction();
		}
	} = string.Empty;

	private string SearchText
	{
		get; set
		{
			if (this.SP(ref field, value))
			{
				RefreshFilteredTokens();
				RecordVaultInteraction();
			}
		}
	} = string.Empty;

	private bool IsAutoLockAfterOneMinuteEnabled
	{
		get; set
		{
			if (this.SP(ref field, value))
				HandleAutoLockAfterOneMinuteSettingChanged();
		}
	} = true;

	private double PasswordStrengthMaximum => PasswordStrengthMaximumScore;
	private Brush NewVaultPasswordStrengthBrush { get; set => this.SP(ref field, value); } = new SolidColorBrush(PasswordStrengthNeutralColor);
	private double NewVaultPasswordStrengthValue { get; set => this.SP(ref field, value); }
	private string NewVaultPasswordStrengthText { get; set => this.SP(ref field, value); } = GetDefaultPasswordStrengthText();

	private bool IsVaultUnlocked { get; set => this.SP(ref field, value); }

	private bool HasVaultFile => File.Exists(TokenStorageFilePath);
	private bool IsChangeVaultPasswordButtonEnabled => IsVaultUnlocked && currentVaultDataKey is not null;
	private bool IsAddButtonEnabled => IsVaultUnlocked && !IsManualTotpEntryMode && HasPasteInputText;
	private bool IsCurrentTotpInputAddEnabled => IsManualTotpEntryMode
		? IsVaultUnlocked && HasManualSecretInput && !string.IsNullOrWhiteSpace(ManualWebsiteText)
		: IsAddButtonEnabled;
	private Visibility TokenListVisibility => IsVaultUnlocked ? Visibility.Visible : Visibility.Collapsed;
	private bool VaultLockedOverlayHitTestVisible => !IsVaultUnlocked;
	private bool VaultContentIsHitTestVisible => IsVaultUnlocked;
	private Visibility CreateVaultSectionVisibility => HasVaultFile ? Visibility.Collapsed : Visibility.Visible;
	private Visibility UnlockVaultSectionVisibility => HasVaultFile ? Visibility.Visible : Visibility.Collapsed;
	private Visibility DeleteVaultMenuItemVisibility => HasVaultFile ? Visibility.Visible : Visibility.Collapsed;
	private string LockedStateCardTitle => HasVaultFile ? "Unlock existing vault" : "Create or import a vault";
	private Thickness LockedBackgroundContentPadding => IsVaultUnlocked ? new(0D) : new(18D);
	private const string TokenStorageFolderName = "TOTPTokens";
	private static string DefaultTokenStorageFolder => Path.Join(Microsoft.Windows.Storage.ApplicationData.GetDefault().LocalCachePath, TokenStorageFolderName);
	private static string TokenStorageFolder => Directory.CreateDirectory(GetConfiguredTokenStorageFolder()).FullName;
	private static string TokenStorageFilePath => Path.Join(TokenStorageFolder, "tokens.json");

	private static string GetConfiguredTokenStorageFolder()
	{
		string customVaultDirectory = Atlas.Settings.CustomTotpVaultDirectory;
		return !string.IsNullOrWhiteSpace(customVaultDirectory) && Path.IsPathRooted(customVaultDirectory)
			? customVaultDirectory
			: DefaultTokenStorageFolder;
	}

	[DynamicWindowsRuntimeCast(typeof(Style))]
	private Style? GetStyleOrNull(string key) => Resources.TryGetValue(key, out object styleResource) && styleResource is Style typedStyle ? typedStyle : null;

	[DynamicWindowsRuntimeCast(typeof(Style))]
	private static Style? GetStyleOrNull(ResourceDictionary resources, string key) => resources.TryGetValue(key, out object styleResource) && styleResource is Style typedStyle ? typedStyle : null;

	private static bool TryHandleEnterKey(KeyRoutedEventArgs args, Action action)
	{
		if (args.Key != Windows.System.VirtualKey.Enter)
			return false;

		args.Handled = true;
		action();
		return true;
	}

	private static bool TryHandlePlainEnterKey(KeyRoutedEventArgs args, Action action)
	{
		if (args.Key != Windows.System.VirtualKey.Enter || (InputKeyboardSource.GetKeyStateForCurrentThread(Windows.System.VirtualKey.Shift) & CoreVirtualKeyStates.Down) == CoreVirtualKeyStates.Down)
			return false;

		args.Handled = true;
		action();
		return true;
	}

	private static bool TryValidatePasswordPair(ReadOnlySpan<char> password, ReadOnlySpan<char> confirmationPassword, Action<string> writeWarning)
	{
		if (password.IsEmpty || confirmationPassword.IsEmpty)
		{
			writeWarning("Enter the new vault password in both boxes first.");
			return false;
		}
		if (!TryValidateVaultPassword(password, out string passwordValidationMessage))
		{
			writeWarning(passwordValidationMessage);
			return false;
		}
		if (!password.SequenceEqual(confirmationPassword))
		{
			writeWarning("The new vault passwords do not match exactly.");
			return false;
		}
		return true;
	}

	private void Unloaded_Handler()
	{
		// Tear down sensitive state deterministically when the page leaves the visual tree.
		ApplyLockedState();
		ClearPasswordInputs();
	}

	private void RefreshTimer_Tick(DispatcherQueueTimer sender, object args)
	{
		RefreshAllTokens();
		EvaluateAutoLockAfterInactivity();
	}

	private void VaultContentPanel_PointerPressed(object sender, PointerRoutedEventArgs args) => RecordVaultInteraction();

	private void HandleAutoLockAfterOneMinuteSettingChanged()
	{
		if (IsAutoLockAfterOneMinuteEnabled)
		{
			RecordVaultInteraction();
			return;
		}

		lastVaultInteractionUtc = null;
	}

	private void RecordVaultInteraction()
	{
		if (!IsVaultUnlocked || !IsAutoLockAfterOneMinuteEnabled)
			return;

		lastVaultInteractionUtc = DateTimeOffset.UtcNow;
	}

	private void EvaluateAutoLockAfterInactivity()
	{
		if (!IsVaultUnlocked || !IsAutoLockAfterOneMinuteEnabled || lastVaultInteractionUtc is null)
			return;

		if ((DateTimeOffset.UtcNow - lastVaultInteractionUtc.Value) < AutoLockAfterOneMinuteDuration)
			return;

		AutoLockVaultAfterInactivity();
	}

	private void AutoLockVaultAfterInactivity()
	{
		if (!IsVaultUnlocked)
			return;

		ApplyLockedState();
		ClearPasswordInputs();
		WriteLockedStateGuidance();
		LockedInfoBar.WriteInfo("Vault was automatically locked after 1 minute of inactivity.");
	}

	private void FocusPrimaryVaultInput()
	{
		RecordVaultInteraction();
		// If vault is unlocked, focus on the search box to make it easy for user to start typing for token name immediately.
		_ = IsVaultUnlocked
			? TokenSearchBox.Focus(FocusState.Programmatic)
			: HasVaultFile ? UnlockVaultPasswordBox.Focus(FocusState.Programmatic) : NewVaultPasswordBox.Focus(FocusState.Programmatic);
	}

	private void LockVault()
	{
		if (!IsVaultUnlocked) return;
		ApplyLockedState();
		ClearPasswordInputs();
		WriteLockedStateGuidance();
		MainInfoBar.WriteSuccess("Vault is locked.");
		FocusPrimaryVaultInput(); // Set the focus to the right element
	}

	private void LockVaultKeyboardAccelerator_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
	{
		args.Handled = true;
		LockVault();
	}

	private void UnlockWithPassword()
	{
		if (!HasVaultFile)
		{
			CreateNewVault();
			return;
		}
		ReadOnlySpan<char> password = UnlockVaultPasswordBox.Password.AsSpan();
		if (password.IsEmpty)
		{
			LockedInfoBar.WriteWarning("Enter the vault password first.");
			return;
		}
		byte[] passwordBytes = EncodePasswordToPinnedUtf8(password);
		try
		{
			UnlockVaultWithPassword(passwordBytes);
			ClearPasswordInputs();
			FocusPrimaryVaultInput();
		}
		catch (CryptographicException)
		{
			ApplyLockedState();
			LockedInfoBar.WriteWarning(VaultPasswordUnlockFailureMessage);
		}
		catch (InvalidOperationException ex) when (string.Equals(ex.Message, VaultPasswordUnlockFailureMessage, StringComparison.OrdinalIgnoreCase))
		{
			ApplyLockedState();
			LockedInfoBar.WriteWarning(VaultPasswordUnlockFailureMessage);
		}
		catch (Exception ex)
		{
			ApplyLockedState();
			LockedInfoBar.WriteError(ex);
		}
		finally
		{
			CryptographicOperations.ZeroMemory(passwordBytes);
		}
	}

	private void CreateNewVault()
	{
		ReadOnlySpan<char> password = NewVaultPasswordBox.Password.AsSpan();
		ReadOnlySpan<char> confirmationPassword = ConfirmNewVaultPasswordBox.Password.AsSpan();
		if (!TryValidatePasswordPair(password, confirmationPassword, message => LockedInfoBar.WriteWarning(message)))
			return;
		byte[] passwordBytes = EncodePasswordToPinnedUtf8(password);
		try
		{
			UnlockVaultWithPassword(passwordBytes);
			ClearPasswordInputs();
			MainInfoBar.WriteSuccess("Created a new encrypted portable vault. It is now unlocked and ready for tokens.");
		}
		catch (Exception ex)
		{
			ApplyLockedState();
			LockedInfoBar.WriteError(ex);
		}
		finally
		{
			CryptographicOperations.ZeroMemory(passwordBytes);
		}
	}

	private void NewVaultPasswordBox_PasswordChanged() => UpdateNewVaultPasswordStrengthState(NewVaultPasswordBox.Password.AsSpan());

	private void NewVaultPasswordBox_KeyDown(object sender, KeyRoutedEventArgs args) => TryHandleEnterKey(args, CreateNewVault);

	private void UnlockVaultPasswordBox_KeyDown(object sender, KeyRoutedEventArgs args) => TryHandleEnterKey(args, UnlockWithPassword);

	// Intercept Enter before TextBox handles it as a newline. Shift+Enter keeps the normal multiline behavior.
	private void PasteInputTextBox_PreviewKeyDown(object sender, KeyRoutedEventArgs args) => _ = TryHandlePlainEnterKey(args, AddPastedTotpEntries);
	private void PasteInputTextBox_TextChanged() => HasPasteInputText = !string.IsNullOrWhiteSpace(PasteInputTextBox.Text);
	private void ManualSecretTextBox_TextChanged() => HasManualSecretInput = !string.IsNullOrWhiteSpace(ManualSecretTextBox.Text);

	private async void OpenWindowsDateAndTimeSettings()
	{
		try
		{
			bool result = await Windows.System.Launcher.LaunchUriAsync(new Uri("ms-settings:dateandtime"));
			if (!result)
				MainInfoBar.WriteWarning("Could not open Windows Date & time settings.");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	private async void ShowVaultLocationDialog_UI() => await ShowVaultLocationDialog();

	private async Task ShowVaultLocationDialog()
	{
		using ContentDialogV2 vaultLocationDialog = new()
		{
			Content = CreateVaultLocationDialogContent(),
			CloseButtonText = "Close",
			DefaultButton = ContentDialogButton.Close
		};
		_ = await vaultLocationDialog.ShowAsync();
	}

	private Grid CreateVaultLocationDialogContent()
	{
		Grid root = new()
		{
			Width = VaultLocationFlyoutWidth,
			Padding = new Thickness(0D, 4D, 0D, 0D),
			RowSpacing = 12D
		};
		root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
		root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
		root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
		root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
		TextBlock titleBlock = new()
		{
			Text = "Vault location",
			TextWrapping = TextWrapping.WrapWholeWords,
			Style = GetStyleOrNull("SubtitleTextBlockStyle")
		};
		Grid.SetRow(titleBlock, 0);
		root.Children.Add(titleBlock);
		TextBlock descriptionBlock = new()
		{
			Text = "The encrypted vault file is stored in this folder. Changing the location moves only that JSON file and saves the new path in app settings.",
			TextWrapping = TextWrapping.WrapWholeWords
		};
		Grid.SetRow(descriptionBlock, 1);
		root.Children.Add(descriptionBlock);
		StackPanel pathsPanel = new()
		{
			Spacing = 8D,
			HorizontalAlignment = HorizontalAlignment.Center
		};
		TextBox currentLocationTextBox = new()
		{
			Header = "Current vault location",
			IsReadOnly = true,
			Width = VaultLocationTextBoxWidth,
			Text = TokenStorageFolder
		};
		TextBox defaultLocationTextBox = new()
		{
			Header = "Default vault location",
			IsReadOnly = true,
			Width = VaultLocationTextBoxWidth,
			Text = DefaultTokenStorageFolder
		};
		pathsPanel.Children.Add(currentLocationTextBox);
		pathsPanel.Children.Add(defaultLocationTextBox);
		Grid.SetRow(pathsPanel, 2);
		root.Children.Add(pathsPanel);
		StackPanel actionsPanel = new()
		{
			Orientation = Orientation.Horizontal,
			HorizontalAlignment = HorizontalAlignment.Center,
			Spacing = 8D
		};
		Button openButton = new() { Content = "Open" };
		Button changeButton = new() { Content = "Change..." };
		Button resetButton = new() { Content = "Reset to default" };
		openButton.Click += async (sender, args) => await OpenCurrentVaultLocationAsync();
		changeButton.Click += async (sender, args) => await ChangeVaultLocation();
		resetButton.Click += async (sender, args) => await ResetVaultLocationToDefault();
		actionsPanel.Children.Add(openButton);
		actionsPanel.Children.Add(changeButton);
		actionsPanel.Children.Add(resetButton);
		Grid.SetRow(actionsPanel, 3);
		root.Children.Add(actionsPanel);
		return root;
	}

	private async Task OpenCurrentVaultLocationAsync()
	{
		try
		{
			bool result = await Windows.System.Launcher.LaunchFolderPathAsync(TokenStorageFolder);
			if (!result)
				MainInfoBar.WriteWarning("Could not open the current vault location.");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	private async Task ChangeVaultLocation()
	{
		try
		{
			string? selectedFolder = FileDialogHelper.ShowDirectoryPickerDialog();
			if (selectedFolder is null)
				return;
			MoveVaultJsonFileToDirectory(selectedFolder);
			await ShowVaultLocationDialog();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	private async Task ResetVaultLocationToDefault()
	{
		try
		{
			MoveVaultJsonFileToDirectory(DefaultTokenStorageFolder);
			await ShowVaultLocationDialog();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	private static void MoveVaultJsonFileToDirectory(string destinationDirectory)
	{
		string currentDirectory = Path.TrimEndingDirectorySeparator(Path.GetFullPath(TokenStorageFolder));
		string targetDirectory = Path.TrimEndingDirectorySeparator(Path.GetFullPath(destinationDirectory));
		string defaultDirectory = Path.TrimEndingDirectorySeparator(Path.GetFullPath(DefaultTokenStorageFolder));
		if (string.Equals(currentDirectory, targetDirectory, StringComparison.OrdinalIgnoreCase))
		{
			Atlas.Settings.CustomTotpVaultDirectory = string.Equals(targetDirectory, defaultDirectory, StringComparison.OrdinalIgnoreCase) ? string.Empty : targetDirectory;
			return;
		}
		string sourceFilePath = TokenStorageFilePath;
		string destinationFilePath = Path.Join(targetDirectory, Path.GetFileName(TokenStorageFilePath));
		_ = Directory.CreateDirectory(targetDirectory);
		File.Move(sourceFilePath, destinationFilePath, true);
		Atlas.Settings.CustomTotpVaultDirectory = string.Equals(targetDirectory, defaultDirectory, StringComparison.OrdinalIgnoreCase) ? string.Empty : targetDirectory;
	}

	private async void ChangeVaultPassword()
	{
		if (!IsVaultUnlocked || currentVaultDataKey is null)
		{
			MainInfoBar.WriteWarning("Unlock the vault before changing its password.");
			return;
		}
		PasswordBox newPasswordBox = new()
		{
			Header = "New vault password",
			PlaceholderText = "Enter the new password for this portable vault",
			PasswordRevealMode = PasswordRevealMode.Peek
		};
		PasswordBox confirmPasswordBox = new()
		{
			Header = "Confirm new vault password",
			PlaceholderText = "Enter the same new password again",
			PasswordRevealMode = PasswordRevealMode.Peek
		};
		TextBlock passwordStrengthTextBlock = new()
		{
			Text = GetDefaultPasswordStrengthText(),
			TextWrapping = TextWrapping.WrapWholeWords,
			Style = GetStyleOrNull("CaptionTextBlockStyle")
		};
		ProgressBar passwordStrengthBar = new()
		{
			Minimum = 0D,
			Maximum = PasswordStrengthMaximum,
			Value = 0D,
			Foreground = new SolidColorBrush(PasswordStrengthNeutralColor)
		};

		StackPanel contentPanel = new()
		{
			Width = 380D,
			Padding = new Thickness(12D),
			Spacing = 10D
		};
		contentPanel.Children.Add(passwordStrengthTextBlock);
		contentPanel.Children.Add(passwordStrengthBar);
		contentPanel.Children.Add(newPasswordBox);
		contentPanel.Children.Add(confirmPasswordBox);

		using ContentDialogV2 changePasswordDialog = new()
		{
			Title = "Change vault password",
			Content = contentPanel,
			PrimaryButtonText = "Change my password",
			CloseButtonText = "Close",
			DefaultButton = ContentDialogButton.Primary
		};
		void RefreshPasswordStrengthMeter() => UpdatePasswordStrengthPresentation(passwordStrengthBar, passwordStrengthTextBlock, newPasswordBox.Password.AsSpan());

		void CommitPasswordChange()
		{
			ReadOnlySpan<char> password = newPasswordBox.Password.AsSpan();
			ReadOnlySpan<char> confirmationPassword = confirmPasswordBox.Password.AsSpan();
			if (!TryValidatePasswordPair(password, confirmationPassword, message => MainInfoBar.WriteWarning(message)))
				return;

			byte[] passwordBytes = EncodePasswordToPinnedUtf8(password);
			try
			{
				if (!SaveStoredTokens(passwordBytes))
					return;

				newPasswordBox.Password = string.Empty;
				confirmPasswordBox.Password = string.Empty;
				RefreshPasswordStrengthMeter();
				changePasswordDialog.Hide();
				MainInfoBar.WriteSuccess("Changed the vault password.");
			}
			catch (Exception ex)
			{
				MainInfoBar.WriteError(ex);
			}
			finally
			{
				CryptographicOperations.ZeroMemory(passwordBytes);
			}
		}
		newPasswordBox.PasswordChanged += (sender, args) =>
		{
			RefreshPasswordStrengthMeter();
			RecordVaultInteraction();
		};

		confirmPasswordBox.PasswordChanged += (sender, args) => RecordVaultInteraction();
		newPasswordBox.KeyDown += (sender, args) => _ = TryHandleEnterKey(args, () => CommitPasswordChange());
		confirmPasswordBox.KeyDown += (sender, args) => _ = TryHandleEnterKey(args, () => CommitPasswordChange());
		changePasswordDialog.PrimaryButtonClick += (sender, args) => CommitPasswordChange();
		RefreshPasswordStrengthMeter();
		changePasswordDialog.Opened += (sender, args) => _ = newPasswordBox.Focus(FocusState.Programmatic);
		_ = await changePasswordDialog.ShowAsync();
	}

	private void ImportVaultJsonFile()
	{
		try
		{
			string? selectedPath = FileDialogHelper.ShowFilePickerDialog(Atlas.JSONPickerFilter);
			if (string.IsNullOrWhiteSpace(selectedPath))
				return;
			string fullSelectedPath = Path.GetFullPath(selectedPath);
			string fullTargetPath = Path.GetFullPath(TokenStorageFilePath);
			if (string.Equals(fullSelectedPath, fullTargetPath, StringComparison.OrdinalIgnoreCase))
			{
				LockedInfoBar.WriteWarning("That JSON file is already the active vault file.");
				return;
			}
			string json = File.ReadAllText(fullSelectedPath);
			TotpVaultEnvelope vaultEnvelope = JsonSerializer.Deserialize(json, TotpButtonJsonContext.Default.TotpVaultEnvelope) ?? throw new InvalidDataException("The selected JSON file is not a valid TOTP vault.");
			ValidateVaultEnvelope(vaultEnvelope);
			_ = Directory.CreateDirectory(TokenStorageFolder);
			File.Copy(fullSelectedPath, TokenStorageFilePath, true);
			ApplyLockedState();
			ClearPasswordInputs();
			LockedInfoBar.WriteSuccess("Imported the selected vault. Enter its password to unlock it.");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	private void DeleteCurrentVault()
	{
		try
		{
			if (!HasVaultFile)
			{
				LockedInfoBar.WriteWarning("There is no current vault to delete.");
				return;
			}

			ShowDestructiveHoldConfirmationDialog(
				titleText: "Delete current vault",
				warningText: "This permanently deletes the entire TOTP vault and every saved token in it. Keep holding the circular button for five seconds to confirm.",
				holdDurationMilliseconds: LongVaultHoldDurationMilliseconds,
				confirmedAction: DeleteCurrentVaultFilesAfterHoldConfirmation);
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	private void DeleteCurrentVaultFilesAfterHoldConfirmation()
	{
		try
		{
			File.Delete(TokenStorageFilePath);
			ApplyLockedState();
			ClearPasswordInputs();
			LockedInfoBar.WriteSuccess("Deleted the current portable vault.");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Opens a separate confirmation dialog for destructive actions so it is not affected by the existing TOTP management flyout lifecycle.
	/// </summary>
	private void ShowDestructiveHoldConfirmationDialog(string titleText, string warningText, int holdDurationMilliseconds, Action confirmedAction)
	{
		_ = DispatcherQueue.TryEnqueue(async () =>
		{
			ContentDialogV2? confirmationDialogLocal = null;
			void wrappedConfirmedAction()
			{
				confirmationDialogLocal?.Hide();
				confirmedAction();
			}
			using ContentDialogV2 confirmationDialog = new()
			{
				Content = CreateDestructiveHoldConfirmationContent(titleText, warningText, holdDurationMilliseconds, wrappedConfirmedAction),
				CloseButtonText = "Cancel",
				DefaultButton = ContentDialogButton.Close
			};
			confirmationDialogLocal = confirmationDialog;
			_ = await confirmationDialog.ShowAsync();
		});
	}

	/// <summary>
	/// Creates the reusable destructive confirmation surface used by delete, clear all, and individual token removal actions.
	/// The action is intentionally gated behind a continuous press and hold gesture.
	/// </summary>
	private Grid CreateDestructiveHoldConfirmationContent(string titleText, string warningTextValue, int holdDurationMilliseconds, Action confirmedAction)
	{
		Grid root = new()
		{
			Width = 360D,
			Padding = new Thickness(0D, 4D, 0D, 0D),
			RowSpacing = 14D
		};
		root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
		root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
		root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
		root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

		TextBlock titleBlock = new()
		{
			Text = titleText,
			TextWrapping = TextWrapping.WrapWholeWords,
			Style = GetStyleOrNull("SubtitleTextBlockStyle")
		};
		Grid.SetRow(titleBlock, 0);
		root.Children.Add(titleBlock);

		TextBlock warningText = new()
		{
			Text = warningTextValue,
			TextWrapping = TextWrapping.WrapWholeWords
		};
		Grid.SetRow(warningText, 1);
		root.Children.Add(warningText);

		Grid holdSurface = new()
		{
			Width = DestructiveHoldRingSize,
			Height = DestructiveHoldRingSize,
			HorizontalAlignment = HorizontalAlignment.Center
		};
		Grid.SetRow(holdSurface, 2);
		root.Children.Add(holdSurface);

		Microsoft.UI.Xaml.Shapes.Ellipse trackRing = new()
		{
			Width = DestructiveHoldRingSize,
			Height = DestructiveHoldRingSize,
			Stroke = new SolidColorBrush(Color.FromArgb(70, 120, 120, 120)),
			StrokeThickness = 8D
		};
		holdSurface.Children.Add(trackRing);

		SolidColorBrush progressBrush = new(DestructiveHoldGreen);
		Microsoft.UI.Xaml.Shapes.Path progressPath = new()
		{
			Width = DestructiveHoldRingSize,
			Height = DestructiveHoldRingSize,
			Stroke = progressBrush,
			StrokeThickness = 8D,
			StrokeStartLineCap = PenLineCap.Round,
			StrokeEndLineCap = PenLineCap.Round,
			Opacity = 0D
		};
		double destructiveHoldCenter = DestructiveHoldRingSize / 2D;
		Point destructiveHoldStartPoint = new(destructiveHoldCenter, destructiveHoldCenter - DestructiveHoldRingRadius);
		ArcSegment progressArcSegment = new()
		{
			Point = destructiveHoldStartPoint,
			Size = new Size(DestructiveHoldRingRadius, DestructiveHoldRingRadius),
			SweepDirection = SweepDirection.Clockwise
		};
		PathFigure progressPathFigure = new()
		{
			StartPoint = destructiveHoldStartPoint,
			IsClosed = false
		};
		progressPathFigure.Segments.Add(progressArcSegment);
		PathGeometry progressPathGeometry = new();
		progressPathGeometry.Figures.Add(progressPathFigure);
		progressPath.Data = progressPathGeometry;
		holdSurface.Children.Add(progressPath);

		Button holdButton = new()
		{
			Width = DestructiveHoldButtonSize,
			Height = DestructiveHoldButtonSize,
			HorizontalAlignment = HorizontalAlignment.Center,
			VerticalAlignment = VerticalAlignment.Center,
			Content = "Hold to confirm",
			CornerRadius = new CornerRadius(DestructiveHoldButtonSize / 2D),
			BorderThickness = new Thickness(1D)
		};
		ToolTipService.SetToolTip(holdButton, string.Concat("Press and hold for ", (holdDurationMilliseconds / 1000D).ToString("0.#", CultureInfo.InvariantCulture), " seconds to confirm"));
		holdSurface.Children.Add(holdButton);

		TextBlock progressText = new()
		{
			HorizontalAlignment = HorizontalAlignment.Center,
			Text = "Release to cancel",
			TextWrapping = TextWrapping.WrapWholeWords
		};
		Grid.SetRow(progressText, 3);
		root.Children.Add(progressText);

		DispatcherQueueTimer holdTimer = DispatcherQueue.CreateTimer();
		holdTimer.Interval = TimeSpan.FromMilliseconds(16D);
		DateTimeOffset holdStartTime = DateTimeOffset.MinValue;
		bool isHolding = false;
		bool isCompleted = false;
		int lastDisplayedPercent = -1;

		void ResetHoldVisuals()
		{
			holdTimer.Stop();
			isHolding = false;
			UpdateDestructiveHoldProgress(progressPath, progressArcSegment, progressBrush, progressText, 0D, ref lastDisplayedPercent);
		}

		void CompleteHold()
		{
			if (isCompleted)
				return;

			isCompleted = true;
			holdTimer.Stop();
			UpdateDestructiveHoldProgress(progressPath, progressArcSegment, progressBrush, progressText, 1D, ref lastDisplayedPercent);
			confirmedAction();
		}

		holdTimer.Tick += (sender, args) =>
		{
			if (!isHolding || isCompleted)
				return;

			double elapsedMilliseconds = (DateTimeOffset.UtcNow - holdStartTime).TotalMilliseconds;
			double progress = Math.Clamp(elapsedMilliseconds / holdDurationMilliseconds, 0D, 1D);
			UpdateDestructiveHoldProgress(progressPath, progressArcSegment, progressBrush, progressText, progress, ref lastDisplayedPercent);

			if (progress >= 1D)
				CompleteHold();
		};

		// ButtonBase handles pointer events internally, so AddHandler with handledEventsToo is required
		// to reliably receive the press and release gestures for this destructive hold action.
		PointerEventHandler pointerPressedHandler = (sender, args) =>
		{
			if (isCompleted)
				return;

			args.Handled = true;
			isHolding = true;
			holdStartTime = DateTimeOffset.UtcNow;
			_ = holdButton.CapturePointer(args.Pointer);
			UpdateDestructiveHoldProgress(progressPath, progressArcSegment, progressBrush, progressText, 0D, ref lastDisplayedPercent);
			holdTimer.Start();
		};
		PointerEventHandler pointerReleasedHandler = (sender, args) =>
		{
			args.Handled = true;
			if (!isCompleted)
				ResetHoldVisuals();
		};
		PointerEventHandler pointerCanceledHandler = (sender, args) =>
		{
			if (!isCompleted)
				ResetHoldVisuals();
		};
		holdButton.AddHandler(PointerPressedEvent, pointerPressedHandler, true);
		holdButton.AddHandler(PointerReleasedEvent, pointerReleasedHandler, true);
		holdButton.AddHandler(PointerCanceledEvent, pointerCanceledHandler, true);
		holdButton.AddHandler(PointerCaptureLostEvent, pointerCanceledHandler, true);
		root.Unloaded += (sender, args) => holdTimer.Stop();

		return root;
	}

	private static void UpdateDestructiveHoldProgress(Microsoft.UI.Xaml.Shapes.Path progressPath, ArcSegment progressArcSegment, SolidColorBrush progressBrush, TextBlock progressText, double progress, ref int lastDisplayedPercent)
	{
		double normalizedProgress = Math.Clamp(progress, 0D, 1D);
		double center = DestructiveHoldRingSize / 2D;
		double angle = (Math.Clamp(normalizedProgress, 0.001D, 0.9999D) * 360D) - 90D;
		double radians = angle * Math.PI / 180D;
		progressArcSegment.Point = new Point(center + (Math.Cos(radians) * DestructiveHoldRingRadius), center + (Math.Sin(radians) * DestructiveHoldRingRadius));
		progressArcSegment.IsLargeArc = normalizedProgress >= 0.5D;
		progressPath.Opacity = normalizedProgress <= 0D ? 0D : 1D;
		progressBrush.Color = GetDestructiveHoldProgressColor(normalizedProgress);
		int percent = (int)Math.Round(normalizedProgress * 100D, MidpointRounding.AwayFromZero);
		if (percent == lastDisplayedPercent)
			return;

		lastDisplayedPercent = percent;
		progressText.Text = normalizedProgress >= 1D ? "Confirmed" : string.Concat(percent.ToString(CultureInfo.InvariantCulture), "% complete. Release to cancel.");
	}

	private static Color GetDestructiveHoldProgressColor(double progress)
	{
		double normalizedProgress = SmoothStep(progress);
		if (normalizedProgress < 0.16D)
			return LerpColor(DestructiveHoldGreen, DestructiveHoldLime, SmoothStep(normalizedProgress / 0.16D));

		if (normalizedProgress < 0.32D)
			return LerpColor(DestructiveHoldLime, DestructiveHoldYellow, SmoothStep((normalizedProgress - 0.16D) / 0.16D));

		if (normalizedProgress < 0.50D)
			return LerpColor(DestructiveHoldYellow, DestructiveHoldOrange, SmoothStep((normalizedProgress - 0.32D) / 0.18D));

		if (normalizedProgress < 0.68D)
			return LerpColor(DestructiveHoldOrange, DestructiveHoldPink, SmoothStep((normalizedProgress - 0.50D) / 0.18D));

		if (normalizedProgress < 0.84D)
			return LerpColor(DestructiveHoldPink, DestructiveHoldRed, SmoothStep((normalizedProgress - 0.68D) / 0.16D));

		if (normalizedProgress < 0.96D)
			return LerpColor(DestructiveHoldRed, DestructiveHoldDarkRed, SmoothStep((normalizedProgress - 0.84D) / 0.12D));

		return LerpColor(DestructiveHoldDarkRed, DestructiveHoldBlack, SmoothStep((normalizedProgress - 0.96D) / 0.04D));
	}

	private static double SmoothStep(double value)
	{
		double clampedValue = Math.Clamp(value, 0D, 1D);
		return clampedValue * clampedValue * (3D - (2D * clampedValue));
	}

	private static Color LerpColor(Color startColor, Color endColor, double amount)
	{
		double clampedAmount = Math.Clamp(amount, 0D, 1D);
		return Color.FromArgb(255, (byte)Math.Round(startColor.R + ((endColor.R - startColor.R) * clampedAmount), MidpointRounding.AwayFromZero), (byte)Math.Round(startColor.G + ((endColor.G - startColor.G) * clampedAmount), MidpointRounding.AwayFromZero), (byte)Math.Round(startColor.B + ((endColor.B - startColor.B) * clampedAmount), MidpointRounding.AwayFromZero));
	}

	private void UnlockVaultWithPassword(ReadOnlySpan<byte> passwordBytes)
	{
		Tokens.Clear();
		byte[] vaultDataKey;
		if (HasVaultFile)
		{
			TotpVaultEnvelope vaultEnvelope = ReadVaultEnvelope();
			vaultDataKey = UnwrapVaultDataKeyWithPassword(vaultEnvelope, passwordBytes);
		}
		else
		{
			vaultDataKey = CreatePinnedByteArray(AesKeySizeInBytes);
			RandomNumberGenerator.Fill(vaultDataKey);
			byte[] passwordBytesCopy = CreatePinnedByteArray(passwordBytes.Length);
			passwordBytes.CopyTo(passwordBytesCopy);
			try
			{
				_ = SaveStoredTokens(passwordBytesCopy, vaultDataKey);
			}
			finally
			{
				CryptographicOperations.ZeroMemory(passwordBytesCopy);
			}
			if (!HasVaultFile)
				throw new IOException("The TOTP vault file was not created.");
		}
		UnlockVaultWithDataKey(vaultDataKey);
	}

	private void UnlockVaultWithDataKey(byte[] vaultDataKey)
	{
		currentVaultDataKey = vaultDataKey;
		try
		{
			ProtectCurrentVaultDataKey();
			if (HasVaultFile)
				LoadStoredTokens();
			LockedInfoBar.IsOpen = false;
			IsVaultUnlocked = true;
			RecordVaultInteraction();
			RaiseVaultStateProperties();
			RefreshAllTokens();
			RefreshFilteredTokens();
			refreshTimer?.Start();
			MainInfoBar.WriteSuccess("Vault is unlocked. Encrypted portable vault is loaded.");
		}
		catch
		{
			CryptographicOperations.ZeroMemory(vaultDataKey);
			currentVaultDataKey = null;
			throw;
		}
	}

	private void ProtectCurrentVaultDataKey()
	{
		if (currentVaultDataKey is null)
			throw new InvalidOperationException("The vault data key is not loaded.");

		ProtectMemoryInPlace(currentVaultDataKey);
	}

	private void UnprotectCurrentVaultDataKey()
	{
		if (currentVaultDataKey is null)
			throw new InvalidOperationException("The vault data key is not loaded.");

		UnprotectMemoryInPlace(currentVaultDataKey);
	}

	private static void ValidateMemoryProtectionBuffer(byte[] buffer)
	{
		ArgumentNullException.ThrowIfNull(buffer);
		if (buffer.Length == 0 || (buffer.Length % CryptProtectMemoryBlockSizeInBytes) != 0)
			throw new CryptographicException(string.Concat("The memory protection buffer length must be a non-zero multiple of ", CryptProtectMemoryBlockSizeInBytes.ToString(CultureInfo.InvariantCulture), " bytes."));
	}

	private static int RoundUpToCryptProtectMemoryBlockSize(int bufferLength)
	{
		ArgumentOutOfRangeException.ThrowIfNegativeOrZero(bufferLength);

		int remainder = bufferLength % CryptProtectMemoryBlockSizeInBytes;
		return remainder == 0 ? bufferLength : checked(bufferLength + (CryptProtectMemoryBlockSizeInBytes - remainder));
	}

	private static byte[] CreatePinnedByteArray(int length) => GC.AllocateUninitializedArray<byte>(length, pinned: true);

	private static byte[] CreatePaddedProtectedSecretBuffer(ReadOnlySpan<byte> secretBytes)
	{
		if (secretBytes.IsEmpty)
			throw new CryptographicException("The TOTP secret did not decode to any bytes.");
		int paddedLength = RoundUpToCryptProtectMemoryBlockSize(secretBytes.Length);
		byte[] paddedSecretBytes = CreatePinnedByteArray(paddedLength);
		try
		{
			secretBytes.CopyTo(paddedSecretBytes);
			ProtectMemoryInPlace(paddedSecretBytes);
			return paddedSecretBytes;
		}
		catch
		{
			CryptographicOperations.ZeroMemory(paddedSecretBytes);
			throw;
		}
	}

	internal static void ProtectMemoryInPlace(byte[] buffer)
	{
		ValidateMemoryProtectionBuffer(buffer);
		GCHandle pinnedBuffer = GCHandle.Alloc(buffer, GCHandleType.Pinned);
		try
		{
			nint bufferPointer = pinnedBuffer.AddrOfPinnedObject();
			if (NativeMethods.CryptProtectMemory(bufferPointer, (uint)buffer.Length, CRYPTPROTECTMEMORY_SAME_PROCESS) == 0)
				throw new Win32Exception(Marshal.GetLastPInvokeError());
		}
		finally
		{
			pinnedBuffer.Free();
		}
	}

	internal static void UnprotectMemoryInPlace(byte[] buffer)
	{
		ValidateMemoryProtectionBuffer(buffer);
		GCHandle pinnedBuffer = GCHandle.Alloc(buffer, GCHandleType.Pinned);
		try
		{
			nint bufferPointer = pinnedBuffer.AddrOfPinnedObject();
			if (NativeMethods.CryptUnprotectMemory(bufferPointer, (uint)buffer.Length, CRYPTPROTECTMEMORY_SAME_PROCESS) == 0)
				throw new Win32Exception(Marshal.GetLastPInvokeError());
		}
		finally
		{
			pinnedBuffer.Free();
		}
	}

	private Visibility GetVisibleWhenTrue(bool value) => value ? Visibility.Visible : Visibility.Collapsed;

	private Visibility GetVisibleWhenFalse(bool value) => value ? Visibility.Collapsed : Visibility.Visible;

	private void ManualTotpInputTextBox_PreviewKeyDown(object sender, KeyRoutedEventArgs args) => _ = TryHandlePlainEnterKey(args, AddCurrentTotpInput);

	private void AddCurrentTotpInput()
	{
		if (IsManualTotpEntryMode)
		{
			AddManualTotpEntry();
			return;
		}

		AddPastedTotpEntries();
	}

	private void AddManualTotpEntry()
	{
		if (!IsVaultUnlocked)
		{
			MainInfoBar.WriteWarning("Unlock the vault before adding tokens.");
			return;
		}
		ReadOnlySpan<char> secret = ManualSecretTextBox.Text.AsSpan().Trim();
		string website = ManualWebsiteText.Trim();
		string accountName = ManualAccountText.Trim();
		string issuer = ManualIssuerText.Trim();
		if (secret.IsEmpty)
		{
			MainInfoBar.WriteWarning("Enter the TOTP secret first.");
			return;
		}
		if (string.IsNullOrWhiteSpace(website))
		{
			MainInfoBar.WriteWarning("Enter the website name first.");
			return;
		}
		try
		{
			byte[] secretBytes = DecodeBase32(secret);
			try
			{
				if (ContainsEquivalentSecret(secretBytes))
				{
					MainInfoBar.WriteInfo("A token with the same secret already exists in the vault.");
					return;
				}
				string effectiveIssuer = string.IsNullOrWhiteSpace(issuer) ? website : issuer;
				string effectiveAccountName = string.IsNullOrWhiteSpace(accountName) ? website : accountName;
				string displayLabel = CreateDisplayLabel(effectiveIssuer, effectiveAccountName);
				TotpTokenItem tokenItem = CreateTokenItemFromSecretBytes(Guid.CreateVersion7().ToString("N"), displayLabel, TotpHashAlgorithm.Sha1, 6, 30, secretBytes, string.Empty);
				Tokens.Add(tokenItem);
				UpdateToken(tokenItem, DateTimeOffset.UtcNow.ToUnixTimeSeconds());
				ClearManualTotpEntryInputs();
				RefreshFilteredTokens();
				if (!SaveStoredTokens(null))
					return;
				MainInfoBar.WriteSuccess(string.Concat("Added ", tokenItem.DisplayName, "."));
			}
			finally
			{
				CryptographicOperations.ZeroMemory(secretBytes);
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	private void ClearManualTotpEntryInputs()
	{
		_ = (ManualSecretTextBox?.Text = string.Empty);
		ManualWebsiteText = string.Empty;
		ManualAccountText = string.Empty;
		ManualIssuerText = string.Empty;
	}

	private void AddPastedTotpEntries()
	{
		if (!IsVaultUnlocked)
		{
			MainInfoBar.WriteWarning("Unlock the vault before adding tokens.");
			return;
		}
		string pastedText = PasteInputTextBox.Text;
		if (string.IsNullOrWhiteSpace(pastedText))
		{
			MainInfoBar.WriteWarning("No otpauth://totp URI was found in the pasted text.");
			return;
		}
		ReadOnlySpan<char> pastedTextSpan = pastedText.AsSpan();
		List<TotpTokenItem> createdTokenItems = new();
		int addedCount = 0;
		int skippedCount = 0;
		int searchIndex = 0;
		bool foundAnyUri = false;
		try
		{
			while (TryGetNextTotpUriCandidate(pastedTextSpan, ref searchIndex, out Range uriRange))
			{
				foundAnyUri = true;
				try
				{
					ReadOnlySpan<char> uriCandidate = pastedTextSpan[uriRange];
					(byte[] secretBytes, TotpDefinition definition) = ParseTotpUriCandidate(uriCandidate);
					try
					{
						if (ContainsEquivalentSecret(secretBytes))
						{
							skippedCount++;
							continue;
						}
						TotpTokenItem tokenItem = CreateTokenItemFromSecretBytes(Guid.CreateVersion7().ToString("N"), definition.DisplayLabel, definition.Algorithm, definition.Digits, definition.Period, secretBytes, string.Empty);
						Tokens.Add(tokenItem);
						createdTokenItems.Add(tokenItem);
						UpdateToken(tokenItem, DateTimeOffset.UtcNow.ToUnixTimeSeconds());
						addedCount++;
					}
					finally
					{
						CryptographicOperations.ZeroMemory(secretBytes);
					}
				}
				catch (FormatException)
				{
					skippedCount++;
				}
			}
			if (!foundAnyUri)
			{
				MainInfoBar.WriteWarning("No otpauth://totp URI was found in the pasted text.");
				return;
			}
			PasteInputTextBox.Text = string.Empty;
			RefreshFilteredTokens();
			if (!SaveStoredTokens(null))
				return;
			MainInfoBar.WriteSuccess(string.Format(CultureInfo.InvariantCulture, "Added {0} token(s). Skipped {1} duplicate(s).", addedCount, skippedCount));
		}
		catch
		{
			foreach (TotpTokenItem tokenItem in CollectionsMarshal.AsSpan(createdTokenItems))
				tokenItem.ClearSensitiveState();
			throw;
		}
	}

	private void ClearAllTokens()
	{
		if (!IsVaultUnlocked)
		{
			MainInfoBar.WriteWarning("Unlock the vault before clearing tokens.");
			return;
		}

		if (Tokens.Count == 0)
		{
			MainInfoBar.WriteWarning("There are no TOTP tokens to clear.");
			return;
		}

		ShowDestructiveHoldConfirmationDialog(
			titleText: "Clear all tokens",
			warningText: "This permanently removes every TOTP token from the encrypted vault. Keep holding the circular button for five seconds to confirm.",
			holdDurationMilliseconds: LongVaultHoldDurationMilliseconds,
			confirmedAction: ClearAllTokensAfterHoldConfirmation);
	}

	private void ClearAllTokensAfterHoldConfirmation()
	{
		ClearTokenSensitiveState(Tokens);
		Tokens.Clear();
		FilteredTokens.Clear();
		if (!SaveStoredTokens(null))
			return;
		MainInfoBar.WriteSuccess("All TOTP tokens were removed from the encrypted vault.");
	}

	[DynamicWindowsRuntimeCast(typeof(Button))]
	private void CopyTotpCode_Click(object sender, RoutedEventArgs args)
	{
		if (sender is not Button button || button.Tag is not TotpTokenItem tokenItem || string.IsNullOrWhiteSpace(tokenItem.Code))
			return;
		ClipboardManagement.CopyText(tokenItem.Code);
		MainInfoBar.WriteSuccess(string.Concat("Copied code for ", tokenItem.DisplayName, "."));
	}

	[DynamicWindowsRuntimeCast(typeof(Button))]
	private void RemoveTotpToken_Click(object sender, RoutedEventArgs args)
	{
		if (!IsVaultUnlocked || sender is not Button button || button.Tag is not TotpTokenItem tokenItem)
			return;

		if (!Tokens.Contains(tokenItem))
			return;

		string displayName = tokenItem.DisplayName;
		ShowDestructiveHoldConfirmationDialog(
			titleText: "Remove token",
			warningText: string.Concat("This permanently removes ", displayName, " from the encrypted vault. Keep holding the circular button for three seconds to confirm."),
			holdDurationMilliseconds: ShortVaultHoldDurationMilliseconds,
			confirmedAction: () => RemoveTotpTokenAfterHoldConfirmation(tokenItem, displayName));
	}

	private void RemoveTotpTokenAfterHoldConfirmation(TotpTokenItem tokenItem, string displayName)
	{
		if (!IsVaultUnlocked || !Tokens.Remove(tokenItem))
			return;

		tokenItem.ClearSensitiveState();
		RefreshFilteredTokens();
		if (!SaveStoredTokens(null))
			return;
		MainInfoBar.WriteSuccess(string.Concat("Removed ", displayName, "."));
	}

	[DynamicWindowsRuntimeCast(typeof(Button))]
	private async void ShowTotpTokenNotes_Click(object sender, RoutedEventArgs args)
	{
		if (sender is not Button button || button.Tag is not TotpTokenItem tokenItem || string.IsNullOrWhiteSpace(tokenItem.Notes))
			return;

		await ShowTokenNotePreviewDialog(tokenItem);
	}

	[DynamicWindowsRuntimeCast(typeof(Button))]
	private async void EditTotpTokenNotes_Click(object sender, RoutedEventArgs args)
	{
		if (!IsVaultUnlocked || sender is not Button button || button.Tag is not TotpTokenItem tokenItem || !Tokens.Contains(tokenItem))
			return;

		await ShowTokenNoteEditorDialog(tokenItem);
	}

	private async Task ShowTokenNotePreviewDialog(TotpTokenItem tokenItem)
	{
		using ContentDialogV2 tokenNotePreviewDialog = new()
		{
			Content = CreateTokenNotePreviewContent(tokenItem),
			CloseButtonText = "Close",
			DefaultButton = ContentDialogButton.Close
		};
		_ = await tokenNotePreviewDialog.ShowAsync();
	}

	private static Border CreateTokenNotePreviewContent(TotpTokenItem tokenItem)
	{
		TextBlock titleTextBlock = new()
		{
			Text = GetTokenNoteHeaderText(tokenItem.Notes),
			Style = GetStyleOrNull(Application.Current.Resources, "CaptionTextBlockStyle")
		};
		TextBlock noteTextBlock = new()
		{
			Text = tokenItem.Notes,
			TextWrapping = TextWrapping.WrapWholeWords,
			IsTextSelectionEnabled = true
		};
		ScrollViewer noteScrollViewer = new()
		{
			MaxHeight = 240D,
			Content = noteTextBlock
		};
		StackPanel contentPanel = new()
		{
			Spacing = 8D
		};
		contentPanel.Children.Add(titleTextBlock);
		contentPanel.Children.Add(noteScrollViewer);
		return new()
		{
			Width = 340D,
			Padding = new Thickness(14D),
			Background = new SolidColorBrush(Color.FromArgb(24, 128, 128, 128)),
			CornerRadius = new CornerRadius(12D),
			Child = contentPanel
		};
	}

	private async Task ShowTokenNoteEditorDialog(TotpTokenItem tokenItem)
	{
		TextBox noteTextBox = new()
		{
			Width = 360D,
			MaxHeight = 190D,
			Header = GetTokenNoteHeaderText(tokenItem.Notes),
			PlaceholderText = "Write notes for this token",
			AcceptsReturn = true,
			IsSpellCheckEnabled = true,
			Text = tokenItem.Notes,
			TextWrapping = TextWrapping.Wrap
		};
		noteTextBox.TextChanged += (sender, args) =>
		{
			noteTextBox.Header = GetTokenNoteHeaderText(noteTextBox.Text);
			RecordVaultInteraction();
		};
		TextBlock hintTextBlock = new()
		{
			Text = "Press Enter to save. Press Shift+Enter for a new line.",
			TextWrapping = TextWrapping.WrapWholeWords,
			Style = GetStyleOrNull("CaptionTextBlockStyle")
		};
		StackPanel editorPanel = new()
		{
			Width = 380D,
			Spacing = 10D
		};
		editorPanel.Children.Add(noteTextBox);
		editorPanel.Children.Add(hintTextBlock);
		Border editorBorder = new()
		{
			Padding = new Thickness(12D),
			CornerRadius = new CornerRadius(12D),
			Child = editorPanel
		};
		using ContentDialogV2 tokenNoteEditorDialog = new()
		{
			Content = editorBorder,
			PrimaryButtonText = "Save",
			SecondaryButtonText = "Clear",
			CloseButtonText = "Cancel",
			DefaultButton = ContentDialogButton.Primary
		};
		bool saveSucceeded = false;
		bool clearSucceeded = false;
		void SaveTokenNote()
		{
			tokenItem.ApplyNotes(noteTextBox.Text);
			if (!SaveStoredTokens(null))
				return;
			saveSucceeded = true;
			tokenNoteEditorDialog.Hide();
			MainInfoBar.WriteSuccess(string.Concat("Saved notes for ", tokenItem.DisplayName, "."));
		}
		void ClearTokenNote()
		{
			noteTextBox.Text = string.Empty;
			tokenItem.ApplyNotes(string.Empty);
			if (!SaveStoredTokens(null))
				return;
			clearSucceeded = true;
			tokenNoteEditorDialog.Hide();
			MainInfoBar.WriteSuccess(string.Concat("Cleared notes for ", tokenItem.DisplayName, "."));
		}
		tokenNoteEditorDialog.PrimaryButtonClick += (sender, args) =>
		{
			saveSucceeded = false;
			SaveTokenNote();
			args.Cancel = !saveSucceeded;
		};
		tokenNoteEditorDialog.SecondaryButtonClick += (sender, args) =>
		{
			clearSucceeded = false;
			ClearTokenNote();
			args.Cancel = !clearSucceeded;
		};
		noteTextBox.PreviewKeyDown += (sender, args) => _ = TryHandlePlainEnterKey(args, SaveTokenNote);
		tokenNoteEditorDialog.Opened += (sender, args) => _ = noteTextBox.Focus(FocusState.Programmatic);
		_ = await tokenNoteEditorDialog.ShowAsync();
	}

	private static string GetTokenNoteHeaderText(string? note)
	{
		int lineCount = GetTokenNoteLineCount(note);
		int characterCount = note?.Length ?? 0;
		return string.Format(CultureInfo.InvariantCulture, "Token notes | {0} line{1}, {2} character{3}", lineCount, lineCount == 1 ? string.Empty : "s", characterCount, characterCount == 1 ? string.Empty : "s");
	}

	private static int GetTokenNoteLineCount(string? note)
	{
		if (string.IsNullOrEmpty(note))
			return 0;

		int lineCount = 1;
		for (int index = 0; index < note.Length; index++)
		{
			if (note[index] == '\n')
			{
				lineCount++;
				continue;
			}

			if (note[index] == '\r' && (index + 1 >= note.Length || note[index + 1] != '\n'))
				lineCount++;
		}

		return lineCount;
	}

	private void RefreshAllTokens()
	{
		if (!IsVaultUnlocked)
			return;
		long unixTimeSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
		foreach (TotpTokenItem tokenItem in CollectionsMarshal.AsSpan(Tokens))
			UpdateToken(tokenItem, unixTimeSeconds);
	}

	private void RefreshFilteredTokens()
	{
		FilteredTokens.Clear();
		if (Tokens.Count == 0) return;
		string searchText = SearchText.Trim();
		IEnumerable<TotpTokenItem> filteredList = string.IsNullOrWhiteSpace(searchText)
			? Tokens
			: Tokens.Where(x =>
				x.DisplayName.Contains(searchText, StringComparison.OrdinalIgnoreCase) ||
				(!string.IsNullOrWhiteSpace(x.Notes) && x.Notes.Contains(searchText, StringComparison.OrdinalIgnoreCase)));
		FilteredTokens.AddRange(filteredList);
	}

	private void UpdateToken(TotpTokenItem tokenItem, long unixTimeSeconds)
	{
		try
		{
			int elapsedInStep = (int)(unixTimeSeconds % tokenItem.TokenPeriod);
			int remainingSeconds = tokenItem.TokenPeriod - elapsedInStep;
			if (tokenItem.IsCodeCurrentForTimestamp(unixTimeSeconds))
			{
				tokenItem.ApplyResult(tokenItem.Code, remainingSeconds);
				return;
			}

			string code = tokenItem.GenerateCode(unixTimeSeconds, out remainingSeconds);
			tokenItem.ApplyResult(code, remainingSeconds);
		}
		catch (Exception ex)
		{
			tokenItem.ApplyError(ex.Message);
		}
	}

	private static (byte[] SecretBytes, TotpDefinition Definition) ParseTotpUriCandidate(ReadOnlySpan<char> uriCandidate)
	{
		ReadOnlySpan<char> trimmedUri = uriCandidate.Trim();
		const string totpUriPrefix = "otpauth://totp/";
		if (!trimmedUri.StartsWith(totpUriPrefix, StringComparison.OrdinalIgnoreCase))
			throw new FormatException("Only otpauth://totp URIs are supported.");
		ReadOnlySpan<char> remainder = trimmedUri[totpUriPrefix.Length..];
		int querySeparatorIndex = remainder.IndexOf('?');
		if (querySeparatorIndex < 0)
			throw new FormatException("The TOTP URI does not contain a secret parameter.");
		ReadOnlySpan<char> encodedLabel = remainder[..querySeparatorIndex];
		ReadOnlySpan<char> query = remainder[(querySeparatorIndex + 1)..];
		string label = Uri.UnescapeDataString(encodedLabel.ToString());
		string issuerFromLabel = string.Empty;
		string accountName = label;
		int labelSeparatorIndex = label.IndexOf(':', StringComparison.Ordinal);
		if (labelSeparatorIndex >= 0)
		{
			issuerFromLabel = label[..labelSeparatorIndex];
			accountName = label[(labelSeparatorIndex + 1)..];
		}
		string issuer = string.Empty;
		TotpHashAlgorithm algorithm = TotpHashAlgorithm.Sha1;
		int digits = 6;
		int period = 30;
		byte[]? secretBytes = null;
		while (!query.IsEmpty)
		{
			int pairSeparatorIndex = query.IndexOf('&');
			ReadOnlySpan<char> pair = pairSeparatorIndex >= 0 ? query[..pairSeparatorIndex] : query;
			int equalsIndex = pair.IndexOf('=');
			if (equalsIndex > 0)
			{
				ReadOnlySpan<char> key = pair[..equalsIndex];
				ReadOnlySpan<char> value = pair[(equalsIndex + 1)..];
				if (key.Equals("secret".AsSpan(), StringComparison.OrdinalIgnoreCase))
					secretBytes = DecodePercentEncodedBase32Value(value);
				else if (key.Equals("issuer".AsSpan(), StringComparison.OrdinalIgnoreCase))
					issuer = Uri.UnescapeDataString(value.ToString().Replace("+", " ", StringComparison.Ordinal));
				else if (key.Equals("algorithm".AsSpan(), StringComparison.OrdinalIgnoreCase))
					algorithm = ParseAlgorithm(value);
				else if (key.Equals("digits".AsSpan(), StringComparison.OrdinalIgnoreCase))
					digits = ParsePositiveInt(value, 6, "digits");
				else if (key.Equals("period".AsSpan(), StringComparison.OrdinalIgnoreCase))
					period = ParsePositiveInt(value, 30, "period");
			}
			if (pairSeparatorIndex < 0)
				break;
			query = query[(pairSeparatorIndex + 1)..];
		}
		if (secretBytes is null)
			throw new FormatException("The TOTP URI does not contain a secret parameter.");
		if (digits is < 6 or > 8)
		{
			CryptographicOperations.ZeroMemory(secretBytes);
			throw new FormatException("Only 6, 7, or 8 digit TOTP codes are supported.");
		}
		string effectiveIssuer = string.IsNullOrWhiteSpace(issuer) ? issuerFromLabel : issuer;
		return (secretBytes, new TotpDefinition(effectiveIssuer, accountName, algorithm, digits, period));
	}

	private static bool IsUriTerminator(char character) => char.IsWhiteSpace(character) || character == '"' || character == '\'' || character == '<' || character == '>';

	private static bool TryGetNextTotpUriCandidate(ReadOnlySpan<char> source, ref int searchIndex, out Range uriRange)
	{
		const string totpUriPrefix = "otpauth://totp/";
		while (searchIndex < source.Length)
		{
			int relativeStart = source[searchIndex..].IndexOf(totpUriPrefix, StringComparison.OrdinalIgnoreCase);
			if (relativeStart < 0)
			{
				uriRange = default;
				return false;
			}
			int uriStart = searchIndex + relativeStart;
			int uriEnd = uriStart;
			while (uriEnd < source.Length && !IsUriTerminator(source[uriEnd]))
				uriEnd++;
			while (uriEnd > uriStart)
			{
				char trailingCharacter = source[uriEnd - 1];
				if (trailingCharacter is ',' or ';' or '.' or ')' or ']' or '}')
				{
					uriEnd--;
					continue;
				}
				break;
			}
			searchIndex = Math.Max(uriEnd, uriStart + 1);
			if (uriEnd <= uriStart)
				continue;
			uriRange = new Range(uriStart, uriEnd);
			return true;
		}
		uriRange = default;
		return false;
	}

	private static byte[] DecodePercentEncodedBase32Value(ReadOnlySpan<char> encodedValue)
	{
		if (encodedValue.IsEmpty)
			throw new FormatException("The TOTP URI does not contain a secret parameter.");

		char[]? rentedBuffer = null;
		Span<char> decodedBuffer = encodedValue.Length <= MaxStackAllocatedSecretNormalizationChars
			? stackalloc char[MaxStackAllocatedSecretNormalizationChars]
			: (rentedBuffer = ArrayPool<char>.Shared.Rent(encodedValue.Length)).AsSpan(0, encodedValue.Length);
		int decodedLength = 0;
		try
		{
			for (int index = 0; index < encodedValue.Length; index++)
			{
				char character = encodedValue[index];
				if (character == '+')
				{
					decodedBuffer[decodedLength] = ' ';
					decodedLength++;
					continue;
				}

				if (character == '%' && (index + 2) < encodedValue.Length)
				{
					int high = DecodeHexDigit(encodedValue[index + 1]);
					int low = DecodeHexDigit(encodedValue[index + 2]);
					if (high >= 0 && low >= 0)
					{
						decodedBuffer[decodedLength] = (char)((high << 4) | low);
						decodedLength++;
						index += 2;
						continue;
					}
				}

				decodedBuffer[decodedLength] = character;
				decodedLength++;
			}

			return DecodeBase32(decodedBuffer[..decodedLength]);
		}
		finally
		{
			if (decodedLength > 0)
				CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(decodedBuffer[..decodedLength]));

			if (rentedBuffer is not null)
				ArrayPool<char>.Shared.Return(rentedBuffer, clearArray: true);
		}
	}

	private static int DecodeHexDigit(char value) => Uri.IsHexDigit(value) ? Uri.FromHex(value) : -1;

	private static TotpHashAlgorithm ParseAlgorithm(ReadOnlySpan<char> algorithm)
	{
		if (algorithm.IsEmpty || algorithm.Equals("SHA1".AsSpan(), StringComparison.OrdinalIgnoreCase))
			return TotpHashAlgorithm.Sha1;
		if (algorithm.Equals("SHA256".AsSpan(), StringComparison.OrdinalIgnoreCase))
			return TotpHashAlgorithm.Sha256;
		if (algorithm.Equals("SHA512".AsSpan(), StringComparison.OrdinalIgnoreCase))
			return TotpHashAlgorithm.Sha512;
		throw new FormatException(string.Concat("Unsupported TOTP algorithm: ", algorithm.ToString()));
	}

	private static int ParsePositiveInt(ReadOnlySpan<char> value, int fallback, string name)
	{
		ReadOnlySpan<char> trimmedValue = value.Trim();
		if (trimmedValue.IsEmpty)
			return fallback;
		if (!int.TryParse(trimmedValue, NumberStyles.None, CultureInfo.InvariantCulture, out int parsed) || parsed <= 0)
			throw new FormatException(string.Format(CultureInfo.InvariantCulture, "The TOTP {0} value is invalid.", name));
		return parsed;
	}

	private static byte[] DecodeBase32(ReadOnlySpan<char> base32)
	{
		ReadOnlySpan<char> trimmedBase32 = base32.Trim();
		if (trimmedBase32.IsEmpty)
			throw new FormatException("The TOTP secret is empty.");
		char[]? rentedBuffer = null;
		Span<char> normalizedBuffer = trimmedBase32.Length <= MaxStackAllocatedSecretNormalizationChars
			? stackalloc char[trimmedBase32.Length]
			: (rentedBuffer = ArrayPool<char>.Shared.Rent(trimmedBase32.Length)).AsSpan(0, trimmedBase32.Length);
		byte[]? decodedBytes = null;
		int normalizedLength = 0;
		try
		{
			for (int index = 0; index < trimmedBase32.Length; index++)
			{
				char character = trimmedBase32[index];
				if (char.IsWhiteSpace(character) || character == '-' || character == '=')
					continue;
				normalizedBuffer[normalizedLength] = char.ToUpperInvariant(character);
				normalizedLength++;
			}
			if (normalizedLength == 0)
				throw new FormatException("The TOTP secret is empty after normalization.");
			decodedBytes = CreatePinnedByteArray(normalizedLength * 5 / 8);
			int outputOffset = 0;
			int buffer = 0;
			int bitsLeft = 0;
			for (int index = 0; index < normalizedLength; index++)
			{
				char character = normalizedBuffer[index];
				int value = Alphabet.IndexOf(character, StringComparison.Ordinal);
				if (value < 0)
					throw new FormatException(string.Format(CultureInfo.InvariantCulture, "The TOTP secret contains an invalid Base32 character: {0}", character));
				buffer = (buffer << 5) | value;
				bitsLeft += 5;
				if (bitsLeft >= 8)
				{
					bitsLeft -= 8;
					decodedBytes[outputOffset] = (byte)((buffer >> bitsLeft) & 0xFF);
					outputOffset++;
				}
			}
			if (outputOffset == 0)
				throw new FormatException("The TOTP secret did not decode to any bytes.");
			return decodedBytes;
		}
		catch
		{
			if (decodedBytes is not null)
				CryptographicOperations.ZeroMemory(decodedBytes);
			throw;
		}
		finally
		{
			if (normalizedLength > 0)
				CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(normalizedBuffer[..normalizedLength]));
			if (rentedBuffer is not null)
				ArrayPool<char>.Shared.Return(rentedBuffer, clearArray: true);
		}
	}

	private static byte[] EncodePasswordToPinnedUtf8(ReadOnlySpan<char> password)
	{
		if (password.IsEmpty)
			throw new CryptographicException("The vault password is empty.");
		int byteCount = Encoding.UTF8.GetByteCount(password);
		byte[] passwordBytes = CreatePinnedByteArray(byteCount);
		try
		{
			int bytesWritten = Encoding.UTF8.GetBytes(password, passwordBytes);
			if (bytesWritten != byteCount)
				throw new CryptographicException("The vault password was not encoded completely.");
			return passwordBytes;
		}
		catch
		{
			CryptographicOperations.ZeroMemory(passwordBytes);
			throw;
		}
	}

	private void LoadStoredTokens()
	{
		try
		{
			if (currentVaultDataKey is null)
				throw new InvalidOperationException("The vault data key is not loaded.");

			UnprotectCurrentVaultDataKey();
			try
			{
				TotpVaultEnvelope vaultEnvelope = ReadVaultEnvelope();
				List<TotpTokenItem> loadedTokens = DecryptVaultRecords(vaultEnvelope, currentVaultDataKey);
				ClearTokenSensitiveState(Tokens);
				Tokens.Clear();
				Tokens.AddRange(loadedTokens);
			}
			finally
			{
				ProtectCurrentVaultDataKey();
			}
		}
		catch (CryptographicException ex)
		{
			throw new InvalidOperationException(VaultPasswordUnlockFailureMessage, ex);
		}
	}

	private bool SaveStoredTokens(byte[]? passwordBytes, byte[]? vaultDataKeyOverride = null)
	{
		byte[]? vaultDataKey = vaultDataKeyOverride ?? currentVaultDataKey;
		if (vaultDataKey is null)
			return false;
		bool useProtectedFieldKey = vaultDataKeyOverride is null;
		try
		{
			if (useProtectedFieldKey)
				UnprotectCurrentVaultDataKey();
			try
			{
				TotpVaultEnvelope? existingVaultEnvelope = HasVaultFile ? ReadVaultEnvelope() : null;
				TotpVaultEnvelope vaultEnvelope = EncryptVaultRecords(Tokens, vaultDataKey, existingVaultEnvelope, passwordBytes);
				string json = JsonSerializer.Serialize(vaultEnvelope, TotpButtonJsonContext.Default.TotpVaultEnvelope);
				WriteVaultEnvelopeJsonAtomically(json);
				return true;
			}
			finally
			{
				if (useProtectedFieldKey)
					ProtectCurrentVaultDataKey();
			}
		}
		catch (Exception ex)
		{
			if (passwordBytes is not null)
				throw;
			MainInfoBar.WriteError(ex);
			return false;
		}
	}

	/// <summary>
	/// Writes the encrypted vault JSON to a temporary file in the same directory and then swaps it into place.
	/// This avoids truncating the live vault file before the replacement content exists.
	/// </summary>
	private static void WriteVaultEnvelopeJsonAtomically(string json)
	{
		_ = Directory.CreateDirectory(TokenStorageFolder);
		string temporaryFilePath = Path.Join(TokenStorageFolder, string.Concat("tokens.", Guid.CreateVersion7().ToString("N"), ".tmp"));
		try
		{
			File.WriteAllText(temporaryFilePath, json);
			if (File.Exists(TokenStorageFilePath))
			{
				File.Replace(temporaryFilePath, TokenStorageFilePath, null, false);
				return;
			}
			File.Move(temporaryFilePath, TokenStorageFilePath);
		}
		finally
		{
			File.Delete(temporaryFilePath);
		}
	}

	private static TotpVaultEnvelope EncryptVaultRecords(List<TotpTokenItem> tokenItems, byte[] vaultDataKey, TotpVaultEnvelope? existingVaultEnvelope, byte[]? passwordBytes)
	{
		string vaultId = existingVaultEnvelope?.VaultId ?? CreateNewVaultId();
		TotpVaultKeyWrap passwordKeyWrap = passwordBytes is not null
			? CreatePasswordVaultKeyWrap(vaultDataKey, passwordBytes)
			: existingVaultEnvelope is not null ? existingVaultEnvelope.GetPasswordKeyWrap() : throw new InvalidOperationException("A vault password is required to create the vault key wrap.");
		byte[]? recordEncryptionKey = null;
		try
		{
			recordEncryptionKey = DeriveVaultPurposeKey(vaultDataKey, VaultRecordEncryptionKeyDomain, vaultId);
			List<TotpVaultEncryptedRecord> tokenRecords = new(tokenItems.Count);
			for (int index = 0; index < tokenItems.Count; index++)
			{
				TotpTokenItem tokenItem = tokenItems[index];
				byte[] plaintextRecord = SerializeTokenRecordBinary(tokenItem);
				byte[] recordNonce = new byte[AesGcmNonceSizeInBytes];
				byte[] recordTag = new byte[AesGcmTagSizeInBytes];
				byte[] recordCiphertext = new byte[plaintextRecord.Length];
				byte[]? recordAssociatedDataHash = null;
				RandomNumberGenerator.Fill(recordNonce);
				try
				{
					recordAssociatedDataHash = CreateVaultRecordAssociatedDataHash(vaultId, index, recordNonce);
					using AesGcm aesGcm = new(recordEncryptionKey, AesGcmTagSizeInBytes);
					aesGcm.Encrypt(recordNonce, plaintextRecord, recordCiphertext, recordTag, recordAssociatedDataHash);
					tokenRecords.Add(new(nonce: Convert.ToBase64String(recordNonce), tag: Convert.ToBase64String(recordTag), ciphertext: Convert.ToBase64String(recordCiphertext)));
				}
				finally
				{
					CryptographicOperations.ZeroMemory(plaintextRecord);
					CryptographicOperations.ZeroMemory(recordCiphertext);
					if (recordAssociatedDataHash is not null)
						CryptographicOperations.ZeroMemory(recordAssociatedDataHash);
					CryptographicOperations.ZeroMemory(recordNonce);
					CryptographicOperations.ZeroMemory(recordTag);
				}
			}
			return new(
				version: VaultVersion,
				vaultId: vaultId,
				purpose: VaultPurpose,
				encryption: VaultEncryptionAlgorithm,
				kdf: VaultKdfAlgorithm,
				kdfIterations: PasswordKdfIterations,
				passwordKdfSalt: passwordKeyWrap.KdfSalt,
				passwordWrapNonce: passwordKeyWrap.Nonce,
				passwordWrapTag: passwordKeyWrap.Tag,
				passwordWrappedVaultKey: passwordKeyWrap.WrappedVaultKey,
				tokenRecords: tokenRecords);
		}
		finally
		{
			if (recordEncryptionKey is not null)
				CryptographicOperations.ZeroMemory(recordEncryptionKey);
		}
	}

	private static List<TotpTokenItem> DecryptVaultRecords(TotpVaultEnvelope vaultEnvelope, byte[] vaultDataKey)
	{
		ValidateVaultEnvelope(vaultEnvelope);
		byte[] passwordKdfSalt = Convert.FromBase64String(vaultEnvelope.PasswordKdfSalt);
		byte[] passwordWrapNonce = Convert.FromBase64String(vaultEnvelope.PasswordWrapNonce);
		byte[] passwordWrapTag = Convert.FromBase64String(vaultEnvelope.PasswordWrapTag);
		byte[] passwordWrappedVaultKey = Convert.FromBase64String(vaultEnvelope.PasswordWrappedVaultKey);
		byte[]? recordEncryptionKey = null;
		try
		{
			ValidateVaultEnvelopeCryptographicFields(vaultEnvelope, passwordKdfSalt, passwordWrapNonce, passwordWrapTag, passwordWrappedVaultKey);
			recordEncryptionKey = DeriveVaultPurposeKey(vaultDataKey, VaultRecordEncryptionKeyDomain, vaultEnvelope.VaultId);
			List<TotpTokenItem> tokenItems = new(vaultEnvelope.TokenRecords.Count);
			for (int index = 0; index < vaultEnvelope.TokenRecords.Count; index++)
			{
				TotpVaultEncryptedRecord record = vaultEnvelope.TokenRecords[index];
				byte[] recordNonce = Convert.FromBase64String(record.Nonce);
				byte[] recordTag = Convert.FromBase64String(record.Tag);
				byte[] recordCiphertext = Convert.FromBase64String(record.Ciphertext);
				byte[] plaintextRecord = CreatePinnedByteArray(recordCiphertext.Length);
				byte[]? recordAssociatedDataHash = null;
				try
				{
					ValidateVaultRecordCryptographicFields(recordNonce, recordTag, recordCiphertext);
					recordAssociatedDataHash = CreateVaultRecordAssociatedDataHash(vaultEnvelope.VaultId, index, recordNonce);
					using AesGcm aesGcm = new(recordEncryptionKey, AesGcmTagSizeInBytes);
					aesGcm.Decrypt(recordNonce, recordCiphertext, recordTag, plaintextRecord, recordAssociatedDataHash);
					DeserializeTokenRecordBinary(
						plaintextRecord,
						out string id,
						out string displayName,
						out TotpHashAlgorithm algorithm,
						out int digits,
						out int period,
						out ReadOnlySpan<byte> secretBytes,
						out string notes);
					if (ContainsEquivalentSecret(tokenItems, secretBytes))
						continue;

					tokenItems.Add(CreateTokenItemFromSecretBytes(id, displayName, algorithm, digits, period, secretBytes, notes));
				}
				finally
				{
					CryptographicOperations.ZeroMemory(plaintextRecord);
					CryptographicOperations.ZeroMemory(recordNonce);
					CryptographicOperations.ZeroMemory(recordTag);
					CryptographicOperations.ZeroMemory(recordCiphertext);
					if (recordAssociatedDataHash is not null)
						CryptographicOperations.ZeroMemory(recordAssociatedDataHash);
				}
			}
			return tokenItems;
		}
		finally
		{
			CryptographicOperations.ZeroMemory(passwordKdfSalt);
			CryptographicOperations.ZeroMemory(passwordWrapNonce);
			CryptographicOperations.ZeroMemory(passwordWrapTag);
			CryptographicOperations.ZeroMemory(passwordWrappedVaultKey);
			if (recordEncryptionKey is not null)
				CryptographicOperations.ZeroMemory(recordEncryptionKey);
		}
	}

	private static TotpVaultKeyWrap CreatePasswordVaultKeyWrap(byte[] vaultDataKey, ReadOnlySpan<byte> passwordBytes)
	{
		byte[] passwordKdfSalt = new byte[SaltSizeInBytes];
		byte[] wrapNonce = new byte[AesGcmNonceSizeInBytes];
		byte[] wrapTag = new byte[AesGcmTagSizeInBytes];
		byte[] wrappedVaultKey = new byte[vaultDataKey.Length];
		byte[]? wrappingKey = null;
		byte[]? associatedDataHash = null;
		RandomNumberGenerator.Fill(passwordKdfSalt);
		RandomNumberGenerator.Fill(wrapNonce);
		try
		{
			wrappingKey = CreatePinnedByteArray(AesKeySizeInBytes);
			Rfc2898DeriveBytes.Pbkdf2(passwordBytes, passwordKdfSalt, wrappingKey, PasswordKdfIterations, HashAlgorithmName.SHA3_512);
			associatedDataHash = CreateVaultAssociatedDataHash(VaultKeyWrapAssociatedDataDomain, VaultVersion, string.Empty, VaultPurpose, VaultEncryptionAlgorithm, VaultKdfAlgorithm, PasswordKdfIterations, passwordKdfSalt, wrapNonce, [], [], []);
			using AesGcm aesGcm = new(wrappingKey, AesGcmTagSizeInBytes);
			aesGcm.Encrypt(wrapNonce, vaultDataKey, wrappedVaultKey, wrapTag, associatedDataHash);
			return new(kdfSalt: Convert.ToBase64String(passwordKdfSalt), nonce: Convert.ToBase64String(wrapNonce), tag: Convert.ToBase64String(wrapTag), wrappedVaultKey: Convert.ToBase64String(wrappedVaultKey));
		}
		finally
		{
			CryptographicOperations.ZeroMemory(passwordKdfSalt);
			CryptographicOperations.ZeroMemory(wrapNonce);
			CryptographicOperations.ZeroMemory(wrapTag);
			CryptographicOperations.ZeroMemory(wrappedVaultKey);
			if (wrappingKey is not null)
				CryptographicOperations.ZeroMemory(wrappingKey);
			if (associatedDataHash is not null)
				CryptographicOperations.ZeroMemory(associatedDataHash);
		}
	}

	private static byte[] UnwrapVaultDataKeyWithPassword(TotpVaultEnvelope vaultEnvelope, ReadOnlySpan<byte> passwordBytes)
	{
		ValidateVaultEnvelope(vaultEnvelope);
		byte[] passwordKdfSalt = Convert.FromBase64String(vaultEnvelope.PasswordKdfSalt);
		byte[] wrapNonce = Convert.FromBase64String(vaultEnvelope.PasswordWrapNonce);
		byte[] wrapTag = Convert.FromBase64String(vaultEnvelope.PasswordWrapTag);
		byte[] wrappedVaultKey = Convert.FromBase64String(vaultEnvelope.PasswordWrappedVaultKey);
		byte[] vaultDataKey = CreatePinnedByteArray(AesKeySizeInBytes);
		byte[]? wrappingKey = null;
		byte[]? associatedDataHash = null;
		try
		{
			ValidateVaultEnvelopeCryptographicFields(vaultEnvelope, passwordKdfSalt, wrapNonce, wrapTag, wrappedVaultKey);
			wrappingKey = CreatePinnedByteArray(AesKeySizeInBytes);
			Rfc2898DeriveBytes.Pbkdf2(passwordBytes, passwordKdfSalt, wrappingKey, vaultEnvelope.KdfIterations, HashAlgorithmName.SHA3_512);
			associatedDataHash = CreateVaultAssociatedDataHash(VaultKeyWrapAssociatedDataDomain, vaultEnvelope.Version, string.Empty, vaultEnvelope.Purpose, VaultEncryptionAlgorithm, vaultEnvelope.Kdf, vaultEnvelope.KdfIterations, passwordKdfSalt, wrapNonce, [], [], []);
			using AesGcm aesGcm = new(wrappingKey, AesGcmTagSizeInBytes);
			aesGcm.Decrypt(wrapNonce, wrappedVaultKey, wrapTag, vaultDataKey, associatedDataHash);
			return vaultDataKey;
		}
		catch
		{
			CryptographicOperations.ZeroMemory(vaultDataKey);
			throw;
		}
		finally
		{
			CryptographicOperations.ZeroMemory(passwordKdfSalt);
			CryptographicOperations.ZeroMemory(wrapNonce);
			CryptographicOperations.ZeroMemory(wrapTag);
			CryptographicOperations.ZeroMemory(wrappedVaultKey);
			if (wrappingKey is not null)
				CryptographicOperations.ZeroMemory(wrappingKey);
			if (associatedDataHash is not null)
				CryptographicOperations.ZeroMemory(associatedDataHash);
		}
	}

	private static byte[] CreateVaultAssociatedDataHash(string domain, int version, string vaultId, string purpose, string encryption, string kdf, int kdfIterations, ReadOnlySpan<byte> firstBinaryField, ReadOnlySpan<byte> secondBinaryField, ReadOnlySpan<byte> thirdBinaryField, ReadOnlySpan<byte> fourthBinaryField, ReadOnlySpan<byte> fifthBinaryField)
	{
		int domainByteCount = Encoding.UTF8.GetByteCount(domain);
		int vaultIdByteCount = Encoding.UTF8.GetByteCount(vaultId);
		int purposeByteCount = Encoding.UTF8.GetByteCount(purpose);
		int encryptionByteCount = Encoding.UTF8.GetByteCount(encryption);
		int kdfByteCount = Encoding.UTF8.GetByteCount(kdf);
		int metadataLength = GetLengthPrefixedFieldSize(domainByteCount) + (sizeof(int) * 6) + GetLengthPrefixedFieldSize(vaultIdByteCount) + GetLengthPrefixedFieldSize(purposeByteCount) + GetLengthPrefixedFieldSize(encryptionByteCount) + GetLengthPrefixedFieldSize(kdfByteCount) + GetLengthPrefixedFieldSize(firstBinaryField.Length) + GetLengthPrefixedFieldSize(secondBinaryField.Length) + GetLengthPrefixedFieldSize(thirdBinaryField.Length) + GetLengthPrefixedFieldSize(fourthBinaryField.Length) + GetLengthPrefixedFieldSize(fifthBinaryField.Length);
		byte[] metadata = new byte[metadataLength];
		int offset = 0;
		WriteLengthPrefixedUtf8(metadata, ref offset, domain, domainByteCount);
		WriteInt32LittleEndian(metadata, ref offset, version);
		WriteInt32LittleEndian(metadata, ref offset, AesKeySizeInBytes);
		WriteInt32LittleEndian(metadata, ref offset, AesGcmNonceSizeInBytes);
		WriteInt32LittleEndian(metadata, ref offset, AesGcmTagSizeInBytes);
		WriteInt32LittleEndian(metadata, ref offset, SaltSizeInBytes);
		WriteInt32LittleEndian(metadata, ref offset, kdfIterations);
		WriteLengthPrefixedUtf8(metadata, ref offset, vaultId, vaultIdByteCount);
		WriteLengthPrefixedUtf8(metadata, ref offset, purpose, purposeByteCount);
		WriteLengthPrefixedUtf8(metadata, ref offset, encryption, encryptionByteCount);
		WriteLengthPrefixedUtf8(metadata, ref offset, kdf, kdfByteCount);
		WriteLengthPrefixedBytes(metadata, ref offset, firstBinaryField);
		WriteLengthPrefixedBytes(metadata, ref offset, secondBinaryField);
		WriteLengthPrefixedBytes(metadata, ref offset, thirdBinaryField);
		WriteLengthPrefixedBytes(metadata, ref offset, fourthBinaryField);
		WriteLengthPrefixedBytes(metadata, ref offset, fifthBinaryField);
		if (offset != metadata.Length)
			throw new CryptographicException("The TOTP vault associated data metadata was not written completely.");
		try
		{
			return SHA3_512.HashData(metadata);
		}
		finally
		{
			CryptographicOperations.ZeroMemory(metadata);
		}
	}

	private static string CreateNewVaultId()
	{
		byte[] vaultIdBytes = new byte[VaultIdSizeInBytes];
		try
		{
			RandomNumberGenerator.Fill(vaultIdBytes);
			return Convert.ToBase64String(vaultIdBytes);
		}
		finally
		{
			CryptographicOperations.ZeroMemory(vaultIdBytes);
		}
	}

	private static byte[] DeriveVaultPurposeKey(ReadOnlySpan<byte> vaultRootKey, string purposeDomain, string vaultId)
	{
		byte[] info = CreateVaultPurposeInfoHash(purposeDomain, vaultId);
		byte[] derivedKey = CreatePinnedByteArray(AesKeySizeInBytes);
		try
		{
			HKDF.DeriveKey(HashAlgorithmName.SHA3_512, vaultRootKey, derivedKey, [], info);
			return derivedKey;
		}
		finally
		{
			CryptographicOperations.ZeroMemory(info);
		}
	}

	private static byte[] CreateVaultPurposeInfoHash(string purposeDomain, string vaultId)
	{
		int purposeDomainByteCount = Encoding.UTF8.GetByteCount(purposeDomain);
		int vaultIdByteCount = Encoding.UTF8.GetByteCount(vaultId);
		int metadataLength = GetLengthPrefixedFieldSize(purposeDomainByteCount) + sizeof(int) + GetLengthPrefixedFieldSize(vaultIdByteCount);
		byte[] metadata = new byte[metadataLength];
		int offset = 0;
		WriteLengthPrefixedUtf8(metadata, ref offset, purposeDomain, purposeDomainByteCount);
		WriteInt32LittleEndian(metadata, ref offset, VaultVersion);
		WriteLengthPrefixedUtf8(metadata, ref offset, vaultId, vaultIdByteCount);
		try
		{
			return SHA3_512.HashData(metadata);
		}
		finally
		{
			CryptographicOperations.ZeroMemory(metadata);
		}
	}

	private static int GetLengthPrefixedFieldSize(int byteCount) => sizeof(int) + byteCount;

	private static void WriteInt32LittleEndian(byte[] destination, ref int offset, int value)
	{
		BinaryPrimitives.WriteInt32LittleEndian(destination.AsSpan(offset, sizeof(int)), value);
		offset += sizeof(int);
	}

	private static void WriteLengthPrefixedUtf8(byte[] destination, ref int offset, string value, int byteCount)
	{
		WriteInt32LittleEndian(destination, ref offset, byteCount);
		int bytesWritten = Encoding.UTF8.GetBytes(value, destination.AsSpan(offset, byteCount));
		if (bytesWritten != byteCount)
			throw new CryptographicException("The TOTP vault associated data metadata string was not written completely.");
		offset += byteCount;
	}

	private static void WriteLengthPrefixedBytes(byte[] destination, ref int offset, ReadOnlySpan<byte> value)
	{
		WriteInt32LittleEndian(destination, ref offset, value.Length);
		value.CopyTo(destination.AsSpan(offset, value.Length));
		offset += value.Length;
	}
	private static byte[] SerializeTokenRecordBinary(TotpTokenItem tokenItem)
	{
		int payloadLength = GetTokenRecordBinaryLength(tokenItem);
		byte[] payload = CreatePinnedByteArray(payloadLength);
		int offset = 0;
		int idByteCount = Encoding.UTF8.GetByteCount(tokenItem.Id);
		WriteLengthPrefixedUtf8(payload, ref offset, tokenItem.Id, idByteCount);
		int displayNameByteCount = Encoding.UTF8.GetByteCount(tokenItem.DisplayName);
		WriteLengthPrefixedUtf8(payload, ref offset, tokenItem.DisplayName, displayNameByteCount);
		WriteInt32LittleEndian(payload, ref offset, (int)tokenItem.Algorithm);
		WriteInt32LittleEndian(payload, ref offset, tokenItem.TokenDigits);
		WriteInt32LittleEndian(payload, ref offset, tokenItem.TokenPeriod);
		WriteInt32LittleEndian(payload, ref offset, tokenItem.SecretLength);
		tokenItem.CopySecretBytesTo(payload.AsSpan(offset, tokenItem.SecretLength));
		offset += tokenItem.SecretLength;
		int notesByteCount = Encoding.UTF8.GetByteCount(tokenItem.Notes);
		WriteLengthPrefixedUtf8(payload, ref offset, tokenItem.Notes, notesByteCount);
		if (offset != payload.Length)
			throw new CryptographicException("The TOTP vault token record was not written completely.");
		return payload;
	}

	private static int GetTokenRecordBinaryLength(TotpTokenItem tokenItem)
	{
		int payloadLength = 0;
		payloadLength = checked(payloadLength + GetLengthPrefixedFieldSize(Encoding.UTF8.GetByteCount(tokenItem.Id)));
		payloadLength = checked(payloadLength + GetLengthPrefixedFieldSize(Encoding.UTF8.GetByteCount(tokenItem.DisplayName)));
		payloadLength = checked(payloadLength + sizeof(int) + sizeof(int) + sizeof(int));
		payloadLength = checked(payloadLength + GetLengthPrefixedFieldSize(tokenItem.SecretLength));
		payloadLength = checked(payloadLength + GetLengthPrefixedFieldSize(Encoding.UTF8.GetByteCount(tokenItem.Notes)));
		return payloadLength;
	}

	/// <summary>
	/// Deserializes the plaintext token record and returns a read-only secret span over the existing decrypted record buffer.
	/// This avoids allocating a second managed plaintext copy of the secret before it is moved into the protected pinned buffer.
	/// </summary>
	private static void DeserializeTokenRecordBinary(ReadOnlySpan<byte> plaintextRecord, out string id, out string displayName, out TotpHashAlgorithm algorithm, out int digits, out int period, out ReadOnlySpan<byte> secretBytes, out string notes)
	{
		int offset = 0;
		id = ReadLengthPrefixedUtf8(plaintextRecord, ref offset);
		displayName = ReadLengthPrefixedUtf8(plaintextRecord, ref offset);
		algorithm = ParseSerializedAlgorithm(ReadInt32LittleEndian(plaintextRecord, ref offset));
		digits = ReadInt32LittleEndian(plaintextRecord, ref offset);
		period = ReadInt32LittleEndian(plaintextRecord, ref offset);
		ReadLengthPrefixedByteRange(plaintextRecord, ref offset, out int secretOffset, out int secretLength);
		secretBytes = plaintextRecord.Slice(secretOffset, secretLength);
		notes = ReadLengthPrefixedUtf8(plaintextRecord, ref offset);
		if (offset != plaintextRecord.Length)
			throw new InvalidDataException("The TOTP vault token record contains unexpected trailing data.");
	}

	private static byte[] CreateVaultRecordAssociatedDataHash(string vaultId, int recordIndex, ReadOnlySpan<byte> recordNonce)
	{
		int domainByteCount = Encoding.UTF8.GetByteCount(VaultRecordAssociatedDataDomain);
		int vaultIdByteCount = Encoding.UTF8.GetByteCount(vaultId);
		int metadataLength = GetLengthPrefixedFieldSize(domainByteCount) + sizeof(int) + sizeof(int) + GetLengthPrefixedFieldSize(vaultIdByteCount) + GetLengthPrefixedFieldSize(recordNonce.Length);
		byte[] metadata = new byte[metadataLength];
		int offset = 0;
		WriteLengthPrefixedUtf8(metadata, ref offset, VaultRecordAssociatedDataDomain, domainByteCount);
		WriteInt32LittleEndian(metadata, ref offset, VaultVersion);
		WriteInt32LittleEndian(metadata, ref offset, recordIndex);
		WriteLengthPrefixedUtf8(metadata, ref offset, vaultId, vaultIdByteCount);
		WriteLengthPrefixedBytes(metadata, ref offset, recordNonce);
		if (offset != metadata.Length)
			throw new CryptographicException("The TOTP vault record associated data metadata was not written completely.");
		try
		{
			return SHA3_512.HashData(metadata);
		}
		finally
		{
			CryptographicOperations.ZeroMemory(metadata);
		}
	}

	private static void ValidateVaultRecordCryptographicFields(byte[] recordNonce, byte[] recordTag, byte[] recordCiphertext)
	{
		if (recordNonce.Length != AesGcmNonceSizeInBytes ||
			recordTag.Length != AesGcmTagSizeInBytes ||
			recordCiphertext.Length == 0)
			throw new InvalidDataException("The TOTP vault token record cryptographic parameters are not supported.");
	}

	private static TotpHashAlgorithm ParseSerializedAlgorithm(int serializedValue) => serializedValue switch
	{
		(int)TotpHashAlgorithm.Sha1 => TotpHashAlgorithm.Sha1,
		(int)TotpHashAlgorithm.Sha256 => TotpHashAlgorithm.Sha256,
		(int)TotpHashAlgorithm.Sha512 => TotpHashAlgorithm.Sha512,
		_ => throw new InvalidDataException("The TOTP vault plaintext payload contains an unsupported TOTP algorithm.")
	};
	private static int ReadInt32LittleEndian(ReadOnlySpan<byte> source, ref int offset)
	{
		EnsurePayloadHasAvailableBytes(source, offset, sizeof(int));
		int value = BinaryPrimitives.ReadInt32LittleEndian(source.Slice(offset, sizeof(int)));
		offset += sizeof(int);
		return value;
	}
	private static string ReadLengthPrefixedUtf8(ReadOnlySpan<byte> source, ref int offset)
	{
		int byteCount = ReadInt32LittleEndian(source, ref offset);
		if (byteCount < 0)
			throw new InvalidDataException("The TOTP vault plaintext payload contains a negative string length.");
		EnsurePayloadHasAvailableBytes(source, offset, byteCount);
		string value = Encoding.UTF8.GetString(source.Slice(offset, byteCount));
		offset += byteCount;
		return value;
	}
	private static void ReadLengthPrefixedByteRange(ReadOnlySpan<byte> source, ref int offset, out int valueOffset, out int valueLength)
	{
		valueLength = ReadInt32LittleEndian(source, ref offset);
		if (valueLength <= 0)
			throw new InvalidDataException("The TOTP vault plaintext payload contains an invalid secret length.");
		EnsurePayloadHasAvailableBytes(source, offset, valueLength);
		valueOffset = offset;
		offset += valueLength;
	}
	private static void EnsurePayloadHasAvailableBytes(ReadOnlySpan<byte> source, int offset, int requiredLength)
	{
		if (requiredLength < 0 || offset < 0 || offset > source.Length || requiredLength > (source.Length - offset))
			throw new InvalidDataException("The TOTP vault plaintext payload is truncated or malformed.");
	}

	private static void ValidateVaultEnvelope(TotpVaultEnvelope vaultEnvelope)
	{
		ArgumentNullException.ThrowIfNull(vaultEnvelope);
		ArgumentNullException.ThrowIfNull(vaultEnvelope.TokenRecords);
		byte[] vaultIdBytes = Convert.FromBase64String(vaultEnvelope.VaultId);
		try
		{
			if (vaultEnvelope.Version != VaultVersion ||
				vaultIdBytes.Length != VaultIdSizeInBytes ||
				!string.Equals(vaultEnvelope.Purpose, VaultPurpose, StringComparison.OrdinalIgnoreCase) ||
				!string.Equals(vaultEnvelope.Encryption, VaultEncryptionAlgorithm, StringComparison.OrdinalIgnoreCase) ||
				!string.Equals(vaultEnvelope.Kdf, VaultKdfAlgorithm, StringComparison.OrdinalIgnoreCase))
				throw new InvalidDataException("The TOTP vault format is not supported.");
		}
		finally
		{
			CryptographicOperations.ZeroMemory(vaultIdBytes);
		}
	}

	private static void ValidateVaultEnvelopeCryptographicFields(TotpVaultEnvelope vaultEnvelope, byte[] passwordKdfSalt, byte[] passwordWrapNonce, byte[] passwordWrapTag, byte[] passwordWrappedVaultKey)
	{
		if (vaultEnvelope.KdfIterations != PasswordKdfIterations ||
			passwordKdfSalt.Length != SaltSizeInBytes ||
			passwordWrapNonce.Length != AesGcmNonceSizeInBytes ||
			passwordWrapTag.Length != AesGcmTagSizeInBytes ||
			passwordWrappedVaultKey.Length != AesKeySizeInBytes)
			throw new InvalidDataException("The TOTP vault cryptographic parameters are not supported.");
	}

	private static TotpVaultEnvelope ReadVaultEnvelope() => JsonSerializer.Deserialize(File.ReadAllText(TokenStorageFilePath), TotpButtonJsonContext.Default.TotpVaultEnvelope) ?? throw new InvalidDataException("The TOTP vault file is not valid.");

	private static string GetDefaultPasswordStrengthText() => string.Concat("Password requirements: at least ", MinimumVaultPasswordLength.ToString(CultureInfo.InvariantCulture), " characters with lowercase, uppercase, and number. Spaces and symbols improve strength.");

	private static bool TryValidateVaultPassword(ReadOnlySpan<char> password, out string validationMessage)
	{
		PasswordStrengthEvaluation evaluation = EvaluatePasswordStrength(password);
		if (evaluation.HasMinimumLength && evaluation.HasLowercase && evaluation.HasUppercase && evaluation.HasDigit)
		{
			validationMessage = string.Empty;
			return true;
		}
		List<string> missingRequirements = new(capacity: 4);
		if (!evaluation.HasMinimumLength)
			missingRequirements.Add(string.Concat(MinimumVaultPasswordLength.ToString(CultureInfo.InvariantCulture), "+ characters"));
		if (!evaluation.HasLowercase)
			missingRequirements.Add("a lowercase letter");
		if (!evaluation.HasUppercase)
			missingRequirements.Add("an uppercase letter");
		if (!evaluation.HasDigit)
			missingRequirements.Add("a number");
		validationMessage = string.Concat("The vault password must include ", FormatPasswordRuleList(missingRequirements), ". Spaces and symbols are optional bonuses.");
		return false;
	}

	private void UpdateNewVaultPasswordStrengthState(ReadOnlySpan<char> password)
	{
		PasswordStrengthEvaluation evaluation = EvaluatePasswordStrength(password);
		NewVaultPasswordStrengthBrush = new SolidColorBrush(evaluation.DisplayColor);
		NewVaultPasswordStrengthValue = evaluation.Score;
		NewVaultPasswordStrengthText = evaluation.SummaryText;
	}

	private void ResetNewVaultPasswordStrengthState()
	{
		NewVaultPasswordStrengthBrush = new SolidColorBrush(PasswordStrengthNeutralColor);
		NewVaultPasswordStrengthValue = 0D;
		NewVaultPasswordStrengthText = GetDefaultPasswordStrengthText();
	}

	private static void UpdatePasswordStrengthPresentation(ProgressBar progressBar, TextBlock textBlock, ReadOnlySpan<char> password)
	{
		PasswordStrengthEvaluation evaluation = EvaluatePasswordStrength(password);
		SolidColorBrush strengthBrush = new(evaluation.DisplayColor);
		textBlock.Text = evaluation.SummaryText;
		progressBar.Foreground = strengthBrush;
		progressBar.Value = evaluation.Score;
	}

	private static PasswordStrengthEvaluation EvaluatePasswordStrength(ReadOnlySpan<char> password)
	{
		if (password.IsEmpty)
			return new(score: 0, hasMinimumLength: false, hasLowercase: false, hasUppercase: false, hasDigit: false, hasSpace: false, hasSymbol: false, summaryText: GetDefaultPasswordStrengthText(), displayColor: PasswordStrengthNeutralColor);
		bool hasLowercase = false;
		bool hasUppercase = false;
		bool hasDigit = false;
		bool hasSpace = false;
		bool hasSymbol = false;
		for (int index = 0; index < password.Length; index++)
		{
			char currentCharacter = password[index];
			if (char.IsLower(currentCharacter))
			{
				hasLowercase = true;
				continue;
			}
			if (char.IsUpper(currentCharacter))
			{
				hasUppercase = true;
				continue;
			}
			if (char.IsDigit(currentCharacter))
			{
				hasDigit = true;
				continue;
			}
			if (char.IsWhiteSpace(currentCharacter))
			{
				hasSpace = true;
				continue;
			}
			hasSymbol = true;
		}
		bool hasMinimumLength = password.Length >= MinimumVaultPasswordLength;
		int score = 0;
		if (hasMinimumLength)
			score++;
		if (hasLowercase)
			score++;
		if (hasUppercase)
			score++;
		if (hasDigit)
			score++;
		if (hasSymbol)
			score++;
		if (hasSpace)
			score++;
		List<string> missingRequired = new(capacity: 4);
		if (!hasMinimumLength)
			missingRequired.Add(string.Concat(MinimumVaultPasswordLength.ToString(CultureInfo.InvariantCulture), "+ characters"));
		if (!hasLowercase)
			missingRequired.Add("lowercase");
		if (!hasUppercase)
			missingRequired.Add("uppercase");
		if (!hasDigit)
			missingRequired.Add("number");
		List<string> missingBonus = new(capacity: 2);
		if (!hasSymbol)
			missingBonus.Add("symbol");
		if (!hasSpace)
			missingBonus.Add("space");
		string strengthLabel = score switch
		{
			<= 1 => "Weak",
			2 => "Fair",
			3 => "Good",
			4 => "Strong",
			5 => "Very strong",
			_ => "Excellent"
		};
		Color displayColor = score switch
		{
			<= 1 => PasswordStrengthWeakColor,
			2 => PasswordStrengthFairColor,
			3 => PasswordStrengthGoodColor,
			4 => PasswordStrengthStrongColor,
			5 => PasswordStrengthVeryStrongColor,
			_ => PasswordStrengthExcellentColor
		};
		string summaryText = missingRequired.Count > 0
			? string.Concat("Password strength: ", strengthLabel, " (", score.ToString(CultureInfo.InvariantCulture), "/", PasswordStrengthMaximumScore.ToString(CultureInfo.InvariantCulture), "). Required: add ", FormatPasswordRuleList(missingRequired), ". Bonus: add ", FormatPasswordRuleList(missingBonus), " for extra strength.")
			: missingBonus.Count > 0
				? string.Concat("Password strength: ", strengthLabel, " (", score.ToString(CultureInfo.InvariantCulture), "/", PasswordStrengthMaximumScore.ToString(CultureInfo.InvariantCulture), "). Meets all required rules. Bonus: add ", FormatPasswordRuleList(missingBonus), " for extra strength.")
				: string.Concat("Password strength: ", strengthLabel, " (", score.ToString(CultureInfo.InvariantCulture), "/", PasswordStrengthMaximumScore.ToString(CultureInfo.InvariantCulture), "). Meets all required rules and includes both space and symbol.");
		return new(score: score, hasMinimumLength: hasMinimumLength, hasLowercase: hasLowercase, hasUppercase: hasUppercase, hasDigit: hasDigit, hasSpace: hasSpace, hasSymbol: hasSymbol, summaryText: summaryText, displayColor: displayColor);
	}

	private static string FormatPasswordRuleList(List<string> items) => items.Count switch
	{
		0 => "nothing",
		1 => items[0],
		2 => string.Concat(items[0], " and ", items[1]),
		_ => string.Concat(string.Join(", ", items.Take(items.Count - 1)), ", and ", items[^1])
	};

	private void ApplyLockedState()
	{
		ClearTokenSensitiveState(Tokens);
		Tokens.Clear();
		FilteredTokens.Clear();
		if (currentVaultDataKey is not null)
		{
			CryptographicOperations.ZeroMemory(currentVaultDataKey);
			currentVaultDataKey = null;
		}

		lastVaultInteractionUtc = null;
		SearchText = string.Empty;
		_ = (PasteInputTextBox?.Text = string.Empty);
		IsVaultUnlocked = false;
		RaiseVaultStateProperties();
		refreshTimer?.Stop();
	}

	private void AnimateVaultVisualState()
	{
		double targetContentOpacity = IsVaultUnlocked ? 1D : LockedContentOpacityValue;
		double targetOverlayOpacity = IsVaultUnlocked ? 0D : 1D;
		AnimateElementOpacity(VaultContentPanel, targetContentOpacity);
		AnimateElementOpacity(VaultLockedOverlay, targetOverlayOpacity);
	}

	private static void AnimateElementOpacity(UIElement element, double targetOpacity)
	{
		DoubleAnimation opacityAnimation = new()
		{
			To = targetOpacity,
			Duration = new Duration(TimeSpan.FromMilliseconds(500)),
			EnableDependentAnimation = true,
			EasingFunction = new CubicEase
			{
				EasingMode = EasingMode.EaseOut
			}
		};
		Storyboard storyboard = new();
		Storyboard.SetTarget(opacityAnimation, element);
		Storyboard.SetTargetProperty(opacityAnimation, nameof(Opacity));
		storyboard.Children.Add(opacityAnimation);
		storyboard.Begin();
	}

	private void RaiseVaultStateProperties()
	{
		RaisePropertyChanged(nameof(IsVaultUnlocked));
		RaisePropertyChanged(nameof(IsAddButtonEnabled));
		RaisePropertyChanged(nameof(IsCurrentTotpInputAddEnabled));
		RaisePropertyChanged(nameof(TokenListVisibility));
		RaisePropertyChanged(nameof(IsChangeVaultPasswordButtonEnabled));
		RaisePropertyChanged(nameof(HasVaultFile));
		RaisePropertyChanged(nameof(VaultLockedOverlayHitTestVisible));
		RaisePropertyChanged(nameof(VaultContentIsHitTestVisible));
		RaisePropertyChanged(nameof(CreateVaultSectionVisibility));
		RaisePropertyChanged(nameof(UnlockVaultSectionVisibility));
		RaisePropertyChanged(nameof(DeleteVaultMenuItemVisibility));
		RaisePropertyChanged(nameof(LockedStateCardTitle));
		RaisePropertyChanged(nameof(LockedBackgroundContentPadding));
		AnimateVaultVisualState();
	}

	private void WriteLockedStateGuidance()
	{
		if (HasVaultFile)
			LockedInfoBar.WriteInfo("Unlock the existing portable TOTP vault with its password. You can also open the vault files directory or delete the current vault from the menu.");
		else
			LockedInfoBar.WriteInfo("No portable TOTP vault exists yet. Create a new encrypted vault with a password, or import an existing vault JSON file.");
	}

	private void ClearPasswordInputs()
	{
		NewVaultPasswordBox.Password = string.Empty;
		ConfirmNewVaultPasswordBox.Password = string.Empty;
		UnlockVaultPasswordBox.Password = string.Empty;
		ResetNewVaultPasswordStrengthState();
		ClearManualTotpEntryInputs();
	}

	private static string CreateDisplayLabel(string issuer, string accountName)
	{
		if (!string.IsNullOrWhiteSpace(issuer) && !string.IsNullOrWhiteSpace(accountName))
			return string.Concat(issuer, ": ", accountName);

		if (!string.IsNullOrWhiteSpace(accountName))
			return accountName;

		if (!string.IsNullOrWhiteSpace(issuer))
			return issuer;

		return "TOTP";
	}
	private static TotpTokenItem CreateTokenItemFromSecretBytes(string id, string displayName, TotpHashAlgorithm algorithm, int digits, int period, ReadOnlySpan<byte> secretBytes, string notes)
	{
		if (secretBytes.IsEmpty)
			throw new CryptographicException("The TOTP secret did not decode to any bytes.");
		byte[] protectedSecretBytes = CreatePaddedProtectedSecretBuffer(secretBytes);
		return new(id, displayName, algorithm, digits, period, protectedSecretBytes, secretBytes.Length, notes);
	}

	private bool ContainsEquivalentSecret(ReadOnlySpan<byte> candidateSecretBytes) => ContainsEquivalentSecret(Tokens, candidateSecretBytes);

	private static bool ContainsEquivalentSecret(List<TotpTokenItem> tokenItems, ReadOnlySpan<byte> candidateSecretBytes)
	{
		foreach (TotpTokenItem tokenItem in CollectionsMarshal.AsSpan(tokenItems))
		{
			if (tokenItem.SecretEquals(candidateSecretBytes))
				return true;
		}
		return false;
	}

	private static void ClearTokenSensitiveState(List<TotpTokenItem> tokenItems)
	{
		foreach (TotpTokenItem tokenItem in CollectionsMarshal.AsSpan(tokenItems))
			tokenItem.ClearSensitiveState();
	}

	private sealed class PasswordStrengthEvaluation(int score, bool hasMinimumLength, bool hasLowercase, bool hasUppercase, bool hasDigit, bool hasSpace, bool hasSymbol, string summaryText, Color displayColor)
	{
		internal int Score => score;
		internal bool HasMinimumLength => hasMinimumLength;
		internal bool HasLowercase => hasLowercase;
		internal bool HasUppercase => hasUppercase;
		internal bool HasDigit => hasDigit;
		internal bool HasSpace => hasSpace;
		internal bool HasSymbol => hasSymbol;
		internal string SummaryText => summaryText;
		internal Color DisplayColor => displayColor;
	}

	private sealed class TotpDefinition(string issuer, string accountName, TotpHashAlgorithm algorithm, int digits, int period)
	{
		internal string Issuer => issuer;
		internal string AccountName => accountName;
		internal TotpHashAlgorithm Algorithm => algorithm;
		internal int Digits => digits;
		internal int Period => period;
		internal string DisplayLabel => CreateDisplayLabel(Issuer, AccountName);
	}

	#region Decrypt and Export implementations

	private void ShowDecryptAndExportConfirmationDialog()
	{
		if (!IsVaultUnlocked)
		{
			MainInfoBar.WriteWarning("Unlock the vault before decrypting and exporting it.");
			return;
		}

		ShowDestructiveHoldConfirmationDialog(
			titleText: "Decrypt and Export",
			warningText: "This writes every decrypted TOTP secret and associated data to a plain-text JSON file at the file path you choose. Anyone with access to that file can read the entire vault. Keep holding the circular button for five seconds to confirm.",
			holdDurationMilliseconds: LongVaultHoldDurationMilliseconds,
			confirmedAction: DecryptAndExportVaultAfterHoldConfirmation);
	}

	private void DecryptAndExportVaultAfterHoldConfirmation()
	{
		try
		{
			DateTimeOffset exportTimeUtc = DateTimeOffset.UtcNow;
			string exportFileName = string.Concat("tokens.decrypted.", exportTimeUtc.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture), ".json");
			string? selectedExportFilePath = FileDialogHelper.ShowSaveFileDialog(Atlas.JSONPickerFilter, exportFileName);
			if (string.IsNullOrWhiteSpace(selectedExportFilePath))
				return;

			TotpVaultEnvelope vaultEnvelope = HasVaultFile ? ReadVaultEnvelope() : new(VaultVersion, CreateNewVaultId(), VaultPurpose, VaultEncryptionAlgorithm, VaultKdfAlgorithm, PasswordKdfIterations, string.Empty, string.Empty, string.Empty, string.Empty, []);
			List<TotpVaultExportToken> exportedTokens = CreateVaultExportTokens();
			TotpVaultExportPayload exportPayload = new(
				exportedUtc: exportTimeUtc.ToString("O", CultureInfo.InvariantCulture),
				encryption: vaultEnvelope.Encryption,
				kdf: vaultEnvelope.Kdf,
				kdfIterations: vaultEnvelope.KdfIterations,
				tokenCount: exportedTokens.Count,
				tokens: exportedTokens);
			string exportJson = JsonSerializer.Serialize(exportPayload, TotpVaultExportJsonContext.Default.TotpVaultExportPayload);
			File.WriteAllText(selectedExportFilePath, exportJson, Encoding.UTF8);
			MainInfoBar.WriteSuccess(string.Concat("Decrypted vault export saved to: ", selectedExportFilePath));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	private List<TotpVaultExportToken> CreateVaultExportTokens()
	{
		List<TotpVaultExportToken> exportedTokens = new(Tokens.Count);
		foreach (TotpTokenItem tokenItem in CollectionsMarshal.AsSpan(Tokens))
		{
			byte[] secretBytes = CreatePinnedByteArray(tokenItem.SecretLength);
			try
			{
				tokenItem.CopySecretBytesTo(secretBytes);
				exportedTokens.Add(new(
					displayName: tokenItem.DisplayName,
					algorithm: tokenItem.Algorithm.ToString(),
					secret: EncodeBase32(secretBytes.AsSpan(0, tokenItem.SecretLength)),
					notes: tokenItem.Notes));
			}
			finally
			{
				CryptographicOperations.ZeroMemory(secretBytes);
			}
		}

		return exportedTokens;
	}

	private static string EncodeBase32(ReadOnlySpan<byte> source)
	{
		if (source.IsEmpty)
			return string.Empty;

		int outputLength = checked(((source.Length * 8) + 4) / 5);
		return string.Create(
			outputLength,
			source,
			static (destination, input) =>
			{
				int buffer = 0;
				int bitsLeft = 0;
				int outputOffset = 0;
				for (int index = 0; index < input.Length; index++)
				{
					buffer = (buffer << 8) | input[index];
					bitsLeft += 8;
					while (bitsLeft >= 5)
					{
						bitsLeft -= 5;
						destination[outputOffset++] = Alphabet[(buffer >> bitsLeft) & 0x1F];
					}
					buffer &= (1 << bitsLeft) - 1;
				}

				if (bitsLeft > 0)
					destination[outputOffset] = Alphabet[(buffer << (5 - bitsLeft)) & 0x1F];
			});
	}

	#endregion

}

internal enum TotpHashAlgorithm
{
	Sha1,
	Sha256,
	Sha512
}

internal sealed partial class TotpTokenItem : ViewModelBase
{
	private readonly byte[] protectedSecretBytes;
	private long? lastGeneratedCounter;

	internal TotpTokenItem(string id, string displayName, TotpHashAlgorithm algorithm, int digits, int period, byte[] protectedSecretBytes, int secretLength, string notes = "")
	{
		Id = id;
		Algorithm = algorithm;
		TokenDigits = digits;
		TokenPeriod = period;
		this.protectedSecretBytes = protectedSecretBytes;
		SecretLength = secretLength;
		DisplayName = string.IsNullOrWhiteSpace(displayName) ? "TOTP" : displayName;
		Notes = notes;
		NotesActionText = string.IsNullOrWhiteSpace(notes) ? "Add note" : "Edit note";
		NotesPreviewButtonVisibility = string.IsNullOrWhiteSpace(notes) ? Visibility.Collapsed : Visibility.Visible;
	}

	internal string Id { get; }
	internal TotpHashAlgorithm Algorithm { get; }
	internal int SecretLength { get; }
	internal int TokenDigits { get; }
	internal int TokenPeriod { get; }
	internal string DisplayName { get; private set => SP(ref field, value); } = "TOTP";
	internal string Code { get; private set => SP(ref field, value); } = "------";
	internal string RemainingText { get; private set => SP(ref field, value); } = "Waiting for code.";
	internal string Notes { get; private set => SP(ref field, value); } = string.Empty;
	internal string NotesActionText { get; private set => SP(ref field, value); } = "Add note";
	internal Visibility NotesPreviewButtonVisibility { get; private set => SP(ref field, value); } = Visibility.Collapsed;
	internal double ElapsedSeconds { get; private set => SP(ref field, value); }
	internal double PeriodSeconds { get; private set => SP(ref field, value); } = 30D;
	internal bool IsCodeCurrentForTimestamp(long unixTimeSeconds) => lastGeneratedCounter == (unixTimeSeconds / TokenPeriod) && !string.Equals(Code, "------", StringComparison.Ordinal);

	internal string GenerateCode(long unixTimeSeconds, out int secondsRemaining)
	{
		SecureVault.UnprotectMemoryInPlace(protectedSecretBytes);
		try
		{
			long counter = unixTimeSeconds / TokenPeriod;
			Span<byte> counterBytes = stackalloc byte[8];
			BinaryPrimitives.WriteInt64BigEndian(counterBytes, counter);
			byte[] hash = ComputeHash(Algorithm, protectedSecretBytes.AsSpan(0, SecretLength), counterBytes);
			try
			{
				int offset = hash[^1] & 0x0F;
				int binaryCode = ((hash[offset] & 0x7F) << 24) |
					((hash[offset + 1] & 0xFF) << 16) |
					((hash[offset + 2] & 0xFF) << 8) |
					(hash[offset + 3] & 0xFF);
				int modulus = Pow10(TokenDigits);
				int otp = binaryCode % modulus;
				int elapsedInStep = (int)(unixTimeSeconds % TokenPeriod);
				secondsRemaining = TokenPeriod - elapsedInStep;
				lastGeneratedCounter = counter;
				return otp.ToString(new string('0', TokenDigits), CultureInfo.InvariantCulture);
			}
			finally
			{
				CryptographicOperations.ZeroMemory(hash);
			}
		}
		finally
		{
			SecureVault.ProtectMemoryInPlace(protectedSecretBytes);
		}
	}

	internal void CopySecretBytesTo(Span<byte> destination)
	{
		if (destination.Length < SecretLength)
			throw new ArgumentException("Destination buffer is too small.", nameof(destination));
		SecureVault.UnprotectMemoryInPlace(protectedSecretBytes);
		try
		{
			protectedSecretBytes.AsSpan(0, SecretLength).CopyTo(destination);
		}
		finally
		{
			SecureVault.ProtectMemoryInPlace(protectedSecretBytes);
		}
	}

	internal bool SecretEquals(ReadOnlySpan<byte> otherSecretBytes)
	{
		if (otherSecretBytes.Length != SecretLength)
			return false;
		SecureVault.UnprotectMemoryInPlace(protectedSecretBytes);
		try
		{
			return CryptographicOperations.FixedTimeEquals(protectedSecretBytes.AsSpan(0, SecretLength), otherSecretBytes);
		}
		finally
		{
			SecureVault.ProtectMemoryInPlace(protectedSecretBytes);
		}
	}

	internal void ApplyResult(string code, int remainingSeconds)
	{
		Code = code;
		PeriodSeconds = Math.Max(1D, TokenPeriod);
		ElapsedSeconds = Math.Clamp(TokenPeriod - remainingSeconds, 0D, PeriodSeconds);
		RemainingText = string.Format(CultureInfo.InvariantCulture, "{0}s remaining", remainingSeconds);
	}

	internal void ApplyError(string error)
	{
		Code = "------";
		RemainingText = error;
		ElapsedSeconds = 0D;
		lastGeneratedCounter = null;
	}

	internal void ApplyNotes(string? notes)
	{
		Notes = notes ?? string.Empty;
		bool hasNotes = !string.IsNullOrWhiteSpace(Notes);
		NotesActionText = hasNotes ? "Edit note" : "Add note";
		NotesPreviewButtonVisibility = hasNotes ? Visibility.Visible : Visibility.Collapsed;
	}

	internal void ClearSensitiveState() => CryptographicOperations.ZeroMemory(protectedSecretBytes);

	private static byte[] ComputeHash(TotpHashAlgorithm algorithm, ReadOnlySpan<byte> secret, ReadOnlySpan<byte> counterBytes) => algorithm switch
	{
		TotpHashAlgorithm.Sha256 => HMACSHA256.HashData(secret, counterBytes),
		TotpHashAlgorithm.Sha512 => HMACSHA512.HashData(secret, counterBytes),
		_ => HMACSHA1.HashData(secret, counterBytes)
	};

	private static int Pow10(int digits)
	{
		int value = 1;
		for (int index = 0; index < digits; index++)
			value *= 10;
		return value;
	}
}

internal sealed class TotpVaultExportPayload(string exportedUtc, string encryption, string kdf, int kdfIterations, int tokenCount, List<TotpVaultExportToken> tokens)
{
	public string ExportedUtc => exportedUtc;
	public string Encryption => encryption;
	public string Kdf => kdf;
	public int KdfIterations => kdfIterations;
	public int TokenCount => tokenCount;
	public List<TotpVaultExportToken> Tokens => tokens;
}

internal sealed class TotpVaultExportToken(string displayName, string algorithm, string secret, string notes)
{
	public string DisplayName => displayName;
	public string Algorithm => algorithm;
	public string Secret => secret;
	public string Notes => notes;
}

internal sealed class TotpVaultKeyWrap(string kdfSalt, string nonce, string tag, string wrappedVaultKey)
{
	public string KdfSalt => kdfSalt;
	public string Nonce => nonce;
	public string Tag => tag;
	public string WrappedVaultKey => wrappedVaultKey;
}

internal sealed class TotpVaultEncryptedRecord(string nonce, string tag, string ciphertext)
{
	public string Nonce => nonce;
	public string Tag => tag;
	public string Ciphertext => ciphertext;
}

internal sealed class TotpVaultEnvelope(int version, string vaultId, string purpose, string encryption, string kdf, int kdfIterations, string passwordKdfSalt, string passwordWrapNonce, string passwordWrapTag, string passwordWrappedVaultKey, List<TotpVaultEncryptedRecord> tokenRecords)
{
	public int Version => version;
	public string VaultId => vaultId;
	public string Purpose => purpose;
	public string Encryption => encryption;
	public string Kdf => kdf;
	public int KdfIterations => kdfIterations;
	public string PasswordKdfSalt => passwordKdfSalt;
	public string PasswordWrapNonce => passwordWrapNonce;
	public string PasswordWrapTag => passwordWrapTag;
	public string PasswordWrappedVaultKey => passwordWrappedVaultKey;
	public List<TotpVaultEncryptedRecord> TokenRecords => tokenRecords;
	internal TotpVaultKeyWrap GetPasswordKeyWrap() => new(kdfSalt: PasswordKdfSalt, nonce: PasswordWrapNonce, tag: PasswordWrapTag, wrappedVaultKey: PasswordWrappedVaultKey);
}

[JsonSerializable(typeof(TotpVaultEnvelope))]
internal sealed partial class TotpButtonJsonContext : JsonSerializerContext;

[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(TotpVaultExportPayload))]
internal sealed partial class TotpVaultExportJsonContext : JsonSerializerContext;
