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

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using CommonCore.MicrosoftGraph;
using Microsoft.Graphics.Canvas;
using Microsoft.Graphics.Canvas.Brushes;
using Microsoft.Graphics.Canvas.Effects;
using Microsoft.Graphics.Canvas.UI.Xaml;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using Windows.Foundation;
using Windows.UI;

namespace AppControlManager.CustomUIElements;

internal sealed partial class GraphAuthPanel : UserControl
{
	private CommonCore.AppSettings.Main AppSettings => Atlas.Settings;

	public IGraphAuthHost Host
	{
		get => (IGraphAuthHost)GetValue(HostProperty); set => SetValue(HostProperty, value);
	}

	private static readonly DependencyProperty HostProperty =
		DependencyProperty.Register(
			nameof(Host),
			typeof(IGraphAuthHost),
			typeof(GraphAuthPanel),
			new PropertyMetadata(null, OnHostChanged));

	internal ThreadSafeObservableCollection<AuthenticatedAccounts> AuthenticatedAccounts => AuthenticationCompanion.AuthenticatedAccounts;

	// Static flag to ensure we only read the cache from disk once per application lifecycle
	private static bool _accountsRestored;

	// Lock to prevent multiple threads/views from triggering initialization concurrently
	private static readonly SemaphoreSlim _restoreLock = new(1, 1);

	internal GraphAuthPanel() => InitializeComponent();

	private async void GraphAuthPanel_Loaded() => await RestoreAccountsAsync();

	private static async void OnHostChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is GraphAuthPanel panel)
		{
			await panel.RestoreAccountsAsync();
		}
	}

	/// <summary>
	/// Restores the cached accounts into the UI. Only runs once per session.
	/// Also handles automatic account selection if available.
	/// </summary>
	private async Task RestoreAccountsAsync()
	{
		// Wait until the Host and AuthCompanionCLS are fully initialized
		if (Host?.AuthCompanionCLS is not null)
		{
			if (!_accountsRestored)
			{
				await _restoreLock.WaitAsync();
				try
				{
					if (!_accountsRestored)
					{
						_accountsRestored = true; // Mark as true so we don't spam the disk on re-navigations
						await Host.AuthCompanionCLS.InitializeAccountsAsync();

						// InitializeAccountsAsync handles the AutoSelectAccountIfApplicable internally,
						// so we return early here to prevent a redundant call.
						return;
					}
				}
				finally
				{
					_ = _restoreLock.Release();
				}
			}

			Host.AuthCompanionCLS.AutoSelectAccountIfApplicable();
		}
	}

	/// <summary>
	/// Gets the account associated with an action button inside an account card template.
	/// </summary>
	private static AuthenticatedAccounts? GetAccountFromSender(object sender) => sender is FrameworkElement frameworkElement ? frameworkElement.DataContext as AuthenticatedAccounts : null;

	/// <summary>
	/// Sets the account card that raised the click as active for this panel's host.
	/// </summary>
	private void SetAccountAsActiveButton_Click(object sender, RoutedEventArgs e)
	{
		AuthenticatedAccounts? account = GetAccountFromSender(sender);
		IGraphAuthHost? host = Host;
		if (account is not null && host is not null)
		{
			host.AuthCompanionCLS.SetActiveAccount(account);
		}
	}

	/// <summary>
	/// Removes the account card that raised the click from this panel's host.
	/// </summary>
	private async void RemoveAccountButton_Click(object sender, RoutedEventArgs e)
	{
		AuthenticatedAccounts? account = GetAccountFromSender(sender);
		IGraphAuthHost? host = Host;
		if (account is not null && host is not null)
		{
			await host.AuthCompanionCLS.LogOutOfAccountAsync(account);
		}
	}

	#region Animations and shadows

	private void GraphAuthPanel_Unloaded()
	{
		List<CanvasControl> canvasControls = [];
		CollectWin2DCanvasControls(this, canvasControls);

		foreach (CanvasControl canvasControl in canvasControls)
		{
			canvasControl.Draw -= AccountMetadataGradientShadowCanvas_Draw;
			canvasControl.RemoveFromVisualTree();
		}
	}

	private static void CollectWin2DCanvasControls(DependencyObject parent, List<CanvasControl> canvasControls)
	{
		int childrenCount = VisualTreeHelper.GetChildrenCount(parent);

		for (int index = 0; index < childrenCount; index++)
		{
			DependencyObject child = VisualTreeHelper.GetChild(parent, index);

			if (child is CanvasControl canvasControl)
			{
				canvasControls.Add(canvasControl);
			}

			CollectWin2DCanvasControls(child, canvasControls);
		}
	}

	/// <summary>
	/// Starts the hover animation for the visible metadata card and its matching gradient shadow.
	/// </summary>
	private void AccountMetadataArea_PointerEntered(object sender, PointerRoutedEventArgs e)
	{
		if (sender is FrameworkElement visualMetadataCard)
		{
			AnimateAccountMetadataArea(visualMetadataCard, true);
		}
	}

	/// <summary>
	/// Restores the visible metadata card whose hover state ended and hides its matching gradient shadow.
	/// </summary>
	private void AccountMetadataArea_PointerExited(object sender, PointerRoutedEventArgs e)
	{
		if (sender is FrameworkElement visualMetadataCard)
		{
			AnimateAccountMetadataArea(visualMetadataCard, false);
		}
	}

	/// <summary>
	/// Animates the visible metadata card and the Win2D gradient shadow that belongs to the same metadata cell.
	/// </summary>
	private static void AnimateAccountMetadataArea(FrameworkElement visualMetadataCard, bool isPointerOver)
	{
		AnimateMetadataAreaCompositeTransform(visualMetadataCard, isPointerOver);
		AnimateMetadataAreaShadow(visualMetadataCard, isPointerOver);
	}

	/// <summary>
	/// Upward translation applied to a hovered metadata card and its matching shadow canvas.
	/// </summary>
	private const double AccountMetadataHoverTranslateY = -3.0d;

	/// <summary>
	/// Applies centered scale and upward translation to a metadata card or its matching shadow canvas.
	/// </summary>
	private static void AnimateMetadataAreaCompositeTransform(FrameworkElement element, bool isPointerOver)
	{
		element.RenderTransformOrigin = new Point(0.5d, 0.5d);

		CompositeTransform compositeTransform;
		if (element.RenderTransform is CompositeTransform existingCompositeTransform)
		{
			compositeTransform = existingCompositeTransform;
		}
		else
		{
			compositeTransform = new CompositeTransform();
			element.RenderTransform = compositeTransform;
		}

		DoubleAnimation translateYAnimation = new()
		{
			To = isPointerOver ? AccountMetadataHoverTranslateY : 0.0d,
			Duration = new Duration(TimeSpan.FromMilliseconds(isPointerOver ? 140 : 160)),
			EnableDependentAnimation = true
		};

		DoubleAnimation scaleXAnimation = new()
		{
			To = isPointerOver ? 1.012d : 1.0d,
			Duration = new Duration(TimeSpan.FromMilliseconds(isPointerOver ? 140 : 160)),
			EnableDependentAnimation = true
		};

		DoubleAnimation scaleYAnimation = new()
		{
			To = isPointerOver ? 1.012d : 1.0d,
			Duration = new Duration(TimeSpan.FromMilliseconds(isPointerOver ? 140 : 160)),
			EnableDependentAnimation = true
		};

		Storyboard.SetTarget(translateYAnimation, compositeTransform);
		Storyboard.SetTargetProperty(translateYAnimation, nameof(CompositeTransform.TranslateY));

		Storyboard.SetTarget(scaleXAnimation, compositeTransform);
		Storyboard.SetTargetProperty(scaleXAnimation, nameof(CompositeTransform.ScaleX));

		Storyboard.SetTarget(scaleYAnimation, compositeTransform);
		Storyboard.SetTargetProperty(scaleYAnimation, nameof(CompositeTransform.ScaleY));

		Storyboard storyboard = new();
		storyboard.Children.Add(translateYAnimation);
		storyboard.Children.Add(scaleXAnimation);
		storyboard.Children.Add(scaleYAnimation);
		storyboard.Begin();
	}

	private const float AccountMetadataGradientShadowBlurRadius = 10.0f;
	private const double AccountMetadataGradientShadowVisibleOpacity = 0.62d;
	private const double AccountMetadataGradientShadowHiddenOpacity = 0.0d;
	private const float AccountMetadataGradientShadowPadding = 18.0f;
	private const float AccountMetadataGradientShadowCornerRadius = 6.0f;
	private const float AccountMetadataGradientShadowTileHeight = 76.0f;

	/// <summary>
	/// Animates the Win2D blurred gradient shadow canvas and applies the same elevation transform as the hovered metadata card.
	/// </summary>
	private static void AnimateMetadataAreaShadow(FrameworkElement visualMetadataCard, bool isPointerOver)
	{
		CanvasControl? shadowCanvas = GetMetadataAreaGradientShadowCanvas(visualMetadataCard);
		if (shadowCanvas is null)
		{
			return;
		}

		AnimateMetadataAreaCompositeTransform(shadowCanvas, isPointerOver);

		if (isPointerOver)
		{
			shadowCanvas.Invalidate();
		}

		DoubleAnimation opacityAnimation = new()
		{
			To = isPointerOver ? AccountMetadataGradientShadowVisibleOpacity : AccountMetadataGradientShadowHiddenOpacity,
			Duration = new Duration(TimeSpan.FromMilliseconds(isPointerOver ? 120 : 150)),
			EnableDependentAnimation = true
		};

		Storyboard.SetTarget(opacityAnimation, shadowCanvas);
		Storyboard.SetTargetProperty(opacityAnimation, nameof(Opacity));

		Storyboard storyboard = new();
		storyboard.Children.Add(opacityAnimation);
		storyboard.Begin();
	}

	private static readonly CanvasGradientStop[] GradientStops =
	[
		new() { Position = 0.0f, Color = Color.FromArgb(255, 0x8B, 0xDE, 0xDA) },
		new() { Position = 0.25f, Color = Color.FromArgb(255, 0x43, 0xAD, 0xD0) },
		new() { Position = 0.5f, Color = Color.FromArgb(255, 0x99, 0x8E, 0xE0) },
		new() { Position = 0.75f, Color = Color.FromArgb(255, 0xE1, 0x7D, 0xC2) },
		new() { Position = 1.0f, Color = Color.FromArgb(255, 0xEF, 0x93, 0x93) }
	];

	/// <summary>
	/// Draws the 5-color blurred gradient shadow and clears the tile interior so the glow remains outside the card surface.
	/// </summary>
	private void AccountMetadataGradientShadowCanvas_Draw(CanvasControl sender, CanvasDrawEventArgs args)
	{
		float canvasWidth = Math.Max(0.0f, (float)sender.ActualWidth);
		float canvasHeight = Math.Max(0.0f, (float)sender.ActualHeight);

		if (canvasWidth <= 0.0f || canvasHeight <= 0.0f)
		{
			return;
		}

		using CanvasRenderTarget shadowSource = new(sender, canvasWidth, canvasHeight, sender.Dpi);

		using (CanvasDrawingSession shadowDrawingSession = shadowSource.CreateDrawingSession())
		{
			shadowDrawingSession.Clear(Colors.Transparent);

			using CanvasLinearGradientBrush gradientBrush = new(shadowDrawingSession, GradientStops)
			{
				StartPoint = new System.Numerics.Vector2(AccountMetadataGradientShadowPadding, 0.0f),
				EndPoint = new System.Numerics.Vector2(Math.Max(AccountMetadataGradientShadowPadding, canvasWidth - AccountMetadataGradientShadowPadding), 0.0f)
			};

			float shadowWidth = Math.Max(0.0f, canvasWidth - (AccountMetadataGradientShadowPadding * 2.0f));

			Rect shadowSourceRect = new(
				AccountMetadataGradientShadowPadding,
				AccountMetadataGradientShadowPadding,
				shadowWidth,
				AccountMetadataGradientShadowTileHeight);

			shadowDrawingSession.FillRoundedRectangle(
				shadowSourceRect,
				AccountMetadataGradientShadowCornerRadius,
				AccountMetadataGradientShadowCornerRadius,
				gradientBrush);
		}

		using GaussianBlurEffect blurEffect = new()
		{
			Source = shadowSource,
			BlurAmount = AccountMetadataGradientShadowBlurRadius,
			BorderMode = EffectBorderMode.Soft,
			Optimization = EffectOptimization.Balanced
		};

		args.DrawingSession.Clear(Colors.Transparent);
		args.DrawingSession.DrawImage(blurEffect);

		float metadataTileWidth = Math.Max(0.0f, canvasWidth - (AccountMetadataGradientShadowPadding * 2.0f));
		Rect metadataTileCutoutRect = new(
			AccountMetadataGradientShadowPadding,
			AccountMetadataGradientShadowPadding,
			metadataTileWidth,
			AccountMetadataGradientShadowTileHeight);

		args.DrawingSession.Blend = CanvasBlend.Copy;
		args.DrawingSession.FillRoundedRectangle(
			metadataTileCutoutRect,
			AccountMetadataGradientShadowCornerRadius,
			AccountMetadataGradientShadowCornerRadius,
			Colors.Transparent);
		args.DrawingSession.Blend = CanvasBlend.SourceOver;
	}

	/// <summary>
	/// Gets the sibling Win2D canvas that shares the metadata layout wrapper's Grid position.
	/// </summary>
	private static CanvasControl? GetMetadataAreaGradientShadowCanvas(FrameworkElement visualMetadataCard)
	{
		if (visualMetadataCard.Parent is not Border metadataLayoutWrapper || metadataLayoutWrapper.Parent is not Grid metadataGrid)
		{
			return null;
		}

		int targetRow = Grid.GetRow(metadataLayoutWrapper);
		int targetColumn = Grid.GetColumn(metadataLayoutWrapper);
		int targetColumnSpan = Grid.GetColumnSpan(metadataLayoutWrapper);

		foreach (UIElement child in metadataGrid.Children)
		{
			if (child is CanvasControl shadowCanvas &&
				Grid.GetRow(shadowCanvas) == targetRow &&
				Grid.GetColumn(shadowCanvas) == targetColumn &&
				Grid.GetColumnSpan(shadowCanvas) == targetColumnSpan)
			{
				return shadowCanvas;
			}
		}

		return null;
	}

	#endregion

}
