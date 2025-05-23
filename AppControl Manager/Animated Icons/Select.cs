//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//
//       LottieGen version:
//           8.1.240821.1+077322fa26
//       
//       Command:
//           LottieGen -Language CSharp -Public -WinUIVersion 3.0 -InputFile Select.json
//       
//       Input file:
//           Select.json (73757 bytes created 9:52+03:00 Apr 4 2025)
//       
//       LottieGen source:
//           http://aka.ms/Lottie
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------
// ____________________________________
// |       Object stats       | Count |
// |__________________________|_______|
// | All CompositionObjects   |    50 |
// |--------------------------+-------|
// | Expression animators     |     1 |
// | KeyFrame animators       |     6 |
// | Reference parameters     |     1 |
// | Expression operations    |     0 |
// |--------------------------+-------|
// | Animated brushes         |     - |
// | Animated gradient stops  |     - |
// | ExpressionAnimations     |     1 |
// | PathKeyFrameAnimations   |     3 |
// |--------------------------+-------|
// | ContainerVisuals         |     1 |
// | ShapeVisuals             |     1 |
// |--------------------------+-------|
// | ContainerShapes          |     - |
// | CompositionSpriteShapes  |     4 |
// |--------------------------+-------|
// | Brushes                  |     2 |
// | Gradient stops           |     - |
// | CompositionVisualSurface |     - |
// ------------------------------------
using Microsoft.Graphics;
using Microsoft.Graphics.Canvas.Geometry;
using Microsoft.UI.Composition;
using System;
using System.Collections.Generic;
using System.Numerics;
using Windows.UI;

namespace AnimatedVisuals
{
    // Name:        down-up-button
    // Frame rate:  24 fps
    // Frame count: 28
    // Duration:    1166.7 mS
    // _____________________________________________________________________________________________
    // |           Marker           |           Constant           | Frame |   mS   |   Progress   |
    // |____________________________|______________________________|_______|________|______________|
    // | NormalToPressed_Start      | M_NormalToPressed_Start      |     0 |    0.0 | 0F           |
    // | NormalToPressed_End        | M_NormalToPressed_End        |     9 |  375.0 | 0.323214293F |
    // | PointerOverToPressed_Start | M_PointerOverToPressed_Start |     9 |  375.0 | 0.323214293F |
    // | PointerOverToPressed_End   | M_PointerOverToPressed_End   |    19 |  791.7 | 0.680357158F |
    // | PressedToNormal_Start      | M_PressedToNormal_Start      |    20 |  833.3 | 0.716071427F |
    // | PressedToNormal_End        | M_PressedToNormal_End        |    28 | 1166.7 | 1F           |
    // | PressedToPointerOver_Start | M_PressedToPointerOver_Start |    28 | 1166.7 | 1F           |
    // | PressedToPointerOver_End   | M_PressedToPointerOver_End   |    28 | 1166.7 | 1F           |
    // ---------------------------------------------------------------------------------------------
    sealed partial class Select
        : Microsoft.UI.Xaml.Controls.IAnimatedVisualSource
        , Microsoft.UI.Xaml.Controls.IAnimatedVisualSource2
    {
        // Animation duration: 1.167 seconds.
        internal const long c_durationTicks = 11666666;

        // Marker: NormalToPressed_Start.
        internal const float M_NormalToPressed_Start = 0F;

        // Marker: NormalToPressed_End.
        internal const float M_NormalToPressed_End = 0.323214293F;

        // Marker: PointerOverToPressed_Start.
        internal const float M_PointerOverToPressed_Start = 0.323214293F;

        // Marker: PointerOverToPressed_End.
        internal const float M_PointerOverToPressed_End = 0.680357158F;

        // Marker: PressedToNormal_Start.
        internal const float M_PressedToNormal_Start = 0.716071427F;

        // Marker: PressedToNormal_End.
        internal const float M_PressedToNormal_End = 1F;

        // Marker: PressedToPointerOver_Start.
        internal const float M_PressedToPointerOver_Start = 1F;

        // Marker: PressedToPointerOver_End.
        internal const float M_PressedToPointerOver_End = 1F;

        public Microsoft.UI.Xaml.Controls.IAnimatedVisual TryCreateAnimatedVisual(Compositor compositor)
        {
            object ignored = null;
            return TryCreateAnimatedVisual(compositor, out ignored);
        }

        public Microsoft.UI.Xaml.Controls.IAnimatedVisual TryCreateAnimatedVisual(Compositor compositor, out object diagnostics)
        {
            diagnostics = null;

            var res = 
                new Select_AnimatedVisual(
                    compositor
                    );
                res.CreateAnimations();
                return res;
        }

        /// <summary>
        /// Gets the number of frames in the animation.
        /// </summary>
        public double FrameCount => 28d;

        /// <summary>
        /// Gets the frame rate of the animation.
        /// </summary>
        public double Framerate => 24d;

        /// <summary>
        /// Gets the duration of the animation.
        /// </summary>
        public TimeSpan Duration => TimeSpan.FromTicks(11666666);

        /// <summary>
        /// Converts a zero-based frame number to the corresponding progress value denoting the
        /// start of the frame.
        /// </summary>
        public double FrameToProgress(double frameNumber)
        {
            return frameNumber / 28d;
        }

        /// <summary>
        /// Returns a map from marker names to corresponding progress values.
        /// </summary>
        public IReadOnlyDictionary<string, double> Markers =>
            new Dictionary<string, double>
            {
                { "NormalToPressed_Start", 0d },
                { "NormalToPressed_End", 0.323214285714286 },
                { "PointerOverToPressed_Start", 0.323214285714286 },
                { "PointerOverToPressed_End", 0.680357142857143 },
                { "PressedToNormal_Start", 0.716071428571429 },
                { "PressedToNormal_End", 1d },
                { "PressedToPointerOver_Start", 1d },
                { "PressedToPointerOver_End", 1d },
            };

        /// <summary>
        /// Sets the color property with the given name, or does nothing if no such property
        /// exists.
        /// </summary>
        public void SetColorProperty(string propertyName, Color value)
        {
        }

        /// <summary>
        /// Sets the scalar property with the given name, or does nothing if no such property
        /// exists.
        /// </summary>
        public void SetScalarProperty(string propertyName, double value)
        {
        }

        sealed partial class Select_AnimatedVisual
            : Microsoft.UI.Xaml.Controls.IAnimatedVisual
            , Microsoft.UI.Xaml.Controls.IAnimatedVisual2
        {
            const long c_durationTicks = 11666666;
            readonly Compositor _c;
            readonly ExpressionAnimation _reusableExpressionAnimation;
            AnimationController _animationController_0;
            CompositionColorBrush _colorBrush_White;
            CompositionPath _path_0;
            CompositionPath _path_1;
            CompositionPath _path_2;
            CompositionPath _path_3;
            CompositionPathGeometry _pathGeometry_1;
            CompositionPathGeometry _pathGeometry_2;
            CompositionPathGeometry _pathGeometry_3;
            CompositionSpriteShape _spriteShape_1;
            CompositionSpriteShape _spriteShape_2;
            CompositionSpriteShape _spriteShape_3;
            ContainerVisual _root;
            CubicBezierEasingFunction _cubicBezierEasingFunction_0;
            CubicBezierEasingFunction _cubicBezierEasingFunction_1;
            StepEasingFunction _holdThenStepEasingFunction;
            StepEasingFunction _stepThenHoldEasingFunction;

            void BindProperty(
                CompositionObject target,
                string animatedPropertyName,
                string expression,
                string referenceParameterName,
                CompositionObject referencedObject)
            {
                _reusableExpressionAnimation.ClearAllParameters();
                _reusableExpressionAnimation.Expression = expression;
                _reusableExpressionAnimation.SetReferenceParameter(referenceParameterName, referencedObject);
                target.StartAnimation(animatedPropertyName, _reusableExpressionAnimation);
            }

            PathKeyFrameAnimation CreatePathKeyFrameAnimation(float initialProgress, CompositionPath initialValue, CompositionEasingFunction initialEasingFunction)
            {
                var result = _c.CreatePathKeyFrameAnimation();
                result.Duration = TimeSpan.FromTicks(c_durationTicks);
                result.InsertKeyFrame(initialProgress, initialValue, initialEasingFunction);
                return result;
            }

            Vector2KeyFrameAnimation CreateVector2KeyFrameAnimation(float initialProgress, Vector2 initialValue, CompositionEasingFunction initialEasingFunction)
            {
                var result = _c.CreateVector2KeyFrameAnimation();
                result.Duration = TimeSpan.FromTicks(c_durationTicks);
                result.InsertKeyFrame(initialProgress, initialValue, initialEasingFunction);
                return result;
            }

            CompositionSpriteShape CreateSpriteShape(CompositionGeometry geometry, Matrix3x2 transformMatrix, CompositionBrush fillBrush)
            {
                var result = _c.CreateSpriteShape(geometry);
                result.TransformMatrix = transformMatrix;
                result.FillBrush = fillBrush;
                return result;
            }

            AnimationController AnimationController_0()
            {
                if (_animationController_0 != null) { return _animationController_0; }
                var result = _animationController_0 = _c.CreateAnimationController();
                result.Pause();
                BindProperty(_animationController_0, "Progress", "_.Progress", "_", _root);
                return result;
            }

            // - - - Layer aggregator
            // - -  RotationDegrees:-90, Offset:<24, 24>
            CanvasGeometry Geometry_0()
            {
                CanvasGeometry result;
                using (var builder = new CanvasPathBuilder(null))
                {
                    builder.SetFilledRegionDetermination(CanvasFilledRegionDetermination.Winding);
                    builder.BeginFigure(new Vector2(20F, 0F));
                    builder.AddCubicBezier(new Vector2(20F, 11.0439997F), new Vector2(11.0439997F, 20F), new Vector2(0F, 20F));
                    builder.AddCubicBezier(new Vector2(-11.0439997F, 20F), new Vector2(-20F, 11.0439997F), new Vector2(-20F, 0F));
                    builder.AddCubicBezier(new Vector2(-20F, -11.0439997F), new Vector2(-11.0439997F, -20F), new Vector2(0F, -20F));
                    builder.AddCubicBezier(new Vector2(11.0439997F, -20F), new Vector2(20F, -11.0439997F), new Vector2(20F, 0F));
                    builder.EndFigure(CanvasFigureLoop.Closed);
                    result = CanvasGeometry.CreatePath(builder);
                }
                return result;
            }

            CanvasGeometry Geometry_1()
            {
                CanvasGeometry result;
                using (var builder = new CanvasPathBuilder(null))
                {
                    builder.SetFilledRegionDetermination(CanvasFilledRegionDetermination.Winding);
                    builder.BeginFigure(new Vector2(4.05100012F, -11.0509996F));
                    builder.AddCubicBezier(new Vector2(4.05100012F, -11.0509996F), new Vector2(7.05100012F, -8.05099964F), new Vector2(7.05100012F, -8.05099964F));
                    builder.AddCubicBezier(new Vector2(7.05100012F, -8.05099964F), new Vector2(-0.847000003F, 0.050999999F), new Vector2(-0.847000003F, 0.050999999F));
                    builder.AddCubicBezier(new Vector2(-0.847000003F, 0.050999999F), new Vector2(7.05100012F, 7.94899988F), new Vector2(7.05100012F, 7.94899988F));
                    builder.AddCubicBezier(new Vector2(7.05100012F, 7.94899988F), new Vector2(3.94899988F, 11.0509996F), new Vector2(3.94899988F, 11.0509996F));
                    builder.AddCubicBezier(new Vector2(3.94899988F, 11.0509996F), new Vector2(-7.05100012F, 0.050999999F), new Vector2(-7.05100012F, 0.050999999F));
                    builder.AddCubicBezier(new Vector2(-7.05100012F, 0.050999999F), new Vector2(4.05100012F, -11.0509996F), new Vector2(4.05100012F, -11.0509996F));
                    builder.EndFigure(CanvasFigureLoop.Closed);
                    result = CanvasGeometry.CreatePath(builder);
                }
                return result;
            }

            CanvasGeometry Geometry_2()
            {
                CanvasGeometry result;
                using (var builder = new CanvasPathBuilder(null))
                {
                    builder.SetFilledRegionDetermination(CanvasFilledRegionDetermination.Winding);
                    builder.BeginFigure(new Vector2(-1.14199996F, -13.0509996F));
                    builder.AddCubicBezier(new Vector2(-1.14199996F, -13.0509996F), new Vector2(3.0999999F, -13.0509996F), new Vector2(3.0999999F, -13.0509996F));
                    builder.AddCubicBezier(new Vector2(3.0999999F, -13.0509996F), new Vector2(3.16300011F, 0.050999999F), new Vector2(3.16300011F, 0.050999999F));
                    builder.AddCubicBezier(new Vector2(3.16300011F, 0.050999999F), new Vector2(3.22600007F, 12.9490004F), new Vector2(3.22600007F, 12.9490004F));
                    builder.AddCubicBezier(new Vector2(3.22600007F, 12.9490004F), new Vector2(-1.14199996F, 12.9490004F), new Vector2(-1.14199996F, 12.9490004F));
                    builder.AddCubicBezier(new Vector2(-1.14199996F, 12.9490004F), new Vector2(-1.14199996F, 0.050999999F), new Vector2(-1.14199996F, 0.050999999F));
                    builder.AddCubicBezier(new Vector2(-1.14199996F, 0.050999999F), new Vector2(-1.14199996F, -13.0509996F), new Vector2(-1.14199996F, -13.0509996F));
                    builder.EndFigure(CanvasFigureLoop.Closed);
                    result = CanvasGeometry.CreatePath(builder);
                }
                return result;
            }

            CanvasGeometry Geometry_3()
            {
                CanvasGeometry result;
                using (var builder = new CanvasPathBuilder(null))
                {
                    builder.SetFilledRegionDetermination(CanvasFilledRegionDetermination.Winding);
                    builder.BeginFigure(new Vector2(1.17499995F, 12.8979998F));
                    builder.AddCubicBezier(new Vector2(1.17499995F, 12.8979998F), new Vector2(-3.19300008F, 12.8979998F), new Vector2(-3.19300008F, 12.8979998F));
                    builder.AddCubicBezier(new Vector2(-3.19300008F, 12.8979998F), new Vector2(-3.19300008F, 0.00100000005F), new Vector2(-3.19300008F, 0.00100000005F));
                    builder.AddCubicBezier(new Vector2(-3.19300008F, 0.00100000005F), new Vector2(-3.19300008F, -13.1020002F), new Vector2(-3.19300008F, -13.1020002F));
                    builder.AddCubicBezier(new Vector2(-3.19300008F, -13.1020002F), new Vector2(1.04900002F, -13.1020002F), new Vector2(1.04900002F, -13.1020002F));
                    builder.AddCubicBezier(new Vector2(1.04900002F, -13.1020002F), new Vector2(1.11199999F, -0.00100000005F), new Vector2(1.11199999F, -0.00100000005F));
                    builder.AddCubicBezier(new Vector2(1.11199999F, -0.00100000005F), new Vector2(1.17499995F, 12.8979998F), new Vector2(1.17499995F, 12.8979998F));
                    builder.EndFigure(CanvasFigureLoop.Closed);
                    result = CanvasGeometry.CreatePath(builder);
                }
                return result;
            }

            CanvasGeometry Geometry_4()
            {
                CanvasGeometry result;
                using (var builder = new CanvasPathBuilder(null))
                {
                    builder.SetFilledRegionDetermination(CanvasFilledRegionDetermination.Winding);
                    builder.BeginFigure(new Vector2(-3.898F, 11.0010004F));
                    builder.AddCubicBezier(new Vector2(-3.898F, 11.0010004F), new Vector2(-7F, 7.89799976F), new Vector2(-7F, 7.89799976F));
                    builder.AddCubicBezier(new Vector2(-7F, 7.89799976F), new Vector2(0.898000002F, 0.00100000005F), new Vector2(0.898000002F, 0.00100000005F));
                    builder.AddCubicBezier(new Vector2(0.898000002F, 0.00100000005F), new Vector2(-7F, -7.90199995F), new Vector2(-7F, -7.90199995F));
                    builder.AddCubicBezier(new Vector2(-7F, -7.90199995F), new Vector2(-3.898F, -11.0010004F), new Vector2(-3.898F, -11.0010004F));
                    builder.AddCubicBezier(new Vector2(-3.898F, -11.0010004F), new Vector2(7F, -0.00100000005F), new Vector2(7F, -0.00100000005F));
                    builder.AddCubicBezier(new Vector2(7F, -0.00100000005F), new Vector2(-3.898F, 11.0010004F), new Vector2(-3.898F, 11.0010004F));
                    builder.EndFigure(CanvasFigureLoop.Closed);
                    result = CanvasGeometry.CreatePath(builder);
                }
                return result;
            }

            // - Layer aggregator
            // RotationDegrees:-90, Offset:<24, 24>
            CompositionColorBrush ColorBrush_AlmostDarkOrchid_FF9C27B0()
            {
                return _c.CreateColorBrush(Color.FromArgb(0xFF, 0x9C, 0x27, 0xB0));
            }

            CompositionColorBrush ColorBrush_White()
            {
                return (_colorBrush_White == null)
                    ? _colorBrush_White = _c.CreateColorBrush(Color.FromArgb(0xFF, 0xFF, 0xFF, 0xFF))
                    : _colorBrush_White;
            }

            CompositionPath Path_0()
            {
                if (_path_0 != null) { return _path_0; }
                var result = _path_0 = new CompositionPath(Geometry_1());
                return result;
            }

            CompositionPath Path_1()
            {
                if (_path_1 != null) { return _path_1; }
                var result = _path_1 = new CompositionPath(Geometry_2());
                return result;
            }

            CompositionPath Path_2()
            {
                if (_path_2 != null) { return _path_2; }
                var result = _path_2 = new CompositionPath(Geometry_3());
                return result;
            }

            CompositionPath Path_3()
            {
                if (_path_3 != null) { return _path_3; }
                var result = _path_3 = new CompositionPath(Geometry_4());
                return result;
            }

            // - Layer aggregator
            // RotationDegrees:-90, Offset:<24, 24>
            CompositionPathGeometry PathGeometry_0()
            {
                return _c.CreatePathGeometry(new CompositionPath(Geometry_0()));
            }

            // - Layer aggregator
            // Layer: Chevron down
            CompositionPathGeometry PathGeometry_1()
            {
                if (_pathGeometry_1 != null) { return _pathGeometry_1; }
                var result = _pathGeometry_1 = _c.CreatePathGeometry();
                return result;
            }

            // - Layer aggregator
            // Layer: Chevron down 2
            CompositionPathGeometry PathGeometry_2()
            {
                if (_pathGeometry_2 != null) { return _pathGeometry_2; }
                var result = _pathGeometry_2 = _c.CreatePathGeometry();
                return result;
            }

            // - Layer aggregator
            // Layer: Chevron up
            CompositionPathGeometry PathGeometry_3()
            {
                if (_pathGeometry_3 != null) { return _pathGeometry_3; }
                var result = _pathGeometry_3 = _c.CreatePathGeometry();
                return result;
            }

            // Layer aggregator
            // Path 1
            CompositionSpriteShape SpriteShape_0()
            {
                // Offset:<24, 24>, Rotation:-90 degrees
                var geometry = PathGeometry_0();
                var result = CreateSpriteShape(geometry, new Matrix3x2(0F, -1F, 1F, 0F, 24F, 24F), ColorBrush_AlmostDarkOrchid_FF9C27B0());;
                return result;
            }

            // Layer aggregator
            // Path 1
            CompositionSpriteShape SpriteShape_1()
            {
                // Offset:<24.051, 25.051>, Rotation:-90 degrees
                var geometry = PathGeometry_1();
                if (_spriteShape_1 != null) { return _spriteShape_1; }
                var result = _spriteShape_1 = CreateSpriteShape(geometry, new Matrix3x2(0F, -1F, 1F, 0F, 24.0510006F, 25.0510006F), ColorBrush_White());;
                return result;
            }

            // Layer aggregator
            // Path 1
            CompositionSpriteShape SpriteShape_2()
            {
                // Offset:<24.051, 25.051>, Rotation:-90 degrees
                var geometry = PathGeometry_2();
                if (_spriteShape_2 != null) { return _spriteShape_2; }
                var result = _spriteShape_2 = CreateSpriteShape(geometry, new Matrix3x2(0F, -1F, 1F, 0F, 24.0510006F, 25.0510006F), ColorBrush_White());;
                result.Scale = new Vector2(0F, 0F);
                return result;
            }

            // Layer aggregator
            // Path 1
            CompositionSpriteShape SpriteShape_3()
            {
                // Offset:<24.101, 23>, Rotation:-90 degrees
                var geometry = PathGeometry_3();
                if (_spriteShape_3 != null) { return _spriteShape_3; }
                var result = _spriteShape_3 = CreateSpriteShape(geometry, new Matrix3x2(0F, -1F, 1F, 0F, 24.1009998F, 23F), ColorBrush_White());;
                result.Scale = new Vector2(0F, 0F);
                return result;
            }

            // The root of the composition.
            ContainerVisual Root()
            {
                if (_root != null) { return _root; }
                var result = _root = _c.CreateContainerVisual();
                var propertySet = result.Properties;
                propertySet.InsertScalar("Progress", 0F);
                // Layer aggregator
                result.Children.InsertAtTop(ShapeVisual_0());
                return result;
            }

            CubicBezierEasingFunction CubicBezierEasingFunction_0()
            {
                return (_cubicBezierEasingFunction_0 == null)
                    ? _cubicBezierEasingFunction_0 = _c.CreateCubicBezierEasingFunction(new Vector2(0.5F, 0F), new Vector2(0.833000004F, 0.833000004F))
                    : _cubicBezierEasingFunction_0;
            }

            CubicBezierEasingFunction CubicBezierEasingFunction_1()
            {
                return (_cubicBezierEasingFunction_1 == null)
                    ? _cubicBezierEasingFunction_1 = _c.CreateCubicBezierEasingFunction(new Vector2(0.166999996F, 0.166999996F), new Vector2(0.5F, 1F))
                    : _cubicBezierEasingFunction_1;
            }

            // - - Layer aggregator
            // - Layer: Chevron down
            // Path
            PathKeyFrameAnimation PathKeyFrameAnimation_0()
            {
                // Frame 0.
                var result = CreatePathKeyFrameAnimation(0F, Path_0(), StepThenHoldEasingFunction());
                // Frame 3.
                result.InsertKeyFrame(0.107142858F, Path_0(), HoldThenStepEasingFunction());
                // Frame 7.
                result.InsertKeyFrame(0.25F, Path_1(), CubicBezierEasingFunction_0());
                return result;
            }

            // - - Layer aggregator
            // - Layer: Chevron down 2
            // Path
            PathKeyFrameAnimation PathKeyFrameAnimation_1()
            {
                // Frame 0.
                var result = CreatePathKeyFrameAnimation(0F, Path_1(), StepThenHoldEasingFunction());
                // Frame 21.
                result.InsertKeyFrame(0.75F, Path_1(), HoldThenStepEasingFunction());
                // Frame 25.
                result.InsertKeyFrame(0.892857134F, Path_0(), CubicBezierEasingFunction_1());
                return result;
            }

            // - - Layer aggregator
            // - Layer: Chevron up
            // Path
            PathKeyFrameAnimation PathKeyFrameAnimation_2()
            {
                // Frame 0.
                var result = CreatePathKeyFrameAnimation(0F, Path_2(), StepThenHoldEasingFunction());
                // Frame 7.
                result.InsertKeyFrame(0.25F, Path_2(), HoldThenStepEasingFunction());
                // Frame 11.
                result.InsertKeyFrame(0.392857134F, Path_3(), CubicBezierEasingFunction_1());
                // Frame 17.
                result.InsertKeyFrame(0.607142866F, Path_3(), _c.CreateCubicBezierEasingFunction(new Vector2(0.5F, 0F), new Vector2(0.5F, 1F)));
                // Frame 21.
                result.InsertKeyFrame(0.75F, Path_2(), CubicBezierEasingFunction_0());
                return result;
            }

            // Layer aggregator
            ShapeVisual ShapeVisual_0()
            {
                var result = _c.CreateShapeVisual();
                result.Size = new Vector2(48F, 48F);
                var shapes = result.Shapes;
                // RotationDegrees:-90, Offset:<24, 24>
                shapes.Add(SpriteShape_0());
                // Layer: Chevron down
                shapes.Add(SpriteShape_1());
                // Layer: Chevron down 2
                shapes.Add(SpriteShape_2());
                // Layer: Chevron up
                shapes.Add(SpriteShape_3());
                return result;
            }

            StepEasingFunction HoldThenStepEasingFunction()
            {
                if (_holdThenStepEasingFunction != null) { return _holdThenStepEasingFunction; }
                var result = _holdThenStepEasingFunction = _c.CreateStepEasingFunction();
                result.IsFinalStepSingleFrame = true;
                return result;
            }

            StepEasingFunction StepThenHoldEasingFunction()
            {
                if (_stepThenHoldEasingFunction != null) { return _stepThenHoldEasingFunction; }
                var result = _stepThenHoldEasingFunction = _c.CreateStepEasingFunction();
                result.IsInitialStepSingleFrame = true;
                return result;
            }

            // - Layer aggregator
            // Layer: Chevron down
            Vector2KeyFrameAnimation ShapeVisibilityAnimation_0()
            {
                // Frame 0.
                var result = CreateVector2KeyFrameAnimation(0F, new Vector2(1F, 1F), HoldThenStepEasingFunction());
                // Frame 7.
                result.InsertKeyFrame(0.25F, new Vector2(0F, 0F), HoldThenStepEasingFunction());
                return result;
            }

            // - Layer aggregator
            // Layer: Chevron down 2
            Vector2KeyFrameAnimation ShapeVisibilityAnimation_1()
            {
                // Frame 0.
                var result = CreateVector2KeyFrameAnimation(0F, new Vector2(0F, 0F), HoldThenStepEasingFunction());
                // Frame 21.
                result.InsertKeyFrame(0.75F, new Vector2(1F, 1F), HoldThenStepEasingFunction());
                return result;
            }

            // - Layer aggregator
            // Layer: Chevron up
            Vector2KeyFrameAnimation ShapeVisibilityAnimation_2()
            {
                // Frame 0.
                var result = CreateVector2KeyFrameAnimation(0F, new Vector2(0F, 0F), HoldThenStepEasingFunction());
                // Frame 7.
                result.InsertKeyFrame(0.25F, new Vector2(1F, 1F), HoldThenStepEasingFunction());
                // Frame 21.
                result.InsertKeyFrame(0.75F, new Vector2(0F, 0F), HoldThenStepEasingFunction());
                return result;
            }

            internal Select_AnimatedVisual(
                Compositor compositor
                )
            {
                _c = compositor;
                _reusableExpressionAnimation = compositor.CreateExpressionAnimation();
                Root();
            }

            public Visual RootVisual => _root;
            public TimeSpan Duration => TimeSpan.FromTicks(c_durationTicks);
            public Vector2 Size => new Vector2(48F, 48F);
            void IDisposable.Dispose() => _root?.Dispose();

            public void CreateAnimations()
            {
                _pathGeometry_1.StartAnimation("Path", PathKeyFrameAnimation_0(), AnimationController_0());
                _pathGeometry_2.StartAnimation("Path", PathKeyFrameAnimation_1(), AnimationController_0());
                _pathGeometry_3.StartAnimation("Path", PathKeyFrameAnimation_2(), AnimationController_0());
                _spriteShape_1.StartAnimation("Scale", ShapeVisibilityAnimation_0(), AnimationController_0());
                _spriteShape_2.StartAnimation("Scale", ShapeVisibilityAnimation_1(), AnimationController_0());
                _spriteShape_3.StartAnimation("Scale", ShapeVisibilityAnimation_2(), AnimationController_0());
            }

            public void DestroyAnimations()
            {
                _pathGeometry_1.StopAnimation("Path");
                _pathGeometry_2.StopAnimation("Path");
                _pathGeometry_3.StopAnimation("Path");
                _spriteShape_1.StopAnimation("Scale");
                _spriteShape_2.StopAnimation("Scale");
                _spriteShape_3.StopAnimation("Scale");
            }

        }
    }
}
