using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;

namespace Vigie.App;

public enum ToastKind { Danger, Warning, Success, Info }

public sealed record ToastAction(string Label, Func<bool> Click, bool Primary = false);

/// <summary>Notification flottante en bas à droite de l'écran.</summary>
public partial class ToastWindow : Window
{
    private static readonly List<ToastWindow> Open = new();
    public static ToastWindow Latest => Open.LastOrDefault();
    private readonly DispatcherTimer _timer;
    private bool _closing;

    public ToastWindow(ToastKind kind, string glyph, string title, string message, string detail, int autoCloseSeconds, params ToastAction[] actions)
    {
        InitializeComponent();
        var (gradient, soft, solid) = kind switch
        {
            ToastKind.Danger => ("DangerGradient", "DangerSoft", "Danger"),
            ToastKind.Warning => ("WarningGradient", "WarningSoft", "Warning"),
            ToastKind.Success => ("AccentGradient", "AccentSoft", "Accent"),
            _ => ("AccentGradient", "InfoSoft", "Info")
        };
        AccentBar.Background = (Brush)FindResource(gradient);
        TimerBar.Background = (Brush)FindResource(gradient);
        Glyph.Foreground = (Brush)FindResource(solid);
        Glyph.Text = glyph;
        TitleText.Text = title;
        MessageText.Text = message ?? "";
        MessageText.Visibility = string.IsNullOrEmpty(message) ? Visibility.Collapsed : Visibility.Visible;
        DetailText.Text = detail ?? "";
        DetailText.Visibility = string.IsNullOrEmpty(detail) ? Visibility.Collapsed : Visibility.Visible;

        foreach (var a in actions)
        {
            var b = new Button
            {
                Content = a.Label,
                Style = (Style)FindResource(a.Primary ? "Btn.Primary" : "Btn.Secondary"),
                Padding = new Thickness(14, 7, 14, 7),
                FontSize = 12.5,
                Margin = new Thickness(0, 0, 8, 6)
            };
            b.Click += (_, _) =>
            {
                bool close;
                try { close = a.Click?.Invoke() ?? true; }
                catch (Exception ex) { ShowError(ex.Message); close = false; }
                if (close) FadeOut();
            };
            Actions.Children.Add(b);
        }
        Actions.Visibility = actions.Length > 0 ? Visibility.Visible : Visibility.Collapsed;

        if (autoCloseSeconds > 0)
        {
            _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(autoCloseSeconds) };
            _timer.Tick += (_, _) => FadeOut();
            Loaded += (_, _) =>
            {
                TimerBar.BeginAnimation(WidthProperty, new DoubleAnimation(Root.ActualWidth - 32, 0, TimeSpan.FromSeconds(autoCloseSeconds)));
                _timer.Start();
            };
            MouseEnter += (_, _) => { _timer.Stop(); TimerBar.BeginAnimation(WidthProperty, null); TimerBar.Width = 0; };
            MouseLeave += (_, _) => _timer.Start();
        }

        Loaded += (_, _) =>
        {
            Reflow();
            var ease = new CubicEase { EasingMode = EasingMode.EaseOut };
            BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(220)));
            Slide.BeginAnimation(TranslateTransform.XProperty, new DoubleAnimation(60, 0, TimeSpan.FromMilliseconds(320)) { EasingFunction = ease });
        };
        SizeChanged += (_, _) => Reflow();
        Closed += (_, _) => { Open.Remove(this); Reflow(); };
    }

    public void ShowError(string error)
    {
        ErrorText.Text = error;
        ErrorText.Visibility = string.IsNullOrEmpty(error) ? Visibility.Collapsed : Visibility.Visible;
    }

    public void Present()
    {
        Open.Add(this);
        while (Open.Count > 4) Open[0].FadeOut();
        var area = SystemParameters.WorkArea;
        Left = area.Right - Width;
        Top = area.Bottom - 10;
        Show();
    }

    private static void Reflow()
    {
        var area = SystemParameters.WorkArea;
        double bottom = area.Bottom;
        for (int i = Open.Count - 1; i >= 0; i--)
        {
            var t = Open[i];
            if (t._closing) continue;
            double h = t.ActualHeight > 0 ? t.ActualHeight : 160;
            t.Left = area.Right - t.Width;
            t.Top = bottom - h;
            bottom -= h - 8;
        }
    }

    public void FadeOut()
    {
        if (_closing) return;
        _closing = true;
        _timer?.Stop();
        Open.Remove(this);
        Reflow();
        var anim = new DoubleAnimation(Opacity, 0, TimeSpan.FromMilliseconds(180));
        anim.Completed += (_, _) => Close();
        BeginAnimation(OpacityProperty, anim);
    }

    public static void CloseAll()
    {
        foreach (var t in Open.ToList()) t.Close();
        Open.Clear();
    }

    private void Close_Click(object sender, RoutedEventArgs e) => FadeOut();
}
