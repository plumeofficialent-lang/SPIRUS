using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Vigie.App;

/// <summary>Petits composants d'interface construits en code (lignes de réglage, sections).</summary>
public static class UiKit
{
    private static T R<T>(string key) => (T)Application.Current.FindResource(key);

    public static TextBlock Icon(string glyph, string brushKey = "Accent", double size = 17) => new()
    {
        Text = glyph,
        Style = R<Style>("Text.Icon"),
        FontSize = size,
        Foreground = R<Brush>(brushKey),
        HorizontalAlignment = HorizontalAlignment.Center
    };

    public static Border Badge(string glyph, string tone = "Accent") => BadgeCore(glyph, tone == "Danger" ? "Danger" : "Accent");

    private static Border BadgeCore(string glyph, string tone) => new()
    {
        Width = 40,
        Height = 40,
        CornerRadius = new CornerRadius(11),
        Background = R<Brush>(tone + "Soft"),
        VerticalAlignment = VerticalAlignment.Center,
        Child = Icon(glyph, tone)
    };

    public static TextBlock SectionTitle(string text) => new()
    {
        Text = text.ToUpperInvariant(),
        Style = R<Style>("Text.Caption"),
        Margin = new Thickness(4, 22, 0, 10)
    };

    /// <summary>Ligne : icône, titre, description et un contrôle à droite.</summary>
    public static Border Row(string glyph, string title, string description, FrameworkElement right, string tone = "Accent")
    {
        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition());
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        if (glyph != null) grid.Children.Add(Badge(glyph, tone));

        var texts = new StackPanel { Margin = new Thickness(glyph != null ? 16 : 0, 0, 16, 0), VerticalAlignment = VerticalAlignment.Center };
        texts.Children.Add(new TextBlock { Text = title, FontWeight = FontWeights.SemiBold, FontSize = 14, TextWrapping = TextWrapping.Wrap });
        if (!string.IsNullOrEmpty(description))
            texts.Children.Add(new TextBlock { Text = description, Style = R<Style>("Text.Muted"), Margin = new Thickness(0, 3, 0, 0) });
        Grid.SetColumn(texts, 1);
        grid.Children.Add(texts);

        if (right != null)
        {
            right.VerticalAlignment = VerticalAlignment.Center;
            Grid.SetColumn(right, 2);
            grid.Children.Add(right);
        }
        return new Border { Style = R<Style>("Row"), Padding = new Thickness(18, 14, 18, 14), Child = grid };
    }

    public static Border Toggle(string glyph, string title, string description, bool value, Action<bool> changed, bool enabled = true, string tone = "Accent")
    {
        var box = new CheckBox { Style = R<Style>("Switch"), IsChecked = value, IsEnabled = enabled };
        box.Click += (_, _) => changed(box.IsChecked == true);
        var row = Row(glyph, title, description, box, tone);
        row.Cursor = enabled ? System.Windows.Input.Cursors.Hand : null;
        row.MouseLeftButtonUp += (_, e) =>
        {
            if (!enabled || e.OriginalSource is DependencyObject d && IsInside(d, box)) return;
            box.IsChecked = box.IsChecked != true;
            changed(box.IsChecked == true);
        };
        return row;
    }

    private static bool IsInside(DependencyObject d, DependencyObject container)
    {
        while (d != null)
        {
            if (d == container) return true;
            d = d is Visual or System.Windows.Media.Media3D.Visual3D ? VisualTreeHelper.GetParent(d) : LogicalTreeHelper.GetParent(d);
        }
        return false;
    }

    public static Button Button(string text, RoutedEventHandler click, string style = "Btn.Secondary", string glyph = null)
    {
        object content = text;
        if (glyph != null)
        {
            var sp = new StackPanel { Orientation = Orientation.Horizontal };
            sp.Children.Add(new TextBlock { Text = glyph, Style = R<Style>("Text.Icon"), FontSize = 13, Margin = new Thickness(0, 0, 8, 0) });
            sp.Children.Add(new TextBlock { Text = text });
            content = sp;
        }
        var b = new Button { Content = content, Style = R<Style>(style) };
        b.Click += click;
        return b;
    }
}
