using System.Linq;
using System.Windows;
using System.Windows.Controls;
using Vigie.Core;

namespace Vigie.App.Pages;

public partial class QuarantinePage : UserControl, IPage
{
    private readonly Guardian _g;

    public QuarantinePage(Guardian guardian)
    {
        _g = guardian;
        InitializeComponent();
    }

    public void Refresh()
    {
        var items = _g.Quarantine.Items;
        Items.ItemsSource = items;
        Empty.Visibility = items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        DeleteAllButton.Visibility = items.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
        Subtitle.Text = items.Count == 0
            ? "Aucun fichier isolé pour le moment."
            : $"{items.Count} fichier(s) isolé(s) — {Format.Size(items.Sum(i => i.Size))}. Ils sont chiffrés et ne peuvent plus rien faire.";
    }

    private void Restore_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not QuarantineItem item) return;
        var answer = MessageBox.Show(Window.GetWindow(this),
            $"Restaurer « {item.FileName} » à son emplacement d'origine ?\n\nVigie l'a identifié comme {item.ThreatName}. Ne le restaurez que si vous êtes certain qu'il est sans danger : il sera ensuite autorisé.",
            "Restaurer un fichier", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return;
        if (_g.RestoreFromQuarantine(item, out var error)) Notifications.Info("Fichier restauré", item.OriginalPath, ToastKind.Success);
        else Notifications.Info("Restauration impossible", error, ToastKind.Danger);
        Refresh();
    }

    private void Delete_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not QuarantineItem item) return;
        var answer = MessageBox.Show(Window.GetWindow(this), $"Supprimer définitivement « {item.FileName} » ?\nCette action est irréversible.",
            "Supprimer de la quarantaine", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return;
        _g.Quarantine.Delete(item);
        _g.Log.Add(LogLevel.Info, "Fichier supprimé de la quarantaine", item.OriginalPath);
        Refresh();
    }

    private void DeleteAll_Click(object sender, RoutedEventArgs e)
    {
        var items = _g.Quarantine.Items;
        var answer = MessageBox.Show(Window.GetWindow(this), $"Supprimer définitivement les {items.Count} fichier(s) en quarantaine ?\nCette action est irréversible.",
            "Vider la quarantaine", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return;
        foreach (var item in items) _g.Quarantine.Delete(item);
        _g.Log.Add(LogLevel.Info, "Quarantaine vidée", $"{items.Count} fichier(s) supprimé(s) définitivement.");
        Refresh();
    }
}
