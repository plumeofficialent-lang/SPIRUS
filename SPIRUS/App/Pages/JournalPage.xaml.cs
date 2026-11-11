using System.Linq;
using System.Windows;
using System.Windows.Controls;
using Vigie.Core;

namespace Vigie.App.Pages;

public partial class JournalPage : UserControl, IPage
{
    private readonly Guardian _g;

    public JournalPage(Guardian guardian)
    {
        _g = guardian;
        InitializeComponent();
    }

    public void Refresh()
    {
        var all = _g.Log.Entries;
        var shown = FilterThreats.IsChecked == true ? all.Where(e => e.Level == LogLevel.Threat)
            : FilterActions.IsChecked == true ? all.Where(e => e.Level is LogLevel.Success or LogLevel.Warning)
            : FilterInfo.IsChecked == true ? all.Where(e => e.Level == LogLevel.Info)
            : all;
        var list = shown.ToList();
        Entries.ItemsSource = list;
        Empty.Visibility = list.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    public void OnLog(LogEntry entry)
    {
        if (IsVisible) Refresh();
    }

    private void Filter_Checked(object sender, RoutedEventArgs e)
    {
        if (_g != null && IsInitialized) Refresh();
    }

    private void Clear_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(Window.GetWindow(this), "Effacer tout le journal d'activité ?", "Journal", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        _g.Log.Clear();
        Refresh();
    }
}
