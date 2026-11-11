using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Vigie.Core;

namespace Vigie.App;

/// <summary>
/// Mode de vérification visuelle : « SPIRUS.exe --snapshot dossier [--page chemin-à-analyser] »
/// affiche chaque page hors écran, l'enregistre en PNG, puis quitte.
/// </summary>
public static class Snapshot
{
    public static async Task RunAsync(MainWindow window, string dir, string scanPath)
    {
        try
        {
            Directory.CreateDirectory(dir);
            window.WindowStartupLocation = WindowStartupLocation.Manual;
            window.ShowActivated = false;
            window.Left = -5000;
            window.Top = 0;
            window.Show();
            await Task.Delay(1500);

            if (!string.IsNullOrEmpty(scanPath))
            {
                var done = new TaskCompletionSource<ScanSummary>();
                App.Guardian.ScanCompleted += s => done.TrySetResult(s);
                window.StartScan(ScanKind.Custom, new[] { scanPath });
                await Task.Delay(120);
                Render(window, Path.Combine(dir, "scan-running.png"));
                var summary = await done.Task;
                await Task.Delay(900);
                Render(window, Path.Combine(dir, "scan-results.png"));

                var threat = summary.Threats.FirstOrDefault(t => File.Exists(t.Path)) ?? summary.Threats.FirstOrDefault();
                if (threat != null)
                {
                    var copy = new ScanResult
                    {
                        Path = threat.Path, DisplayPath = threat.DisplayPath, ThreatName = threat.ThreatName, Category = threat.Category,
                        Verdict = Verdict.Suspicious, Score = threat.Score, Reasons = threat.Reasons, Engine = threat.Engine
                    };
                    Notifications.ShowThreat(new ThreatAlert { Result = copy, Source = DetectionSource.RealTime });
                    await Task.Delay(900);
                    if (ToastWindow.Latest is { } toast) Render(toast, Path.Combine(dir, "toast.png"));
                }
            }

            foreach (var key in new[] { "dashboard", "scan", "protection", "quarantine", "journal", "settings" })
            {
                window.Navigate(key);
                await Task.Delay(800);
                Render(window, Path.Combine(dir, key + ".png"));
            }
        }
        catch (Exception ex)
        {
            File.WriteAllText(Path.Combine(dir, "snapshot-error.txt"), ex.ToString());
        }
        App.Instance.ExitApplication();
    }

    private static void Render(Window window, string file)
    {
        var content = (FrameworkElement)window.Content;
        double w = content.ActualWidth, h = content.ActualHeight;
        var dpi = VisualTreeHelper.GetDpi(window);
        var visual = new DrawingVisual();
        using (var dc = visual.RenderOpen())
        {
            if (window.Background is SolidColorBrush b && b.Color.A > 0) dc.DrawRectangle(b, null, new Rect(0, 0, w, h));
            else dc.DrawRectangle(new SolidColorBrush(Color.FromRgb(0x30, 0x34, 0x40)), null, new Rect(0, 0, w, h));
            dc.DrawRectangle(new VisualBrush(content), null, new Rect(0, 0, w, h));
        }
        var rtb = new RenderTargetBitmap((int)Math.Ceiling(w * dpi.DpiScaleX), (int)Math.Ceiling(h * dpi.DpiScaleY), dpi.PixelsPerInchX, dpi.PixelsPerInchY, PixelFormats.Pbgra32);
        rtb.Render(visual);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(rtb));
        using var fs = File.Create(file);
        encoder.Save(fs);
    }
}
