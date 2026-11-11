using System;
using System.Drawing;
using System.Windows.Forms;
using Vigie.Core;

namespace Vigie.App;

/// <summary>Icône de la zone de notification : SPIRUS continue de tourner quand la fenêtre est fermée.</summary>
public sealed class TrayIcon : IDisposable
{
    private readonly Guardian _guardian;
    private readonly NotifyIcon _icon;
    private readonly Icon _ok;
    private readonly Icon _alert;
    private readonly ToolStripMenuItem _realTime;

    public TrayIcon(Guardian guardian)
    {
        _guardian = guardian;
        _ok = LoadIcon("vigie.ico");
        _alert = LoadIcon("vigie-alert.ico");

        var menu = new ContextMenuStrip
        {
            Renderer = new DarkRenderer(),
            ShowImageMargin = false,
            ShowCheckMargin = true,
            Font = new Font("Segoe UI", 9.75f),
            Padding = new Padding(4)
        };
        menu.Items.Add(Item("Ouvrir SPIRUS", (_, _) => App.Instance.ShowMain(), bold: true));
        menu.Items.Add(Item("Analyse rapide", (_, _) => App.Instance.StartQuickScan()));
        menu.Items.Add(new ToolStripSeparator());
        _realTime = Item("Protection en temps réel", (_, _) =>
        {
            _guardian.Settings.RealTimeEnabled = !_guardian.Settings.RealTimeEnabled;
            _guardian.ApplySettings();
        });
        menu.Items.Add(_realTime);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(Item("Quitter SPIRUS", (_, _) => App.Instance.ExitApplication()));

        _icon = new NotifyIcon { Icon = _ok, Text = "SPIRUS", Visible = true, ContextMenuStrip = menu };
        _icon.MouseClick += (_, e) => { if (e.Button == MouseButtons.Left) App.Instance.ShowMain(); };
        _icon.BalloonTipClicked += (_, _) => App.Instance.ShowMain();
        Refresh();
    }

    private static ToolStripMenuItem Item(string text, EventHandler onClick, bool bold = false)
    {
        var item = new ToolStripMenuItem(text) { Padding = new Padding(4, 6, 4, 6) };
        if (bold) item.Font = new Font("Segoe UI Semibold", 9.75f);
        item.Click += onClick;
        return item;
    }

    private static Icon LoadIcon(string name)
    {
        var info = System.Windows.Application.GetResourceStream(new Uri($"pack://application:,,,/Assets/{name}"));
        using var stream = info!.Stream;
        return new Icon(stream, SystemInformation.SmallIconSize);
    }

    public void Refresh()
    {
        _realTime.Checked = _guardian.Settings.RealTimeEnabled;
        bool ok = _guardian.FullyProtected;
        _icon.Icon = ok ? _ok : _alert;
        _icon.Text = ok ? "SPIRUS — Vous êtes protégé" : "SPIRUS — Protection incomplète";
    }

    public void Balloon(string title, string text, bool warning = false)
    {
        _icon.ShowBalloonTip(5000, title, text, warning ? ToolTipIcon.Warning : ToolTipIcon.Info);
    }

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.Dispose();
        _ok.Dispose();
        _alert.Dispose();
    }

    private sealed class DarkRenderer : ToolStripProfessionalRenderer
    {
        public DarkRenderer() : base(new DarkColors()) { RoundedEdges = false; }

        protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
        {
            e.TextColor = Color.FromArgb(242, 242, 242);
            base.OnRenderItemText(e);
        }

        protected override void OnRenderItemCheck(ToolStripItemImageRenderEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            var r = e.ImageRectangle;
            using var pen = new Pen(Color.FromArgb(242, 242, 242), 2.2f) { StartCap = System.Drawing.Drawing2D.LineCap.Round, EndCap = System.Drawing.Drawing2D.LineCap.Round };
            g.DrawLines(pen, new[]
            {
                new PointF(r.Left + r.Width * 0.18f, r.Top + r.Height * 0.52f),
                new PointF(r.Left + r.Width * 0.42f, r.Top + r.Height * 0.74f),
                new PointF(r.Left + r.Width * 0.84f, r.Top + r.Height * 0.28f)
            });
        }
    }

    private sealed class DarkColors : ProfessionalColorTable
    {
        private static readonly Color Back = Color.FromArgb(10, 10, 10);
        private static readonly Color Hover = Color.FromArgb(30, 30, 30);
        private static readonly Color Border = Color.FromArgb(40, 40, 40);
        public override Color ToolStripDropDownBackground => Back;
        public override Color ImageMarginGradientBegin => Back;
        public override Color ImageMarginGradientMiddle => Back;
        public override Color ImageMarginGradientEnd => Back;
        public override Color MenuBorder => Border;
        public override Color MenuItemBorder => Hover;
        public override Color MenuItemSelected => Hover;
        public override Color MenuItemSelectedGradientBegin => Hover;
        public override Color MenuItemSelectedGradientEnd => Hover;
        public override Color SeparatorDark => Border;
        public override Color SeparatorLight => Back;
        public override Color CheckBackground => Back;
        public override Color CheckSelectedBackground => Hover;
        public override Color CheckPressedBackground => Hover;
    }
}
