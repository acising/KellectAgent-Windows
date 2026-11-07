using System;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace KellectGui
{
    public sealed class MainForm : Form
    {
        private readonly string baseDir;
        private readonly string kellectExe;
        private Process child;
        private EventWaitHandle stopEvent;

        // collection
        private ComboBox profileCombo;
        private CheckBox customMaskCheck;
        private CheckBox threadCheck;
        private CheckBox callstackCheck;
        private CheckBox adaptiveCheck;
        private readonly CheckBox[] maskChecks = new CheckBox[8];
        private TextBox outputBox;
        private CheckBox appendCheck;
        private NumericUpDown maxFileMb;
        private NumericUpDown statsInterval;
        private NumericUpDown serializeThreads;
        private Button startButton;
        private Button stopButton;
        private Button browseOutputButton;

        // mqtt
        private CheckBox mqttCheck;
        private TextBox mqttHost;
        private NumericUpDown mqttPort;
        private TextBox mqttConfig;

        // advanced
        private TextBox evidenceDir;
        private CheckBox kernelEtlCheck;
        private TextBox schemaProbe;
        private TextBox initImages;
        private ComboBox prewarmCombo;
        private NumericUpDown outputThreshold;
        private TextBox dropEvents;
        private TextBox socketText;
        private ComboBox userProvider;
        private CheckBox probeCheck;
        private TextBox probeUrl;
        private TextBox probeId;
        private TextBox probeToken;
        private TextBox probeConfig;
        private NumericUpDown probeQueue;
        private NumericUpDown probeBatch;
        private NumericUpDown probeRate;

        // stats / log
        private Label receivedLabel;
        private Label parsedLabel;
        private Label queuedLabel;
        private Label lostLabel;
        private Label parseQLabel;
        private Label serializeQLabel;
        private Label outputQLabel;
        private Label mqttLabel;
        private Label pipelineLabel;
        private Label mqttDetailLabel;
        private ProgressBar parseBar;
        private ProgressBar serializeBar;
        private ProgressBar outputBar;
        private TextBox logBox;
        private Label statusLabel;
        private TabControl tabs;

        private static readonly Color Bg = SystemColors.Control;
        private static readonly Color PanelBg = SystemColors.Control;
        private static readonly Color BoxBg = SystemColors.Window;
        private static readonly Color TextColor = SystemColors.ControlText;
        private static readonly Color DimColor = SystemColors.GrayText;
        private static readonly Color Accent = SystemColors.Highlight;

        public MainForm()
        {
            baseDir = AppDomain.CurrentDomain.BaseDirectory;
            kellectExe = Path.Combine(baseDir, "kellect.exe");

            Text = "Kellect - Windows Behavior Collector";
            Width = 1120;
            Height = 840;
            MinimumSize = new Size(960, 720);
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = SystemColors.Control;
            ForeColor = SystemColors.ControlText;
            Font = new Font("Segoe UI", 9f);

            BuildUi();
            LoadSettings();
        }

        // ------------------------------------------------------------------
        // layout
        // ------------------------------------------------------------------
        private void BuildUi()
        {
            var root = new TableLayoutPanel();
            root.Dock = DockStyle.Fill;
            root.BackColor = Bg;
            root.ColumnCount = 1;
            root.RowCount = 4;
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 158)); // stats
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 320)); // parameters
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));  // log
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));  // status
            Controls.Add(root);

            root.Controls.Add(BuildStatsPanel(), 0, 0);
            tabs = BuildTabs();
            root.Controls.Add(tabs, 0, 1);

            logBox = new TextBox();
            logBox.Multiline = true;
            logBox.ScrollBars = ScrollBars.Vertical;
            logBox.ReadOnly = true;
            logBox.Dock = DockStyle.Fill;
            logBox.Font = new Font("Consolas", 9f);
            logBox.BackColor = SystemColors.Window;
            logBox.ForeColor = SystemColors.WindowText;
            root.Controls.Add(logBox, 0, 2);

            statusLabel = new Label();
            statusLabel.Text = "就绪";
            statusLabel.Dock = DockStyle.Fill;
            statusLabel.TextAlign = ContentAlignment.MiddleLeft;
            statusLabel.ForeColor = SystemColors.GrayText;
            root.Controls.Add(statusLabel, 0, 3);
        }

        private Control BuildStatsPanel()
        {
            var stats = new GroupBox();
            stats.Text = "实时统计 / Live pipeline";
            stats.Dock = DockStyle.Fill;
            stats.ForeColor = SystemColors.ControlText;
            stats.Padding = new Padding(8);

            receivedLabel = AddStat(stats, "Received", 14, 24);
            parsedLabel = AddStat(stats, "Parsed", 14, 48);
            queuedLabel = AddStat(stats, "Queued", 14, 72);
            lostLabel = AddStat(stats, "ETW lost", 14, 96);

            parseQLabel = AddStat(stats, "Parse Q", 360, 24);
            serializeQLabel = AddStat(stats, "Serialize Q", 360, 48);
            outputQLabel = AddStat(stats, "Output Q", 360, 72);
            mqttLabel = AddStat(stats, "MQTT", 360, 96);

            parseBar = AddBar(stats, 500, 24);
            serializeBar = AddBar(stats, 500, 48);
            outputBar = AddBar(stats, 500, 72);

            pipelineLabel = new Label();
            pipelineLabel.Text = "filtered=0  decode_failed=0  image_rundown=0  thread_rundown=0  thread_other=0";
            pipelineLabel.SetBounds(14, 116, 1020, 16);
            pipelineLabel.Font = new Font("Consolas", 8f);
            pipelineLabel.ForeColor = DimColor;
            stats.Controls.Add(pipelineLabel);

            mqttDetailLabel = new Label();
            mqttDetailLabel.Text = "MQTT events: sent=0 acked=0 spool=0 dropped=0";
            mqttDetailLabel.SetBounds(14, 132, 1020, 16);
            mqttDetailLabel.Font = new Font("Consolas", 8f);
            mqttDetailLabel.ForeColor = Color.DarkGreen;
            stats.Controls.Add(mqttDetailLabel);

            return stats;
        }

        private TabControl BuildTabs()
        {
            var tab = new TabControl();
            tab.Dock = DockStyle.Fill;
            tab.ItemSize = new Size(150, 26);
            tab.SizeMode = TabSizeMode.Fixed;
            tab.BackColor = SystemColors.Control;

            tab.TabPages.Add(BuildCollectionPage());
            tab.TabPages.Add(BuildMqttPage());
            tab.TabPages.Add(BuildAdvancedPage());
            return tab;
        }

        private void TabDraw(object sender, DrawItemEventArgs e)
        {
            var control = (TabControl)sender;
            var page = control.TabPages[e.Index];
            var selected = control.SelectedIndex == e.Index;
            using (var brush = new SolidBrush(selected ? PanelBg : Bg))
                e.Graphics.FillRectangle(brush, e.Bounds);
            TextRenderer.DrawText(e.Graphics, page.Text, Font,
                e.Bounds, selected ? Color.White : DimColor,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
        }

        private TabPage NewPage(string title)
        {
            var page = new TabPage(title);
            page.BackColor = SystemColors.Control;
            page.ForeColor = SystemColors.ControlText;
            return page;
        }

        private TabPage BuildCollectionPage()
        {
            var page = NewPage("采集 / Collection");

            AddLabel(page, "Profile", 16, 18);
            profileCombo = AddCombo(page, 90, 16, 200);
            profileCombo.Items.AddRange(new object[]
            {
                "behavior", "diagnostic", "lightweight", "provenance",
                "full_kernel", "full_research"
            });
            profileCombo.SelectedIndex = 0;

            customMaskCheck = AddCheck(page, "自定义掩码", 320, 17);
            customMaskCheck.CheckedChanged += delegate { UpdateMaskEnabled(); };

            threadCheck = AddCheck(page, "Thread 事件", 450, 17);
            callstackCheck = AddCheck(page, "CallStack", 570, 17);

            adaptiveCheck = AddCheck(page, "自适应调节", 690, 17);
            adaptiveCheck.Checked = true;
            AddHint(page, "behavior 默认不含 Thread/Image；诊断模式含全量事件。CallStack 默认关闭。", 700, 18, 360);

            var maskGroup = new GroupBox();
            maskGroup.Text = "事件掩码（自定义时生效）";
            maskGroup.SetBounds(16, 50, 1040, 58);
            maskGroup.ForeColor = SystemColors.ControlText;
            page.Controls.Add(maskGroup);

            string[] names = { "Process", "Thread", "Image", "File", "Disk", "Registry", "CallStack", "TcpIp" };
            int[] bits = { 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80 };
            for (int i = 0; i < names.Length; ++i)
            {
                var check = AddCheck(maskGroup, names[i], 12 + i * 122, 22);
                check.Tag = bits[i];
                maskChecks[i] = check;
            }
            maskChecks[0].Checked = true;
            maskChecks[3].Checked = true;
            maskChecks[5].Checked = true;
            maskChecks[7].Checked = true;
            customMaskCheck.Checked = false;

            AddLabel(page, "输出 JSONL", 16, 126);
            outputBox = AddText(page, 100, 124, 760);
            outputBox.Text = "";
            browseOutputButton = AddButton(page, "浏览...", 872, 123, 84, false);
            browseOutputButton.Click += BrowseOutput;

            appendCheck = AddCheck(page, "追加", 16, 158);
            AddLabel(page, "轮转 MB", 150, 160);
            maxFileMb = AddNumber(page, 220, 158, 70, 0, 10240, 0);

            AddLabel(page, "统计间隔 (s)", 310, 160);
            statsInterval = AddNumber(page, 410, 158, 70, 1, 3600, 1);
            AddLabel(page, "序列化线程", 510, 160);
            serializeThreads = AddNumber(page, 600, 158, 70, 0, 8, 0);

            startButton = AddButton(page, "开始采集", 700, 156, 130, true);
            startButton.Click += StartClicked;
            stopButton = AddButton(page, "停止", 844, 156, 100, false);
            stopButton.Enabled = false;
            stopButton.Click += StopClicked;

            AddHint(page, "输出留空 = 只统计、不写文件；序列化线程 0 = 默认 1；自适应会动态增加序列化线程/Buffer 上限。", 16, 194, 1000);
            UpdateMaskEnabled();
            return page;
        }

        private TabPage BuildMqttPage()
        {
            var page = NewPage("MQTT");

            mqttCheck = AddCheck(page, "启用 MQTT", 16, 20);
            AddLabel(page, "Broker", 150, 22);
            mqttHost = AddText(page, 210, 20, 220);
            mqttHost.Text = "192.168.1.93";
            AddLabel(page, "端口", 450, 22);
            mqttPort = AddNumber(page, 500, 20, 100, 1, 65535, 1883);

            AddLabel(page, "配置文件", 16, 60);
            mqttConfig = AddText(page, 100, 58, 700);
            mqttConfig.Text = "config\\secargus.ini";

            AddHint(page, "QoS1 批次 + 业务 ACK；没有 ACK responder 时 spool 会保留批次。", 16, 100, 900);
            AddHint(page, "运行 tools\\mqtt_ack_responder.py 可模拟后端 ACK。", 16, 122, 900);
            return page;
        }

        private TabPage BuildAdvancedPage()
        {
            var page = NewPage("高级 / Advanced");

            int x1 = 16, x2 = 520;
            int y = 18;

            AddLabel(page, "证据目录", x1, y);
            evidenceDir = AddText(page, x1 + 90, y - 2, 320);
            kernelEtlCheck = AddCheck(page, "同时保存 kernel.etl", x1, y + 30);

            AddLabel(page, "Schema 报告", x1, y + 62);
            schemaProbe = AddText(page, x1 + 100, y + 60, 300);

            AddLabel(page, "initImages", x1, y + 94);
            initImages = AddText(page, x1 + 90, y + 92, 310);

            AddLabel(page, "预热模式", x1, y + 126);
            prewarmCombo = AddCombo(page, x1 + 90, y + 124, 160);
            prewarmCombo.Items.AddRange(new object[] { "adaptive", "hybrid", "static", "off" });
            prewarmCombo.SelectedIndex = 0;

            AddLabel(page, "输出阈值", x2, y);
            outputThreshold = AddNumber(page, x2 + 90, y - 2, 100, 0, 500000, 0);

            AddLabel(page, "丢弃事件 -x", x2, y + 30);
            dropEvents = AddText(page, x2 + 110, y + 28, 360);

            AddLabel(page, "Socket -s", x2, y + 62);
            socketText = AddText(page, x2 + 100, y + 60, 370);

            AddLabel(page, "用户 Provider", x2, y + 94);
            userProvider = AddCombo(page, x2 + 120, y + 92, 160);
            userProvider.Items.AddRange(new object[] { "关闭", "0x01 Thread_Pool", "0x02 DNS_Client", "0x03 PrintService" });
            userProvider.SelectedIndex = 0;

            var probeGroup = new GroupBox();
            probeGroup.Text = "Kellect Probe (WebSocket)";
            probeGroup.SetBounds(16, 190, 1040, 100);
            probeGroup.ForeColor = SystemColors.ControlText;
            page.Controls.Add(probeGroup);

            probeCheck = AddCheck(probeGroup, "启用 Probe", 12, 22);
            AddLabel(probeGroup, "URL", 130, 24);
            probeUrl = AddText(probeGroup, 170, 22, 340);
            probeUrl.Text = "ws://127.0.0.1:9001/ws/probe";

            AddLabel(probeGroup, "ID", 530, 24);
            probeId = AddText(probeGroup, 560, 22, 140);
            AddLabel(probeGroup, "Token", 720, 24);
            probeToken = AddText(probeGroup, 780, 22, 200);

            AddLabel(probeGroup, "Config", 12, 62);
            probeConfig = AddText(probeGroup, 80, 60, 300);
            probeConfig.Text = "config\\probe.ini";
            AddLabel(probeGroup, "Queue", 400, 64);
            probeQueue = AddNumber(probeGroup, 460, 60, 80, 0, 1000000, 0);
            AddLabel(probeGroup, "Batch", 560, 64);
            probeBatch = AddNumber(probeGroup, 620, 60, 80, 0, 500, 0);
            AddLabel(probeGroup, "Rate", 720, 64);
            probeRate = AddNumber(probeGroup, 770, 60, 90, 0, 1000000, 0);

            AddHint(page, "所有参数会原样传给 kellect.exe；留空/0 表示使用默认值。", 16, 298, 1000);
            return page;
        }

        // ------------------------------------------------------------------
        // control helpers
        // ------------------------------------------------------------------
        private static Label AddLabel(Control parent, string text, int x, int y)
        {
            var l = new Label();
            l.Text = text;
            l.AutoSize = true;
            l.SetBounds(x, y, 10, 20);
            l.ForeColor = SystemColors.ControlText;
            parent.Controls.Add(l);
            return l;
        }

        private static void AddHint(Control parent, string text, int x, int y, int width)
        {
            var l = new Label();
            l.Text = text;
            l.SetBounds(x, y, width, 18);
            l.ForeColor = SystemColors.GrayText;
            l.Font = new Font("Segoe UI", 8.25f);
            parent.Controls.Add(l);
        }

        private TextBox AddText(Control parent, int x, int y, int width)
        {
            var box = new TextBox();
            box.SetBounds(x, y, width, 26);
            box.BackColor = SystemColors.Window;
            box.ForeColor = SystemColors.WindowText;
            parent.Controls.Add(box);
            return box;
        }

        private static CheckBox AddCheck(Control parent, string text, int x, int y)
        {
            var check = new CheckBox();
            check.Text = text;
            check.SetBounds(x, y, 120, 24);
            check.ForeColor = SystemColors.ControlText;
            parent.Controls.Add(check);
            return check;
        }

        private static NumericUpDown AddNumber(Control parent, int x, int y, int width,
                                               int min, int max, int value)
        {
            var num = new NumericUpDown();
            num.SetBounds(x, y, width, 26);
            num.Minimum = min;
            num.Maximum = max;
            num.Value = value;
            num.BackColor = SystemColors.Window;
            num.ForeColor = SystemColors.WindowText;
            parent.Controls.Add(num);
            return num;
        }

        private static ComboBox AddCombo(Control parent, int x, int y, int width)
        {
            var combo = new ComboBox();
            combo.SetBounds(x, y, width, 26);
            combo.DropDownStyle = ComboBoxStyle.DropDownList;
            combo.BackColor = SystemColors.Window;
            combo.ForeColor = SystemColors.WindowText;
            parent.Controls.Add(combo);
            return combo;
        }

        private static Button AddButton(Control parent, string text, int x, int y,
                                        int width, bool primary)
        {
            var button = new Button();
            button.Text = text;
            button.SetBounds(x, y, width, 30);
            button.FlatStyle = FlatStyle.Standard;
            button.UseVisualStyleBackColor = true;
            button.Cursor = Cursors.Hand;
            parent.Controls.Add(button);
            return button;
        }

        private static Label AddStat(Control parent, string caption, int x, int y)
        {
            var label = new Label();
            label.Text = caption + ": -";
            label.SetBounds(x, y, 240, 20);
            label.ForeColor = SystemColors.ControlText;
            parent.Controls.Add(label);
            return label;
        }

        private static ProgressBar AddBar(Control parent, int x, int y)
        {
            var bar = new ProgressBar();
            bar.SetBounds(x, y, 120, 18);
            bar.Maximum = 10000;
            parent.Controls.Add(bar);
            return bar;
        }

        private void UpdateMaskEnabled()
        {
            var custom = customMaskCheck.Checked;
            profileCombo.Enabled = !custom;
            foreach (var check in maskChecks)
                check.Enabled = custom;
        }

        // ------------------------------------------------------------------
        // commands
        // ------------------------------------------------------------------
        private void BrowseOutput(object sender, EventArgs e)
        {
            using (var dialog = new SaveFileDialog())
            {
                dialog.Filter = "JSON Lines (*.jsonl)|*.jsonl|All files (*.*)|*.*";
                if (dialog.ShowDialog(this) == DialogResult.OK)
                    outputBox.Text = dialog.FileName;
            }
        }

        private string BuildArguments()
        {
            var args = new StringBuilder();

            if (customMaskCheck.Checked)
            {
                int mask = 0;
                foreach (var check in maskChecks)
                    if (check.Checked)
                        mask |= (int)check.Tag;
                args.Append("-e 0x").Append(mask.ToString("X2"));
            }
            else
            {
                args.Append("--profile ").Append(profileCombo.Text);
                if (threadCheck.Checked)
                    args.Append(" --enable-thread-events");
            }
            if (callstackCheck.Checked)
                args.Append(" --callstack");
            if (!adaptiveCheck.Checked)
                args.Append(" --no-adaptive");

            var output = outputBox.Text.Trim();
            if (output.Length > 0)
            {
                if (!Path.IsPathRooted(output))
                    output = Path.Combine(baseDir, output);
                args.Append(" -f \"").Append(output).Append('"');
                if (appendCheck.Checked)
                    args.Append(" --append");
                if (maxFileMb.Value > 0)
                    args.Append(" --max-file-mb ").Append((int)maxFileMb.Value);
            }

            if (statsInterval.Value > 0)
                args.Append(" --stats-interval ").Append((int)statsInterval.Value);
            if (serializeThreads.Value > 0)
                args.Append(" --serialize-threads ").Append((int)serializeThreads.Value);
            if (outputThreshold.Value > 0)
                args.Append(" --outputThreshold ").Append((int)outputThreshold.Value);
            if (dropEvents.Text.Trim().Length > 0)
                args.Append(" -x \"").Append(dropEvents.Text.Trim()).Append('"');
            if (socketText.Text.Trim().Length > 0)
                args.Append(" -s \"").Append(socketText.Text.Trim()).Append('"');
            if (userProvider.SelectedIndex > 0)
                args.Append(" -u 0x0").Append(userProvider.SelectedIndex);

            if (evidenceDir.Text.Trim().Length > 0)
                args.Append(" --evidence-dir \"").Append(evidenceDir.Text.Trim()).Append('"');
            if (kernelEtlCheck.Checked)
                args.Append(" --kernel-etl");
            if (schemaProbe.Text.Trim().Length > 0)
                args.Append(" --schema-probe \"").Append(schemaProbe.Text.Trim()).Append('"');
            if (initImages.Text.Trim().Length > 0)
                args.Append(" --init-images \"").Append(initImages.Text.Trim()).Append('"');
            if (prewarmCombo.SelectedIndex >= 0)
                args.Append(" --prewarm-mode ").Append(prewarmCombo.Text);

            if (probeCheck.Checked)
            {
                args.Append(" --probe");
                if (probeUrl.Text.Trim().Length > 0)
                    args.Append(" --probe-url \"").Append(probeUrl.Text.Trim()).Append('"');
                if (probeId.Text.Trim().Length > 0)
                    args.Append(" --probe-id \"").Append(probeId.Text.Trim()).Append('"');
                if (probeToken.Text.Trim().Length > 0)
                    args.Append(" --probe-token \"").Append(probeToken.Text.Trim()).Append('"');
                if (probeConfig.Text.Trim().Length > 0)
                    args.Append(" --probe-config \"").Append(probeConfig.Text.Trim()).Append('"');
                if (probeQueue.Value > 0)
                    args.Append(" --probe-queue ").Append((int)probeQueue.Value);
                if (probeBatch.Value > 0)
                    args.Append(" --probe-batch ").Append((int)probeBatch.Value);
                if (probeRate.Value > 0)
                    args.Append(" --probe-rate ").Append((int)probeRate.Value);
            }

            if (mqttCheck.Checked)
            {
                args.Append(" --mqtt");
                if (mqttConfig.Text.Trim().Length > 0)
                    args.Append(" --mqtt-config \"").Append(mqttConfig.Text.Trim()).Append('"');
                if (mqttHost.Text.Trim().Length > 0)
                    args.Append(" --mqtt-host \"").Append(mqttHost.Text.Trim()).Append('"');
                args.Append(" --mqtt-port ").Append((int)mqttPort.Value);
            }

            return args.ToString();
        }

        private void StartClicked(object sender, EventArgs e)
        {
            if (child != null)
                return;
            if (!File.Exists(kellectExe))
            {
                MessageBox.Show(this, "找不到 kellect.exe:\n" + kellectExe, "Kellect",
                                MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            var stopName = "KellectGuiStop-" + Guid.NewGuid().ToString("N");
            stopEvent = new EventWaitHandle(false, EventResetMode.ManualReset, stopName);

            if (customMaskCheck.Checked && maskChecks[2].Checked)
            {
                var answer = MessageBox.Show(this,
                    "Image 会触发 Windows 的模块启动枚举，可能产生大量 etw_lost。\n" +
                    "DCStart 会被丢弃，ImageLoad/Unload 保留。继续？",
                    "Image 事件", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                if (answer != DialogResult.Yes)
                    return;
            }

            var args = BuildArguments();
            args += " --stop-event \"" + stopName + "\"";

            var psi = new ProcessStartInfo(kellectExe, args);
            psi.WorkingDirectory = baseDir;
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.StandardOutputEncoding = Encoding.UTF8;
            psi.StandardErrorEncoding = Encoding.UTF8;

            try
            {
                child = new Process();
                child.StartInfo = psi;
                child.EnableRaisingEvents = true;
                child.OutputDataReceived += ChildOutput;
                child.ErrorDataReceived += ChildError;
                child.Exited += ChildExited;
                child.Start();
                child.BeginOutputReadLine();
                child.BeginErrorReadLine();
            }
            catch (Exception ex)
            {
                CleanupChild();
                MessageBox.Show(this, "启动 kellect 失败:\n" + ex.Message, "Kellect",
                                MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            startButton.Enabled = false;
            stopButton.Enabled = true;
            statusLabel.Text = "采集中 -> " + (outputBox.Text.Trim().Length > 0
                ? outputBox.Text.Trim() : "仅统计，不写文件");
            AppendLog("启动: kellect.exe " + args);
            SaveSettings();
        }

        private void StopClicked(object sender, EventArgs e)
        {
            StopChild();
        }

        private void StopChild()
        {
            var proc = child;
            if (proc == null)
                return;
            statusLabel.Text = "正在停止（等待 ETW 排空）...";
            try
            {
                if (stopEvent != null)
                    stopEvent.Set();
            }
            catch
            {
            }
            var exited = false;
            try
            {
                exited = proc.WaitForExit(8000);
            }
            catch
            {
            }
            if (!exited)
            {
                try { proc.Kill(); } catch { }
            }
        }

        // ------------------------------------------------------------------
        // child output / stats
        // ------------------------------------------------------------------
        private void ChildOutput(object sender, DataReceivedEventArgs e)
        {
            if (e.Data == null)
                return;
            var line = e.Data;
            if (line.StartsWith("[stats-live]") || line.StartsWith("[stats]"))
            {
                UpdateStats(line);
                return;
            }
            if (line.StartsWith("{"))
            {
                line = WithEventTime(line);
                if (line.Length > 220)
                    line = line.Substring(0, 220) + "...";
            }
            AppendLog(line);
        }

        private void ChildError(object sender, DataReceivedEventArgs e)
        {
            if (e.Data != null)
                AppendLog("ERR " + e.Data);
        }

        private void ChildExited(object sender, EventArgs e)
        {
            var exitCode = -1;
            try
            {
                if (child != null)
                    exitCode = child.ExitCode;
            }
            catch
            {
            }
            try
            {
                BeginInvoke(new Action(delegate
                {
                    statusLabel.Text = "已停止 (exit " + exitCode + ")";
                    AppendLog("kellect 退出，exit code=" + exitCode);
                    startButton.Enabled = true;
                    stopButton.Enabled = false;
                    CleanupChild();
                }));
            }
            catch
            {
            }
        }

        private void UpdateStats(string line)
        {
            try
            {
                BeginInvoke(new Action(delegate
                {
                    var values = ParseValues(line);
                    receivedLabel.Text = "Received: " + Get(values, "received");
                    parsedLabel.Text = "Parsed: " + Get(values, "parsed");
                    queuedLabel.Text = "Queued: " + Get(values, "queued");
                    lostLabel.Text = "ETW lost: " + Get(values, "etw_lost");

                    var parseQ = ToInt(Get(values, "parse_q"));
                    var serializeQ = ToInt(Get(values, "serialize_q"));
                    var outputQ = ToInt(Get(values, "output_q"));
                    parseQLabel.Text = "Parse Q: " + parseQ;
                    serializeQLabel.Text = "Serialize Q: " + serializeQ;
                    outputQLabel.Text = "Output Q: " + outputQ;
                    SetBar(parseBar, parseQ);
                    SetBar(serializeBar, serializeQ);
                    SetBar(outputBar, outputQ);

                    pipelineLabel.Text = "filtered=" + Get(values, "filtered")
                        + "  decode_failed=" + Get(values, "decode_failed")
                        + "  image_rundown=" + Get(values, "image_rundown")
                        + "  thread_rundown=" + Get(values, "thread_rundown")
                        + "  thread_other=" + Get(values, "thread_other")
                        + "  serializers=" + Get(values, "serializers");

                    var connected = Get(values, "mqtt_connected") == "1";
                    mqttLabel.Text = "MQTT: " + (connected ? "connected" : "off/disconnected")
                        + "  batches sent=" + Get(values, "mqtt_sent")
                        + "  acked=" + Get(values, "mqtt_acked");
                    mqttDetailLabel.Text = "MQTT events: sent=" + Get(values, "mqtt_events_sent")
                        + "  acked=" + Get(values, "mqtt_events_acked")
                        + "  spool=" + Get(values, "mqtt_spool")
                        + "  dropped=" + Get(values, "mqtt_dropped");
                }));
            }
            catch
            {
            }
        }

        private static void SetBar(ProgressBar bar, int value)
        {
            if (value < 0)
                value = 0;
            if (value > bar.Maximum)
                value = bar.Maximum;
            bar.Value = value;
        }

        private static System.Collections.Generic.Dictionary<string, string> ParseValues(string line)
        {
            var result = new System.Collections.Generic.Dictionary<string, string>();
            foreach (var part in line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var eq = part.IndexOf('=');
                if (eq > 0)
                    result[part.Substring(0, eq)] = part.Substring(eq + 1);
            }
            return result;
        }

        private static string Get(System.Collections.Generic.Dictionary<string, string> values, string key)
        {
            string value;
            return values.TryGetValue(key, out value) ? value : "-";
        }

        private static int ToInt(string text)
        {
            int value;
            return int.TryParse(text, out value) ? value : 0;
        }

        private static string WithEventTime(string json)
        {
            try
            {
                var marker = "\"TimeStamp\":";
                var at = json.IndexOf(marker, StringComparison.Ordinal);
                if (at < 0)
                    return json;
                at += marker.Length;
                var end = at;
                while (end < json.Length && (char.IsDigit(json[end]) || json[end] == '-'))
                    ++end;
                long fileTime;
                if (!long.TryParse(json.Substring(at, end - at), out fileTime) || fileTime <= 0)
                    return json;
                var local = DateTime.FromFileTimeUtc(fileTime).ToLocalTime();
                return "[" + local.ToString("HH:mm:ss.fff") + "] " + json;
            }
            catch
            {
                return json;
            }
        }

        private void AppendLog(string text)
        {
            try
            {
                if (logBox.TextLength > 400000)
                    logBox.Text = logBox.Text.Substring(logBox.TextLength - 200000);
                logBox.AppendText(text + Environment.NewLine);
            }
            catch
            {
            }
        }

        private void CleanupChild()
        {
            if (child != null)
            {
                try { child.Dispose(); } catch { }
                child = null;
            }
            if (stopEvent != null)
            {
                try { stopEvent.Close(); } catch { }
                stopEvent = null;
            }
        }

        // ------------------------------------------------------------------
        // settings
        // ------------------------------------------------------------------
        private string SettingsPath
        {
            get { return Path.Combine(baseDir, "KellectGui.ini"); }
        }

        private void LoadSettings()
        {
            try
            {
                if (!File.Exists(SettingsPath))
                    return;
                foreach (var line in File.ReadAllLines(SettingsPath))
                {
                    var eq = line.IndexOf('=');
                    if (eq <= 0)
                        continue;
                    var key = line.Substring(0, eq).Trim();
                    var value = line.Substring(eq + 1).Trim();
                    if (key == "output") outputBox.Text = value;
                    else if (key == "host") mqttHost.Text = value;
                    else if (key == "port")
                    {
                        int portValue;
                        if (int.TryParse(value, out portValue))
                            mqttPort.Value = Math.Min(Math.Max(portValue, 1), 65535);
                    }
                    else if (key == "mqtt") mqttCheck.Checked = value == "1";
                    else if (key == "thread") threadCheck.Checked = value == "1";
                    else if (key == "adaptive") adaptiveCheck.Checked = value == "1";
                    else if (key == "callstack") callstackCheck.Checked = value == "1";
                    else if (key == "profile") SelectCombo(profileCombo, value);
                }
            }
            catch
            {
            }
        }

        private static void SelectCombo(ComboBox combo, string value)
        {
            for (int i = 0; i < combo.Items.Count; ++i)
            {
                if (string.Equals(combo.Items[i].ToString(), value, StringComparison.OrdinalIgnoreCase))
                {
                    combo.SelectedIndex = i;
                    return;
                }
            }
        }

        private void SaveSettings()
        {
            try
            {
                File.WriteAllLines(SettingsPath, new[]
                {
                    "output=" + outputBox.Text.Trim(),
                    "host=" + mqttHost.Text.Trim(),
                    "port=" + mqttPort.Value.ToString(CultureInfo.InvariantCulture),
                    "mqtt=" + (mqttCheck.Checked ? "1" : "0"),
                    "thread=" + (threadCheck.Checked ? "1" : "0"),
                    "callstack=" + (callstackCheck.Checked ? "1" : "0"),
                    "adaptive=" + (adaptiveCheck.Checked ? "1" : "0"),
                    "profile=" + profileCombo.Text
                });
            }
            catch
            {
            }
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (child != null)
            {
                var result = MessageBox.Show(this, "采集仍在运行，停止并退出？", "Kellect",
                                             MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                if (result != DialogResult.Yes)
                {
                    e.Cancel = true;
                    return;
                }
                StopChild();
            }
            base.OnFormClosing(e);
        }

        [STAThread]
        public static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }
}
