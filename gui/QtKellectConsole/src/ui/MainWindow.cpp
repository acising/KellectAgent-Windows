// src/ui/MainWindow.cpp
#include "MainWindow.h"
#include "LogDelegate.h"
#include "LogHeader.h"
#include "../domain/Preset.h"
#include "../domain/LogParser.h"
#include <QCheckBox>
#include <QComboBox>
#include <QRadioButton>
#include <QSpinBox>
#include <QLineEdit>
#include <QLabel>
#include <QPushButton>
#include <QListView>
#include <QSortFilterProxyModel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QTimer>
#include <QCloseEvent>
#include <QFileDialog>
#include <QDialog>
#include <QDialogButtonBox>
#include <QTextEdit>
#include <QMenu>
#include <QAction>
#include <QFile>
#include <QFileInfo>
#include <QCoreApplication>

using namespace kellect; // Resolution #1: EventFlag/buildMask/buildKellectArgs 在 namespace kellect;Preset/defaultPresets 全局,不受影响

// Defect #6(本任务构建时发现,brief 遗漏):enum class 无内置 qHash,
// QHash<kellect::EventFlag, QCheckBox*> 作键需要 ADL 找到本重载。
// 仅在本 TU 内提供,不动 Flags.h(其他任务组件)。
// 内层 ::qHash 显式限定到全局,绕过本命名空间的递归解析。
namespace kellect {
inline uint qHash(EventFlag f, uint seed = 0) noexcept {
    return ::qHash(static_cast<quint8>(f), seed);
}
}

MainWindow::MainWindow(SettingsStore* store, QWidget* parent)
    : QMainWindow(parent), store_(store) {
    setWindowTitle("KellectConsole");
    resize(960, 640);

    auto* central = new QWidget;
    auto* root = new QVBoxLayout(central);

    // —— 工具栏:分组 ——
    auto* bar = new QHBoxLayout;

    // 组1:事件 flags(#2 改为 4 列 × 2 行 QGridLayout,保留分组标题)
    auto* flagsBox = new QGroupBox(tr("事件类型"));
    auto* flagsLay = new QGridLayout(flagsBox);
    flagsLay->setSpacing(4);
    flagsLay->setContentsMargins(8, 6, 8, 6);
    const QVector<QPair<EventFlag, QString>> flagItems = {
        {EventFlag::Process,  tr("进程")},  {EventFlag::Thread,   tr("线程")},
        {EventFlag::Image,    tr("镜像")},  {EventFlag::File,     tr("文件")},
        {EventFlag::Disk,     tr("磁盘")},  {EventFlag::Registry, tr("注册表")},
        {EventFlag::CallStack,tr("调用栈")},{EventFlag::TcpIp,    tr("网络")},
    };
    // row0 = 进程/线程/镜像/文件,row1 = 磁盘/注册表/调用栈/网络
    for (int i = 0; i < flagItems.size(); ++i) {
        auto* cb = new QCheckBox(flagItems[i].second, flagsBox);
        flagBoxes_.insert(flagItems[i].first, cb);
        flagsLay->addWidget(cb, i / 4, i % 4);
    }
    bar->addWidget(flagsBox);

    // 组2:预设 + 启停 + 保存/清除/设置(#3 + 方案A)
    auto* ctrlBox = new QGroupBox(tr("控制"));
    auto* ctrlLay = new QHBoxLayout(ctrlBox);
    presetCombo_ = new QComboBox;
    for (const auto& p : defaultPresets()) presetCombo_->addItem(p.name);
    auto* startBtn    = new QPushButton(tr("启动"));
    auto* stopBtn     = new QPushButton(tr("停止"));
    auto* saveBtn     = new QPushButton(tr("保存"));
    auto* clearBtn    = new QPushButton(tr("清除"));
    auto* settingsBtn = new QPushButton(tr("⚙ 设置"));
    ctrlLay->addWidget(new QLabel(tr("预设:")));
    ctrlLay->addWidget(presetCombo_);
    ctrlLay->addWidget(startBtn);
    ctrlLay->addWidget(stopBtn);
    ctrlLay->addWidget(saveBtn);
    ctrlLay->addWidget(clearBtn);
    ctrlLay->addWidget(settingsBtn);
    bar->addWidget(ctrlBox);

    // 组3:搜索 + 自动滚动 + 异常计数
    auto* optBox = new QGroupBox(tr("显示"));
    auto* optLay = new QHBoxLayout(optBox);
    filterEdit_ = new QLineEdit;
    filterEdit_->setPlaceholderText(tr("搜索…"));
    autoScrollBox_ = new QCheckBox(tr("自动滚动"), optBox);
    autoScrollBox_->setChecked(true);
    errLabel_ = new QLabel(QStringLiteral("⚠ 0"));
    errLabel_->setObjectName("errLabel"); // Resolution #3:让 dark.qss 的 QLabel#errLabel 规则生效
    optLay->addWidget(new QLabel(tr("搜索:")));
    optLay->addWidget(filterEdit_);
    optLay->addWidget(autoScrollBox_);
    optLay->addWidget(errLabel_);
    bar->addWidget(optBox, 1);

    root->addLayout(bar);

    // 方案A:exe 路径行已从主界面移除,改由"⚙ 设置"对话框配置。

    // —— 列表头(#1):列宽与 LogDelegate 常量对齐 ——
    auto* header = new LogHeader;
    root->addWidget(header);

    // —— 日志视图 ——
    // proxy 套在 model_ 上做关键字搜索;view 看 proxy。delegate 经 proxy 的 data()
    // 转发读 source 各 role,无需改;书签/autoscroll 的 index 走 proxy↔source 映射。
    proxy_ = new QSortFilterProxyModel(this);
    proxy_->setSourceModel(&model_);
    proxy_->setFilterRole(LogModel::SearchRole);     // 按显示列(事件/PID/进程名/详情)匹配,不匹配原始 JSON
    proxy_->setFilterCaseSensitivity(Qt::CaseInsensitive);

    view_ = new QListView;
    view_->setModel(proxy_);
    view_->setItemDelegate(new LogDelegate(this));
    view_->setUniformItemSizes(true);
    view_->setFrameShape(QFrame::NoFrame); // 无边框,viewport 左缘与表头左缘对齐
    root->addWidget(view_, 1);

    // —— 状态区:运行状态(左,拉伸)+ 当前 exe 路径(右,可点开设置)——
    auto* statusLay = new QHBoxLayout;
    statusLay->setContentsMargins(0, 0, 0, 0);
    statusLabel_ = new QLabel(tr("就绪"));
    pathLabel_ = new QLabel;
    pathLabel_->setOpenExternalLinks(false);
    connect(pathLabel_, &QLabel::linkActivated, this, &MainWindow::openSettingsDialog);
    statusLay->addWidget(statusLabel_, 1);
    statusLay->addWidget(pathLabel_);
    outputLabel_ = new QLabel;
    statusLay->addWidget(outputLabel_);
    root->addLayout(statusLay);

    setCentralWidget(central);

    // —— 信号槽 ——
    connect(presetCombo_, qOverload<int>(&QComboBox::activated), this, &MainWindow::applyPreset);
    connect(startBtn,    &QPushButton::clicked, this, &MainWindow::onStart);
    connect(stopBtn,     &QPushButton::clicked, this, &MainWindow::onStop);
    connect(saveBtn,     &QPushButton::clicked, this, &MainWindow::onSave);
    connect(clearBtn,    &QPushButton::clicked, this, &MainWindow::onClear);
    connect(settingsBtn, &QPushButton::clicked, this, &MainWindow::openSettingsDialog);
    connect(&proc_, &KellectProcessService::outputLine, this, &MainWindow::onOutputLine);
    connect(&proc_, &KellectProcessService::stateChanged, this, [this](ProcessState s){
        statusLabel_->setText(s == ProcessState::Running ? tr("运行中") :
                              s == ProcessState::Starting ? tr("启动中…") : tr("就绪"));
    });
    connect(&proc_, &KellectProcessService::startFailed, this, [this](const QString& r){
        statusLabel_->setText(tr("启动失败:%1").arg(r));
    });
    connect(&proc_, &KellectProcessService::decodeErrorCountChanged, this, [this](int n){
        errLabel_->setText(QStringLiteral("⚠ %1").arg(n));
    });
    connect(filterEdit_, &QLineEdit::textChanged, proxy_, &QSortFilterProxyModel::setFilterFixedString);
    // 双击:打开详情对话框(显示解析后的分列字段 + 原始整行)。
    connect(view_, &QListView::doubleClicked, this, [this](const QModelIndex& i){
        openDetailDialog(i);
    });
    // 右键:书签菜单(取代旧的双击切换书签)。
    view_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(view_, &QWidget::customContextMenuRequested, this, [this](const QPoint& point){
        const QModelIndex proxyIdx = view_->indexAt(point);
        if (!proxyIdx.isValid()) return;
        const QModelIndex src = proxy_->mapToSource(proxyIdx);
        if (!src.isValid() || src.row() < 0 || src.row() >= model_.rows().size()) return;
        const bool marked = model_.rows().at(src.row()).marked;
        QMenu menu(this);
        QAction* act = menu.addAction(marked ? tr("取消书签") : tr("标记书签"));
        if (menu.exec(view_->viewport()->mapToGlobal(point)) == act)
            model_.toggleMark(src.row());
    });

    // forwarder 状态/错误 → 状态栏
    connect(&forwarder_, &OutputForwarder::error, this, [this](const QString& m){
        outputLabel_->setStyleSheet("color:#E07070;");
        outputLabel_->setText(m);
    });
    connect(&forwarder_, &OutputForwarder::stateChanged, this, [this](const QString&){
        updateOutputStatus();   // 用规范文案刷新(覆盖"连接中/重连中"等瞬态)
    });

    // 服务模式:SCM 状态/错误 → 状态栏
    connect(&svc_, &WindowsServiceClient::stateChanged, this, [this](WindowsServiceClient::State s){
        updateStatusFromServiceState(s);
    });
    connect(&svc_, &WindowsServiceClient::errorOccurred, this, [this](const QString& m){
        statusLabel_->setText(tr("服务错误:%1").arg(m));
    });

    // —— 自动滚动节流(QTimer 120ms,与 CollectionChanged 解耦)——
    scrollTimer_ = new QTimer(this);
    scrollTimer_->setInterval(120);
    scrollTimer_->start();
    connect(scrollTimer_, &QTimer::timeout, this, [this]{
        if (!logDirty_) return;
        logDirty_ = false;
        // scrollToBottom 走 view/proxy 内容:搜索时滚到最后一条匹配,未搜索时最后一条。
        if (autoScrollBox_->isChecked() && proxy_->rowCount() > 0)
            view_->scrollToBottom();
    });

    updateOutputStatus();
    loadSettings();
}

quint8 MainWindow::currentMask() const {
    QVector<EventFlag> on;
    for (auto it = flagBoxes_.begin(); it != flagBoxes_.end(); ++it)
        if (it.value()->isChecked()) on.append(it.key());
    return buildMask(on);
}

void MainWindow::applyPreset(int idx) {
    const auto presets = defaultPresets();
    if (idx < 0 || idx >= presets.size()) return;
    for (auto cb : flagBoxes_) cb->setChecked(false);
    for (auto f : presets[idx].flags) if (auto* cb = flagBoxes_.value(f)) cb->setChecked(true);
}

void MainWindow::onStart() {
    if (runAsService_) { startViaService(); return; }
    if (kellectExePath_.trimmed().isEmpty()) {
        statusLabel_->setText(tr("请先在设置中选择 kellect.exe"));
        return;
    }
    const quint8 mask = currentMask();
    updateOutputStatus();   // 先设规范文案;若下方 setMode(File) 随即 emit error(打不开),红字不被尾随调用覆盖(spec §8)
    QStringList args;
    if (static_cast<OutputMode>(outputMode_) == OutputMode::Kafka) {
        if (kafkaBroker_.isEmpty() || kafkaTopic_.isEmpty()) {
            statusLabel_->setText(tr("请先在设置中填 Kafka broker/topic"));
            return;
        }
        args = QStringList{ "-e", maskToHex(mask),
                            "-k", kafkaBroker_ + "/" + kafkaTopic_ };
        forwarder_.setMode(OutputForwarder::Mode::None);   // kellect 直传,不 tee
    } else {
        args = buildKellectArgs(mask);                     // {"-e", hex, "-c"}
        forwarder_.setFile(outputFile_);
        forwarder_.setSocket(socketHost_, socketPort_);
        forwarder_.setMode(static_cast<OutputMode>(outputMode_) == OutputMode::File   ? OutputForwarder::Mode::File   :
                           static_cast<OutputMode>(outputMode_) == OutputMode::Socket ? OutputForwarder::Mode::Socket :
                                                                                       OutputForwarder::Mode::None);
    }
    proc_.start(kellectExePath_.trimmed(), args);
}

void MainWindow::onStop() {
    if (runAsService_) {
        statusLabel_->setText(tr("正在停止服务…"));
        svc_.stop();
        svc_.stopPolling();
        return;
    }
    proc_.stop(); forwarder_.close();
}

void MainWindow::startViaService() {
    // 服务模式:把当前输出配置写入 HKLM\SOFTWARE\Kellect\Service,再启动 KellectService。
    // kellect.exe 在 Session 0 运行,stdout 不可被 GUI 捕获 → 本地日志视图为空,
    // 输出由服务写入其配置目标(文件/Socket/Kafka)。
    if (!svc_.isInstalled()) {
        statusLabel_->setText(tr("服务 %1 未安装,请先安装 KellectService").arg(serviceName_));
        return;
    }
    QString mode;
    switch (static_cast<OutputMode>(outputMode_)) {
        case OutputMode::File:   mode = QStringLiteral("file");   break;
        case OutputMode::Socket: mode = QStringLiteral("socket"); break;
        case OutputMode::Kafka:  mode = QStringLiteral("kafka");  break;
        default:
            statusLabel_->setText(tr("服务模式不支持控制台输出,请在设置中选择 文件/Socket/Kafka"));
            return;
    }
    WindowsServiceClient::OutputConfig cfg;
    cfg.outputMode   = mode;
    cfg.eventMask    = maskToHex(currentMask());
    cfg.outputFile   = outputFile_;
    cfg.socketHost   = socketHost_;
    cfg.socketPort   = socketPort_;
    cfg.kafkaBroker  = kafkaBroker_;
    cfg.kafkaTopic   = kafkaTopic_;
    if (!WindowsServiceClient::installRegistryConfig(cfg)) {
        statusLabel_->setText(tr("写入服务注册表配置失败(需要管理员权限)"));
        return;
    }
    forwarder_.setMode(OutputForwarder::Mode::None); // 输出归服务所有,GUI 不 tee
    svc_.setServiceName(serviceName_);
    svc_.startPolling();
    statusLabel_->setText(tr("正在启动服务…"));
    updateStatusFromServiceState(svc_.start());
}

void MainWindow::updateStatusFromServiceState(WindowsServiceClient::State s) {
    QString t;
    switch (s) {
        case WindowsServiceClient::State::Running:      t = tr("服务运行中"); break;
        case WindowsServiceClient::State::StartPending: t = tr("服务启动中…"); break;
        case WindowsServiceClient::State::StopPending:  t = tr("服务停止中…"); break;
        case WindowsServiceClient::State::Stopped:      t = tr("服务已停止"); break;
        case WindowsServiceClient::State::NotInstalled: t = tr("服务未安装"); break;
        default:                                        t = tr("服务状态未知"); break;
    }
    statusLabel_->setText(t);
}

void MainWindow::onOutputLine(const QString& line, int decodeErrors) {
    const ParsedLine pl = parseKellectLine(line);
    LogEntry e;
    e.time = QDateTime::currentDateTime();
    e.text = line;              // 原始整行(搜索/保存仍可用)
    e.decodeErrors = decodeErrors;
    e.marked = false;
    e.event = pl.event;
    e.pid = pl.pid;
    e.pname = pl.pname;
    e.detail = pl.detail;
    model_.append(e);
    model_.trimIfFull();
    logDirty_ = true;
    forwarder_.writeLine(line);   // tee 原始行;None/Kafka 模式自动 noop
}

void MainWindow::onSave() {
    // #3:格式化文本逐行写全部 source 行(不受搜索影响,保数据完整)
    const QString path = QFileDialog::getSaveFileName(
        this, tr("保存日志"), "kellect.log",
        tr("文本文件 (*.log *.txt);;所有文件 (*.*)"));
    if (path.isEmpty()) return;

    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        statusLabel_->setText(tr("保存失败:%1").arg(f.errorString()));
        return;
    }
    const auto& rows = model_.rows();
    for (const auto& e : rows) {
        // 列序与显示一致:时间(去毫秒)|事件|PID|进程名|详情
        const QString line = "[" + e.time.toString("HH:mm:ss") + "] " +
                             e.event +
                             (e.pid.isEmpty()    ? QString() : " PID=" + e.pid) +
                             (e.pname.isEmpty()  ? QString() : " " + e.pname) +
                             (e.detail.isEmpty() ? QString() : " " + e.detail) +
                             "\n";
        f.write(line.toUtf8());
    }
    f.close();
    statusLabel_->setText(tr("已保存 %1 行 → %2").arg(rows.size()).arg(QFileInfo(path).fileName()));
}

void MainWindow::onClear() { model_.clear(); }

void MainWindow::openDetailDialog(const QModelIndex& proxyIndex) {
    if (!proxyIndex.isValid()) return;
    const QModelIndex src = proxy_->mapToSource(proxyIndex);
    if (!src.isValid() || src.row() < 0 || src.row() >= model_.rows().size()) return;
    const LogEntry& e = model_.rows().at(src.row());

    QDialog dlg(this);
    dlg.setWindowTitle(e.event.isEmpty() ? tr("详情") : e.event);
    auto* lay = new QVBoxLayout(&dlg);
    auto* te = new QTextEdit(&dlg);
    te->setReadOnly(true);
    te->setFont(QFont("Consolas", 9));
    QString body;
    body += tr("事件: %1\n").arg(e.event);
    body += tr("PID: %1\n").arg(e.pid);
    body += tr("进程: %1\n").arg(e.pname);
    body += tr("详情: %1\n").arg(e.detail);
    body += QStringLiteral("\n") + tr("原始:") + QStringLiteral("\n") + e.text;
    te->setPlainText(body);
    lay->addWidget(te);
    dlg.resize(640, 320);
    dlg.exec();
}

void MainWindow::editOutputFieldsDialog(OutputMode m,
                                        QString& file, QString& sockHost, quint16& sockPort,
                                        QString& kBroker, QString& kTopic) {
    // 弹某输出模式的字段编辑子对话框;accept → 写回入参引用,reject → 不改。
    // 控制台无字段(主界面控制台行无"配置…"按钮),正常不会进来,兜底直接返回。
    if (m == OutputMode::Console) return;

    QDialog dlg(this);
    auto* lay = new QVBoxLayout(&dlg);

    QLineEdit* fileEdit = nullptr;
    QPushButton* fileBrowse = nullptr;
    QLineEdit* hostEdit = nullptr;
    QSpinBox* portSpin = nullptr;
    QLineEdit* brokerEdit = nullptr;
    QLineEdit* topicEdit = nullptr;

    // label + 单行编辑(带占位符),创建后把指针写回 out。
    auto addLabelEdit = [&dlg, lay](const QString& label, QLineEdit*& out,
                                    const QString& val, const QString& ph) {
        auto* row = new QHBoxLayout;
        row->addWidget(new QLabel(label, &dlg));
        out = new QLineEdit(val, &dlg);
        out->setPlaceholderText(ph);
        row->addWidget(out, 1);
        lay->addLayout(row);
    };

    switch (m) {
        case OutputMode::File: {
            dlg.setWindowTitle(tr("配置 文件输出"));
            addLabelEdit(tr("路径:"), fileEdit, file, tr("C:\\out.log"));
            auto* row = new QHBoxLayout;
            row->addStretch();
            fileBrowse = new QPushButton(tr("浏览…"), &dlg);
            row->addWidget(fileBrowse);
            lay->addLayout(row);
            break;
        }
        case OutputMode::Socket: {
            dlg.setWindowTitle(tr("配置 Socket 输出"));
            addLabelEdit(tr("host:"), hostEdit, sockHost, tr("192.168.1.2"));
            auto* row = new QHBoxLayout;
            row->addWidget(new QLabel(tr("port:"), &dlg));
            portSpin = new QSpinBox(&dlg);
            portSpin->setRange(0, 65535);
            portSpin->setValue(sockPort);
            row->addWidget(portSpin);
            row->addStretch();
            lay->addLayout(row);
            break;
        }
        case OutputMode::Kafka: {
            dlg.setWindowTitle(tr("配置 Kafka 输出"));
            addLabelEdit(tr("broker:"), brokerEdit, kBroker, tr("192.168.1.2:9092"));
            addLabelEdit(tr("topic:"),  topicEdit,  kTopic,  tr("kellect"));
            break;
        }
        default: return;
    }

    auto* btns = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    lay->addWidget(btns);
    connect(btns, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(btns, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

    if (fileBrowse) {
        connect(fileBrowse, &QPushButton::clicked, this, [this, fileEdit]{
            const QString cur = fileEdit->text().isEmpty()
                ? QCoreApplication::applicationDirPath() : fileEdit->text();
            const auto path = QFileDialog::getSaveFileName(this, tr("选择输出文件"), cur,
                                                           tr("日志文件 (*.log *.txt);;所有文件 (*.*)"));
            if (!path.isEmpty()) fileEdit->setText(path);
        });
    }

    if (dlg.exec() != QDialog::Accepted) return;   // 取消:不改入参

    if (fileEdit)   file     = fileEdit->text();
    if (hostEdit)   sockHost = hostEdit->text();
    if (portSpin)   sockPort = static_cast<quint16>(portSpin->value());
    if (brokerEdit) kBroker  = brokerEdit->text();
    if (topicEdit)  kTopic   = topicEdit->text();
}

void MainWindow::openSettingsDialog() {
    // 模态对话框:kellect.exe 路径 + 输出目标(控制台/文件/Socket/Kafka)
    QDialog dlg(this);
    dlg.setWindowTitle(tr("设置"));
    auto* lay = new QVBoxLayout(&dlg);

    // —— kellect.exe 路径(原有)——
    auto* row = new QHBoxLayout;
    row->addWidget(new QLabel(tr("kellect.exe 路径:")));
    auto* pathEdit = new QLineEdit(kellectExePath_, &dlg);
    row->addWidget(pathEdit, 1);
    auto* browseBtn = new QPushButton(tr("浏览…"), &dlg);
    row->addWidget(browseBtn);
    lay->addLayout(row);

    // —— 输出分组:radio + 每模式"配置…"按钮;字段收进二级对话框,避免四套字段全堆在一起 ——
    auto* outBox = new QGroupBox(tr("输出"), &dlg);
    auto* outLay = new QVBoxLayout(outBox);

    auto* rConsole = new QRadioButton(tr("控制台"), outBox);
    auto* rFile    = new QRadioButton(tr("文件"), outBox);
    auto* rSocket  = new QRadioButton(tr("Socket"), outBox);
    auto* rKafka   = new QRadioButton(tr("Kafka(kellect 直传,本地显示关)"), outBox);
    rConsole->setChecked(static_cast<OutputMode>(outputMode_) == OutputMode::Console);
    rFile->setChecked   (static_cast<OutputMode>(outputMode_) == OutputMode::File);
    rSocket->setChecked (static_cast<OutputMode>(outputMode_) == OutputMode::Socket);
    rKafka->setChecked  (static_cast<OutputMode>(outputMode_) == OutputMode::Kafka);

    // 本地值缓存:子对话框编辑这些引用;主 Apply 读它们写成员,主 Cancel 丢弃(契约同原 Apply)。
    QString file = outputFile_, sockHost = socketHost_, kBroker = kafkaBroker_, kTopic = kafkaTopic_;
    quint16 sockPort = socketPort_;

    outLay->addWidget(rConsole);   // 控制台无字段 → 无"配置…"按钮

    // 每个有字段的模式一行:radio + 拉伸 + "配置…"(弹该模式专属字段子对话框)
    auto makeCfgRow = [outBox, outLay, this](QRadioButton* r) -> QPushButton* {
        auto* row = new QHBoxLayout;
        row->addWidget(r);
        row->addStretch();
        auto* cfgBtn = new QPushButton(tr("配置…"), outBox);
        row->addWidget(cfgBtn);
        outLay->addLayout(row);
        return cfgBtn;
    };
    auto* fileCfgBtn   = makeCfgRow(rFile);
    auto* socketCfgBtn = makeCfgRow(rSocket);
    auto* kafkaCfgBtn  = makeCfgRow(rKafka);
    connect(fileCfgBtn,   &QPushButton::clicked, this,
            [this,&file,&sockHost,&sockPort,&kBroker,&kTopic]{ editOutputFieldsDialog(OutputMode::File,   file, sockHost, sockPort, kBroker, kTopic); });
    connect(socketCfgBtn, &QPushButton::clicked, this,
            [this,&file,&sockHost,&sockPort,&kBroker,&kTopic]{ editOutputFieldsDialog(OutputMode::Socket, file, sockHost, sockPort, kBroker, kTopic); });
    connect(kafkaCfgBtn,  &QPushButton::clicked, this,
            [this,&file,&sockHost,&sockPort,&kBroker,&kTopic]{ editOutputFieldsDialog(OutputMode::Kafka,  file, sockHost, sockPort, kBroker, kTopic); });

    // Windows 服务模式(与输出模式无关,留在主分组)
    auto* svcRow = new QHBoxLayout;
    auto* runAsSvcBox = new QCheckBox(tr("以 Windows 服务运行(KellectService 托管)"), outBox);
    runAsSvcBox->setChecked(runAsService_);
    svcRow->addWidget(runAsSvcBox);
    svcRow->addWidget(new QLabel(tr("服务名:")));
    auto* svcNameEdit = new QLineEdit(serviceName_, outBox);
    svcNameEdit->setPlaceholderText(QStringLiteral("KellectService"));
    svcRow->addWidget(svcNameEdit, 1);
    outLay->addLayout(svcRow);

    lay->addWidget(outBox);

    // 应用按钮(替代原 OK):即时落盘 + 刷新主界面,不关对话框(可连续改连续应用);
    // 取消/X = 关闭并丢弃自上次应用以来的改动(未点应用 = 不生效)。
    auto* btns = new QDialogButtonBox(QDialogButtonBox::Apply | QDialogButtonBox::Cancel, &dlg);
    lay->addWidget(btns);
    auto* applyStatus = new QLabel(&dlg);   // 应用反馈(空 = 尚未应用)
    lay->addWidget(applyStatus);

    // 浏览按钮
    connect(browseBtn, &QPushButton::clicked, this, [this, pathEdit]{
        const QString cur = pathEdit->text().isEmpty()
            ? QCoreApplication::applicationDirPath() : pathEdit->text();
        const auto path = QFileDialog::getOpenFileName(this, tr("选择 kellect.exe"), cur,
                                                       tr("可执行文件 (*.exe)"));
        if (!path.isEmpty()) pathEdit->setText(path);
    });
    // 输出文件的"浏览…"已随字段移入"配置…"二级对话框(editOutputFieldsDialog)。

    // 应用:读对话框控件 → 写成员 + saveSettings + 刷新主界面;不关对话框。
    auto applySettings = [this, pathEdit, rKafka, rSocket, rFile,
                          &file, &sockHost, &sockPort, &kBroker, &kTopic,
                          runAsSvcBox, svcNameEdit, applyStatus] {
        kellectExePath_ = pathEdit->text();
        if (rKafka->isChecked())        outputMode_ = static_cast<int>(OutputMode::Kafka);
        else if (rSocket->isChecked())  outputMode_ = static_cast<int>(OutputMode::Socket);
        else if (rFile->isChecked())    outputMode_ = static_cast<int>(OutputMode::File);
        else                            outputMode_ = static_cast<int>(OutputMode::Console);
        outputFile_  = file;
        socketHost_  = sockHost;
        socketPort_  = sockPort;
        kafkaBroker_ = kBroker;
        kafkaTopic_  = kTopic;
        runAsService_ = runAsSvcBox->isChecked();
        serviceName_  = svcNameEdit->text().trimmed().isEmpty()
                        ? QStringLiteral("KellectService") : svcNameEdit->text().trimmed();
        svc_.setServiceName(serviceName_);
        updatePathLabel();
        updateOutputStatus();
        saveSettings();   // 即时落盘,避免崩溃/强退丢失设置(closeEvent 仍会再存最终运行态)
        applyStatus->setText(tr("已应用并保存"));
    };
    connect(btns->button(QDialogButtonBox::Apply), &QPushButton::clicked, this, applySettings);
    connect(btns, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

    dlg.exec();   // 模态:应用即时生效;取消/X 关闭并丢弃未应用改动(返回值忽略)
}

void MainWindow::updatePathLabel() {
    const QString fn = QFileInfo(kellectExePath_).fileName();
    const QString shown = fn.isEmpty() ? kellectExePath_ : fn;
    pathLabel_->setText(QStringLiteral("<a href=\"#\">kellect.exe: %1</a>")
                            .arg(shown.toHtmlEscaped()));
    pathLabel_->setToolTip(kellectExePath_);
}

void MainWindow::loadSettings() {
    auto s = store_->load();
    // 方案A:为空则回退到 KellectConsole.exe 所在目录下的 kellect.exe
    kellectExePath_ = s.kellectExePath;
    if (kellectExePath_.trimmed().isEmpty())
        kellectExePath_ = QCoreApplication::applicationDirPath() + "/kellect.exe";
    autoScrollBox_->setChecked(s.autoScroll);
    filterEdit_->setText(s.filterKeyword);
    for (int b = 0; b < 8; ++b)
        if (auto* cb = flagBoxes_.value(static_cast<EventFlag>(1 << b)))
            cb->setChecked((s.lastMask >> b) & 1);
    outputMode_  = s.outputMode;
    outputFile_  = s.outputFile;
    socketHost_  = s.socketHost;
    socketPort_  = s.socketPort;
    kafkaBroker_ = s.kafkaBroker;
    kafkaTopic_  = s.kafkaTopic;
    runAsService_ = s.runAsService;
    serviceName_  = s.serviceName.isEmpty() ? QStringLiteral("KellectService") : s.serviceName;
    svc_.setServiceName(serviceName_);
    updateOutputStatus();
    updatePathLabel();
}

void MainWindow::saveSettings() {
    SettingsStore::Settings s;
    s.kellectExePath = kellectExePath_;
    s.lastMask = currentMask();
    s.autoScroll = autoScrollBox_->isChecked();
    s.filterKeyword = filterEdit_->text();
    s.outputMode  = outputMode_;
    s.outputFile  = outputFile_;
    s.socketHost  = socketHost_;
    s.socketPort  = socketPort_;
    s.kafkaBroker = kafkaBroker_;
    s.kafkaTopic  = kafkaTopic_;
    s.runAsService = runAsService_;
    s.serviceName  = serviceName_;
    store_->save(s);
}

void MainWindow::closeEvent(QCloseEvent* e) {
    if (runAsService_) svc_.stop(); // 回收服务托管的 kellect.exe
    proc_.stop(); // C1:关闭前回收子进程,否则 Windows 不回收提权子进程
    forwarder_.close();
    saveSettings();
    QMainWindow::closeEvent(e);
}

void MainWindow::updateOutputStatus() {
    QString t;
    switch (static_cast<OutputMode>(outputMode_)) {
        case OutputMode::Console: t = tr("输出: 控制台"); break;
        case OutputMode::File:    t = tr("输出: 文件 %1").arg(QFileInfo(outputFile_).fileName()); break;
        case OutputMode::Socket:  t = tr("输出: socket %1:%2").arg(socketHost_).arg(socketPort_); break;
        case OutputMode::Kafka:   t = tr("输出: kafka %1/%2(直传,显示关)").arg(kafkaBroker_).arg(kafkaTopic_); break;
        default:                  t = tr("输出: 控制台"); break;
    }
    if (runAsService_) t = tr("[服务模式] ") + t;
    outputLabel_->setStyleSheet(QString());   // 清红
    outputLabel_->setText(t);
}
