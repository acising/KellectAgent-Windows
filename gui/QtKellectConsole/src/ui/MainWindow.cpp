// src/ui/MainWindow.cpp
#include "MainWindow.h"
#include "LogDelegate.h"
#include "LogHeader.h"
#include "../domain/Preset.h"
#include "../domain/LogParser.h"
#include <QCheckBox>
#include <QComboBox>
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

    // 组3:过滤 + 自动滚动 + 异常计数
    auto* optBox = new QGroupBox(tr("显示"));
    auto* optLay = new QHBoxLayout(optBox);
    filterEdit_ = new QLineEdit;
    filterEdit_->setPlaceholderText(tr("过滤关键字…"));
    autoScrollBox_ = new QCheckBox(tr("自动滚动"), optBox);
    autoScrollBox_->setChecked(true);
    errLabel_ = new QLabel(QStringLiteral("⚠ 0"));
    errLabel_->setObjectName("errLabel"); // Resolution #3:让 dark.qss 的 QLabel#errLabel 规则生效
    optLay->addWidget(new QLabel(tr("过滤:")));
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
    // proxy 套在 model_ 上做关键字过滤;view 看 proxy。delegate 经 proxy 的 data()
    // 转发读 source 各 role,无需改;书签/autoscroll 的 index 走 proxy↔source 映射。
    proxy_ = new QSortFilterProxyModel(this);
    proxy_->setSourceModel(&model_);
    proxy_->setFilterRole(LogModel::TextRole);       // 按正文匹配
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

    // —— 自动滚动节流(QTimer 120ms,与 CollectionChanged 解耦)——
    scrollTimer_ = new QTimer(this);
    scrollTimer_->setInterval(120);
    scrollTimer_->start();
    connect(scrollTimer_, &QTimer::timeout, this, [this]{
        if (!logDirty_) return;
        logDirty_ = false;
        // scrollToBottom 走 view/proxy 内容:过滤时滚到最后一条匹配,不过滤时最后一条。
        if (autoScrollBox_->isChecked() && proxy_->rowCount() > 0)
            view_->scrollToBottom();
    });

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
    if (kellectExePath_.trimmed().isEmpty()) {
        statusLabel_->setText(tr("请先在设置中选择 kellect.exe"));
        return;
    }
    proc_.start(kellectExePath_.trimmed(), buildKellectArgs(currentMask()));
}

void MainWindow::onStop() { proc_.stop(); }

void MainWindow::onOutputLine(const QString& line, int decodeErrors) {
    const ParsedLine pl = parseKellectLine(line);
    LogEntry e;
    e.time = QDateTime::currentDateTime();
    e.text = line;              // 原始整行(过滤/保存仍可用)
    e.decodeErrors = decodeErrors;
    e.marked = false;
    e.event = pl.event;
    e.pid = pl.pid;
    e.pname = pl.pname;
    e.detail = pl.detail;
    model_.append(e);
    model_.trimIfFull();
    logDirty_ = true;
}

void MainWindow::onSave() {
    // #3:格式化文本逐行写全部 source 行(不过滤,保数据完整)
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
        const QString line = "[" + e.time.toString("HH:mm:ss.zzz") + "] " +
                             e.event +
                             (e.pid.isEmpty()    ? QString() : " PID=" + e.pid) +
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

void MainWindow::openSettingsDialog() {
    // 方案A:模态对话框,内含 exe 路径输入 + 浏览 + OK/取消
    QDialog dlg(this);
    dlg.setWindowTitle(tr("设置"));
    auto* lay = new QVBoxLayout(&dlg);

    auto* row = new QHBoxLayout;
    row->addWidget(new QLabel(tr("kellect.exe 路径:")));
    auto* pathEdit = new QLineEdit(kellectExePath_, &dlg);
    row->addWidget(pathEdit, 1);
    auto* browseBtn = new QPushButton(tr("浏览…"), &dlg);
    row->addWidget(browseBtn);
    lay->addLayout(row);

    auto* btns = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    lay->addWidget(btns);

    connect(browseBtn, &QPushButton::clicked, this, [this, pathEdit]{
        const QString cur = pathEdit->text().isEmpty()
            ? QCoreApplication::applicationDirPath() : pathEdit->text();
        const auto path = QFileDialog::getOpenFileName(this, tr("选择 kellect.exe"), cur,
                                                       tr("可执行文件 (*.exe)"));
        if (!path.isEmpty()) pathEdit->setText(path);
    });
    connect(btns, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(btns, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

    if (dlg.exec() == QDialog::Accepted) {
        kellectExePath_ = pathEdit->text();
        updatePathLabel();
    }
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
    updatePathLabel();
}

void MainWindow::saveSettings() {
    SettingsStore::Settings s;
    s.kellectExePath = kellectExePath_;
    s.lastMask = currentMask();
    s.autoScroll = autoScrollBox_->isChecked();
    s.filterKeyword = filterEdit_->text();
    store_->save(s);
}

void MainWindow::closeEvent(QCloseEvent* e) {
    proc_.stop(); // C1:关闭前回收子进程,否则 Windows 不回收提权子进程
    saveSettings();
    QMainWindow::closeEvent(e);
}
