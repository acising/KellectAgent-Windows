// src/service/ServicePanel.cpp
#include "ServicePanel.h"

#include <QDir>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QLabel>
#include <QProcess>
#include <QPushButton>
#include <QVBoxLayout>

namespace kellect {

namespace {
const char* kServiceName = "KellectAgent";
}

ServicePanel::ServicePanel(const QString& kellectExePath, QWidget* parent)
    : QDialog(parent), kellectExePath_(kellectExePath) {
    setWindowTitle(tr("Windows 服务 (KellectAgent)"));
    setMinimumWidth(480);

    // 服务程序与 kellect.exe 同目录（bin\ 或安装根目录）。
    const QString dir = QFileInfo(kellectExePath_).absolutePath();
    const QString candidate = QDir(dir).filePath(QStringLiteral("KellectService.exe"));
    if (QFileInfo::exists(candidate)) serviceExePath_ = candidate;

    auto* lay = new QVBoxLayout(this);

    statusLabel_ = new QLabel(this);
    statusLabel_->setWordWrap(true);
    statusLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    lay->addWidget(statusLabel_);

    auto* row = new QHBoxLayout;
    auto* refreshBtn = new QPushButton(tr("刷新"), this);
    auto* installBtn = new QPushButton(tr("安装并启动"), this);
    auto* startBtn = new QPushButton(tr("启动"), this);
    auto* stopBtn = new QPushButton(tr("停止"), this);
    auto* uninstallBtn = new QPushButton(tr("卸载"), this);
    row->addWidget(refreshBtn);
    row->addWidget(installBtn);
    row->addWidget(startBtn);
    row->addWidget(stopBtn);
    row->addWidget(uninstallBtn);
    lay->addLayout(row);

    hintLabel_ = new QLabel(this);
    hintLabel_->setWordWrap(true);
    hintLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    lay->addWidget(hintLabel_);

    auto* bottom = new QHBoxLayout;
    bottom->addStretch(1);
    auto* closeBtn = new QPushButton(tr("关闭"), this);
    bottom->addWidget(closeBtn);
    lay->addLayout(bottom);

    connect(refreshBtn, &QPushButton::clicked, this, [this] { refreshStatus(); });
    connect(installBtn, &QPushButton::clicked, this, [this] {
        runCommand(QStringList{QStringLiteral("--install")});
    });
    connect(uninstallBtn, &QPushButton::clicked, this, [this] {
        runCommand(QStringList{QStringLiteral("--uninstall")});
    });
    connect(startBtn, &QPushButton::clicked, this, [this] {
        QProcess::execute(QStringLiteral("sc"),
                          {QStringLiteral("start"), QString::fromLatin1(kServiceName)});
        refreshStatus();
    });
    connect(stopBtn, &QPushButton::clicked, this, [this] {
        QProcess::execute(QStringLiteral("sc"),
                          {QStringLiteral("stop"), QString::fromLatin1(kServiceName)});
        refreshStatus();
    });
    connect(closeBtn, &QPushButton::clicked, this, &QDialog::accept);

    if (serviceExePath_.isEmpty()) {
        for (QPushButton* b : {installBtn, startBtn, stopBtn, uninstallBtn}) b->setEnabled(false);
        hintLabel_->setText(tr("未找到 KellectService.exe（应与 kellect.exe 位于同一目录）。\n"
                               "请先构建服务端：cmd /c scripts\\build-collector.bat"));
    } else {
        hintLabel_->setText(
            tr("服务程序：%1\n配置：%2\\config\\agent.ini\n"
               "采集事件写入 agent.ini 中的 file=（默认 %ProgramData%\\Kellect\\events\\）。")
                .arg(serviceExePath_, QFileInfo(serviceExePath_).absolutePath()));
    }

    refreshStatus();
}

QString ServicePanel::runCapture(const QStringList& args) {
    if (serviceExePath_.isEmpty()) return QString();

    QProcess process;
    process.start(serviceExePath_, args);
    if (!process.waitForStarted(3000)) return QString();
    if (!process.waitForFinished(15000)) {
        process.kill();
        process.waitForFinished(1000);
        return QString();
    }
    return QString::fromUtf8(process.readAllStandardOutput()).trimmed();
}

void ServicePanel::refreshStatus() {
    if (serviceExePath_.isEmpty()) {
        statusLabel_->setText(tr("状态：服务程序缺失"));
        return;
    }

    QString out = runCapture(QStringList{QStringLiteral("--status")});
    if (out.isEmpty()) {
        statusLabel_->setText(tr("状态：无法查询（服务未安装，或需要管理员权限）"));
        return;
    }
    statusLabel_->setText(tr("状态：%1").arg(out));
}

void ServicePanel::runCommand(const QStringList& args) {
    if (serviceExePath_.isEmpty()) return;

    const int rc = QProcess::execute(serviceExePath_, args);
    if (rc == 0) {
        hintLabel_->setText(tr("命令成功：%1").arg(args.join(' ')));
    } else {
        hintLabel_->setText(tr("命令失败（退出码 %1）：%2\n"
                               "安装/卸载需要管理员权限。").arg(rc).arg(args.join(' ')));
    }
    refreshStatus();
}

} // namespace kellect
