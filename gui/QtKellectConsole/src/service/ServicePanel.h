// src/service/ServicePanel.h
#pragma once
//
// 服务面板：管理 KellectService.exe（无 GUI 的 Windows 服务形态）。
//
// GUI 自身仍以子进程方式运行 kellect.exe（崩溃隔离、不共享 ETW 全局状态）；
// 这个对话框用于在同一个界面里查询/安装/启停/卸载服务产品。
// GUI 的 manifest 要求管理员权限，因此子进程（--install/--uninstall）天然带权限。
#include <QDialog>
#include <QString>
#include <QStringList>

class QLabel;

namespace kellect {

class ServicePanel : public QDialog {
    Q_OBJECT
public:
    explicit ServicePanel(const QString& kellectExePath, QWidget* parent = nullptr);

private:
    void refreshStatus();
    void runCommand(const QStringList& args);
    QString runCapture(const QStringList& args);

    QString kellectExePath_;
    QString serviceExePath_;
    QLabel* statusLabel_ = nullptr;
    QLabel* hintLabel_ = nullptr;
};

} // namespace kellect
