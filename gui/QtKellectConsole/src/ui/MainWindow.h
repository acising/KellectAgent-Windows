// src/ui/MainWindow.h
#pragma once
#include <QMainWindow>
#include <QHash>
#include <QString>
#include "LogModel.h"
#include "../process/KellectProcessService.h"
#include "../process/OutputForwarder.h"
#include "../domain/SettingsStore.h"
#include "../domain/Flags.h"

class QCheckBox;
class QComboBox;
class QPushButton;
class QLineEdit;
class QLabel;
class QListView;
class QTimer;
class QSortFilterProxyModel;

class MainWindow : public QMainWindow {
    Q_OBJECT
    enum class OutputMode;   // 前向声明:方法签名提前引用(完整定义见私有成员区)
public:
    explicit MainWindow(SettingsStore* store, QWidget* parent = nullptr);
protected:
    void closeEvent(QCloseEvent* e) override;
private slots:
    void onStart();
    void onStop();
    void onOutputLine(const QString& line);
    void onSave();
    void onClear();
    void openSettingsDialog();
    void openServicePanel();   // 管理 KellectService.exe（无 GUI 的服务形态）
private:
    void openDetailDialog(const QModelIndex& proxyIndex);
    // 弹某输出模式的字段编辑子对话框(openSettingsDialog 的"配置…"按钮调用)。
    void editOutputFieldsDialog(OutputMode m, QString& file, QString& sockHost,
                                quint16& sockPort);
private:
    void applyPreset(int idx);
    quint8 currentMask() const;
    void loadSettings();
    void saveSettings();
    void updatePathLabel();
    void updateOutputStatus();

    SettingsStore* store_;
    KellectProcessService proc_;
    enum class OutputMode { Console = 0, File = 1, Socket = 2 };
    OutputForwarder forwarder_;
    int outputMode_ = 0;
    QString outputFile_, socketHost_;
    quint16 socketPort_ = 0;
    QLabel* outputLabel_ = nullptr;
    LogModel model_;
    QHash<kellect::EventFlag, QCheckBox*> flagBoxes_;
    QComboBox* presetCombo_ = nullptr;
    QString kellectExePath_;          // kellect.exe 路径(唯一真相源)
    QLineEdit* filterEdit_ = nullptr;
    QCheckBox* autoScrollBox_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    QLabel* pathLabel_ = nullptr;     // 状态区显示当前 exe 路径(可点开设置)
    QListView* view_ = nullptr;
    QSortFilterProxyModel* proxy_ = nullptr;
    QTimer* scrollTimer_ = nullptr;
    bool logDirty_ = false;
};
