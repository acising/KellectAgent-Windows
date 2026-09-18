// src/ui/MainWindow.h
#pragma once
#include <QMainWindow>
#include <QHash>
#include <QString>
#include "LogModel.h"
#include "../process/KellectProcessService.h"
#include "../process/OutputForwarder.h"
#include "../process/WindowsServiceClient.h"
#include "../domain/SettingsStore.h"
#include "../domain/Flags.h" // Resolution #1: EventFlag 位于 namespace kellect

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
private:
    void openDetailDialog(const QModelIndex& proxyIndex);
    // 弹某输出模式的字段编辑子对话框(openSettingsDialog 的"配置…"按钮调用)。
    void editOutputFieldsDialog(OutputMode m, QString& file, QString& sockHost,
                                quint16& sockPort, QString& kBroker, QString& kTopic);
private:
    void applyPreset(int idx);
    quint8 currentMask() const;
    void loadSettings();
    void saveSettings();
    void updatePathLabel();
    void updateOutputStatus();
    void startViaService();   // 服务模式启动分支
    void updateStatusFromServiceState(kellect::WindowsServiceClient::State s);

    SettingsStore* store_;
    KellectProcessService proc_;
    enum class OutputMode { Console = 0, File = 1, Socket = 2, Kafka = 3 };
    OutputForwarder forwarder_;
    int outputMode_ = 0;
    QString outputFile_, socketHost_, kafkaBroker_, kafkaTopic_;
    quint16 socketPort_ = 0;
    bool runAsService_ = false;                          // Windows 服务模式开关
    QString serviceName_ = QStringLiteral("KellectService");
    kellect::WindowsServiceClient svc_;                 // 服务模式 SCM 客户端(无 parent,成员析构回收)
    QLabel* outputLabel_ = nullptr;
    LogModel model_;
    QHash<kellect::EventFlag, QCheckBox*> flagBoxes_; // Resolution #1: 全限定
    QComboBox* presetCombo_ = nullptr;
    QString kellectExePath_;          // 方案A:路径真相源(替代 exeEdit_)
    QLineEdit* filterEdit_ = nullptr;
    QCheckBox* autoScrollBox_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    QLabel* pathLabel_ = nullptr;     // 状态区显示当前 exe 路径(可点开设置)
    QListView* view_ = nullptr;
    QSortFilterProxyModel* proxy_ = nullptr;
    QTimer* scrollTimer_ = nullptr;
    bool logDirty_ = false;
};
