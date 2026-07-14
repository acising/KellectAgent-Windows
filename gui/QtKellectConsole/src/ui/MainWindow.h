// src/ui/MainWindow.h
#pragma once
#include <QMainWindow>
#include <QHash>
#include <QString>
#include "LogModel.h"
#include "../process/KellectProcessService.h"
#include "../domain/SettingsStore.h"
#include "../domain/Flags.h" // Resolution #1: EventFlag 位于 namespace kellect

class QCheckBox;
class QComboBox;
class QLineEdit;
class QLabel;
class QListView;
class QTimer;
class QSortFilterProxyModel;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(SettingsStore* store, QWidget* parent = nullptr);
protected:
    void closeEvent(QCloseEvent* e) override;
private slots:
    void onStart();
    void onStop();
    void onOutputLine(const QString& line, int decodeErrors);
    void onSave();
    void onClear();
    void openSettingsDialog();
private:
    void openDetailDialog(const QModelIndex& proxyIndex);
private:
    void applyPreset(int idx);
    quint8 currentMask() const;
    void loadSettings();
    void saveSettings();
    void updatePathLabel();

    SettingsStore* store_;
    KellectProcessService proc_;
    LogModel model_;
    QHash<kellect::EventFlag, QCheckBox*> flagBoxes_; // Resolution #1: 全限定
    QComboBox* presetCombo_ = nullptr;
    QString kellectExePath_;          // 方案A:路径真相源(替代 exeEdit_)
    QLineEdit* filterEdit_ = nullptr;
    QCheckBox* autoScrollBox_ = nullptr;
    QLabel* errLabel_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    QLabel* pathLabel_ = nullptr;     // 状态区显示当前 exe 路径(可点开设置)
    QListView* view_ = nullptr;
    QSortFilterProxyModel* proxy_ = nullptr;
    QTimer* scrollTimer_ = nullptr;
    bool logDirty_ = false;
};
