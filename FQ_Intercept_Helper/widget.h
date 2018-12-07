#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>
#include <QMessageBox>
#include <winsock2.h>
#include <iphlpapi.h>
#include <iostream>
#include <QDebug>
#include "arpsendthread.h"
#include "arpacceptthread.h"
#include "updatemacthread.h"
#include "arpattackthread.h"
#include "buttonlist.h"
#include "fqmessage.h"

using namespace std;

namespace Ui {
class Widget;
}

class Widget : public QWidget
{
    Q_OBJECT

public:
    explicit Widget(QWidget *parent = nullptr);
    ~Widget();
private:
    void getAllAdapterInfo();
    void fillAdapterInfo();
signals:
    void stopScan();

private slots:
    void on_scanButton_clicked();

    void on_stopButton_clicked();

    void on_clearButton_clicked();

    void on_updateButton_clicked();

private:
    Ui::Widget *ui;
    WSADATA mWasData;
    // 网卡信息列表
    QList<QMap<QString,QString>> mAdapterList;
    // 网卡名称，IP->设备名称
    QMap<QString,QString> mAdapterName;
    // ARP发送线程
    ArpSendThread* mArpSendThread;
    // ARP接受线程
    ArpAcceptThread* mArpAcceptThread;
    // 厂商Mac地址处理
    UpdateMacThread* mUpdateMacThread;
    // ARP攻击线程
    ArpAttackThread* mArpAttackThread;

    // 下来厂商Mac文件
    QNetworkAccessManager qnam;
    QNetworkReply *reply;
    QFile *file;
    bool httpRequestAborted;

    // 记录扫描到的网卡 数量
    int mMacNum = 0;
    // 局域网ip -> mac映射
    QMap<QString,QString> mIpMac;
};

#endif // WIDGET_H
