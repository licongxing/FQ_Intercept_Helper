#ifndef ARPSENDTHREAD_H
#define ARPSENDTHREAD_H

#include <QObject>
#include <QThread>
#include <QDebug>
#include "utils.h"

class ArpSendThread : public QThread
{
    Q_OBJECT
public:
    explicit ArpSendThread(QObject *parent = nullptr);

    ArpSendThread(uint32_t curIPAddr,uint32_t broadcastAddr,uint32_t networkAddr,const uint8_t* macAddr,QString adapterName);
    void run();

signals:
    void sendDone();
    void sendOne(int num);
public slots:
    void stopSend();
private:
    // 当前IP
    uint32_t mCurIPAddr;
    // 广播地址
    uint32_t mBroadcastAddr;
    // 网络地址
    uint32_t mNetworkAddr;
    // 物理地址
    uint8_t mMacAddr[6] = {0};
    // 网卡设备 句柄
    pcap_t *mAdapterHandle = nullptr;
    // 停止扫描 标志
    bool isScan = true;
};

#endif // ARPSENDTHREAD_H
