#ifndef FQMSGINTERCEPTTHREAD_H
#define FQMSGINTERCEPTTHREAD_H

#include <QObject>
#include <QThread>
#include "utils.h"

class FqMsgInterceptThread : public QThread
{
    Q_OBJECT
public:
    explicit FqMsgInterceptThread(QObject *parent = nullptr);
    FqMsgInterceptThread(QString curIPAddr,QString curMacAddr,QString mAtkIPAddr,QString adapterName,QObject *parent = nullptr);
    void run();

signals:

public slots:

private:
    // 当前IP
    QString mCurIPAddr;
    // 物理地址
    QString mCurMacAddr;
    // 拦截的IP
    QString mAtkIPAddr;

    // 网卡设备 句柄
    pcap_t *mAdapterHandle = nullptr;
    // 停止拦截 标志
    bool isIntercept = true;
};

#endif // FQMSGINTERCEPTTHREAD_H
