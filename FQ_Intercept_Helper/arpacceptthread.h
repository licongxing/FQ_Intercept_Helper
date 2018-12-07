#ifndef ARPACCEPTTHREAD_H
#define ARPACCEPTTHREAD_H

#include <QObject>
#include <QThread>
#include <QDebug>
#include "utils.h"

class ArpAcceptThread : public QThread
{
    Q_OBJECT
public:
    explicit ArpAcceptThread(QObject *parent = nullptr);
    ArpAcceptThread(QString adapterName,QString ip);
    ~ArpAcceptThread(){
        qDebug() << "ArpAcceptThread 析构函数";
    };
    void run();
signals:
    // 接受到ARP应答包 信号
    void acceptArp(QMap<QString,QString> info);
    // 接受完毕 信号
    void acceptDone();
public slots:
    // 停止接受ARP包 槽函数
    void stopAccept();
private:
    // 网卡设备 句柄
    pcap_t *mAdapterHandle = nullptr;
    // 是否接受包 标志
    bool isAccept = true;
    // 本机IP
    QString mIP;
};

#endif // ARPACCEPTTHREAD_H
