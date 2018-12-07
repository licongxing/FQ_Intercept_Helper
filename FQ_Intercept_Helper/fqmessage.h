#ifndef FQMESSAGE_H
#define FQMESSAGE_H

#include <QWidget>
#include "utils.h"

namespace Ui {
class FqMessage;
}

class FqMessage : public QWidget
{
    Q_OBJECT

public:
    explicit FqMessage(QWidget *parent = nullptr);
    FqMessage(QString atkIpAddr,QString curMacAddr,QMap<QString,QString> ipMac,QWidget *parent = nullptr);
    ~FqMessage();

private:
    Ui::FqMessage *ui;
    QString mAtkIpAddr;
    QString mCurMacAddr;
    QMap<QString,QString> mIpMac;
};

#endif // FQMESSAGE_H
