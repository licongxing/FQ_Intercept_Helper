#include "fqmessage.h"
#include "ui_fqmessage.h"

FqMessage::FqMessage(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::FqMessage)
{
    ui->setupUi(this);
}

FqMessage::FqMessage(QString atkIpAddr,QString curMacAddr,QMap<QString,QString> ipMac,QWidget *parent) :
    QWidget(parent),
    ui(new Ui::FqMessage)
{
    ui->setupUi(this);
    this->mAtkIpAddr = atkIpAddr;
    this->mCurMacAddr = curMacAddr;
    this->mIpMac = ipMac;
}
FqMessage::~FqMessage()
{
    delete ui;
}
