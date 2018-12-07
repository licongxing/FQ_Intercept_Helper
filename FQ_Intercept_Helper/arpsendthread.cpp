#include "arpsendthread.h"

ArpSendThread::ArpSendThread(QObject *parent) : QThread(parent)
{

}

ArpSendThread::ArpSendThread(uint32_t curIPAddr,uint32_t broadcastAddr,uint32_t networkAddr,const uint8_t* macAddr,QString adapterName)
{
    mCurIPAddr = curIPAddr;
    mBroadcastAddr = broadcastAddr;
    mNetworkAddr = networkAddr;
    memcpy(mMacAddr,macAddr,sizeof(uint8_t)*6);

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
// 发送ARP报文
void ArpSendThread::run()
{
    if( this->mAdapterHandle == nullptr){
        qDebug() << "网卡设备没有开启";
        return;
    }
    char tmp[18] = {0};
    Utils::macToHexString(this->mMacAddr,tmp);
    qDebug() <<"begin：" << tmp;

    // 构造ARP请求包 ，2字节及以上的 存在大小端对齐问题，需要转换为网络字节序
    ArpPackage package;

    // 以太网 头部
    uint64_t ethBroadcastAddr = 0xffffffffffff;// 6字节 以太网 广播地址，局域网主机无条件接受
    memcpy(package.ethHead.destEthAddr,&ethBroadcastAddr,6);
    memcpy(package.ethHead.srcEthAddr,this->mMacAddr,6);
    package.ethHead.frameType = htons(0x0806);

    memset(tmp,0,18);
    Utils::macToHexString(this->mMacAddr,tmp);
    qDebug() <<"origin：" << tmp;

    memset(tmp,0,18);
    Utils::macToHexString(package.ethHead.srcEthAddr,tmp);
    qDebug() <<"now：" << tmp;

    // 构造ARP请求体内容
    package.arpBody.hardType = htons(1);// 以太网地址
    package.arpBody.protocolType = htons(0x0800); // IP地址
    package.arpBody.hardLen = 6;
    package.arpBody.protocolLen = 4;
    package.arpBody.op = htons(1);

    memcpy(package.arpBody.srcEthAddr,this->mMacAddr,6);
    // 硬件厂商 Mac地址 http://standards-oui.ieee.org/oui/oui.txt
    Utils::htonN(reinterpret_cast<uint8_t*>(&(this->mCurIPAddr)),package.arpBody.srcIpAddr,4);
    memset(package.arpBody.destEthAddr,0,6);
    int i = 1;
    // 往当前局域网中所有IP发送 ARP报文
    for(uint32_t ipAddr = mNetworkAddr+1; ipAddr < mBroadcastAddr; ipAddr++,i++){
        if(this->isScan == false)
            break;
        if( ipAddr == this->mCurIPAddr)
            continue;

        struct in_addr addr;
        addr.S_un.S_addr = htonl(ipAddr);
        qDebug() << inet_ntoa( addr);

        Utils::htonN(reinterpret_cast<uint8_t*>(&(ipAddr)),package.arpBody.destIpAddr,4);
        int ret = pcap_sendpacket(this->mAdapterHandle,reinterpret_cast<unsigned char*>(&package),42);
        if( ret != 0){
            qDebug() << inet_ntoa( addr) << " 发送失败！" ;
        }
        emit sendOne(i);
        Sleep(100);
    }

    // 关闭设备
    pcap_close(this->mAdapterHandle);

    // arp数据包发送完毕，通知主线程
    emit sendDone();
}

void ArpSendThread::stopSend(){
    this->isScan = false;
}
