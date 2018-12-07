#include "arpacceptthread.h"

ArpAcceptThread::ArpAcceptThread(QObject *parent) : QThread(parent)
{

}
ArpAcceptThread::ArpAcceptThread(QString adapterName,QString ip){
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
    this->mIP = ip;
}

void ArpAcceptThread::run(){
    if( this->mAdapterHandle == nullptr){
        qDebug() << "网卡设备没有开启";
        return;
    }

    int res;
    struct tm *ltime;
    char timestr[16];
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    time_t local_tv_sec;
    struct bpf_program fcode;
    QMap<QString,QString> info;

    // 表达式 (arp[16:2]&0x00010!=0) and (dst host 192.168.1.2)
    // (arp[6:2]&0x0002!=0) 过滤ARP应答
    // http://www.ferrisxu.com/WinPcap/html/group__language.html 过滤表达
    QString exp = QString("(arp[6:2]&0x0002!=0)");

    // compile the filter
    if (pcap_compile(this->mAdapterHandle, &fcode, exp.toStdString().c_str() , 1, 0) < 0)
    {
        qDebug() << "pcap_compile error:" <<  pcap_geterr(this->mAdapterHandle);

    }

    // set the filter
    if (pcap_setfilter(this->mAdapterHandle, &fcode) < 0)
    {
        qDebug() << "pcap_setfilter error";
    }

    // 获取数据包
    while((res = pcap_next_ex( this->mAdapterHandle, &header, &pkt_data)) >= 0){
        if( this->isAccept == false)
            break;
        if(res == 0)
            // 超时时间到
            continue;

        // 将时间戳转换成可识别的格式
        local_tv_sec = header->ts.tv_sec;
        ltime=localtime(&local_tv_sec);
        strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
        printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
        fflush(stdout);

        const ArpPackage *package = reinterpret_cast<const ArpPackage*>(pkt_data);
        struct in_addr addr ;
        memcpy(&addr.S_un.S_addr,package->arpBody.srcIpAddr,4);
        info["ip"] = inet_ntoa(addr);
        qDebug() << "ip=" << inet_ntoa(addr);
        // 从视觉上看 macCh已经转为本地字节序
        char macCh[18] = {0};
        Utils::macToHexString(package->arpBody.srcEthAddr,macCh);
        qDebug() << "mac=" << macCh;
        info["mac"] = QString(macCh);
        emit acceptArp(info);
    }

    if(res == -1){
        qDebug() << "Error reading the packets: "<< pcap_geterr(this->mAdapterHandle);
    }
    emit acceptDone();
}

void ArpAcceptThread::stopAccept(){
    this->isAccept = false;
}
