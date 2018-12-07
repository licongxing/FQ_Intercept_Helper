#include "utils.h"
#include <iostream>
#include <stdlib.h>
using namespace std;

Utils::Utils()
{

}
QMap<QString,QString> Utils::geValidAdapter(){
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE+1];
    // 获得接口列表
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        qDebug() << "网卡获取错误" ;
        exit(1);
    }
    // ip->设备名称（为使用pcap_open做准备）
    QMap<QString,QString> map;
    // 扫描每一项
    for(d=alldevs;d;d=d->next)
    {
        Utils::ifprocess(d,&map);
    }
    pcap_freealldevs(alldevs);
    return map;
}
void Utils::ifprocess(pcap_if_t *d,QMap<QString,QString> *map){
    pcap_addr_t *a;
    // IP地址
    for(a=d->addresses;a;a=a->next) {
        switch(a->addr->sa_family)
        {
        case AF_INET:
        {
            // 只取IPV4地址
            if (a->addr){
                map->insert(iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr),d->name);
            }

        }
            break;
        }
    }
}
uint8_t* Utils::htonN(const uint8_t* parm,uint8_t *dest,uint32_t size){
    for(uint32_t i = 0 ; i < size; i++){
        dest[i] = parm[size-1-i];
    }
    return dest;
}

uint8_t* Utils::ntohN(const uint8_t* parm,uint8_t *dest,uint32_t size){
    for(uint32_t i = 0 ; i < size; i++){
        dest[i] = parm[size-1-i];
    }
    return dest;
}


void Utils::macToHexString(const uint8_t* mac,char* macStr){
    // 二进制物理地址 转为00-0C-56-2A-1B-DA形式的字符串
    int k = 0;
    char hex[16] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'} ;
    for(int j = 0; j < 6; j++){
        macStr[k++] = hex[(mac[j] & 0xf0) >> 4];
        macStr[k++] = hex[mac[j] & 0x0f];
        macStr[k++] = '-';
    }
    macStr[k-1] = 0;
}

void Utils::hexToMacByte(const char* mac,uint8_t* macByte){
    // 还原物理地址 00-0C-56-2A-1B-DA 还原为二进制
    for( int i = 0,j = 0; i < 6*3; i+=3,j++){
        uint8_t high4 = (uint8_t)mac[i+0];
        uint8_t low4 = (uint8_t)mac[i+1];

        if( high4 < 58){
            // 0-9
            macByte[j] = macByte[j] | ((high4-48) << 4);
        }else{
            // A-F
            macByte[j] = macByte[j] | ((high4- 65 + 10) << 4);
        }

        if(low4< 58){
            macByte[j] = macByte[j] | (low4-48);
        }else{
            macByte[j] = macByte[j] | (low4-65 + 10);
        }
    }
}

char *iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}
