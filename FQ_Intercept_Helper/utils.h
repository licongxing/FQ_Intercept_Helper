#ifndef UTILS_H
#define UTILS_H
#include <stdint.h>
#include <stdlib.h>
#include <QDebug>
#define HAVE_REMOTE
#include "pcap.h"

// 以太网首部 12byte
typedef struct _ethhead{
    // 以太网目地址 6byte
    uint8_t destEthAddr[6];
    // 以太网源地址 6byte
    uint8_t srcEthAddr[6];
    // 帧类型 2byte ,ARP请求或应答
    uint16_t frameType;
}EthHead;

// ARP请求和应答数据结构 28byte
typedef struct _arpstruct{
    // 硬件地址类型，1 表示以太网地址
    uint16_t hardType;
    // 映射的协议地址类型，0x0800 表示IP地址
    uint16_t protocolType;
    // 硬件地址长度
    uint8_t hardLen;
    // 协议地址长度
    uint8_t protocolLen;
    // 操作字段，ARP请求 1，ARP 应答 2，RARP请求 3，RARP应答 4
    uint16_t op;
    // 发送到以太网地址
    uint8_t srcEthAddr[6];
    // 发送端IP地址
    uint8_t srcIpAddr[4];
    // 目的端以太网地址
    uint8_t destEthAddr[6];
    // 目的端IP地址
    uint8_t destIpAddr[4];
}ArpStruct;

// 以太网ARP请求或应答数据包 结构 42byte
typedef struct _arppackage{
    EthHead ethHead;
    ArpStruct arpBody;
}ArpPackage;


/* 将数字类型的IP地址转换成字符串类型的 */
#define IPTOSBUFFERS    12
char *iptos(u_long in);

class Utils
{
public:
    Utils();
    // 获取有效网卡的 ip -> 设备名称
    static QMap<QString,QString> geValidAdapter();

    // N字节本地字节序 转为网络字节序 dest 为传出参数，需要用户提供空间，size 转换字节的长度
    static uint8_t* htonN(const uint8_t* parm,uint8_t *dest,uint32_t size);
    // N字节网络字节序 转为本地字节序
    static uint8_t* ntohN(const uint8_t* parm,uint8_t *dest,uint32_t size);

    // 物理地址BYTE 转 HEX字符串 00-0C-56-2A-1B-DA
    static void macToHexString(const uint8_t* mac,char* hex);
    // HEX字符串 00-0C-56-2A-1B-DA 转 物理地址BYTE
    static void hexToMacByte(const char* hex,uint8_t* mac);
private:
    static void ifprocess(pcap_if_t *d,QMap<QString,QString> *map);
};

#endif // UTILS_H
