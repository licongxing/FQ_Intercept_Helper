#include "updatemacthread.h"

UpdateMacThread::UpdateMacThread(QObject *parent) : QThread(parent)
{

}
void UpdateMacThread::run(){
    // 解析下载的oui文件
    qDebug() << "解析oui文件 开始";
    QFile file("oui.txt");

    // 将解析的文件 转成为json文件
    QFile jsonFile("oui.json");
    if( jsonFile.exists()){
        // 清空文件
        jsonFile.resize(0);
    }
    if(!file.open(QIODevice::ReadOnly)){
        qDebug() << "打开oui.txt文件失败";
        return;
    }
    if(!jsonFile.open(QIODevice::ReadWrite)){
        qDebug() << "打开oui.json文件失败";
        return;
    }

    QJsonObject all;
    QJsonDocument jsonDoc;
    while (!file.atEnd()) {
        QByteArray array =  file.readLine();
        QString line = QString(array);
        int index1 = line.indexOf("(hex)");
        if( index1>0 ){
            QString key = line.mid(0,index1).trimmed();
            QString value = line.mid(index1+5).trimmed();
            all[key] = value;
        }
        //Sleep(2000);
    }
    jsonDoc.setObject(all);

    QByteArray bb = jsonDoc.toJson();
    char* st = bb.data();
    jsonFile.write(st,strlen(st));
    // 关闭文件
    file.close();
    jsonFile.close();
    qDebug() << "解析oui文件 结束";
    emit updateDone();
}
