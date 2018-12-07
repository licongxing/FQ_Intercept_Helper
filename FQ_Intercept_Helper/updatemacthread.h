#ifndef UPDATEMACTHREAD_H
#define UPDATEMACTHREAD_H

#include <QObject>
#include <QThread>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QFile>
#include <windows.h>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>

class UpdateMacThread : public QThread
{
    Q_OBJECT
public:
    explicit UpdateMacThread(QObject *parent = nullptr);
    void run();
    void httpReadyRead();
    void httpFinished();
signals:
    void updateDone();
public slots:
private:
    // http请求错误
    bool httpRequestAborted = false;
    // Mac厂商文件是否下载完毕
    bool isDownDone = false;
};

#endif // UPDATEMACTHREAD_H
