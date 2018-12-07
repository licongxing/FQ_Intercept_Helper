#include "widget.h"
#include <QApplication>
#include "utils.h"

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    Widget w;
    w.show();
//    qDebug() << sizeof(EthHead);
//    qDebug() << sizeof(ArpStruct);
//    qDebug() << sizeof(ArpPackage);
    return a.exec();
}
