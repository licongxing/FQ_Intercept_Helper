#-------------------------------------------------
#
# Project created by QtCreator 2018-11-29T08:03:39
#
#-------------------------------------------------

QT       += core gui network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = FQ_Intercept_Helper
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

CONFIG += c++11

SOURCES += \
        main.cpp \
        widget.cpp \
    utils.cpp \
    arpsendthread.cpp \
    arpacceptthread.cpp \
    updatemacthread.cpp \
    buttonlist.cpp \
    arpattackthread.cpp \
    fqmessage.cpp \
    fqmsginterceptthread.cpp

HEADERS += \
        widget.h \
    arpsendthread.h \
    utils.h \
    arpsendthread.h \
    arpacceptthread.h \
    updatemacthread.h \
    buttonlist.h \
    arpattackthread.h \
    fqmessage.h \
    fqmsginterceptthread.h

FORMS += \
        widget.ui \
    buttonlist.ui \
    fqmessage.ui

LIBS += -lpthread libwsock32 libws2_32 libiphlpapi

INCLUDEPATH += E:/Soft/Soft_Tool/WpdPack_4_1_2/WpdPack/Include
LIBS += E:/Soft/Soft_Tool/WpdPack_4_1_2/WpdPack/Lib/wpcap.lib


# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
