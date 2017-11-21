#-------------------------------------------------
#
# Project created by QtCreator 2017-11-14T10:05:02
#
#-------------------------------------------------
include(../security_global.pri)
QT       -= gui

TARGET = $$qtLibraryTarget(platform_security)
TEMPLATE = lib
CONFIG += staticlib c++11 debug_and_release build_all

DESTDIR = D:\software\dev\qt\platform\lib

# The following define makes your compiler emit warnings if you use
# any feature of Qt which as been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

HEADERS += \
    $$PWD/des.h \
    $$PWD/deskey.h \
    $$PWD/messagedigest.h \
    $$PWD/md5digest.h \
    $$PWD/sha1digest.h \
    $$PWD/sha224digest.h \
    $$PWD/sha256digest.h \
    $$PWD/sha384digest.h \
    $$PWD/sha512digest.h \
    filedigest.h

SOURCES += \
    $$PWD/des.cpp \
    $$PWD/deskey.cpp \
    $$PWD/messagedigest.cpp \
    $$PWD/md5digest.cpp \
    $$PWD/sha1digest.cpp \
    $$PWD/sha224digest.cpp \
    $$PWD/sha256digest.cpp \
    $$PWD/sha384digest.cpp \
    $$PWD/sha512digest.cpp \
    filedigest.cpp

