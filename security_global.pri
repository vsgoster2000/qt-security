# Append current directory into the path where the compiler to find the head files
INCLUDEPATH += $$PWD

PROJECT_DIR = $$PWD
PROJECT_SRC = $$PWD/security

INCLUDEPATH += D:\software\dev\qt\platform\include\platform
INCLUDEPATH += C:/OpenSSL-Win32/include

LIBS += -LD:\software\dev\qt\platform\lib
LIBS += -l$$qtLibraryTarget(platform_base)

LIBS += -LC:/OpenSSL-Win32/lib -llibcrypto
LIBS += -LC:/OpenSSL-Win32/lib -llibssl
LIBS += -LC:/OpenSSL-Win32/lib -lopenssl
