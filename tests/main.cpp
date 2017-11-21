#include "deskeytest.h"
#include "destest.h"
#include "filedigesttest.h"
#include "messagedigesttest.h"
#include "md5digesttest.h"
#include "sha1digesttest.h"
#include "sha224digesttest.h"
#include "sha256digesttest.h"
#include "sha384digesttest.h"
#include "sha512digesttest.h"
#include <QCoreApplication>
#include <QDebug>
#include <QTest>

void addTest(QObject *testObject, bool failedToAbort = true)
{
    if (QTest::qExec(testObject) != 0){
        qCritical("Test [%s] failed!", testObject->metaObject()->className());
        if (failedToAbort){
            abort();
        }
    }
}

int main(int argc, char *argv[]){
    QCoreApplication(argc, argv);

    addTest(new DesKeyTest());
    addTest(new DesTest());
    addTest(new FileDigestTest());
    addTest(new MessageDigestTest());
    addTest(new MD5DigestTest());
    addTest(new Sha1DigestTest());
    addTest(new Sha224DigestTest());
    addTest(new Sha256DigestTest());
    addTest(new Sha384DigestTest());
    addTest(new Sha512DigestTest());
    return 0;
}


