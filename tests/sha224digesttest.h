#ifndef SHA224DIGESTTEST_H
#define SHA224DIGESTTEST_H

#include <security/sha224digest.h>

#include <QtTest>
#include <string>

using std::string;
using namespace moon::security;

class Sha224DigestTest : public QObject
{
    Q_OBJECT
public:
    Sha224DigestTest(){}

private Q_SLOTS:
    void createTest(){
        MessageDigest *md = Sha224Digest::create();

        QVERIFY(NULL != md);
        QVERIFY(md->length() == 28);

        const string data1 = "hello";
        md->update(data1);
        QVERIFY(md->digest() == "EA09AE9CC6768C50FCEE903ED054556E5BFC8347907F12598AA24193");

        md->reset();
        QVERIFY(md->digest(data1) == "EA09AE9CC6768C50FCEE903ED054556E5BFC8347907F12598AA24193");

        delete md;
    }
};


#endif // SHA224DIGESTTEST_H
