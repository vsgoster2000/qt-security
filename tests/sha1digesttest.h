#ifndef SHA1DIGESTTEST_H
#define SHA1DIGESTTEST_H

#include <security/sha1digest.h>

#include <QtTest>
#include <string>

using std::string;
using namespace moon::security;

class Sha1DigestTest : public QObject
{
    Q_OBJECT
public:
    Sha1DigestTest(){}

private Q_SLOTS:
    void createTest(){
        MessageDigest *md = Sha1Digest::create();

        QVERIFY(NULL != md);
        QVERIFY(md->length() == 20);

        const string data1 = "hello";
        md->update(data1);
        QVERIFY(md->digest() == "AAF4C61DDCC5E8A2DABEDE0F3B482CD9AEA9434D");

        md->reset();
        QVERIFY(md->digest(data1) == "AAF4C61DDCC5E8A2DABEDE0F3B482CD9AEA9434D");

        delete md;
    }
};

#endif // SHA1DIGESTTEST_H
