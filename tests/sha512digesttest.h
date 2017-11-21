#ifndef SHA512DIGESTTEST_H
#define SHA512DIGESTTEST_H

#include <security/sha512digest.h>

#include <QtTest>
#include <string>

using std::string;
using namespace moon::security;

class Sha512DigestTest : public QObject
{
    Q_OBJECT
public:
    Sha512DigestTest(){}

private Q_SLOTS:
    void createTest(){
        MessageDigest *md = Sha512Digest::create();

        QVERIFY(NULL != md);
        QVERIFY(md->length() == 64);

        const string data1 = "hello";
        md->update(data1);
        QVERIFY(md->digest() == "9B71D224BD62F3785D96D46AD3EA3D73319BFBC2890CAADAE2DFF72519673CA72323C3D99BA5C11D7C7ACC6E14B8C5DA0C4663475C2E5C3ADEF46F73BCDEC043");

        md->reset();
        QVERIFY(md->digest(data1) == "9B71D224BD62F3785D96D46AD3EA3D73319BFBC2890CAADAE2DFF72519673CA72323C3D99BA5C11D7C7ACC6E14B8C5DA0C4663475C2E5C3ADEF46F73BCDEC043");

        delete md;
    }
};


#endif // SHA512DIGESTTEST_H
