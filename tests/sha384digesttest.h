#ifndef SHA384DIGESTTEST_H
#define SHA384DIGESTTEST_H

#include <security/sha384digest.h>

#include <QtTest>
#include <string>

using std::string;
using namespace moon::security;

class Sha384DigestTest : public QObject
{
    Q_OBJECT
public:
    Sha384DigestTest(){}

private Q_SLOTS:
    void createTest(){
        MessageDigest *md = Sha384Digest::create();

        QVERIFY(NULL != md);
        QVERIFY(md->length() == 48);

        const string data1 = "hello";
        md->update(data1);
        QVERIFY(md->digest() == "59E1748777448C69DE6B800D7A33BBFB9FF1B463E44354C3553BCDB9C666FA90125A3C79F90397BDF5F6A13DE828684F");

        md->reset();
        QVERIFY(md->digest(data1) == "59E1748777448C69DE6B800D7A33BBFB9FF1B463E44354C3553BCDB9C666FA90125A3C79F90397BDF5F6A13DE828684F");

        delete md;
    }
};


#endif // SHA384DIGESTTEST_H
