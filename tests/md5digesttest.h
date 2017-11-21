#ifndef MD5DIGESTTEST_H
#define MD5DIGESTTEST_H

#include <security/md5digest.h>

#include <QtTest>

#include <string>

using std::string;
using namespace moon::security;

class MD5DigestTest : public QObject
{
    Q_OBJECT
public:
    MD5DigestTest(){}

private Q_SLOTS:
    void createTest(){
        MessageDigest *md5 = MD5Digest::create();

        QVERIFY(NULL != md5);
        QVERIFY(md5->length() == 16);

        const string data1 = "C39685C0C3063755179EDF8891A16157B23431";
        md5->update(data1);
        QVERIFY(md5->digest() == "DC68FEDFA7895F36ED3B97E74010AD45");

        md5->reset();
        QVERIFY(md5->digest("Xi6LLrcHYiZD1uY4mluMNH找不到标识符vqW+DkCxGT4mtE8ZT+Lw4") == "0E6945BD0677747CD2420485D365E8FD");

        delete md5;
    }
};


#endif // MD5DIGESTTEST_H
