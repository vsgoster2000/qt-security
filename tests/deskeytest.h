#include <security/deskey.h>

#include <QString>
#include <QtTest>

#include <string>

using std::string;
using namespace moon::security;

class DesKeyTest : public QObject
{
    Q_OBJECT
public:
    DesKeyTest(){}

private Q_SLOTS:

    void createDesKey_test1(){
        QVERIFY(DesKey::createDesKey("31313131313131313131313131313131") == NULL);
        QVERIFY(DesKey::createDesKey("31313131313131") == NULL);
        QVERIFY(DesKey::createDesKey("") == NULL);

        DesKey *desKey = DesKey::createDesKey("3131313131313131");
        QVERIFY(NULL != desKey);
        QVERIFY(NULL != desKey->key1());
        QVERIFY(NULL == desKey->key2());
        QVERIFY(NULL == desKey->key3());
    }

    void createDesKey_test2(){
        QVERIFY(DesKey::createDesKey((const unsigned char *)"1111111111111111", 16u) == NULL);
        QVERIFY(DesKey::createDesKey((const unsigned char *)"11111111", 7u) == NULL);
        QVERIFY(DesKey::createDesKey(NULL, 8u) == NULL);

        DesKey *desKey = DesKey::createDesKey((const unsigned char *)"11111111", 8u);
        QVERIFY(NULL != desKey);
        QVERIFY(NULL != desKey->key1());
        QVERIFY(NULL == desKey->key2());
        QVERIFY(NULL == desKey->key3());
    }

};


