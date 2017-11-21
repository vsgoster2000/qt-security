#ifndef MESSAGEDIGESTTEST_H
#define MESSAGEDIGESTTEST_H

#include <security/messagedigest.h>

#include <QtTest>

using std::string;
using namespace moon::security;

class MessageDigestTest : public QObject
{
    Q_OBJECT
public:
    MessageDigestTest(){}
private:
    void testMessageDigest(MessageDigest::Algorithm algorithm){
        MessageDigestPtr md = MessageDigest::create(algorithm);
        QVERIFY(md != NULL);
    }

private Q_SLOTS:
    void createTest(){
        testMessageDigest(MessageDigest::ALGORIHM_MD5);

        testMessageDigest(MessageDigest::ALGORIHM_SHA224);
        testMessageDigest(MessageDigest::ALGORIHM_SHA256);
        testMessageDigest(MessageDigest::ALGORIHM_SHA384);
        testMessageDigest(MessageDigest::ALGORIHM_SHA512);
    }
};


#endif // MESSAGEDIGESTTEST_H
