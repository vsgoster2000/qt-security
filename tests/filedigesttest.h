#ifndef FILEDIGESTTEST_H
#define FILEDIGESTTEST_H

#include <security/filedigest.h>

#include <QtTest>

using namespace moon::security;

static const char *filepath = "D:/project/qt/moon/security/tmp/mdftest.txt";
class FileDigestTest : public QObject
{
    Q_OBJECT
public:
    FileDigestTest(){}
private Q_SLOTS:
    void testCommon(){
        std::string result = FileDigest::digest(NULL, MessageDigest::ALGORIHM_MD5);
        QVERIFY(result.empty());
    }

    void testMd5(){
        std::string result = FileDigest::digest(filepath, MessageDigest::ALGORIHM_MD5);
        QVERIFY2(result == "016A2B6115821650AD263F24F1AF213B", result.c_str());
    }

    void testSha1(){
        std::string result = FileDigest::digest(filepath, MessageDigest::ALGORIHM_SHA1);
        QVERIFY2(result == "B8F1D3909ED150C26AB3A9FC14D2B7B32AA96AEC", result.c_str());
    }

    void testSha224(){
        std::string result = FileDigest::digest(filepath, MessageDigest::ALGORIHM_SHA224);
        QVERIFY2(result == "9382979883607670E30157DB00CA51035790DC55A68680CFE3070AD1", result.c_str());
    }

    void testSha256(){
        std::string result = FileDigest::digest(filepath, MessageDigest::ALGORIHM_SHA256);
        QVERIFY2(result == "0909DFA7B8FD12D3D70E0D9C1A23855EB4B08325A8CFD8481A71F3955F404714", result.c_str());
    }

    void testSha384(){
        std::string result = FileDigest::digest(filepath, MessageDigest::ALGORIHM_SHA384);
        QVERIFY2(result == "C96951D2EF2D0D04E4988D0B4FBB39BA7C74DC2C1B5AFCCF98F7B78A0F39282285E74184D6AC2411C4CEC40C73A7DD41", result.c_str());
    }

    void testSha512(){
        std::string result = FileDigest::digest(filepath, MessageDigest::ALGORIHM_SHA512);
        QVERIFY2(result == "61D3B532D773FBB4B9AF3CA7D1D2B61154DBE76153BE46184451C819079F0218DB365B2DF6B032E00CBB4E6C9635BAE7A8F7282CBE5AE03FDF97BE7E6A35C16C", result.c_str());
    }
};

#endif // FILEDIGESTTEST_H
