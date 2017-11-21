#ifndef DESTEST_H
#define DESTEST_H


#include <security/des.h>

#include <QString>
#include <QtTest>

#include <string>

using std::string;
using namespace moon::security;

class DesTest : public QObject
{
    Q_OBJECT
public:
    DesTest(){}

private Q_SLOTS:

    /**
     * Test des encryption with ecb mode
     */
    void des_ecb_pkcs5padding_encrypt_test(){
        Des des = Des::createDes(Des::Mode::MODE_ECB, Des::Padding::PADDING_PKCS5);
        const string key = "6706C3A238D5AA66";

        // exception tests for invalid key
        QVERIFY(des.encrypt("", "31") == "");
        QVERIFY(des.encrypt("6706C3A238D5AA", "31") == "");
        QVERIFY(des.encrypt("6706C3A238D5AA111111", "31") == "");

        // exception tests for invalid data
        QVERIFY(des.encrypt(key, "") == "");


        // normal tests for ecb mode
        QVERIFY(des.encrypt(key, "31") == "A18F38BC6C6C8238");
        QVERIFY(des.encrypt(key, "3131313131313131") == "F05BFB5C8E04E45C63E259C8A1DF0F3A");
        QVERIFY(des.encrypt(key, "313131313131313111") == "F05BFB5C8E04E45C2E722C21276F163E");
        QVERIFY(des.encrypt(key, "31313131313131311111111111111111") == "F05BFB5C8E04E45CDC9FA62FDE4B2CAF63E259C8A1DF0F3A");
        QVERIFY(des.encrypt(key, "3131313131313131111111111111111112") == "F05BFB5C8E04E45CDC9FA62FDE4B2CAF62532503CE358960");


        // normal tests for cbc mode
        des = Des::createDes(Des::Mode::MODE_CBC, Des::Padding::PADDING_PKCS5);
        QVERIFY(des.encrypt(key, "31") == "A18F38BC6C6C8238");
        QVERIFY(des.encrypt(key, "3131313131313131") == "F05BFB5C8E04E45CD1804BBC1BBF1625");
        QVERIFY(des.encrypt(key, "313131313131313111") == "F05BFB5C8E04E45CDEC3090B36F387EB");
        QVERIFY(des.encrypt(key, "31313131313131311111111111111111") == "F05BFB5C8E04E45C174983BF61CC11407EB17EEA9BB260AC");
        QVERIFY(des.encrypt(key, "3131313131313131111111111111111112") == "F05BFB5C8E04E45C174983BF61CC11401794C34D3E9A5AA9");
    }

    void des_ecb_pkcs5padding_decrypt_test(){
        Des des = Des::createDes(Des::Mode::MODE_ECB, Des::Padding::PADDING_PKCS5);
        const string key = "6706C3A238D5AA66";

        // exception tests for invalid key
        QVERIFY(des.decrypt("", "31") == "");
        QVERIFY(des.decrypt("6706C3A238D5AA", "31") == "");
        QVERIFY(des.decrypt("6706C3A238D5AA111111", "31") == "");

        // exception tests for invalid data
        QVERIFY(des.decrypt(key, "A18F38BC6C6C82") == "");
        QVERIFY(des.decrypt(key, "A18F38BC6C6C821112") == "");

        // normal tests for ecb mode
        QVERIFY(des.decrypt(key, "A18F38BC6C6C8238") == "31");
        QVERIFY(des.decrypt(key, "F05BFB5C8E04E45C63E259C8A1DF0F3A") == "3131313131313131");
        QVERIFY(des.decrypt(key, "F05BFB5C8E04E45C2E722C21276F163E") == "313131313131313111");
        QVERIFY(des.decrypt(key, "F05BFB5C8E04E45CDC9FA62FDE4B2CAF63E259C8A1DF0F3A") == "31313131313131311111111111111111");
        QVERIFY(des.decrypt(key, "F05BFB5C8E04E45CDC9FA62FDE4B2CAF62532503CE358960") == "3131313131313131111111111111111112");

        // normal tests for cbc mode
        des = Des::createDes(Des::Mode::MODE_CBC, Des::Padding::PADDING_PKCS5);
        QVERIFY(des.decrypt(key, "A18F38BC6C6C8238") == "31");
        QVERIFY(des.decrypt(key, "F05BFB5C8E04E45CD1804BBC1BBF1625") == "3131313131313131");
        QVERIFY(des.decrypt(key, "F05BFB5C8E04E45CDEC3090B36F387EB") == "313131313131313111");
        QVERIFY(des.decrypt(key, "F05BFB5C8E04E45C174983BF61CC11407EB17EEA9BB260AC") == "31313131313131311111111111111111");
        QVERIFY(des.decrypt(key, "F05BFB5C8E04E45C174983BF61CC11401794C34D3E9A5AA9") == "3131313131313131111111111111111112");
    }

    // Need to test nopadding encryption but no need to test decryption, because decryption does not padding data.
    void des_ecb_nopadding_encrypt_test(){
        Des des = Des::createDes(Des::Mode::MODE_ECB, Des::Padding::PADDING_NO_PADDING);
        const string key = "6706C3A238D5AA66";

        // exception tests for invalid key
        QVERIFY(des.encrypt("", "31") == "");
        QVERIFY(des.encrypt("6706C3A238D5AA", "31") == "");
        QVERIFY(des.encrypt("6706C3A238D5AA111111", "31") == "");

        // exception tests for invalid data
        QVERIFY(des.encrypt(key, "") == "");
        QVERIFY(des.encrypt(key, "31") == "");
        QVERIFY(des.encrypt(key, "313131313131313131") == "");

        // normal tests for ecb mode
        QVERIFY(des.encrypt(key, "3131313131313131") == "F05BFB5C8E04E45C");
        QVERIFY(des.encrypt(key, "31313131313131311111111111111111") == "F05BFB5C8E04E45CDC9FA62FDE4B2CAF");

        // normal tests for cbc mode
        des = Des::createDes(Des::Mode::MODE_CBC, Des::Padding::PADDING_NO_PADDING);
        QVERIFY(des.encrypt(key, "3131313131313131") == "F05BFB5C8E04E45C");
        QVERIFY(des.encrypt(key, "31313131313131311111111111111111") == "F05BFB5C8E04E45C174983BF61CC1140");
    }



    // ---des3 test---
    void des3_ecb_pkcs5padding_encrypt_test(){
        Des des = Des::create3Des(Des::Mode::MODE_ECB, Des::Padding::PADDING_PKCS5);
        const string key = "000000000000000012345678123456783131313131313131";

        // exception tests for invalid key
        QVERIFY(des.encrypt("", "31") == "");
        QVERIFY(des.encrypt("6706C3A238D5AA", "31") == "");
        QVERIFY(des.encrypt("6706C3A238D5AA111111", "31") == "");

        // exception tests for invalid data
        QVERIFY(des.encrypt(key, "") == "");

        // normal tests for  ecb  mode
        QVERIFY(des.encrypt(key, "31") == "54209DABCD0312FC");
        QVERIFY(des.encrypt(key, "3131313131313131") == "E4B3A6E156F5941AA471016933503C64");
        QVERIFY(des.encrypt(key, "313131313131313111") == "E4B3A6E156F5941A17FF9B772A96C17D");
        QVERIFY(des.encrypt(key, "31313131313131311111111111111111") == "E4B3A6E156F5941A81609715C1D3D2FAA471016933503C64");
        QVERIFY(des.encrypt(key, "3131313131313131111111111111111112") == "E4B3A6E156F5941A81609715C1D3D2FA336E82974A9737E9");

        // normal tests for cbc mode
        des = Des::create3Des(Des::Mode::MODE_CBC, Des::Padding::PADDING_PKCS5);
        QVERIFY(des.encrypt(key, "31") == "54209DABCD0312FC");
        QVERIFY(des.encrypt(key, "3131313131313131") == "E4B3A6E156F5941A69D74943305A948F");
        QVERIFY(des.encrypt(key, "313131313131313111") == "E4B3A6E156F5941AD9B3E4C604F1BAC5");
        QVERIFY(des.encrypt(key, "31313131313131311111111111111111") == "E4B3A6E156F5941AE4AD4F34C7978D578BD673BAC35748C8");
        QVERIFY(des.encrypt(key, "3131313131313131111111111111111112") == "E4B3A6E156F5941AE4AD4F34C7978D5795661365E1B290A1");
    }

    void des3_ecb_pkcs5padding_decrypt_test(){
        Des des = Des::create3Des(Des::Mode::MODE_ECB, Des::Padding::PADDING_PKCS5);
        const string key = "000000000000000012345678123456783131313131313131";

        // exception tests for invalid key
        QVERIFY(des.decrypt("", "31") == "");
        QVERIFY(des.decrypt("6706C3A238D5AA", "31") == "");
        QVERIFY(des.decrypt("6706C3A238D5AA111111", "31") == "");

        // exception tests for invalid data
        QVERIFY(des.decrypt(key, "A18F38BC6C6C82") == "");
        QVERIFY(des.decrypt(key, "A18F38BC6C6C821112") == "");

        // normal tests for ecb mode
        QVERIFY(des.decrypt(key, "54209DABCD0312FC") == "31");
        QVERIFY(des.decrypt(key, "E4B3A6E156F5941AA471016933503C64") == "3131313131313131");
        QVERIFY(des.decrypt(key, "E4B3A6E156F5941A17FF9B772A96C17D") == "313131313131313111");
        QVERIFY(des.decrypt(key, "E4B3A6E156F5941A81609715C1D3D2FAA471016933503C64") == "31313131313131311111111111111111");
        QVERIFY(des.decrypt(key, "E4B3A6E156F5941A81609715C1D3D2FA336E82974A9737E9") == "3131313131313131111111111111111112");

        // normal tests for cbc mode
        des = Des::create3Des(Des::Mode::MODE_CBC, Des::Padding::PADDING_PKCS5);
        QVERIFY(des.decrypt(key, "54209DABCD0312FC") == "31");
        QVERIFY(des.decrypt(key, "E4B3A6E156F5941A69D74943305A948F") == "3131313131313131");
        QVERIFY(des.decrypt(key, "E4B3A6E156F5941AD9B3E4C604F1BAC5") == "313131313131313111");
        QVERIFY(des.decrypt(key, "E4B3A6E156F5941AE4AD4F34C7978D578BD673BAC35748C8") == "31313131313131311111111111111111");
        QVERIFY(des.decrypt(key, "E4B3A6E156F5941AE4AD4F34C7978D5795661365E1B290A1") == "3131313131313131111111111111111112");
    }

    // Need to test nopadding encryption but no need to test decryption, because decryption does not padding data.
    void des3_ecb_nopadding_encrypt_test(){
        Des des = Des::create3Des(Des::Mode::MODE_ECB, Des::Padding::PADDING_NO_PADDING);
        const string key = "000000000000000012345678123456783131313131313131";

        // exception tests for invalid key
        QVERIFY(des.encrypt("", "31") == "");
        QVERIFY(des.encrypt("6706C3A238D5AA", "31") == "");
        QVERIFY(des.encrypt("6706C3A238D5AA111111", "31") == "");

        // exception tests for invalid data
        QVERIFY(des.encrypt(key, "") == "");
        QVERIFY(des.encrypt(key, "31") == "");
        QVERIFY(des.encrypt(key, "313131313131313131") == "");

        // normal tests for ecb mode
        QVERIFY(des.encrypt(key, "3131313131313131") == "E4B3A6E156F5941A");
        QVERIFY(des.encrypt(key, "31313131313131311111111111111111") == "E4B3A6E156F5941A81609715C1D3D2FA");

        // normal tests for cbc mode
        des = Des::create3Des(Des::Mode::MODE_CBC, Des::Padding::PADDING_NO_PADDING);
        QVERIFY(des.encrypt(key, "3131313131313131") == "E4B3A6E156F5941A");
        QVERIFY(des.encrypt(key, "31313131313131311111111111111111") == "E4B3A6E156F5941AE4AD4F34C7978D57");
    }

    void otherTestAll(){
        const unsigned char *key = new unsigned char[32];
        const unsigned char *data = new unsigned char[32];
        unsigned char *output = new unsigned char[32];

        Des des = Des::createDes(Des::Mode::MODE_ECB, Des::Padding::PADDING_NO_PADDING);
        // test for encrypt
        QVERIFY(des.encrypt(NULL, 0, NULL, 0, NULL) < 0);
        QVERIFY(des.encrypt(key, 0, NULL, 0, NULL) < 0);
        QVERIFY(des.encrypt(key, 0, data, 0, NULL) < 0);
        QVERIFY(des.encrypt(key, 7u, data, 0, output) < 0);
        QVERIFY(des.encrypt(key, 9u, data, 0, output) < 0);
        QVERIFY(des.encrypt(key, 8u, data, 7u, output) < 0);
        QVERIFY(des.encrypt(key, 8u, data, 9u, output) < 0);

        QVERIFY(des.encrypt(key, 8u, data, 8u, output) == 8u);

        // test for decrypt
        QVERIFY(des.decrypt(NULL, 0, NULL, 0, NULL) < 0);
        QVERIFY(des.decrypt(key, 0, NULL, 0, NULL) < 0);
        QVERIFY(des.decrypt(key, 0, data, 0, NULL) < 0);
        QVERIFY(des.decrypt(key, 7u, data, 0, output) < 0);
        QVERIFY(des.decrypt(key, 9u, data, 0, output) < 0);
        QVERIFY(des.decrypt(key, 8u, data, 7u, output) < 0);
        QVERIFY2(des.decrypt(key, 8u, data, 9u, output) < 0, "");
        QVERIFY(des.decrypt(key, 8u, data, 8u, output) == 8u);

        des = Des::createDes(Des::Mode::MODE_ECB, Des::Padding::PADDING_PKCS5);
        QVERIFY2(des.encrypt(key, 8u, data, 7u, output) == 8u, "");
        QVERIFY2(des.encrypt(key, 8u, data, 8u, output) == 16u, "");
        QVERIFY(des.decrypt(key, 8u, data, 9u, output) == -1);
    }

};




#endif // DESTEST_H
