#ifndef SHA256DIGESTTEST_H
#define SHA256DIGESTTEST_H

#include <security/sha256digest.h>

#include <QtTest>
#include <string>

using std::string;
using namespace moon::security;

class Sha256DigestTest : public QObject
{
    Q_OBJECT
public:
    Sha256DigestTest(){}

private Q_SLOTS:
    void createTest(){
        MessageDigest *md = Sha256Digest::create();

        QVERIFY(NULL != md);
        QVERIFY(md->length() == 32);

        const string data1 = "hello";
        md->update(data1);
        QVERIFY(md->digest() == "2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824");

        md->reset();
        QVERIFY(md->digest(data1) == "2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824");

        delete md;
    }
};


#endif // SHA256DIGESTTEST_H
