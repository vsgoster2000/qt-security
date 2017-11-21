#ifndef PLATFORM_SECURITY_DESKEY_H
#define PLATFORM_SECURITY_DESKEY_H

#include <openssl/des.h>

#include <string>

typedef struct DES_ks DES_key_schedule;

namespace moon {
namespace security{

class DesKey
{
public:
    ~DesKey();

    static DesKey* createDesKey(const std::string &key);
    static DesKey* createDesKey(const unsigned char *key, unsigned int keyLen);

    static DesKey* create3DesKey(const std::string &key);
    static DesKey* create3DesKey(const unsigned char *key, unsigned int keyLen);

    static DesKey* create(const std::string &key, bool isDes = true);
    static DesKey* create(const unsigned char *key, unsigned int keyLen, bool isDes = true);

    static DesKey* copy(const DesKey *desKey);

    DES_key_schedule* key1() const {return mKey1;}
    DES_key_schedule* key2() const {return mKey2;}
    DES_key_schedule* key3() const {return mKey3;}
    bool equals(const unsigned char *key, size_t keyLen);
private:
    DesKey(const DesKey&);
    DesKey& operator=(const DesKey&);
    DesKey(const unsigned char *key, unsigned int keyLen, bool isDes);
private:
    void init(const unsigned char *key, unsigned int keyLen, bool isDes);
private:
    const unsigned int mKeyLen;
    unsigned char mKey[32];
    const bool mIsDes;
    DES_key_schedule *mKey1;
    DES_key_schedule *mKey2;
    DES_key_schedule *mKey3;
};

}
}  // ~moon

#endif // PLATFORM_SECURITY_DESKEY_H
