#include <security/deskey.h>
#include <base/byteconverter.h>

#include <openssl/des.h>
#include <assert.h>

namespace moon {
namespace security{

DesKey::DesKey(const unsigned char *key, unsigned int keyLen, bool isDes) : mKeyLen(keyLen), mIsDes(isDes)
{
    mKey1 = NULL;
    mKey2 = NULL;
    mKey3 = NULL;
    memset(mKey, 0, sizeof(mKey));
    memcpy(mKey, key, keyLen);
}

DesKey::~DesKey(){
    assert(NULL != mKey1);

    delete mKey1;
    mKey1 = NULL;

    if (!mIsDes){
        assert(NULL != mKey2);
        assert(NULL != mKey3);

        delete mKey2;
        delete mKey3;
        mKey2 = NULL;
        mKey3 = NULL;
    }
}

DesKey *DesKey::createDesKey(const std::string &key){
    return create(key, true);
}

DesKey *DesKey::createDesKey(const unsigned char *key, unsigned int keyLen){
    return create(key, keyLen, true);
}

DesKey *DesKey::create3DesKey(const std::string &key){
    return create(key, true);
}

DesKey *DesKey::create3DesKey(const unsigned char *key, unsigned int keyLen){
    return create(key, keyLen, false);
}

DesKey *DesKey::create(const std::string &keyStr, bool isDes){
    if (isDes){
        if (16 != keyStr.length()){
            return NULL;
        }
    }else{
        if ((32 != keyStr.length()) && (48 != keyStr.length())){
            return NULL;
        }
    }

    unsigned char key[32] = {0};
    int keyLen = ByteConverter::hexToDec(keyStr.c_str(), key);
    assert(keyStr.length()/2 == keyLen);

    return create(key, keyLen, isDes);
}

DesKey *DesKey::create(const unsigned char *key, unsigned int keyLen, bool isDes){
    if (NULL == key){
        return NULL;
    }

    if (isDes){
        if (8 != keyLen){
            return NULL;
        }
    }else {
        if ( (16 != keyLen) && (24 != keyLen) ){
            return NULL;
        }
    }

    DesKey *desKey = new DesKey(key, keyLen, isDes);
    desKey->init(key, keyLen, isDes);

    return desKey;
}

DesKey *DesKey::copy(const DesKey *desKey){
    if (NULL == desKey){
        return NULL;
    }

    return create((unsigned char *)desKey->mKey, desKey->mKeyLen, desKey->mIsDes);
}

bool DesKey::equals(const unsigned char *key, size_t keyLen){
    assert(NULL != mKey);
    assert( (8 == mKeyLen) || (16 == mKeyLen) || (24 == mKeyLen) );

    if ( (NULL == key) || (mKeyLen != keyLen) ){
        return false;
    }

    return strncmp((char const*)mKey, (char const*)key, keyLen) == 0;
}

void DesKey::init(const unsigned char *key, unsigned int keyLen, bool isDes){
    assert(NULL != key);
    assert( (8 == keyLen) || (16 == keyLen) || (24 == keyLen) );
    assert(NULL == mKey1);
    assert(NULL == mKey2);
    assert(NULL == mKey3);

    mKey1 = new DES_key_schedule();
    DES_set_key_unchecked((const_DES_cblock *)key, mKey1);

    if (!isDes){
        // Setting keys for 3DES
        mKey2 = new DES_key_schedule();
        DES_set_key_unchecked((const_DES_cblock *)(key + 8), mKey2);

        if (16 == keyLen){
            mKey3 = new DES_key_schedule();
            DES_set_key_unchecked((const_DES_cblock *)key, mKey3);
        }else{
            mKey3 = new DES_key_schedule();
            DES_set_key_unchecked((const_DES_cblock *)(key + 16), mKey3);
        }
    }
}


}
}  // ~moon
