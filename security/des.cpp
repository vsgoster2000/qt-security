#include <security/des.h>
#include <security/deskey.h>
#include <security/des.h>

#include <base/byteconverter.h>

#include <openssl/des.h>

#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <vector>

namespace moon {
namespace security{

Des::Des(Algorithm algorithm, Mode mode, Padding padding) : mAlgorithm(algorithm), mMode(mode) , mPadding(padding){
    mDesKey = NULL;
}

Des::Des(const Des &other) : mAlgorithm(other.mAlgorithm), mMode(other.mMode) , mPadding(other.mPadding){
    mDesKey = DesKey::copy(other.mDesKey);
}

Des::~Des() {
    if (NULL != mDesKey){
        delete mDesKey;
        mDesKey = NULL;
    }
}

Des &Des::operator=(const Des &other){
    mAlgorithm = other.mAlgorithm;
    mMode = other.mMode;
    mPadding = other.mPadding;
    mDesKey = DesKey::copy(other.mDesKey);
    return *this;
}

Des Des::createDes(Des::Mode mode, Des::Padding padding){
    return Des(Algorithm::ALGORITHM_DES, mode, padding);
}

Des Des::create3Des(Des::Mode mode, Des::Padding padding){
    return Des(Algorithm::ALGORITHM_DES3, mode, padding);
}

std::string Des::encrypt(const std::string& key, const std::string &data) const{
    if (!generateKey(key)){
        return "";
    }

    if (data.empty()){
        //(const_cast<std::string &>(data)).append("0808080808080808");
        setError("Des::encrypt error, data is empry");
        return "";
    }

    if (Padding::PADDING_NO_PADDING == mPadding){
        if ( (data.length()) % 16 != 0){
            setError("Des::encrypt error, used NoPadding, but the data[%s] length is not a mulitple of 16", data.c_str());
            return "";
        }
    }

    return encryptAndDecrypt(data, true);
}

std::string Des::decrypt(const std::string& key, const std::string &data) const{
    if (!generateKey(key)){
        return "";
    }
    if (data.empty()){
        setError("Des::decrypt error, data is empry");
        return "";
    }

    if (data.length() % 16 != 0){
        setError("Des::decrypt error, data length is not a multiple of 18, length[%l]", data.length());
        return "";
    }

    return encryptAndDecrypt(data, false);
}

int Des::encrypt(const unsigned char *key, unsigned int keyLen, const unsigned char *data, unsigned int dataLen, unsigned char *output) const{
    if ( (NULL == data) || (NULL == output)){
        setError("Des::encrypt error, argument data or output is NULL.");
        return -1;
    }

    if (!generateKey(key, keyLen)){
        return -1;
    }

    if (Padding::PADDING_NO_PADDING == mPadding){
        if ( (dataLen % 8) != 0){
            setError("Des::encrypt error, used NoPadding, but the data length is not a mulitple of 8, but[%u].", dataLen);
            return -1;
        }
    }

    return (int)encryptAndDecrypt(data, dataLen, output, true);
}

int Des::decrypt(const unsigned char *key, unsigned int keyLen, const unsigned char *data, unsigned int dataLen, unsigned char *output) const{
    if ( (NULL == data) || (NULL == output)){
        setError("Des::decrypt error, argument data or output is NULL.");
        return -1;
    }
    if (!generateKey(key, keyLen)){
        return -1;
    }

    if ( (dataLen % 8) != 0){
        setError("Des::decrypt error, used NoPadding, but the data length is not a mulitple of 8, but[%u].", dataLen);
        return -1;
    }

    return (int)encryptAndDecrypt(data, dataLen, output, false);
}

std::string Des::encryptAndDecrypt(const std::string &data, bool encrypt) const{
    assert(enabled());
    assert(data.length() > 0);

    // Convert data as decimal bytes
    size_t decDataLen = data.length() / 2;
    std::vector<unsigned char> dataDecDst(decDataLen, 0);
    unsigned char *decData = &*dataDecDst.begin();
    ByteConverter::hexToDec(data.c_str(), decData, decDataLen);

    std::vector<unsigned char> outputDst(decDataLen + 16, 0);
    unsigned char *dataOutput = &*outputDst.begin();

    // Excecute encryption
    size_t len = encryptAndDecrypt(decData, decDataLen, dataOutput, encrypt);
    assert(len > 0);

    return ByteConverter::decToHex(dataOutput, len);
}

size_t Des::encryptAndDecrypt(const unsigned char *data, size_t dataLen, unsigned char *output, bool encrypt) const{
    assert(enabled());
    assert(NULL != data);
    assert(NULL != output);

    unsigned char *srcData = (unsigned char *)data;
    size_t srcDataLen = dataLen;
    std::vector<unsigned char> dataDst(dataLen + 16, 0);

    if ( (encrypt) && (mPadding == Padding::PADDING_PKCS5) ){
        srcData = &*dataDst.begin();
        srcDataLen = paddingData(data, dataLen, srcData);
    }

    if (isEcb()){
        encryptEcb(srcData, srcDataLen, output, encrypt);
    }else{
        encryptCbc(srcData, srcDataLen, output, encrypt);
    }

    if ( (!encrypt) && (mPadding == Padding::PADDING_PKCS5) ){
        return unpaddingData(output, srcDataLen);
    }

    return srcDataLen;
}

void Des::encryptEcb(const unsigned char *data, size_t dataLen, unsigned char *output, bool encrypt) const{
    if (isDes()){
        for (unsigned int i = 0; i < dataLen; i += 8){
            DES_ecb_encrypt((const_DES_cblock*)(data + i), (DES_cblock*)(output + i), mDesKey->key1(), encrypt ? DES_ENCRYPT : DES_DECRYPT);
        }
        return ;
    }

    for (unsigned int i = 0; i < dataLen; i += 8){
        DES_ecb3_encrypt((const_DES_cblock*)(data + i), (DES_cblock*)(output + i), mDesKey->key1(), mDesKey->key2(), mDesKey->key3(), encrypt ? DES_ENCRYPT : DES_DECRYPT);
    }
}

void Des::encryptCbc(const unsigned char *data, size_t dataLen, unsigned char *output, bool encrypt) const{
    DES_cblock ivec = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    if (isDes()){
        DES_ncbc_encrypt(data, output, (long)dataLen, mDesKey->key1(), &ivec, encrypt ? DES_ENCRYPT : DES_DECRYPT);
        return ;
    }

    for (unsigned int i = 0; i < dataLen; i += 8){
        DES_ede3_cbc_encrypt(data + i, output + i, 8u, mDesKey->key1(), mDesKey->key2(), mDesKey->key3(), &ivec, encrypt ? DES_ENCRYPT : DES_DECRYPT);
    }
}

size_t Des::paddingData(const unsigned char * const data, size_t dataLen, unsigned char *newData) const{
    assert(NULL != data);
    assert(NULL != newData);
    memcpy(newData, data, dataLen);

    const int mode = dataLen % 8;
    unsigned char paddingChar = 8 - mode;
    memset(newData + dataLen, paddingChar, 8 - mode);

    return dataLen + 8 - mode;
}

size_t Des::unpaddingData(unsigned char *data, size_t dataLen) const{
    assert(NULL != data);
    unsigned int lastByte = data[dataLen-1];
    assert( (0x00 < lastByte) && (lastByte <= 0x08) );

    return dataLen - lastByte;
}

bool Des::generateKey(const std::string &key) const{
    if (isDes()){
        if (16 != key.length()){
            setError("Des::generateKey error, Algorithm[DES] key[%s] keylen[%l].", key.c_str(), key.length());
            return false;
        }
    }else{
        if ((32 != key.length()) && (48 != key.length())){
            setError("Des::generateKey error, Algorithm[3DES] key[%s] keylen[%l].", key.c_str(), key.length());
            return false;
        }
    }

    unsigned char keyBytes[32] = {0};
    int keyLen = ByteConverter::hexToDec(key.c_str(), keyBytes);
    assert(key.length()/2 == keyLen);

    return generateKey(keyBytes, keyLen);
}

bool Des::generateKey(const void *key, unsigned int keyLen) const{
    if (NULL != mDesKey){
        if (mDesKey->equals((const unsigned char*)key, keyLen)){
            return true;
        }
        delete mDesKey;
        mDesKey = NULL;
    }

    mDesKey = isDes() ? DesKey::createDesKey((const unsigned char*)key, keyLen) : DesKey::create3DesKey((const unsigned char*)key, keyLen);
    if (NULL == mDesKey){
        setError("Des::generateKey error, Algorithm[%s] key[%s] keylen[%u].", isDes() ? "DES" : "3DES", (const char*)key, keyLen);
        return false;
    }
    return true;
}

void Des::setError(const char *format, ...) const{
    va_list ap;
    va_start(ap, format);

    char szMessage[1024] = {0};
    vsnprintf(szMessage, sizeof(szMessage), format, ap);
    va_end(ap);

    mError = std::string(szMessage);
}


}
}  // ~moon
