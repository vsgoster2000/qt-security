#ifndef PLATFORM_SECURITY_DES_H
#define PLATFORM_SECURITY_DES_H

#include <string>

namespace moon {
namespace security{

class DesKey;

class Des
{
public:
    enum Algorithm{ALGORITHM_DES, ALGORITHM_DES3};
    enum Mode{MODE_ECB, MODE_CBC};
    enum Padding{PADDING_NO_PADDING, PADDING_PKCS5};

    Des(Algorithm algorithm, Mode mode, Padding padding);
    Des(const Des &other);
    ~Des();
    Des& operator=(const Des &other);

    /**
     * @brief Returns a Des object for des encryption
     * @param mode Support ecb and cbc only
     * @param padding Support PKCS5Padding and NoPadding
     * @return Returns a Des object
     */
    static Des createDes(Mode mode = Mode::MODE_CBC, Padding padding = Padding::PADDING_PKCS5);

    /**
     * @brief Returns a Des object for triple des encryption
     * @param mode Support ecb and cbc only
     * @param padding Support PKCS5Padding and NoPadding
     * @return Returns a Des object
     */
    static Des create3Des(Mode mode = Mode::MODE_CBC, Padding padding = Padding::PADDING_PKCS5);

    /**
     * @brief Use &key to encrypt @data. If the object being used to des encryption, @key must be 16-length string,
     * if the object being used to triple des enryption, @key must be 32-length string or 48-length string.
     * @data should not be empty, if the padding is Padding::PADDING_PKCS5, the @data can be any string that length is a multiple of 2,
     * system will padding the @data automatically, but if the padding is Padding::PADDING_NO_PADDING,
     * the @data must be a string that length is a multiple of 16.
     *
     * @param key A std::string object represents the key, if the @key is used for des encryption, it should be a 16-length string,
     * if the @key is used for triple des encryption. it should be a 32-length, or 48-length string.
     * @param data A std::string object represents the plaintext that is used to generate the ciphertext.
     *
     * @return If success, returns a string that length is a multiple of 16. if on failure returns an empty string.
     */
    std::string encrypt(const std::string &key, const std::string& data) const;

    /**
     * @brief Use @key to encrypt @data, this method is very like the method #encrypt(const std::string &, const std::string&),
     * but the @data will not be padding whatever the padding mode is, the @data must be a 16-length string.
     * @param key A std::string object represents the key.
     * @param data A std::string object represents the ciphertext, must be a string that length is a mulitple of 16.
     * @return If success, returns a string that length that length is a multiple of 16. if on failure returns an empry string.
     */
    std::string decrypt(const std::string &key, const std::string& data) const;

    /**
     * @brief Use @key to encrypt @data, and stores the cipher into the @output. If the object being used to des encryption the @keyLen must be 8,
     * if the object being used to triple des enryption, the @keyLen must be 16 or 24.
     * @data should not be NULL, if the padding is Padding::PADDING_PKCS5, system will padding the @data automatically,
     * but if the padding is Padding::PADDING_NO_PADDING, the @dataLen must be a multiple of 8.
     *
     * @param key A pointer point to a buffer that represents the key used to encrypt the @data, should not be NULL.
     * @param keyLen The length that the @key has.
     * @param data A pointer point to a unsigned char string.
     * @param dataLen The length that the @data has.
     * @param output A pointer point to a buffer in which the cipher will be placed.
     * @return If success returns a positive indicate the cipher length, if on failure returns a negative number.
     */
    int encrypt(const unsigned char *key, unsigned int keyLen, const unsigned char *data, unsigned int dataLen, unsigned char *output) const;

    /**
     * @brief Use @key to decrypt @data.
     * @param key A pointer point to a memory that stores the key.
     * @param keyLen The length of the @key, must be 8 for des, 16 or 24 for 3des,
     * @param data A pointer point to a memory that stores the data going to be encrypted.
     * @param dataLen dataLen must be a mulitple of 8.
     * @param output A pointer point to a memory in which the results will placed.
     * @return
     */
    int decrypt(const unsigned char *key, unsigned int keyLen, const unsigned char *data, unsigned int dataLen, unsigned char *output) const;

    const char* error() const {return mError.c_str();}
private:

    std::string encryptAndDecrypt(const std::string& data, bool encrypt) const;
    size_t encryptAndDecrypt(const unsigned char *data, size_t dataLen, unsigned char *output, bool encrypt) const;

    void encryptEcb(const unsigned char *data, size_t dataLen, unsigned char *output, bool encrypt) const;
    void encryptCbc(const unsigned char *data, size_t dataLen, unsigned char *output, bool encrypt) const;

    size_t paddingData(const unsigned char * const data, size_t dataLen, unsigned char *output) const;
    size_t unpaddingData(unsigned char *data, size_t dataLen) const;

    bool generateKey(const std::string& key) const;
    bool generateKey(const void *key, unsigned int keyLen) const;

    void setError(const char *format, ...) const;
    bool enabled() const {return NULL != mDesKey;}

    bool isDes() const {return ALGORITHM_DES == mAlgorithm;}
    bool is3Des() const {return ALGORITHM_DES3 == mAlgorithm;}
    bool isEcb() const {return MODE_ECB == mMode;}
    bool isCbc() const {return MODE_CBC == mMode;}
private:
    mutable std::string mError;
    Algorithm mAlgorithm;
    Mode mMode;
    Padding mPadding;
    mutable DesKey *mDesKey;
};


}
}  // ~moon

#endif // PLATFORM_SECURITY_DES_H
