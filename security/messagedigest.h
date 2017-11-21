#ifndef PLATFORM_SECURITY_MESSAGEDIGEST_H
#define PLATFORM_SECURITY_MESSAGEDIGEST_H

#include <stdio.h>
#include <memory>
#include <string>

namespace moon{
namespace security{

class MessageDigest;
typedef std::shared_ptr<MessageDigest> MessageDigestPtr;

class MessageDigest
{
public:
    enum Algorithm{ALGORIHM_MD5, ALGORIHM_SHA1, ALGORIHM_SHA224, ALGORIHM_SHA256, ALGORIHM_SHA384, ALGORIHM_SHA512};

    static MessageDigestPtr create(Algorithm algorithm);

    static std::string toHex(const unsigned char *data, size_t len);

    MessageDigest();
    virtual ~MessageDigest();

    virtual void update(const void *data, size_t offset, size_t len) = 0;
    virtual std::string digest() = 0;
    virtual void reset() = 0;
    virtual size_t length() const = 0;
    virtual const unsigned char* bytes() const = 0;

    void update(const std::string &data){
        update(data.c_str(), 0, data.length());
    }

    void update(const void *data){
        update(data, 0, strlen((const char *)data));
    }

    void update(const void *data, size_t len){
        update(data, 0, len);
    }

    std::string digest(const std::string &data){
        return digest(data.c_str(), 0, data.length());
    }

    std::string digest(const void *data){
        return digest(data, 0, strlen((const char *)data));
    }

    std::string digest(const void *data, size_t len){
        return digest(data, 0, len);
    }

    std::string digest(const void *data, size_t offset, size_t len){
        if (NULL == data){
            return NULL;
        }
        update(data, offset, len);
        return digest();
    }
};

}
}  // ~moon
#endif // PLATFORM_SECURITY_MESSAGEDIGEST_H
