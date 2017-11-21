#ifndef PLATFORM_SECURITY_MD5DIGEST_H
#define PLATFORM_SECURITY_MD5DIGEST_H

#include <security/messagedigest.h>

typedef struct MD5state_st MD5_CTX;

namespace moon {
namespace security{

class MD5Digest : public MessageDigest
{
    enum {RESULT_BYTES = 16};
private:
    MD5Digest();
public:
    static MD5Digest* create() {return new MD5Digest();}

    virtual ~MD5Digest();

    virtual void update(const void *data, size_t offset, size_t len);
    virtual std::string digest();
    virtual void reset(){init();}
    virtual size_t length() const { return RESULT_BYTES; }
    virtual const unsigned char* bytes() const {return mResults;}
private:
    void init();
private:
    unsigned char mResults[RESULT_BYTES];
    MD5_CTX *mCtx;

};

}
}  // ~moon
#endif // PLATFORM_SECURITY_MD5DIGEST_H
