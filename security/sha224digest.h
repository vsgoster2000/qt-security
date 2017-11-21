#ifndef PLATYFORM_SECURITY_SHA224DIGEST_H
#define PLATYFORM_SECURITY_SHA224DIGEST_H

#include <security/messagedigest.h>

typedef struct SHA256state_st SHA256_CTX;

namespace moon {
namespace security{


class Sha224Digest : public MessageDigest
{
    enum {RESULT_BYTES = 28};
private:
    Sha224Digest();
public:
    static Sha224Digest* create() {return new Sha224Digest();}

    virtual ~Sha224Digest();

    virtual void update(const void *data, size_t offset, size_t len);
    virtual std::string digest();
    virtual void reset(){init();}
    virtual size_t length() const { return RESULT_BYTES; }
    virtual const unsigned char* bytes() const {return mResults;}
private:
    void init();
private:
    unsigned char mResults[RESULT_BYTES];
    SHA256_CTX *mCtx;

};

}
}  // ~moon

#endif // PLATYFORM_SECURITY_SHA224DIGEST_H
