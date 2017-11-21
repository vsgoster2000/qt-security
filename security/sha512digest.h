#ifndef PLATYFORM_SECURITY_SHA512DIGEST_H
#define PLATYFORM_SECURITY_SHA512DIGEST_H

#include <security/messagedigest.h>

typedef struct SHA512state_st SHA512_CTX;

namespace moon {
namespace security{


class Sha512Digest : public MessageDigest
{
    enum {RESULT_BYTES = 64};
private:
    Sha512Digest();
public:
    static Sha512Digest* create() {return new Sha512Digest();}

    virtual ~Sha512Digest();

    virtual void update(const void *data, size_t offset, size_t len);
    virtual std::string digest();
    virtual void reset(){init();}
    virtual size_t length() const { return RESULT_BYTES; }
    virtual const unsigned char* bytes() const {return mResults;}
private:
    void init();
private:
    unsigned char mResults[RESULT_BYTES];
    SHA512_CTX *mCtx;

};

}
}  // ~moon

#endif // PLATYFORM_SECURITY_SHA512DIGEST_H
