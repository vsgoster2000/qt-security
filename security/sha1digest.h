#ifndef PLATYFORM_SECURITY_SHA1DIGEST_H
#define PLATYFORM_SECURITY_SHA1DIGEST_H

#include <security/messagedigest.h>

typedef struct SHAstate_st SHA_CTX;

namespace moon {
namespace security{

class Sha1Digest : public MessageDigest
{
    enum {RESULT_BYTES = 20};
private:
    Sha1Digest();
public:
    static Sha1Digest* create() {return new Sha1Digest();}

    virtual ~Sha1Digest();

    virtual void update(const void *data, size_t offset, size_t len);
    virtual std::string digest();
    virtual void reset(){init();}
    virtual size_t length() const { return RESULT_BYTES; }
    virtual const unsigned char* bytes() const {return mResults;}
private:
    void init();
private:
    unsigned char mResults[RESULT_BYTES];
    SHA_CTX *mCtx;

};

}
}  // ~moon

#endif // PLATYFORM_SECURITY_SHA1DIGEST_H
