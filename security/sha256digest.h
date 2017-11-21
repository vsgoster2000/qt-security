#ifndef PLATYFORM_SECURITY_SHA256DIGEST_H
#define PLATYFORM_SECURITY_SHA256DIGEST_H

#include <security/messagedigest.h>

typedef struct SHA256state_st SHA256_CTX;

namespace moon {
namespace security{

class Sha256Digest : public MessageDigest
{
    enum {RESULT_BYTES = 32};
private:
    Sha256Digest();
public:
    static Sha256Digest* create() {return new Sha256Digest();}

    virtual ~Sha256Digest();

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

#endif // PLATYFORM_SECURITY_SHA256DIGEST_H
