#include <security/sha512digest.h>

#include <openssl/sha.h>
#include <assert.h>

namespace moon {
namespace security{


Sha512Digest::Sha512Digest() : mCtx(new SHA512_CTX()){
    init();
}

Sha512Digest::~Sha512Digest(){
    assert(NULL != mCtx);

    delete mCtx;
    mCtx = NULL;
}

void Sha512Digest::update(const void *data, size_t offset, size_t len){
    if (NULL == data){
        return ;
    }

    assert(NULL != mCtx);
    SHA512_Update(mCtx, (const char*)data + offset, len);
}

std::string Sha512Digest::digest(){
    assert(NULL != mCtx);

    SHA512_Final(mResults, mCtx);
    return toHex(mResults, length());
}

void Sha512Digest::init(){
    memset(mResults, 0, sizeof(mResults));

    assert(NULL != mCtx);
    SHA512_Init(mCtx);
}

}
}  // ~moon
