#include <security/sha384digest.h>

#include <openssl/sha.h>
#include <assert.h>

namespace moon {
namespace security{


Sha384Digest::Sha384Digest() : mCtx(new SHA512_CTX()){
    init();
}

Sha384Digest::~Sha384Digest(){
    assert(NULL != mCtx);

    delete mCtx;
    mCtx = NULL;
}

void Sha384Digest::update(const void *data, size_t offset, size_t len){
    if (NULL == data){
        return ;
    }

    assert(NULL != mCtx);
    SHA384_Update(mCtx, (const char*)data + offset, len);
}

std::string Sha384Digest::digest(){
    assert(NULL != mCtx);

    SHA384_Final(mResults, mCtx);
    return toHex(mResults, length());
}

void Sha384Digest::init(){
    memset(mResults, 0, sizeof(mResults));

    assert(NULL != mCtx);
    SHA384_Init(mCtx);
}

}
}  // ~moon
