#include <security/sha256digest.h>

#include <openssl/sha.h>
#include <assert.h>

namespace moon {
namespace security{


Sha256Digest::Sha256Digest() : mCtx(new SHA256_CTX()){
    init();
}

Sha256Digest::~Sha256Digest(){
    assert(NULL != mCtx);

    delete mCtx;
    mCtx = NULL;
}

void Sha256Digest::update(const void *data, size_t offset, size_t len){
    if (NULL == data){
        return ;
    }

    assert(NULL != mCtx);
    SHA256_Update(mCtx, (const char*)data + offset, len);
}

std::string Sha256Digest::digest(){
    assert(NULL != mCtx);

    SHA256_Final(mResults, mCtx);
    return toHex(mResults, length());
}

void Sha256Digest::init(){
    memset(mResults, 0, sizeof(mResults));

    assert(NULL != mCtx);
    SHA256_Init(mCtx);
}

}
}  // ~moon
