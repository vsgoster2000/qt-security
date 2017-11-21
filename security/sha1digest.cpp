#include <security/sha1digest.h>

#include <openssl/sha.h>
#include <assert.h>

namespace moon {
namespace security{

Sha1Digest::Sha1Digest() : mCtx(new SHA_CTX()){
    init();
}

Sha1Digest::~Sha1Digest(){
    assert(NULL != mCtx);

    delete mCtx;
    mCtx = NULL;
}

void Sha1Digest::update(const void *data, size_t offset, size_t len){
    if (NULL == data){
        return ;
    }

    assert(NULL != mCtx);
    SHA1_Update(mCtx, (const char*)data + offset, len);
}

std::string Sha1Digest::digest(){
    assert(NULL != mCtx);

    SHA1_Final(mResults, mCtx);
    return toHex(mResults, length());
}

void Sha1Digest::init(){
    memset(mResults, 0, sizeof(mResults));

    assert(NULL != mCtx);
    SHA1_Init(mCtx);
}

}
}  // ~moon
