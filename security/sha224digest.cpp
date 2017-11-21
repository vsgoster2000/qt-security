#include <security/sha224digest.h>

#include <openssl/sha.h>
#include <assert.h>

namespace moon {
namespace security{


Sha224Digest::Sha224Digest() : mCtx(new SHA256_CTX()){
    init();
}

Sha224Digest::~Sha224Digest(){
    assert(NULL != mCtx);

    delete mCtx;
    mCtx = NULL;
}

void Sha224Digest::update(const void *data, size_t offset, size_t len){
    if (NULL == data){
        return ;
    }

    assert(NULL != mCtx);
    SHA224_Update(mCtx, (const char*)data + offset, len);
}

std::string Sha224Digest::digest(){
    assert(NULL != mCtx);

    SHA224_Final(mResults, mCtx);
    return toHex(mResults, length());
}

void Sha224Digest::init(){
    memset(mResults, 0, sizeof(mResults));

    assert(NULL != mCtx);
    SHA224_Init(mCtx);
}

}
}  // ~moon
