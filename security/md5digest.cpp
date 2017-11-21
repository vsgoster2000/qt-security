#include <security/md5digest.h>

#include <openssl/md5.h>

#include <assert.h>

namespace moon {
namespace security{

MD5Digest::MD5Digest() : mCtx(new MD5_CTX()){
    init();
}

MD5Digest::~MD5Digest(){
    assert(NULL != mCtx);

    delete mCtx;
    mCtx = NULL;
}

void MD5Digest::update(const void *data, size_t offset, size_t len){
    if (NULL == data){
        return ;
    }

    assert(NULL != mCtx);
    MD5_Update(mCtx, (const char*)data + offset, len);
}

std::string MD5Digest::digest(){
    assert(NULL != mCtx);

    MD5_Final(mResults, mCtx);
    return toHex(mResults, length());
}

void MD5Digest::init(){
    memset(mResults, 0, sizeof(mResults));

    assert(NULL != mCtx);
    MD5_Init(mCtx);
}


}
}  // ~moon
