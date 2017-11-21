#include <security/messagedigest.h>
#include <security/md5digest.h>
#include <security/sha1digest.h>
#include <security/sha224digest.h>
#include <security/sha256digest.h>
#include <security/sha384digest.h>
#include <security/sha512digest.h>
#include <base/byteconverter.h>

#include <assert.h>

namespace moon{
namespace security{

MessageDigestPtr MessageDigest::create(MessageDigest::Algorithm algorithm){
    switch (algorithm) {
    case MessageDigest::ALGORIHM_MD5:
        return MessageDigestPtr(MD5Digest::create());

    case MessageDigest::ALGORIHM_SHA1:
        return MessageDigestPtr(Sha1Digest::create());

    case MessageDigest::ALGORIHM_SHA224:
        return MessageDigestPtr(Sha224Digest::create());

    case MessageDigest::ALGORIHM_SHA256:
        return MessageDigestPtr(Sha256Digest::create());

    case MessageDigest::ALGORIHM_SHA384:
        return MessageDigestPtr(Sha384Digest::create());

    case MessageDigest::ALGORIHM_SHA512:
        return MessageDigestPtr(Sha512Digest::create());
    default:
        assert(false);
        return NULL;
    }
}

std::string MessageDigest::toHex(const unsigned char *data, size_t len){
    if (NULL == data){
        return "";
    }
    return ByteConverter::decToHex(data, len);
}

MessageDigest::MessageDigest() {
}

MessageDigest::~MessageDigest() {
}


}
}  // ~moon
