#ifndef PLATFORM_SECURITY_FILEDIGEST_H
#define PLATFORM_SECURITY_FILEDIGEST_H

#include <security/messagedigest.h>
#include <string>

namespace moon {
namespace security{

class FileDigest
{
private:
    FileDigest();
public:
    static std::string digest(const char *filepath, MessageDigest::Algorithm algorithm);
};

}  // ~security
}  // ~moon
#endif // FILEDIGEST_H
