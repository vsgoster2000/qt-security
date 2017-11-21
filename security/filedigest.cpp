#include <security/filedigest.h>

#include <QDebug>

namespace moon {
namespace security{

static const int FILE_READ_SIZE = 4096;

FileDigest::FileDigest()
{

}

std::string FileDigest::digest(const char *filepath, moon::security::MessageDigest::Algorithm algorithm) {
    if (NULL == filepath){
        qWarning() << "FileDigest::digest error, filepath should not be NULL.";
        return "";
    }

    FILE *fp = fopen(filepath, "rb");
    if (NULL == fp){
        qWarning() << "FileDigest::digest error, could not open file:" << filepath;
        return "";
    }

    MessageDigestPtr md = MessageDigest::create(algorithm);
    if (NULL == md){
        qWarning() << "FileDigest::digest error, not support Algorithm:" << algorithm;
        return "";
    }

    int readBytes = 0;
    char readBuffer[FILE_READ_SIZE] = {0};
    while (true){
        readBytes = fread(readBuffer, 1, FILE_READ_SIZE, fp);
        if (readBytes <= 0){
            break;
        }
        md->update(readBuffer, readBytes);
        memset(readBuffer, 0, FILE_READ_SIZE);
    }
    fclose(fp);
    return md->digest();
}


}  // ~security
}  // ~moon
