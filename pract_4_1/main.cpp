#include <iostream>
#include <vector>
#include <iomanip>
#include <fstream>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <string>
using namespace std;
int main (int argc, char* argv[])
{
    using namespace CryptoPP;
    SHA1 hash;
    std::cout << "Name: " << hash.AlgorithmName() << std::endl;
    std::cout << "Digest size: " << hash.DigestSize() << std::endl;
    std::cout << "Block size: " << hash.BlockSize() << std::endl;
    std::string msg;
    ifstream file;
    file.open("/home/kali/Documents/pract_4/pract_4_1/pract_4.txt");
    while (getline(file,msg)) {
        std::vector<byte> digest(hash.DigestSize());
        hash.Update((const byte*)msg.data(), msg.size());
        hash.Final(digest.data());
        std::cout << "Message: " << msg << std::endl;
        std::cout << "Digest: ";
        StringSource(digest.data(), digest.size(), true, new HexEncoder(new FileSink(std::cout)));
        std::cout << std::endl;
    }
    file.close();
    return 0;
}