#include <iostream>
#include <string>
#include <cstdlib>
#include <unistd.h>
#include <fstream>
#include "GOST.h"

GOST_Cryptor::GOST_Cryptor(const string& Input, const string& Output, const string& Pass)
{
    FileIn = Input;
    FileOut = Output;
    psw = Pass;
}

bool GOST_Cryptor::GOST_Encrypt ()
{
    SecByteBlock key(GOST::DEFAULT_KEYLENGTH);
    PKCS12_PBKDF<SHA512> pbkdf;
    pbkdf.DeriveKey(key.data(), key.size(), 0, (byte*)psw.data(), psw.size(), (byte*)salt.data(), salt.size(), 1024, 0.0f);

    cout << "\nKey: ";
    StringSource(key.data(), key.size(), true, new HexEncoder( new FileSink(cout) ));

    AutoSeededRandomPool prng;
    byte iv[GOST::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    ofstream pull(string(FileOut + ".iv").c_str(), ios::out | ios::binary);
    pull.write((char*)iv, GOST::BLOCKSIZE);
    pull.close();

    cout << "\nIV Successfully created: " << FileOut << ".iv" << endl;

    try {
        CBC_Mode<GOST>::Encryption encr;
        encr.SetKeyWithIV(key, key.size(), iv);

        FileSource fs(FileIn.c_str(), true, new StreamTransformationFilter(encr, new FileSink(FileOut.c_str())));
    }

    catch (const Exception& e) {
        cerr << e.what() << endl;

        return false;
    }

    return true;
}

bool GOST_Cryptor::GOST_Decrypt ()
{
    SecByteBlock key(GOST::DEFAULT_KEYLENGTH);
    PKCS12_PBKDF<SHA512> pbkdf;
    pbkdf.DeriveKey(key.data(), key.size(), 0, (byte*)psw.data(), psw.size(), (byte*)salt.data(), salt.size(), 1024, 0.0f);

    cout << "Key: ";
    StringSource(key.data(), key.size(), true, new HexEncoder( new FileSink(cout) ));

    cout << endl;

    byte iv[GOST::BLOCKSIZE];
    ifstream pool(string(FileIn + ".iv").c_str(), ios::in | ios::binary);

    if (pool.good()) {
        pool.read((char*)&iv, GOST::BLOCKSIZE);
        pool.close();
    }

    else if (pool.bad()) {
        cerr << "IV file not found!" << endl;
        pool.close();
        return false;
    }

    else {
        cerr << "Incorrect IV file!" << endl;
        pool.close();
        return false;
    }

    try {
        CBC_Mode<GOST>::Decryption decr;
        decr.SetKeyWithIV(key, key.size(), iv);

        FileSource fs(FileIn.c_str(), true, new StreamTransformationFilter(decr, new FileSink(FileOut.c_str())));
    }

    catch (const Exception& e) {
        cerr << e.what() << endl;

        return false;
    }

    return true;
}