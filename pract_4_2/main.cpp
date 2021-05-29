#include <iostream>
#include <string>
#include <cstdlib>
#include <unistd.h>
#include "AES.h"
#include "GOST.h"
using namespace std;
using namespace CryptoPP;

int main ()
{
    unsigned op, cip;
    string FIn, FOut, Pass;

    do {
        cout << "\nEnter the operation (0 - exit, 1 - encrypt, 2 - decrypt): ";
        cin >> op;

        if (op != 0) {
            cout << "\nEnter the algorithms: (1 - AES-256, 2 - GOST-89): ";
            cin >> cip;
        }

        if (op > 2) {
            cerr << "Error! Invalid operation\n";
        }

        else if (op > 0) {
            cout << "\nEnter a path to input file: ";
            cin >> FIn;

            cout << "\nEnter a path to output file: ";
            cin >> FOut;

            cout << "\nEnter a password: ";
            cin >> Pass;

            if (cip == 1) {
                AES_Cryptor aes(FIn, FOut, Pass);

                if (op == 1) {
                    if (aes.AES_Encrypt())
                        cout << "Successfull encrypting!" << endl;
                    else
                        cout << "Encryption failed!" << endl;
                } else {
                    if (aes.AES_Decrypt())
                        cout << "Successfull decrypting!" << endl;
                    else
                        cout << "Decryption failed!" << endl;
                }
            }


            else if (cip == 2) {
                GOST_Cryptor go(FIn, FOut, Pass);

                if (op == 1) {
                    if (go.GOST_Encrypt())
                        cout << "Successfull encrypting!" << endl;
                    else
                        cout << "Encryption failed!" << endl;
                } else {
                    if (go.GOST_Decrypt())
                        cout << "Successfull decrypting!" << endl;
                    else
                        cout << "Decryption failed!" << endl;
                }
            } else {
                cerr << "Error! Incorrect algorithm number!!!\n";
            }
        }

    } while (op != 0);

    return 0;
}