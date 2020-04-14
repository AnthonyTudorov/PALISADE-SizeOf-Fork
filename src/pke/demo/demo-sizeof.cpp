
#include <iostream>
#include <fstream>
#include <iterator>

#include "palisade.h"
#include "ciphertext.h"

using namespace std;
using namespace lbcrypto;

int main(int argc, char *argv[]){

    cout << "--------------TESTING SIZEOF FUNCTION ON CIPHERTEXT--------------" << endl;

    CryptoContext<Poly> pcryptoContext = CryptoContextHelper::getNewContext("BGV3");
    if (!pcryptoContext){
        cout << "Unable to create CryptoContext with Poly Element" << endl;
        return 0;
    }
/*
    CryptoContext<NativePoly> npcryptoContext = CryptoContextHelper::getNewContext("BGV3");
    if (!npcryptoContext){
        cout  << "Unable to create CryptoContext with NativePoly Element" << endl;
        return 0;
    }
*/
    CryptoContext<DCRTPoly> dcrtcryptoContext = CryptoContextHelper::getNewDCRTContext("BGV3",5,32);
    if (!dcrtcryptoContext){
        cout  << "Unable to create CryptoContext with DCRTPoly Element" << endl;
        return 0;
    }

    pcryptoContext->Enable(ENCRYPTION);
    //npcryptoContext->Enable(ENCRYPTION);
    dcrtcryptoContext->Enable(ENCRYPTION);

    //Making Plaintexts using scalar encoding

    int64_t plaintextval = 1;

    Plaintext pPlainText = pcryptoContext->MakeScalarPlaintext(plaintextval);
    //Plaintext npPlainText = npcryptoContext->MakeScalarPlaintext(plaintextval);
    Plaintext dcrtPlainText = dcrtcryptoContext->MakeScalarPlaintext(plaintextval);

    //Generate Key Pairs
    LPKeyPair<Poly> polyKeyPair = pcryptoContext->KeyGen();
    if (!polyKeyPair.good()){
        cout << "Poly Key failed to be generated" << endl;
        return 0;
    }
    /*
    LPKeyPair<NativePoly> nativepolyKeyPair = npcryptoContext->KeyGen();
        if (!nativepolyKeyPair.good()){
        cout << "NativePoly Key failed to be generated" << endl;
        return 0;
    }
    */
    LPKeyPair<DCRTPoly> dcrtpolyKeyPair = dcrtcryptoContext->KeyGen();
        if (!dcrtpolyKeyPair.good()){
        cout << "DCRTPoly Key failed to be generated" << endl;
        return 0;
    }


    //Making Ciphertexts
    Ciphertext<Poly> polyciphertext;
    //Ciphertext<NativePoly> npolyciphertext;
    Ciphertext<DCRTPoly> dcrtpolyciphertext;

    polyciphertext = pcryptoContext->Encrypt(polyKeyPair.secretKey,pPlainText);
    //npolyciphertext = npcryptoContext->Encrypt(nativepolyKeyPair,npPlainText);
    dcrtpolyciphertext = dcrtcryptoContext->Encrypt(dcrtpolyKeyPair.secretKey,dcrtPlainText);

    cout << "--------------EVAULATING SIZEOF CIPHERTEXT--------------" << endl;

    cout << "Size of Ciphertext with Element Poly: " << polyciphertext->sizeofCiphertext() << endl;
    //cout << "Size of Ciphertext with Element Native Poly" << npolyciphertext->sizeofCiphertext() << endl;
    cout << "Size of Ciphertext with Element DCRTPoly: " << dcrtpolyciphertext->sizeofCiphertext() << endl;

    return 1;

}

