#include <iostream>
#include <fstream>
#include <cstring>
#include <vector>
#include <algorithm>
#include <random>
#include <stdio.h>
#include <unistd.h>

#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "../lib/utils/rapidjson/filewritestream.h"
#include "../lib/utils/rapidjson/rapidjson.h"

#include "../lib/cryptocontext.h"
#include "../lib/cryptocontexthelper.h"
#include "../lib/cryptocontexthelper-impl.cpp"
#include "../lib/utils/serializable.h"
#include "../lib/utils/serializablehelper.h"

#include "encoding/encodings.h"

#include "utils/debug.h"

#include <cstdio>

using namespace std;
using namespace lbcrypto;
using namespace rapidjson;


struct EncInfo
{
    CryptoContext<DCRTPoly> cryptocontext;
    LPKeyPair<DCRTPoly> keypair;
};

EncInfo info;

//const int IntVectorLen = 2;

int generate_crypto_context_and_keys() {
    // benchmarking variables

    usint plaintextModulus = 65537;
    double sigma = 3.2;
    double rootHermiteFactor = 1.006;
    size_t batchSize = 2;

    ////////////////////////////////////////////////////////////
    // Parameter generation
    ////////////////////////////////////////////////////////////

    EncodingParams encodingParams(new EncodingParamsImpl(plaintextModulus, batchSize));
    //Set Crypto Parameters
    // # of evalMults = 3 (first 3) is used to support the multiplication of 7 ciphertexts, i.e., ceiling{log2{7}}
    // Max depth is set to 3 (second 3) to generate homomorphic evaluation multiplication keys for s^2 and s^3
    CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
            encodingParams, rootHermiteFactor, sigma, 0, 1, 0, OPTIMIZED, 2);



    // enable features that you wish to use
    cc->Enable(ENCRYPTION);
    cc->Enable(SHE);
    
    LPKeyPair<DCRTPoly> kp = cc->KeyGen();
    
    if( !kp.good() ) {
        std::cout << "Key generation failed!" << std::endl;
        exit(1);
    }
    
    usint m = cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder();
    cout << *cc->GetCryptoParameters()->GetEncodingParams() << endl;
    cout << *cc->GetCryptoParameters()->GetElementParams() << endl;

    PackedEncoding::SetParams(m, encodingParams);
    
    cc->EvalSumKeyGen(kp.secretKey);
    cc->EvalMultKeyGen(kp.secretKey);
    
    Serialized emKeys, esKeys;

    if (cc->SerializeEvalMultKey(&emKeys)) {
        if (!SerializableHelper::WriteSerializationToFile(emKeys, "./key-eval-mult.txt")) {
            cerr << "Error writing serialization of the eval mult keys to ./key-eval-mult.txt" << endl;
            return 0;
        }
    }
    else {
        cerr << "Error serializing eval mult keys" << endl;
        return 0;
    }

    if (cc->SerializeEvalSumKey(&esKeys)) {
        if (!SerializableHelper::WriteSerializationToFile(esKeys, "./key-eval-sum.txt")) {
            cerr << "Error writing serialization of the eval sum keys to ./key-eval-sum.txt" << endl;
            return 0;
        }
    }
    else {
        cerr << "Error serializing eval sum keys" << endl;
        return 0;
    }
    
    Serialized pubK, privK;
    if ( kp.publicKey->Serialize(&pubK) ) {
        if (!SerializableHelper::WriteSerializationToFile(pubK, "./encryption_info_pubK.txt") ) {
            cerr << "Error writing serialization of public key to ./encryption_info_pubK.txt" << endl;
            return 0;
        }
    } else {
        cerr << "Error serializing public key" << endl;
        return 0;
    }
    if ( kp.secretKey->Serialize(&privK) ) {
        if (!SerializableHelper::WriteSerializationToFile(privK, "./encryption_info_priK.txt") ) {
            cerr << "Error writing serialization of public key to ./encryption_info_priK.txt" << endl;
            return 0;
        }
    } else {
        cerr << "Error serializing private key" << endl;
        return 0;
    }
    
    info.cryptocontext = cc;
    info.keypair = kp;
        
    return 1;
}

vector<uint64_t> split(const string &s, char delim) {
    stringstream ss(s);
    string item;
    vector<uint64_t> tokens;
    while (getline(ss, item, delim)) {
        tokens.push_back(stod(item));
        }
    return tokens;
}

int encrypt_content( string& content_file ) {
    ifstream file ( content_file );
    string value;
    vector<uint64_t> tokens;
    string output_filename = content_file;
    output_filename.replace(output_filename.end()-4,output_filename.end(),"_enc.txt");
    ofstream enc_file( output_filename, ios::out | ios::binary );
    OStreamWrapper oo(enc_file);
    
    Writer<OStreamWrapper> ww(oo);
    
    ww.StartArray();

    Serialized serial;
    SerialItem a(kArrayType);
    Serialized::AllocatorType& allocator = serial.GetAllocator();
    
    if ( !file.good() ) {
        cerr << "Failed to open input plaintext file" << endl;
        return 0;
    }

    if( !enc_file.is_open() ) {
        cerr << "could not open output file " << output_filename << endl;
        return 0;
    }
    while ( file.good() ) {    
        vector<int> *v = new vector<int>();
        getline ( file, value ); 
        tokens = split(value, ',');
        for ( vector<uint64_t>::size_type i = 0; i != tokens.size(); i++ ) {
            v->push_back(tokens[i]);
        }
        vector<uint64_t> *vToSub = new vector<uint64_t>();
    
        vector<uint64_t> *vMod = new vector<uint64_t>();
        for(vector<int>::size_type i = 0; i != 2; i++) {
            
            int val = (*v)[i];
            if (val >= 0) {
                vToSub->push_back(0);
                vMod->push_back(val);
            } else {
                vToSub->push_back(val*-2);
                vMod->push_back(val*-1);
            }
        }
        
        Ciphertext<DCRTPoly> ciphertextPositive;
        vector<uint64_t> vectorOfInts = move(*vMod);
        Plaintext intArray = info.cryptocontext->MakePackedPlaintext(vectorOfInts); // TODO INCORPORATE NEGATIVE VALUES AS WELL
    
        ciphertextPositive = info.cryptocontext->Encrypt(info.keypair.publicKey, intArray);
        
        Ciphertext<DCRTPoly> ciphertextToSub;
        vector<uint64_t> vectorOfIntsToSub = move(*vToSub);
        Plaintext intArrayToSub = info.cryptocontext->MakePackedPlaintext(vectorOfIntsToSub); // TODO INCORPORATE NEGATIVE VALUES AS WELL
    
        ciphertextToSub = info.cryptocontext->Encrypt(info.keypair.publicKey, intArrayToSub);
        
        Ciphertext<DCRTPoly> ciphertext = info.cryptocontext->EvalSub(ciphertextPositive, ciphertextToSub);
        
        Serialized cSer;
        string str;
        if ( ciphertext->Serialize(&cSer) ) {
            //cSer.Accept(ww);
            SerializableHelper::SerializationToString(cSer,str);
            ww.String(str);
            a.PushBack(cSer, allocator);
        } else {
            cerr << "Error serializing ciphertext" << endl;
            return 0;
        }
    }
    ww.EndArray();
    file.close();
    enc_file.close();
    return 1;
}

int read_public_key_from_file(){
    Serialized kser;
    if ( SerializableHelper::ReadSerializationFromFile("./encryption_info_pubK.txt", &kser) == false ) {
        cerr << "Could not read public key" << endl;
        return 0;
    }

    LPPublicKey<DCRTPoly> pk = info.cryptocontext->deserializePublicKey(kser);
    if ( !pk ) {
        cerr << "Could not deserialize public key" << endl;
        return 0;
    }
    info.keypair.publicKey = pk;

    return 1;
}

int read_private_key_from_file(){
    Serialized kser;
    FILE* fp = fopen("./encryption_info_priK.txt", "r");
    char readBuffer[65536];
    FileReadStream sSK(fp, readBuffer, sizeof(readBuffer));
    
    kser.ParseStream(sSK);
    fclose(fp);
    
    info.cryptocontext = CryptoContextFactory<DCRTPoly>::DeserializeAndCreateContext(kser);
  
    const auto encodingParams = info.cryptocontext->GetCryptoParameters()->GetEncodingParams();
    const auto elementParams = info.cryptocontext->GetCryptoParameters()->GetElementParams();
    cout << *info.cryptocontext->GetCryptoParameters()->GetEncodingParams() << endl;
    cout << *info.cryptocontext->GetCryptoParameters()->GetElementParams() << endl;
    usint m = elementParams->GetCyclotomicOrder();

	PackedEncoding::SetParams(m, encodingParams);
    LPPrivateKey<DCRTPoly> sk = info.cryptocontext->deserializeSecretKey(kser);
    info.keypair.secretKey = sk;


    if ( !sk ) {
        cerr << "Could not deserialize public key" << endl;
        return 0;
    }

    Serialized ccEmk;
    if ( !SerializableHelper::ReadSerializationFromFile("./key-eval-mult.txt", &ccEmk) ) {
        cerr << "I cannot read serialization from " << "./key-eval-mult.txt" << endl;
        return 0;
    }

    Serialized ccEsk;
    if ( !SerializableHelper::ReadSerializationFromFile("./key-eval-sum.txt", &ccEsk) ) {
        cerr << "I cannot read serialization from " << "./key-eval-sum.txt" << endl;
        return 0;
    }  

    info.cryptocontext->DeserializeEvalMultKey(ccEmk);
    info.cryptocontext->DeserializeEvalSumKey(ccEsk);

    return 1;
}

Ciphertext<DCRTPoly> multiplication() {
    Ciphertext<DCRTPoly> result;
    string filepath = "./Sample1_vecs_enc.txt";
    string value;

//    struct stat filestat;

    FILE* fp = fopen(filepath.c_str(), "r");
    vector<uint64_t> tokens;
    char readBuffer[65536];
    FileReadStream enc_file(fp, readBuffer, sizeof(readBuffer));
    Serialized a;
    a.ParseStream(enc_file);
    fclose(fp);
    for (Value::ConstValueIterator itr = a.Begin(); itr != a.End(); ++itr) {
        string str;
        str = itr->GetString();
        Serialized cSer;
        if ( !SerializableHelper::StringToSerialization(str, &cSer) ) {
            cerr << "Error transforming string into Serialized" << endl;
        }
        Ciphertext<DCRTPoly> ct = info.cryptocontext->deserializeCiphertext(cSer);
        //cout << itr << endl;
        ++itr;
        //cout << itr << endl;
        string str2;
        str2 = itr->GetString();
        Serialized cSer2;
        if ( !SerializableHelper::StringToSerialization(str2, &cSer2) ) {
            cerr << "Error transforming string into Serialized" << endl;
        }
        Ciphertext<DCRTPoly> ct2 = info.cryptocontext->deserializeCiphertext(cSer2);

        Plaintext ptxt,ptxt2;
        info.cryptocontext->Decrypt(info.keypair.secretKey, ct, &ptxt);
        info.cryptocontext->Decrypt(info.keypair.secretKey, ct2, &ptxt2);
        cout << ptxt->GetPackedValue()[0] << ", " << ptxt ->GetPackedValue()[1] << endl;
        cout << ptxt2->GetPackedValue()[0] << ", " << ptxt2 ->GetPackedValue()[1] << endl;

        info.cryptocontext->EvalAdd(ct,ct2);
           
        Ciphertext<DCRTPoly> ciphertextMult = info.cryptocontext->EvalMult(ct,ct2);
        return ciphertextMult;
    }
    return result;
}

bool FileExists( const string& name ) {
    ifstream file(name);
    if(!file) {
        return false;
    } else {
        return true;
    }
}

int main(int argc, char** argv){
    string content_file = "./Sample1_vecs.csv";
    bool exists = FileExists("./encryption_info_priK.txt") and FileExists("./encryption_info_pubK.txt");
    if (exists) {
        if ( read_private_key_from_file() == false ) {
            cerr << "Failed to read private key from file" << endl;
            return 0;
        }
        if ( read_public_key_from_file() == false ) {
            cerr << "Failed to read public key from file" << endl;
            return 0;
        }
        Ciphertext<DCRTPoly> result = multiplication();
        cout << 1;
    } else {
        if ( generate_crypto_context_and_keys() == false) {
            cerr << "Failed to generate cryptocontext or keypair" << endl;
        }
        encrypt_content(content_file);
        cout << "Content encrypted. Please run code again for multiplication." << endl;
    }
    return 0;
}
