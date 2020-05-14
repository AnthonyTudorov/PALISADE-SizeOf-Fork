#include "palisade.h"
#include <typeinfo>

using namespace std;
using namespace lbcrypto;

	int main() {

	int plaintextModulus = 256;
	double sigma = 4;
	double rootHermiteFactor = 1.006;

	//Set Crypto Parameters
	CryptoContext<DCRTPoly> cryptoContext1 = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
			plaintextModulus, rootHermiteFactor, sigma, 0, 5, 0, OPTIMIZED, 6);

    uint32_t multDepth = 1;
    uint32_t scaleFactorBits = 50;
    uint32_t batchSize1 = 8;
    SecurityLevel securityLevel = HEStd_128_classic;
	CryptoContext<DCRTPoly> cryptoContext2 = CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
			   multDepth, scaleFactorBits, batchSize1, securityLevel);

    //

    usint m = 22;
	PlaintextModulus p = 2333;
	BigInteger modulusP(p);
	BigInteger modulusQ("955263939794561");
	BigInteger squareRootOfRoot("941018665059848");
	BigInteger bigmodulus("80899135611688102162227204937217");
	BigInteger bigroot("77936753846653065954043047918387");

	auto cycloPoly = GetCyclotomicPolynomial<BigVector>(m, modulusQ);
	ChineseRemainderTransformArb<BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	float stdDev = 4;

	usint batchSize2 = 8;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	EncodingParams encodingParams(new EncodingParamsImpl(p, batchSize2, PackedEncoding::GetAutomorphismGenerator(m)));

	PackedEncoding::SetParams(m, encodingParams);

	CryptoContext<Poly> cryptoContext3 = CryptoContextFactory<Poly>::genCryptoContextBGV(params, encodingParams, 8, stdDev);

	////////////////////////////////////////////////////////////
	// Encode source data
	////////////////////////////////////////////////////////////

    std::vector<complex<double>> vectorOfComplex = {5.0, 4.0, 3.0, 2.0, 1.0, .75, .5, .25};
    Plaintext plaintext1 = cryptoContext2->MakeCKKSPackedPlaintext(vectorOfComplex);

	std::vector<int64_t> vectorOfInts1 = {5,4,3,2,1,0,5,4,3,2,1,0};
	Plaintext plaintext2 = cryptoContext1->MakeCoefPackedPlaintext(vectorOfInts1);

    int64_t num = 7;
    int64_t den = 3;
    Plaintext plaintext3 = cryptoContext1->MakeFractionalPlaintext(num, den);

    int64_t x = 27;
    Plaintext plaintext4 = cryptoContext1->MakeIntegerPlaintext(x);

    std::vector<int64_t> vectorOfInts2 = {37, 22, 18, 4, 3, 2, 1, 9};
	Plaintext plaintext5 = cryptoContext3->MakePackedPlaintext(vectorOfInts2);

    int64_t y = 35;
    Plaintext plaintext6 = cryptoContext1->MakeScalarPlaintext(y);

    string str = "Hello World";
    Plaintext plaintext7 = cryptoContext1->MakeStringPlaintext(str);

    cout << "Size of plaintext1 (CKKSPackedPlaintext): " << plaintext1->SizeOf() << endl;
    cout << "Size of plaintext2 (CoefPackedPlaintext): " << plaintext2->SizeOf() << endl;
    cout << "Size of plaintext3 (FractionalPlaintext): " << plaintext3->SizeOf() << endl;
    cout << "Size of plaintext4 (IntegerPlaintext): " << plaintext4->SizeOf() << endl;
    cout << "Size of plaintext5 (PackedPlaintext): " << plaintext5->SizeOf() << endl;
    cout << "Size of plaintext6 (ScalarPlaintext): " << plaintext6->SizeOf() << endl;
    cout << "Size of plaintext7 (StringPlaintext): " << plaintext7->SizeOf() << endl;

    }