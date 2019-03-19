/*
 * Temp-cereal.cpp
 *
 *  Created on: Jan 4, 2018
 *      Author: gerardryan
 */

#include "palisade.h"
#include "cryptocontext.h"
using namespace lbcrypto;

class Foo {
	int		x;
	int		xa[3];
	vector<int>	xv;
	vector<NativeInteger>	xnv;
	unsigned __int128	z;

public:
	Foo(int z = 0) : x(z) {
		for( int i=0; i < 3; i++ ) xa[i] = z;
		xv.resize(z);
		xnv = { 4, 9 };
		z = 404;
	}

	template <class Archive>
	typename std::enable_if <cereal::traits::is_output_serializable<cereal::BinaryData<Foo>,Archive>::value,void>::type
	save( Archive & ar, std::uint32_t const version ) const
	{
		ar( CEREAL_NVP(x), CEREAL_NVP(xa), CEREAL_NVP(xv), CEREAL_NVP(xnv) );
		ar( (long double)z );
		ar( *xv.data() );
	}

	template <class Archive>
	typename std::enable_if <!cereal::traits::is_output_serializable<cereal::BinaryData<Foo>,Archive>::value,void>::type
	save( Archive & ar, std::uint32_t const version ) const
	{
		ar( CEREAL_NVP(x), CEREAL_NVP(xa), CEREAL_NVP(xv), CEREAL_NVP(xnv) );
		ar( (long double)z );
		ar( *xv.data() );
	}

	template <class Archive> //, class std::enable_if <cereal::traits::is_output_serializable<cereal::BinaryData<Foo>,Archive>::value,void>>
	void load( Archive & ar, std::uint32_t const version )
	{
		ar( CEREAL_NVP(x), CEREAL_NVP(xa), CEREAL_NVP(xv), CEREAL_NVP(xnv) );
		ar( (long double)z );
		ar( *xv.data() );
	}

};

CEREAL_CLASS_VERSION( Foo, 2 );

const int repcount = 10; //5000;

template<typename T>
void RunSerialOptions(string objname, const shared_ptr<T> obj) {
	Serialized	ser;
	string str;

	cout << objname << endl;

	obj->Serialize(&ser);
	SerializableHelper::SerializationToString(ser, str);
	cout << "Legacy serialization:" << endl << "   bytes: " << str.length() << endl;

	TimeVar t;

	TIC(t);
	for( int i=0; i<repcount; i++ ) {
		Serialized ser;
		ser.SetObject();
		obj->Serialize(&ser);
		SerializableHelper::SerializationToString(ser, str);
	}
	cout << "   serialization time: " << (double)TOC_US(t)/repcount << "us" << endl;

	shared_ptr<T> newobj;
	TIC(t);
	for( int i=0; i<repcount; i++ ) {
		newobj.reset( new T() );
		newobj->Deserialize(ser);
	}
	cout << "   deserialization time: " << (double)TOC_US(t)/repcount << "us" << endl;

	stringstream s;
	auto nam = obj->SerializedObjectName();

	cout << "JSON serialization: " << endl;
	{
		s.str("");
		SERIALIZE(obj, s, Serializable::JSON);
	}
	cout << "   bytes: " << s.tellp() << endl;
	TIC(t);
	for( int i=0; i<repcount; i++ ) {
		s.str("");
		SERIALIZE(obj, s, Serializable::JSON);
	}
	cout << "   serialization time: " << (double)TOC_US(t)/repcount << "us" << endl;
	TIC(t);
	for( int i=0; i<repcount; i++ ) {
		newobj.reset( new T() );
		DESERIALIZEWITHNAME(newobj, nam, s, Serializable::JSON);
		s.clear();
		s.seekg(0, std::ios::beg);
	}
	cout << "   deserialization time: " << (double)TOC_US(t)/repcount << "us" << endl;

	cout << "BINARY serialization: " << endl;
	{
		s.clear();
		s.str("");
		SERIALIZE(obj, s, Serializable::BINARY);
	}
	cout << "   bytes: " << s.tellp() << endl;
	TIC(t);
	for( int i=0; i<repcount; i++ ) {
		s.str("");
		SERIALIZE(obj, s, Serializable::BINARY);
	}
	cout << "   serialization time: " << (double)TOC_US(t)/repcount << "us" << endl;
	TIC(t);
	for( int i=0; i<repcount; i++ ) {
		newobj.reset( new T() );
		DESERIALIZEWITHNAME(newobj, nam, s, Serializable::BINARY);
		s.clear();
		s.seekg(0, std::ios::beg);
	}
	cout << "   deserialization time: " << (double)TOC_US(t)/repcount << "us" << endl;

	cout << "PORTABLEBINARY serialization: " << endl;
	{
		s.clear();
		s.str("");
		SERIALIZE(obj, s, Serializable::PORTABLEBINARY);
	}
	cout << "   bytes: " << s.tellp() << endl;
	TIC(t);
	for( int i=0; i<repcount; i++ ) {
		s.str("");
		SERIALIZE(obj, s, Serializable::PORTABLEBINARY);
	}
	cout << "   serialization time: " << (double)TOC_US(t)/repcount << "us" << endl;
	TIC(t);
	for( int i=0; i<repcount; i++ ) {
		newobj.reset( new T() );
		DESERIALIZEWITHNAME(newobj, nam, s, Serializable::PORTABLEBINARY);
		s.clear();
		s.seekg(0, std::ios::beg);
	}
	cout << "   deserialization time: " << (double)TOC_US(t)/repcount << "us" << endl;
}

//ostream& operator<<(ostream& out, const __int128 i) {
//	out << std::to_string(i);
//	return out;
//}

template <class T, cereal::traits::EnableIf<std::is_arithmetic<T>::value,
                                    !std::is_same<T, long>::value,
                                    !std::is_same<T, unsigned long>::value,
                                    !std::is_same<T, std::int64_t>::value,
                                    !std::is_same<T, std::uint64_t>::value,
                                    (sizeof(T) >= sizeof(long double) || sizeof(T) >= sizeof(long long))> = cereal::traits::sfinae> inline
void func(T const & t)
{
  std::stringstream ss; //ss.precision( std::numeric_limits<long double>::max_digits10 );
  ss << t;
  cout << ( ss.str() ) << endl;
}

int
main()
{
	cout << "std::is_arithmetic<__int128>::value " << std::is_arithmetic<__int128>::value << endl;
	cout << "(sizeof(__int128) >= sizeof(long double) || sizeof(__int128) >= sizeof(long long)) "
			<< (sizeof(__int128) >= sizeof(long double) || sizeof(__int128) >= sizeof(long long)) << endl;
	cout << "!std::is_same<__int128, long>::value " << !std::is_same<__int128, long>::value << endl;

	__int128 xx = 101;
	cout << xx << endl;
	func(xx);

	Foo	xxx(4);
	ostringstream ss;
	{
		cereal::JSONOutputArchive archive( ss );
		archive( cereal::make_nvp("Foo", xxx) );
	}
	cout << "JSON of foo is " << ss.tellp() << endl;
	ss.str("");
	{
		cereal::BinaryOutputArchive archive( ss );
		archive( cereal::make_nvp("Foo", xxx) );
	}
	cout << "BINARY of foo is " << ss.tellp() << endl << endl;

	if( false ) {
		EncodingParams ep2( new EncodingParamsImpl(5, 7, 9, 11, 13, 15) );
		RunSerialOptions("Encoding Params", ep2);
	}

	if( false ) {
		usint plaintextModulus = 536903681;
		double sigma = 3.2;
		SecurityLevel securityLevel = HEStd_128_classic;

		////////////////////////////////////////////////////////////
		// Parameter generation
		////////////////////////////////////////////////////////////

		EncodingParams encodingParams(new EncodingParamsImpl(plaintextModulus));

		//Set Crypto Parameters
		// # of evalMults = 3 (first 3) is used to support the multiplication of 7 ciphertexts, i.e., ceiling{log2{7}}
		// Max depth is set to 3 (second 3) to generate homomorphic evaluation multiplication keys for s^2 and s^3
		CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
				encodingParams, securityLevel, sigma, 0, 3, 0, OPTIMIZED,3);

		// enable features that you wish to use
		cryptoContext->Enable(ENCRYPTION);
		cryptoContext->Enable(SHE);

		std::cout << "\np = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
		std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
		std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

		// Initialize Public Key Containers
		LPKeyPair<DCRTPoly> keyPair;

		keyPair = cryptoContext->KeyGen();

		if( !keyPair.good() ) {
			std::cout << "Key generation failed!" << std::endl;
			exit(1);
		}

		cryptoContext->EvalMultKeysGen(keyPair.secretKey);

		////////////////////////////////////////////////////////////
		// Encode source data
		////////////////////////////////////////////////////////////

		std::vector<int64_t> vectorOfInts1 = {1,2,3,4,5,6,7,8,9,10,11,12};
		Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);

		auto ct1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);

		RunSerialOptions("Ciphertext", ct1);
	}

	return 0;
}


