/*
 * Temp-cereal.cpp
 *
 *  Created on: Jan 4, 2018
 *      Author: gerardryan
 */

#include "palisade.h"
#include "cryptocontext.h"
using namespace lbcrypto;

// If you need to serialize/deserialize an unsigned ___int128 to JSON, use these two routines
//class Large128 {
//public:
//	unsigned __int128	v;
//
//	Large128(unsigned __int128 v) : v(v) {}
//};
//
//namespace cereal {
//	template<class Archive>
//	void CEREAL_SAVE_FUNCTION_NAME(Archive & ar, const Large128 & v)
//	{
//		uint64_t hi = v.v>>64, lo = v.v&(~uint64_t(0));
//		ar( lo );
//		ar( hi );
//	}
//
//	template<class Archive>
//	void CEREAL_LOAD_FUNCTION_NAME(Archive & ar, Large128 & v)
//	{
//		uint64_t hi, lo;
//		ar( lo );
//		ar( hi );
//		v.v = __int128(hi)<<64 | lo;
//	}
//}

//namespace cereal {
//	template<class Archive>
//	void CEREAL_SAVE_FUNCTION_NAME(Archive & ar, const unsigned __int128 & v)
//	{
//		uint64_t hi = v>>64, lo = v&(~uint64_t(0));
//		ar( lo );
//		ar( hi );
//	}
//
//	template<class Archive>
//	void CEREAL_LOAD_FUNCTION_NAME(Archive & ar, unsigned __int128 & v)
//	{
//		uint64_t hi, lo;
//		ar( lo );
//		ar( hi );
//		v = __int128(hi)<<64 | lo;
//	}
//}

template <class Archive>
inline void SerializeInt128(Archive& ar, const unsigned __int128 & v) {
	uint64_t hi = v>>64, lo = v&(~uint64_t(0));
	ar( lo );
	ar( hi );
}

template <class Archive>
inline void DeserializeInt128(Archive& ar, unsigned __int128 & v) {
	uint64_t hi, lo;
	ar( lo );
	ar( hi );
	v = __int128(hi)<<64 | lo;
}

//ostream& operator<<(ostream& out, const unsigned __int128& v) {
//	out << "FOCUS!";
//	return out;
//}

class Foo {
public:
	int		x;
	int		xa[3];
	vector<int>	xv;
	vector<NativeInteger>	xnv;
	unsigned __int128	z;

	Foo(int n = 0) : x(n) {
		for( int i=0; i < 3; i++ ) xa[i] = n;
		xv.resize(n);
		xnv = { 4, 9 };
		z = 404;
	}

	template <class Archive>
	typename std::enable_if <cereal::traits::is_output_serializable<cereal::BinaryData<Foo>,Archive>::value,void>::type
	save( Archive & ar, std::uint32_t const version ) const
	{
		ar( CEREAL_NVP(x), CEREAL_NVP(xa), CEREAL_NVP(xv), CEREAL_NVP(xnv) );
		ar( z );
		ar( *xv.data() );
	}

	template <class Archive>
	typename std::enable_if <!cereal::traits::is_output_serializable<cereal::BinaryData<Foo>,Archive>::value,void>::type
	save( Archive & ar, std::uint32_t const version ) const
	{
		ar( CEREAL_NVP(x), CEREAL_NVP(xa), CEREAL_NVP(xv), CEREAL_NVP(xnv) );
		ar( CEREAL_NVP(z) );
		//SerializeInt128(ar, z);
		ar( *xv.data() );
	}

	template <class Archive>
	typename std::enable_if <cereal::traits::is_output_serializable<cereal::BinaryData<Foo>,Archive>::value,void>::type
	load( Archive & ar, std::uint32_t const version )
	{
		ar( CEREAL_NVP(x), CEREAL_NVP(xa), CEREAL_NVP(xv), CEREAL_NVP(xnv) );
		ar( z );
		ar( *xv.data() );
	}

	template <class Archive>
	typename std::enable_if <!cereal::traits::is_output_serializable<cereal::BinaryData<Foo>,Archive>::value,void>::type
	load( Archive & ar, std::uint32_t const version )
	{
		ar( CEREAL_NVP(x), CEREAL_NVP(xa), CEREAL_NVP(xv), CEREAL_NVP(xnv) );
		ar( CEREAL_NVP(z) );
		//SerializeInt128(ar, z);
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

int
main()
{
	QuadFloat	qf(20,30), qf2, qf3;
	{
		stringstream ss;
		{
			cereal::JSONOutputArchive archive( ss );
			archive( qf );
		}
		{
			cereal::JSONInputArchive archive( ss );
			archive( qf2 );
		}
		cout << (qf == qf2 ? "yes" : "no") << endl;

		ss.str("");
		{
			cereal::BinaryOutputArchive archive( ss );
			archive( qf );
		}
		{
			cereal::BinaryInputArchive archive( ss );
			archive( qf3 );
		}
		cout << (qf == qf3 ? "yes" : "no") << endl;
	}

	Foo	xxx(4);
	Foo yyy, zzz;
	stringstream ss;
	{
		cereal::JSONOutputArchive archive( ss );
		archive( cereal::make_nvp("Foo", xxx) );
	}
	cout << "JSON of foo is " << ss.tellp() << endl;
	{
		cereal::JSONInputArchive archive( ss );
		archive( cereal::make_nvp("Foo", yyy) );
	}
	cout << (xxx.z == yyy.z ? "yes" : "no") << endl;

	ss.str("");
	{
		cereal::BinaryOutputArchive archive( ss );
		archive( cereal::make_nvp("Foo", xxx) );
	}
	cout << "BINARY of foo is " << ss.tellp() << endl;
	{
		cereal::BinaryInputArchive archive( ss );
		archive( cereal::make_nvp("Foo", zzz) );
	}
	cout << (xxx.z == zzz.z ? "yes" : "no") << endl << endl;


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


