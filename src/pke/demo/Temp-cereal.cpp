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
public:
	int		x;
	int		xa[3];
	vector<int>	xv;
	vector<int> ev;
	vector<NativeInteger>	xnv;
	unsigned __int128	z;

	Foo(int n = 0) : x(n) {
		for( int i=0; i < 3; i++ ) xa[i] = n;
		xv.resize(n);
		xnv = { 4, 9 };
		z = 404;
	}

	bool operator==(const Foo& o) const {
		if( x != o.x ) return false;
		for( size_t i=0; i<3; i++ )
			if( xa[i] != o.xa[i] ) return false;
		if( xv.size() != o.xv.size() ) return false;
		for( size_t i=0; i<xv.size(); i++ )
			if( xv[i] != o.xv[i] ) return false;
		if( ev.size() != o.ev.size() ) return false;
		for( size_t i=0; i<ev.size(); i++ )
			if( ev[i] != o.ev[i] ) return false;
		if( xnv.size() != o.xnv.size() ) return false;
		for( size_t i=0; i<xnv.size(); i++ )
			if( xnv[i] != o.xnv[i] ) return false;
		if( z != o.z ) return false;

		return true;
	}

	template <class Archive>
	void save( Archive & ar, std::uint32_t const version ) const
	{
		ar( CEREAL_NVP(x), CEREAL_NVP(xa), CEREAL_NVP(xv), CEREAL_NVP(xnv) );
		ar( CEREAL_NVP(z) );
		ar( CEREAL_NVP(ev) );
	}

	template <class Archive>
	void load( Archive & ar, std::uint32_t const version )
	{
		ar( CEREAL_NVP(x), CEREAL_NVP(xa), CEREAL_NVP(xv), CEREAL_NVP(xnv) );
		ar( CEREAL_NVP(z) );
		ar( CEREAL_NVP(ev) );
	}
};

CEREAL_CLASS_VERSION( Foo, 2 );

const int repcount = 1;

template<typename T>
void RunSerialOptions(const shared_ptr<T> obj, string nam) {
	TimeVar t;
	string str;

	stringstream s;
	shared_ptr<T> newobj;

	cout << "===== " << nam << " =====" << endl;

	cout << "JSON serialization: " << endl;
		s.str("");
		Serializable::Serialize(obj, s, Serializable::JSON);
	cout << "   bytes: " << s.tellp() << endl;

	TIC(t);
	for( int i=0; i<repcount; i++ ) {
		s.str("");
		Serializable::Serialize(obj, s, Serializable::JSON);
	}
	cout << "   serialization time: " << (double)TOC_US(t)/repcount << "us" << endl;
	TIC(t);
	for( int i=0; i<repcount; i++ ) {
		newobj.reset( new T() );
		Serializable::Deserialize(newobj, s, Serializable::JSON);
		s.clear();
		s.seekg(0, std::ios::beg);
	}
	cout << "   deserialization time: " << (double)TOC_US(t)/repcount << "us" << endl;
	cout << "JSON " << ((*obj == *newobj) ? "MATCHES" : "DOES NOT MATCH") << endl << endl;

	cout << "BINARY serialization: " << endl;
	{
		s.str("");
		Serializable::Serialize(obj, s, Serializable::BINARY);
	}
	cout << "   bytes: " << s.tellp() << endl;
	TIC(t);
	for( int i=0; i<repcount; i++ ) {
		s.str("");
		Serializable::Serialize(obj, s, Serializable::BINARY);
	}
	cout << "   serialization time: " << (double)TOC_US(t)/repcount << "us" << endl;
	TIC(t);
	for( int i=0; i<repcount; i++ ) {
		newobj.reset( new T() );
		Serializable::Deserialize(newobj, s, Serializable::BINARY);
		s.clear();
		s.seekg(0, std::ios::beg);
	}
	cout << "   deserialization time: " << (double)TOC_US(t)/repcount << "us" << endl;
	cout << "BINARY " << ((*obj == *newobj) ? "MATCHES" : "DOES NOT MATCH") << endl;
	cout  << endl << "=END= " << nam << " =END=" << endl << endl;
}

template<typename T>
void
Deserialize(CryptoContext<T>& obj, std::istream& stream, Serializable::Type sertype, std::string withname="") {
	cout << "MINE" << endl;
	//obj.reset( new CryptoContextImpl<T>() );
	CryptoContextImpl<T> newob;
	std::string usename = withname.length() == 0 ? obj->SerializedObjectName() : withname;
	if( sertype == Serializable::Type::JSON ) {
		cereal::JSONInputArchive archive( stream );
		archive( cereal::make_nvp(usename, newob) );
	}
	else if( sertype == Serializable::Type::BINARY ) {
		cereal::PortableBinaryInputArchive archive( stream );
		archive( newob );
	}
	else {

	}

	obj = CryptoContextFactory<T>::GetContext(newob.GetCryptoParameters(), newob.GetEncryptionAlgorithm());
}

int
main()
{
	if( false ) {
		uint64_t m(1);
		m <<= 60;

		vector<string> sv({"this","is","fun"});
		BigVector bv(8, m, {345, 212, 984, 2405, 107040, 10312, 0, 909});
		NativeVector nv(8, m, {345, 212, 984, 2405, 107040, 10312, 0, 909});

		cout << Serializable::SerializeToString(sv) << endl;
		cout << Serializable::SerializeToString(nv) << endl;
		{
			stringstream s;

			NativeVector re;
			Serializable::Serialize(nv, s, Serializable::Type::JSON);
			Serializable::Deserialize(re, s, Serializable::Type::JSON);
			cout << "json " << Serializable::SerializeToString(re) << endl;

			s.str("");
			NativeVector re2;
			Serializable::Serialize(nv, s, Serializable::Type::BINARY);
			Serializable::Deserialize(re2, s, Serializable::Type::BINARY);
			cout << "binary " << Serializable::SerializeToString(re2) << endl;
		}

		cout << Serializable::SerializeToString(bv) << endl;
		{
			stringstream s;

			BigVector re;
			Serializable::Serialize(bv, s, Serializable::Type::JSON);
			Serializable::Deserialize(re, s, Serializable::Type::JSON);
			cout << "json " << Serializable::SerializeToString(re) << endl;

			s.str("");
			BigVector re2;
			Serializable::Serialize(bv, s, Serializable::Type::BINARY);
			Serializable::Deserialize(re2, s, Serializable::Type::BINARY);
			cout << "binary " << Serializable::SerializeToString(re2) << endl;
		}


	}

	if( false ) {
		stringstream s;
		BigInteger W, X;

		W = 5;
		{
			cereal::BinaryOutputArchive archive( s );
			archive( W );
		}
		{
			cereal::BinaryInputArchive archive( s );
			archive( X );
		}
		cout << W << endl;
		cout << X << endl;

		s.str("");
		s.clear();
		W = 0; X = 17;
		{
			cereal::BinaryOutputArchive archive( s );
			archive( W );
		}
		{
			cereal::BinaryInputArchive archive( s );
			archive( X );
		}
		cout << W << endl;
		cout << X << endl;
	}

	if( false ) {
		Foo	xxx(4);
		Foo yyy, zzz;
		stringstream ss;
		{
			cereal::JSONOutputArchive archive( ss );
			archive( cereal::make_nvp("Foo", xxx) );
		}
		{
			cereal::JSONInputArchive archive( ss );
			archive( cereal::make_nvp("Foo", yyy) );
		}
		cout << (xxx == yyy ? "yes" : "no") << endl;

		ss.str("");
		{
			cereal::BinaryOutputArchive archive( ss );
			archive( cereal::make_nvp("Foo", xxx) );
		}
		{
			cereal::BinaryInputArchive archive( ss );
			archive( cereal::make_nvp("Foo", zzz) );
		}
		cout << (xxx == zzz ? "yes" : "no") << endl << endl;

		shared_ptr<Foo> xxx1 = make_shared<Foo>( xxx );

		RunSerialOptions(xxx1, "wombat");
	}

	if( false ) {
		EncodingParams ep2( new EncodingParamsImpl(5, 7, 9, 11, 13, 15) );
		RunSerialOptions(ep2,"ep");
	}

	if( true ) {
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

		//RunSerialOptions(cryptoContext);
		stringstream s;
		Serializable::Serialize(cryptoContext, s, Serializable::Type::JSON);
		cout << "serialized" << endl;
		cout << cryptoContext.get() << endl;
		CryptoContext<DCRTPoly> c2;
		c2.reset( new CryptoContextImpl<DCRTPoly>() );
		cout << c2.get() << endl;
		/*Serializable::*/
		Deserialize(c2, s, Serializable::Type::JSON);
		cout << c2.get() << endl;
		return 0;

		// Initialize Public Key Containers
		LPKeyPair<DCRTPoly> keyPair;

		keyPair = cryptoContext->KeyGen();

		if( !keyPair.good() ) {
			std::cout << "Key generation failed!" << std::endl;
			exit(1);
		}

		RunSerialOptions(keyPair.publicKey, "public");
		RunSerialOptions(keyPair.secretKey, "private");

		cryptoContext->EvalMultKeysGen(keyPair.secretKey);

		////////////////////////////////////////////////////////////
		// Encode source data
		////////////////////////////////////////////////////////////

		std::vector<int64_t> vectorOfInts1 = {1,2,3,4,5,6,7,8,9,10,11,12};
		Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);

		auto ct1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);

		cout << endl << "Ciphertext" << endl;

		auto nam = ct1->SerializedObjectName();
		RunSerialOptions(ct1, nam);
	}

	return 0;
}


