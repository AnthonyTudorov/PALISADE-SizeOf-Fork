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

public:
	Foo(int z = 0) : x(z) {
		for( int i=0; i < 3; i++ ) xa[i] = z;
		xv.resize(z);
		xnv = { 4, 9 };
	}

	template <class Archive>
	void serialize( Archive & ar, std::uint32_t const version )
	{
		ar( CEREAL_NVP(x), CEREAL_NVP(xa), CEREAL_NVP(xv), CEREAL_NVP(xnv) );
		ar( *xv.data() );
	}

};

CEREAL_CLASS_VERSION( Foo, 2 );

const int repcount = 100000;

template<typename T>
void RunSerialOptionsPtr(const T& obj) {
	Serialized	ser;
	string str;

	cout << typeid(obj).name() << endl;

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

	stringstream s;

	cout << "JSON serialization: " << endl;
	{
		s.str("");
		SERIALIZEPTR(obj, s, Serializable::JSON);
	}
	cout << "   bytes: " << s.tellp() << endl;
	TIC(t);
	for( int i=0; i<repcount; i++ ) {
		s.str("");
		SERIALIZEPTR(obj, s, Serializable::JSON);
	}
	cout << "   serialization time: " << (double)TOC_US(t)/repcount << "us" << endl;

	cout << "BINARY serialization: " << endl;
	{
		s.str("");
		SERIALIZEPTR(obj, s, Serializable::BINARY);
	}
	cout << "   bytes: " << s.tellp() << endl;
	TIC(t);
	for( int i=0; i<repcount; i++ ) {
		s.str("");
		SERIALIZEPTR(obj, s, Serializable::BINARY);
	}
	cout << "   serialization time: " << (double)TOC_US(t)/repcount << "us" << endl;

	cout << "PORTABLEBINARY serialization: " << endl;
	{
		s.str("");
		SERIALIZEPTR(obj, s, Serializable::PORTABLEBINARY);
	}
	cout << "   bytes: " << s.tellp() << endl;
	TIC(t);
	for( int i=0; i<repcount; i++ ) {
		s.str("");
		SERIALIZEPTR(obj, s, Serializable::PORTABLEBINARY);
	}
	cout << "   serialization time: " << (double)TOC_US(t)/repcount << "us" << endl;
}

template<typename T>
void RunSerialOptionsObj(const T& obj) {
	Serialized	ser;
	string str;

	cout << typeid(obj).name() << endl;

	obj.Serialize(&ser);
	SerializableHelper::SerializationToString(ser, str);
	cout << "Legacy serialization:" << endl << "   bytes: " << str.length() << endl;

	TimeVar t;

	TIC(t);
	for( int i=0; i<repcount; i++ ) {
		Serialized ser;
		ser.SetObject();
		obj.Serialize(&ser);
		SerializableHelper::SerializationToString(ser, str);
	}
	cout << "   serialization time: " << (double)TOC_US(t)/repcount << "us" << endl;

	stringstream s;

	cout << "JSON serialization: " << endl;
	{
		s.str("");
		SERIALIZEOBJ(obj, s, Serializable::JSON);
	}
	cout << "   bytes: " << s.tellp() << endl;
	TIC(t);
	for( int i=0; i<repcount; i++ ) {
		s.str("");
		SERIALIZEOBJ(obj, s, Serializable::JSON);
	}
	cout << "   serialization time: " << (double)TOC_US(t)/repcount << "us" << endl;

	cout << "BINARY serialization: " << endl;
	{
		s.str("");
		SERIALIZEOBJ(obj, s, Serializable::BINARY);
	}
	cout << "   bytes: " << s.tellp() << endl;
	TIC(t);
	for( int i=0; i<repcount; i++ ) {
		s.str("");
		SERIALIZEOBJ(obj, s, Serializable::BINARY);
	}
	cout << "   serialization time: " << (double)TOC_US(t)/repcount << "us" << endl;

	cout << "PORTABLEBINARY serialization: " << endl;
	{
		s.str("");
		SERIALIZEOBJ(obj, s, Serializable::PORTABLEBINARY);
	}
	cout << "   bytes: " << s.tellp() << endl;
	TIC(t);
	for( int i=0; i<repcount; i++ ) {
		s.str("");
		SERIALIZEOBJ(obj, s, Serializable::PORTABLEBINARY);
	}
	cout << "   serialization time: " << (double)TOC_US(t)/repcount << "us" << endl;
}

int
main()
{
	Foo	xxx(4);
	ostringstream ss0, ss1, ss2;
	{
		cereal::JSONOutputArchive archive( ss0 );
		archive( cereal::make_nvp("Foo", xxx) );
	}
	cout << ss0.str() << endl;

	//	NativeInteger foo = 12;
	//	{
	//		cereal::JSONOutputArchive archive( cout );
	//		archive( cereal::make_nvp("NativeInt", foo) );
	//	}
	//
	////	NativeVector vec(8, 55, { 8, 6, 7, 5, 3, 0, 9 });
	////	{
	////		cereal::JSONOutputArchive archive( cout );
	////		archive( vec );
	////	}

	EncodingParams ep2( new EncodingParamsImpl(5, 7, 9, 11, 13, 15) );

//	stringstream ss;
//	SERIALIZEPTR(ep2, ss, Serializable::JSON);
//	EncodingParams epnew;
//	{
//		cereal::JSONInputArchive archive(ss);
//		archive(epnew);
//	}
//	cout << ((ep2 == epnew) ? "" : "DOES NOT ") << "MATCH" << endl;

	RunSerialOptionsPtr(ep2);

//	{
//		stringstream ss;
//		BigInteger x("1234567875643");
//		{
//			cereal::JSONOutputArchive archive( ss );
//			archive( x );
//		}
//		BigInteger y;
//		{
//			cereal::JSONInputArchive archive(ss);
//			archive(y);
//		}
//		cout << x << ":" << y << endl;
//	}

//	{
//		stringstream ss;
//		BigVector x(8, 73, { 8, 6, 7, 5, 3, 0, 9 });
//		{
//			cereal::JSONOutputArchive archive( ss );
//			archive( x );
//		}
//		cout << ss.str() << endl;
//		BigVector y;
//		{
//			cereal::JSONInputArchive archive(ss);
//			archive(y);
//		}
//		cout << x << endl;
//		cout << y << endl;
//	}

	{
		stringstream ss;
		ILParams parm(128, BigInteger(73), BigInteger(22));
		shared_ptr<ILParams> pp = make_shared<ILParams>(parm);
		DiscreteGaussianGenerator gen;
		Poly pol(gen, pp);
//		{
//			cereal::JSONOutputArchive archive( ss );
//			archive( pol );
//		}
//		Poly np;
//		{
//			cereal::JSONInputArchive archive( ss );
//			archive( np );
//		}
//		cout << ((pol == np) ? "" : "DOES NOT ") << "MATCH" << endl;

		cout << endl << "Polynomial with cyclotomic order " << pol.GetCyclotomicOrder() << endl;
		RunSerialOptionsObj(pol);
	}

	return 0;
}


