

#include "palisade.h"
#include "cryptocontextgen.h"

using namespace std;

void TestPowersAndDecompose(CryptoContext<ILVector2n> cc) {

	typename ILVector2n::DugType dug;
	ILVector2n randomVec(dug, cc.GetElementParams());

	std::cout << randomVec << endl;

	vector<ILVector2n> decomp = randomVec.BaseDecompose(cc.GetCryptoParameters()->GetRelinWindow());
	cout << "BaseDecompose result is " << decomp.size() << " vectors" << endl;

	for( usint v=0; v < decomp.size() ; v++ )
		cout << "Decomposed vector " << v << " == " << decomp[v] << endl;

	usint nBits = cc.GetCryptoParameters()->GetRelinWindow();
	ILVector2n answer(cc.GetElementParams(), EVALUATION, true); // zero vector
	for (usint i = 0; i < decomp.size(); i++) {
		ILVector2n thisProduct = decomp[i] * ILVector2n::Integer::TWO.ModExp( typename ILVector2n::Integer(i * nBits), cc.GetElementParams()->GetModulus());
		answer += thisProduct;
	}

	if (randomVec == answer)
		cout << "Success!" << endl;
	else
		cout << "Failure!" << endl;

	ILVector2n randomDgg(cc.GetCryptoParameters()->GetDiscreteGaussianGenerator(), cc.GetElementParams());
	vector<ILVector2n> pows = randomDgg.PowersOfBase(cc.GetCryptoParameters()->GetRelinWindow());
	cout << "PowersOfBase result is " << decomp.size() << " vectors" << endl;

	ILVector2n answer2(cc.GetElementParams(), EVALUATION, true); // zero vector
	for (usint i = 0; i < pows.size(); i++) {
		answer2 += decomp[i] * pows[i];
	}
	if ((randomVec * randomDgg) == answer2)
		cout << "Success!" << endl;
	else
		cout << "Failure!" << endl;
}

void TestPowersAndDecompose(CryptoContext<ILVectorArray2n> cc) {

	const shared_ptr<ILVectorArray2n::Params> eParms = std::dynamic_pointer_cast<ILVectorArray2n::Params>(cc.GetElementParams());
	typename ILVectorArray2n::DugType dug;
	ILVectorArray2n randomVec(dug, cc.GetElementParams());

	std::cout << randomVec << endl;

	vector<ILVectorArray2n> decomp = randomVec.BaseDecompose(cc.GetCryptoParameters()->GetRelinWindow());
	cout << "BaseDecompose result is " << decomp.size() << " vectors" << endl;

	for( usint v=0; v < decomp.size() ; v++ )
		cout << "Decomposed vector " << v << " == " << decomp[v] << endl;

	usint nBits = cc.GetCryptoParameters()->GetRelinWindow();
	ILVectorArray2n answer(cc.GetElementParams(), EVALUATION, true); // zero vector

	std::vector<ILVectorArray2n::Integer> mods(eParms->GetParams().size());
	for( usint i = 0; i < eParms->GetParams().size(); i++ )
		mods[i] = eParms->GetParams()[i]->GetModulus().ConvertToInt();

	for (usint i = 0; i < decomp.size(); i++) {
		ILVectorArray2n::Integer twoPow( ILVectorArray2n::Integer::TWO.Exp(i * nBits) );
		vector<ILVectorArray2n::ILVectorType> scalars(eParms->GetParams().size());

		for( int t = 0; t < eParms->GetParams().size(); t++ ) {
			ILVectorArray2n::Integer factor = twoPow % mods[t];
			ILVectorArray2n::ILVectorType thisScalar(eParms->GetParams()[t], COEFFICIENT);
			thisScalar = factor.ConvertToInt();
			scalars[t] = thisScalar;
			cout << t << " poly is " << scalars[t] << endl;
		}
		ILVectorArray2n thisProduct(scalars);
		thisProduct.SwitchFormat();

		cout << "scalars! " << thisProduct << endl;

		cout << thisProduct.GetFormat() << ":" << decomp[i].GetFormat() << endl;
		//ILVectorArray2n thisProduct = decomp[i] * ILVectorArray2n::Integer::TWO.ModExp( typename ILVectorArray2n::Integer(i * nBits),
																						//typename ILVectorArray2n::Integer((*eParms)[???]->GetModulus().ConvertToInt()));
		answer += thisProduct * decomp[i];
	}

	if (randomVec == answer)
		cout << "Success!" << endl;
	else
		cout << "Failure!" << endl;

	ILVectorArray2n randomDgg(cc.GetCryptoParameters()->GetDiscreteGaussianGenerator(), cc.GetElementParams());
	vector<ILVectorArray2n> pows = randomDgg.PowersOfBase(cc.GetCryptoParameters()->GetRelinWindow());
	cout << "PowersOfBase result is " << decomp.size() << " vectors" << endl;

	ILVectorArray2n answer2(cc.GetElementParams(), EVALUATION, true); // zero vector
	for (usint i = 0; i < pows.size(); i++) {
		answer2 += decomp[i] * pows[i];
	}
	if ((randomVec * randomDgg) == answer2)
		cout << "Success!" << endl;
	else
		cout << "Failure!" << endl;
}

int main()
{
	const usint ORDER = 8;
	const usint PTM = 2;
	const usint TOWERS = 3;

	CryptoContext<ILVector2n> cc = GenCryptoContextElementBV(ORDER, PTM);
	cout << "ILVector2n modulus " << cc.GetElementParams()->GetModulus() << " order " << ORDER << " ptm is " << PTM << " relin window is " << cc.GetCryptoParameters()->GetRelinWindow() << endl;
	TestPowersAndDecompose(cc);

	typename ILVector2n::DugType dug;
	dug.SetModulus( cc.GetElementParams()->GetModulus() );

//	{
//		CryptoContext<ILVector2n> cc = GenCryptoContextElementBV(ORDER, PTM);
//		CryptoContext<ILVectorArray2n> cc2 = GenCryptoContextElementArrayBV(ORDER, 1, PTM);
//		typename ILVector2n::DugType dug;
//		ILVector2n randomVec(dug, cc.GetElementParams(), COEFFICIENT);
//		ILVectorArray2n randomArrayVec(randomVec, cc2.GetElementParams());
//
//		cout << "TWO VECTORS" << endl;
//		cout << *cc.GetCryptoParameters() << endl;
//		cout << randomVec << endl;
//		cout << *cc2.GetCryptoParameters() << endl;
//		cout << randomArrayVec << endl;
//
////		const std::vector<ILVectorArray2n::ILVectorType>& parts = randomVec.GetAllElements();
////		for( usint i=0; i<parts.size(); i++ )
////			cout << i << ": " << parts[i].GetValues() << endl;
////
//	}

	for ( usint i = 1; i <= TOWERS; i++ ) {
		CryptoContext<ILVectorArray2n> cc2 = GenCryptoContextElementArrayBV(ORDER, i, PTM);
		cout << "ILVectorArray2n " << i << " towers, modulus " << cc2.GetElementParams()->GetModulus() << " order " << ORDER << " ptm is " << PTM << " relin window is " << cc2.GetCryptoParameters()->GetRelinWindow() << endl;
		TestPowersAndDecompose(cc2);
	}

	return 0;
}
