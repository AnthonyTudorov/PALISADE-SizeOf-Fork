

#include "palisade.h"
#include "cryptocontextgen.h"

using namespace std;

void TestPowersAndDecompose(CryptoContext<ILVector2n> cc, ILVector2n& randomVec) {

	const shared_ptr<ILVector2n::Params> eParms = std::dynamic_pointer_cast<ILVector2n::Params>(cc.GetElementParams());
	cout << *eParms << endl;

	vector<ILVector2n> decomp = randomVec.BaseDecompose(cc.GetCryptoParameters()->GetRelinWindow());
	cout << "BaseDecompose result is " << decomp.size() << " vectors" << endl;

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

void TestPowersAndDecompose(CryptoContext<ILVectorArray2n> cc, ILVectorArray2n& randomVec) {

	const shared_ptr<ILVectorArray2n::Params> eParms = std::dynamic_pointer_cast<ILVectorArray2n::Params>(cc.GetElementParams());
	cout << *eParms << endl;

	vector<ILVectorArray2n> decomp = randomVec.BaseDecompose(cc.GetCryptoParameters()->GetRelinWindow());
	cout << "BaseDecompose result is " << decomp.size() << " vectors" << endl;

	usint nBits = cc.GetCryptoParameters()->GetRelinWindow();
	ILVectorArray2n answer(cc.GetElementParams(), EVALUATION, true); // zero vector

	std::vector<ILVectorArray2n::Integer> mods(eParms->GetParams().size());
	for( usint i = 0; i < eParms->GetParams().size(); i++ )
		mods[i] = ILVectorArray2n::Integer(eParms->GetParams()[i]->GetModulus().ConvertToInt());

	//native64::BigBinaryInteger tp( native64::BigBinaryInteger(2).Exp(32) - 1 );
	for (usint i = 0; i < decomp.size(); i++) {
		ILVectorArray2n::Integer twoPow( ILVectorArray2n::Integer(2).Exp(i * nBits) );
		vector<ILVectorArray2n::ILVectorType> scalars(eParms->GetParams().size());

		for( int t = 0; t < eParms->GetParams().size(); t++ ) {
			ILVectorArray2n::Integer factor = twoPow % mods[t];
			ILVectorArray2n::ILVectorType thisScalar(eParms->GetParams()[t], EVALUATION);
			thisScalar = factor.ConvertToInt();
			scalars[t] = thisScalar;
		}
		ILVectorArray2n thisProduct(scalars);

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
	const usint BITS = 34;

	CryptoContext<ILVector2n> cc = GenCryptoContextElementBV(ORDER, PTM, BITS);
	cout << "ILVector2n modulus " << cc.GetElementParams()->GetModulus() << " order " << ORDER << " ptm is " << PTM << " relin window is " << cc.GetCryptoParameters()->GetRelinWindow() << endl;

	typename ILVector2n::DugType dug;
	dug.SetModulus( cc.GetElementParams()->GetModulus() );

	ILVector2n randomVec(dug, cc.GetElementParams());

	TestPowersAndDecompose(cc, randomVec);


	for ( usint i = 1; i <= TOWERS; i++ ) {
		CryptoContext<ILVectorArray2n> cc2 = GenCryptoContextElementArrayBV(ORDER, i, PTM, BITS);
		cout << "ILVectorArray2n " << i << " towers, modulus " << cc2.GetElementParams()->GetModulus() << " order " << ORDER << " ptm is " << PTM << " relin window is " << cc2.GetCryptoParameters()->GetRelinWindow() << endl;

		ILVectorArray2n randomVecA(randomVec, cc2.GetElementParams());

		TestPowersAndDecompose(cc2, randomVecA);
	}

	return 0;
}
