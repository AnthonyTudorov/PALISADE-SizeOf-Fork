#include "discretegaussiangenerator.h"
#include "nbtheory.h"
#include "backend.h"

namespace lbcrypto {

DiscreteGaussianGenerator::DiscreteGaussianGenerator() : DiscreteDistributionGenerator() {
	// Set the random seed for std::rand. This is a temporary fix to facilitate the use of std::rand in this class.
	// This will be removed when all uses of std::rand are removed.
	std::random_device rd;
	std::srand(rd());

	SetStd(1);
	Initialize();
}

DiscreteGaussianGenerator::DiscreteGaussianGenerator (const BigBinaryInteger & modulus, const sint std) : DiscreteDistributionGenerator (modulus) {
	// Set the random seed for std::rand. This is a temporary fix to facilitate the use of std::rand in this class.
	// This will be removed when all uses of std::rand are removed.
	std::random_device rd;
	std::srand(rd());

	SetStd(std);
	Initialize();
}

void DiscreteGaussianGenerator::SetStd (const sint std) {
	m_std = std;
}

sint DiscreteGaussianGenerator::GetStd () const {
	return m_std;
}

void DiscreteGaussianGenerator::Initialize () {

	const double pi = 3.1415926;
	//weightDiscreteGaussian
	double acc = 0.00000001;
	sint variance = m_std * m_std;

	int fin = (int)ceil(sqrt(2 * pi) * m_std * sqrt(-1 * log(acc) / pi));

	double cusum = 1.0;

	for (sint x = 1; x <= fin; x++) {
		cusum = cusum + 2 * exp(-pi * (x * x) / (variance * 2 * pi));
	}

	m_a = 1 / cusum;

	fin = (int)ceil(sqrt(-2 * variance * log(acc)));
	double temp;

	for (sint i = 1; i <= fin; i++) {
		temp = m_a * exp(-((double) (i * i) / (2 * variance)));
		m_vals.push_back(temp);
	}

	/*
	for(usint i=0;i<m_vals.size();i++){
		std::cout<<m_vals[i]<<std::endl;
	}
	std::cout<<std::endl<<std::endl;
	*/

	// take cumulative summation
	for (usint i = 1; i < m_vals.size(); i++) {
		m_vals[i] += m_vals[i - 1];
	}

	//std::cout<<m_a<<std::endl;

	/*
	for(usint i=0;i<m_vals.size();i++){
		std::cout<<m_vals[i]<<std::endl;
	}
	std::cout<<std::endl<<std::endl;
	*/
}

schar * DiscreteGaussianGenerator::GenerateCharVector (usint size) const {

	//std::default_random_engine generator;
	//std::uniform_real_distribution<double> distribution(0.0,1.0);
	//generator.seed(time(NULL));

	double val = 0;
	double seed;
	schar * ans = new schar[size];

	for (usint i = 0; i < size; i++) {
		//generator.seed(time(NULL));
		seed = ((double) std::rand() / (RAND_MAX)) - 0.5;
		//std::cout<<seed<<std::endl;
		//seed = distribution(generator)-0.5;
		if (std::abs(seed) <= m_a / 2) {
			val = 0;
		} else if (seed > 0) {
			val = FindInVector(m_vals, (std::abs(seed) - m_a / 2));
		} else {
			val = - (int) FindInVector(m_vals, (std::abs(seed) - m_a / 2));
		}
		ans[i] = val;
	}

	return ans;
}

usint DiscreteGaussianGenerator::FindInVector (const std::vector<double> &S, double search) const {
	for (usint i = 0; i < S.size(); i++) {
		if (S[i] >= search) {
			return i;
		}
	}
}

BigBinaryVector DiscreteGaussianGenerator::DiscreteGaussianPositiveGenerator(usint vectorLength, const BigBinaryInteger &modValue) {

	BigBinaryVector ans(vectorLength);
	ans.SetModulus(modValue);

	for (usint i = 0; i < vectorLength; i++) {
		ans.SetValAtIndex(i, UintToBigBinaryInteger(std::rand() % 8));
	}

	return ans;
}

BigBinaryInteger DiscreteGaussianGenerator::GenerateInteger() {
	return std::move(*(new BigBinaryInteger()));
}

BigBinaryVector DiscreteGaussianGenerator::GenerateVector(const usint size) {
	//BigBinaryVector ans(DiscreteGaussianGenerator::DiscreteGaussianPositiveGenerator(size,this->m_modulus));

	//return ans;
	schar* result = GenerateCharVector(size);

	BigBinaryVector ans(size);
	ans.SetModulus(m_modulus);

	for (usint i = 0; i < size; i++) {
		if (result[i] < 0) {
			result[i] *= -1;
			ans.SetValAtIndex(i, UintToBigBinaryInteger(result[i]));
			ans.SetValAtIndex(i, m_modulus - ans.GetValAtIndex(i));
		} else {
			ans.SetValAtIndex(i, UintToBigBinaryInteger(result[i]));
		}
	}

	delete []result;

	return ans;
}

} // namespace lbcrypto