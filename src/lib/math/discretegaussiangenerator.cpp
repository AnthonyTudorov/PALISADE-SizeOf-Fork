#include "discretegaussiangenerator.h"
#include "nbtheory.h"
#include "backend.h"

namespace lbcrypto {

DiscreteGaussianGenerator::DiscreteGaussianGenerator() : DistributionGenerator() {

	SetStd(1);
	Initialize();
}

DiscreteGaussianGenerator::DiscreteGaussianGenerator (const sint std) : DistributionGenerator () {

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

	//int fin = (int)ceil(sqrt(2 * pi) * m_std * sqrt(-1 * log(acc) / pi));
	int fin = (int)ceil(m_std * sqrt(-2 * log(acc))); //this value of fin (M) may be too low; 
																		  // usually the bound of m_std * M is used where M = 20 .. 40
																		  // see DG14 for details

	double cusum = 1.0;

	for (sint x = 1; x <= fin; x++) {
		cusum = cusum + 2 * exp(-pi * (x * x) / (variance * 2 * pi));
		//cusum = cusum + 2 * exp(-(x * x) / (variance * 2));  //simplified
	}

	m_a = 1 / cusum;

	//fin = (int)ceil(sqrt(-2 * variance * log(acc))); //not needed - same as above
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

}

sint DiscreteGaussianGenerator::GenerateInt () const {

	std::uniform_real_distribution<double> distribution(0.0,1.0);

	usint val = 0;
	double seed;
	sint ans;


	seed = distribution(GetPRNG()) - 0.5; //we need to use the binary uniform generator rathen than regular continuous distribution; see DG14 for details
	if (std::abs(seed) <= m_a / 2) {
		val = 0;
	} else if (seed > 0) {
		val = FindInVector(m_vals, (std::abs(seed) - m_a / 2));
	} else {
		val = - (int) FindInVector(m_vals, (std::abs(seed) - m_a / 2));
	}
	ans = val;

	return ans;
}

sint * DiscreteGaussianGenerator::GenerateIntVector (usint size) const {

	std::uniform_real_distribution<double> distribution(0.0,1.0);

	usint val = 0;
	double seed;
	sint * ans = new sint[size];

	for (usint i = 0; i < size; i++) {
		seed = distribution(GetPRNG()) - 0.5; //we need to use the binary uniform generator rathen than regular continuous distribution; see DG14 for details
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
	throw std::runtime_error("FindInVector value not found");
}

BigBinaryInteger DiscreteGaussianGenerator::GenerateInteger(const BigBinaryInteger &modulus) const {

	int32_t val = 0;
	double seed;
	BigBinaryInteger ans;
	std::uniform_real_distribution<double> distribution(0.0,1.0);

	seed = distribution(GetPRNG())-0.5;

	if (std::abs(seed) <= m_a / 2) {
		val = 0;
	} else if (seed > 0) {
		val = FindInVector(m_vals, (std::abs(seed) - m_a / 2));
	} else {
		val = -(int) FindInVector(m_vals, (std::abs(seed) - m_a / 2));
	}

	if (val < 0)
	{
		val *= -1;
		ans = modulus - UintToBigBinaryInteger(val);
	}
	else
		ans = BigBinaryInteger(val);

	return ans;

}

BigBinaryVector DiscreteGaussianGenerator::GenerateVector(const usint size, const BigBinaryInteger &modulus) const {

	//return ans;
	sint* result = GenerateIntVector(size);

	BigBinaryVector ans(size);
	ans.SetModulus(modulus);

	for (usint i = 0; i < size; i++) {
		if (result[i] < 0) {
			result[i] *= -1;
			ans.SetValAtIndex(i, modulus - UintToBigBinaryInteger(result[i]));
		} else {
			ans.SetValAtIndex(i, UintToBigBinaryInteger(result[i]));
		}
	}

	delete []result;

	return ans;
}

BigBinaryInteger DiscreteGaussianGenerator::GenerateInteger(double mean, double stddev, size_t n, const BigBinaryInteger &modulus) const {

		double t = log(n)/log(2)*stddev;  //this representation of log_2 is used for Visual Studio

		BigBinaryInteger result;

		std::uniform_int_distribution<int32_t> uniform_int(floor(mean - t), ceil(mean + t));
		std::uniform_real_distribution<double> uniform_real(0.0,1.0);

		bool flagSuccess = false;
		int32_t x;

		while (!flagSuccess) {
			//  pick random int
			x = uniform_int(GetPRNG());
			//  roll the uniform dice
			double dice = uniform_real(GetPRNG());
			//  check if dice land below pdf
			if (dice <= UnnormalizedGaussianPDF(mean, stddev, x)) {
				flagSuccess = true;
			}
		}

		if (x < 0)
		{
			x *= -1;
			result = modulus - UintToBigBinaryInteger(x);
		}
		else
			result = BigBinaryInteger(x);

		return result;

}

int32_t DiscreteGaussianGenerator::GenerateInteger(double mean, double stddev, size_t n) const {

		double t = log(n)/log(2)*stddev;  //this representation of log_2 is used for Visual Studio

		BigBinaryInteger result;

		std::uniform_int_distribution<int32_t> uniform_int(floor(mean - t), ceil(mean + t));
		std::uniform_real_distribution<double> uniform_real(0.0,1.0);

		bool flagSuccess = false;
		int32_t x;

		while (!flagSuccess) {
			//  pick random int
			x = uniform_int(GetPRNG());
			//  roll the uniform dice
			double dice = uniform_real(GetPRNG());
			//  check if dice land below pdf
			if (dice <= UnnormalizedGaussianPDF(mean, stddev, x)) {
				flagSuccess = true;
			}
		}

		return x;

}


} // namespace lbcrypto
