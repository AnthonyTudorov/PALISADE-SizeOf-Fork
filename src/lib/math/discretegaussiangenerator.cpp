#include "discretegaussiangenerator.h"
#include "nbtheory.h"
#include "backend.h"

#include <boost/multiprecision/random.hpp>
#include <boost/random.hpp>
#include <boost/random/uniform_int_distribution.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/cpp_dec_float.hpp>

namespace lbcrypto {

	DiscreteGaussianGenerator::DiscreteGaussianGenerator() : DistributionGenerator() {

		SetStd(1);
		Initialize();
	}

	DiscreteGaussianGenerator::DiscreteGaussianGenerator(const sint std) : DistributionGenerator() {

		SetStd(std);
		Initialize();
	}

	void DiscreteGaussianGenerator::SetStd(const sint std) {
		m_std = std;
	}

	sint DiscreteGaussianGenerator::GetStd() const {
		return m_std;
	}

	void DiscreteGaussianGenerator::Initialize() {

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
			temp = m_a * exp(-((double)(i * i) / (2 * variance)));
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

	sint DiscreteGaussianGenerator::GenerateInt() const {

		std::uniform_real_distribution<double> distribution(0.0, 1.0);

		usint val = 0;
		double seed;
		sint ans;


		seed = distribution(GetPRNG()) - 0.5; //we need to use the binary uniform generator rathen than regular continuous distribution; see DG14 for details
		if (std::abs(seed) <= m_a / 2) {
			val = 0;
		}
		else if (seed > 0) {
			val = FindInVector(m_vals, (std::abs(seed) - m_a / 2));
		}
		else {
			val = -(int)FindInVector(m_vals, (std::abs(seed) - m_a / 2));
		}
		ans = val;

		return ans;
	}

	sint * DiscreteGaussianGenerator::GenerateIntVector(usint size) const {

		std::uniform_real_distribution<double> distribution(0.0, 1.0);

		usint val = 0;
		double seed;
		sint * ans = new sint[size];

		for (usint i = 0; i < size; i++) {
			seed = distribution(GetPRNG()) - 0.5; //we need to use the binary uniform generator rathen than regular continuous distribution; see DG14 for details
			if (std::abs(seed) <= m_a / 2) {
				val = 0;
			}
			else if (seed > 0) {
				val = FindInVector(m_vals, (std::abs(seed) - m_a / 2));
			}
			else {
				val = -(int)FindInVector(m_vals, (std::abs(seed) - m_a / 2));
			}
			ans[i] = val;
		}

		return ans;
	}

	usint DiscreteGaussianGenerator::FindInVector(const std::vector<double> &S, double search) const {
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
		std::uniform_real_distribution<double> distribution(0.0, 1.0);

		seed = distribution(GetPRNG()) - 0.5;

		if (std::abs(seed) <= m_a / 2) {
			val = 0;
		}
		else if (seed > 0) {
			val = FindInVector(m_vals, (std::abs(seed) - m_a / 2));
		}
		else {
			val = -(int)FindInVector(m_vals, (std::abs(seed) - m_a / 2));
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
			}
			else {
				ans.SetValAtIndex(i, UintToBigBinaryInteger(result[i]));
			}
		}

		delete[]result;

		return ans;
	}

	BigBinaryInteger DiscreteGaussianGenerator::GenerateInteger(double mean, double stddev, size_t n, const BigBinaryInteger &modulus) const {

		double t = log(n) / log(2)*stddev;  //this representation of log_2 is used for Visual Studio

		BigBinaryInteger result;

		std::uniform_int_distribution<int32_t> uniform_int(floor(mean - t), ceil(mean + t));
		std::uniform_real_distribution<double> uniform_real(0.0, 1.0);

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

		double t = log(n) / log(2)*stddev;  //this representation of log_2 is used for Visual Studio

		BigBinaryInteger result;

		std::uniform_int_distribution<int32_t> uniform_int(floor(mean - t), ceil(mean + t));
		std::uniform_real_distribution<double> uniform_real(0.0, 1.0);

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

	/**
		*  int32_t is used here as the components are relatively small
		*  this is a simple inefficient implementation as noted in DG14; will need to be improved
		*/
	int32_t DiscreteGaussianGenerator::GenerateInteger(const LargeFloat &mean, const LargeFloat &stddev, size_t n) {

		LargeFloat t = log(n) / log(2)*stddev;  //fix for Visual Studio

		//YSP this double conversion is necessary for uniform_int to work properly; the use of double is justified in this case
		double dbmean = mean.convert_to<double>();
		double dbt = t.convert_to<double>();

		std::uniform_int_distribution<int32_t> uniform_int(floor(dbmean - dbt), ceil(dbmean + dbt));
		boost::random::uniform_real_distribution<LargeFloat> uniform_real(0.0, 1.0);

		while (true) {
			//  pick random int
			int32_t x = uniform_int(GetPRNG());
			//  roll the uniform dice
			LargeFloat dice = uniform_real(GetPRNG());
			//  check if dice land below pdf
			if (dice <= UnnormalizedGaussianPDF(mean, stddev, x)) {
				return x;
			}
		}
	}
	/**
		*Generates the probability matrix of given distribution, which is used in Knuth-Yao method
	*/
	void DiscreteGaussianGenerator::GenerateProbMatrix(double stddev, double m) {
		if (probMatrix != nullptr) {
			delete[] probMatrix;
		}
		else {
			probMatrix = new uint32_t[m + 2];
			probMatrixSize = m + 2;
			double error = 1;
			for (int i = -m/2;i <= m/2;i++) {
				double prob = pow(M_E, -pow(i, 2) / (2. * stddev * stddev)) / (stddev * sqrt(2.*M_PI));
				error -= prob;
				probMatrix[int(i+m/2)] = prob * pow(2, 32);
			}
			std::cout << "Error: "<< error << std::endl;
			probMatrix[probMatrixSize-1] = error * pow(2, 32);
		}
	}
	/**
	* Returns a generated integer. Uses Knuth-Yao method defined as Algorithm 1 in http://link.springer.com/chapter/10.1007%2F978-3-662-43414-7_19#page-1
	*/
	int32_t DiscreteGaussianGenerator::GenerateIntegerKnuthYao() {
		int32_t S = 0;
		bool discard = true;
		std::uniform_int_distribution<int32_t> uniform_int(0, 1);
		int32_t MAX_ROW = probMatrixSize - 1;
		while (discard == true) {
			int32_t d = 0;
			uint32_t hit = 0;
			uint32_t col = 0;
			while (hit == 0 && col<=32) {
				uint32_t r = uniform_int(GetPRNG());
				d = 2 * d + (~r & 1);
				for (int32_t row = MAX_ROW;row > -1 && hit == 0;row--) {
					d -= ((probMatrix[row] >> (31 - col)) & 1);
					if (d == -1) {
						hit = 1;
						if (row == MAX_ROW) {
							std::cout << "Hit error row, discarding sample..." << std::endl;
						}
						else {
							S = row;
							discard = false;
						}
					}
				}
				col++;
			}
		}
		return S - (MAX_ROW - 1) / 2;
	}


} // namespace lbcrypto
