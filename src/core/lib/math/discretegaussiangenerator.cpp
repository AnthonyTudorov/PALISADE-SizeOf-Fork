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

	DiscreteGaussianGenerator::DiscreteGaussianGenerator(float std) : DistributionGenerator() {

		SetStd(std);
		Initialize();
	}

	void DiscreteGaussianGenerator::SetStd(float std) {
		m_std = std;
	}

	float DiscreteGaussianGenerator::GetStd() const {
		return m_std;
	}

	void DiscreteGaussianGenerator::Initialize() {

		//weightDiscreteGaussian
		double acc = 1e-15;
		double variance = m_std * m_std;

		int fin = (int)ceil(m_std * sqrt(-2 * log(acc)));
		//this value of fin (M) corresponds to the limit for double precision
		// usually the bound of m_std * M is used, where M = 20 .. 40 - see DG14 for details
		// M = 20 corresponds to 1e-87
		//double mr = 20; // see DG14 for details
		//int fin = (int)ceil(m_std * mr);

		double cusum = 1.0;

		for (sint x = 1; x <= fin; x++) {
			cusum = cusum + 2 * exp(-x * x / (variance * 2));
		}

		m_a = 1 / cusum;

		//fin = (int)ceil(sqrt(-2 * variance * log(acc))); //not needed - same as above
		double temp;

		for (sint i = 1; i <= fin; i++) {
			temp = m_a * exp(-((double)(i * i) / (2 * variance)));
			m_vals.push_back(temp);
		}

		// take cumulative summation
		for (usint i = 1; i < m_vals.size(); i++) {
			m_vals[i] += m_vals[i - 1];
		}

		//for (usint i = 0; i<m_vals.size(); i++) {
		//	std::cout << m_vals[i] << std::endl;
		//}

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

	std::shared_ptr<sint> DiscreteGaussianGenerator::GenerateIntVector(usint size) const {

		std::uniform_real_distribution<double> distribution(0.0, 1.0);

		usint val = 0;
		double seed;
		std::shared_ptr<sint> ans( new sint[size], std::default_delete<int[]>() );

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
			(ans.get())[i] = val;
		}

		return ans;
	}

	usint DiscreteGaussianGenerator::FindInVector(const std::vector<double> &S, double search) const {
		//STL binary search implementation
		auto lower = std::lower_bound(S.begin(), S.end(), search);
		if (lower != S.end())
			return lower - S.begin();
		else
			throw std::runtime_error("DGG Inversion Sampling. FindInVector value not found: " + std::to_string(search));
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

		std::shared_ptr<sint> result = GenerateIntVector(size);

		BigBinaryVector ans(size);
		ans.SetModulus(modulus);

		for (usint i = 0; i < size; i++) {
			sint v = (result.get())[i];
			if (v < 0) {
				v *= -1;
				ans.SetValAtIndex(i, modulus - UintToBigBinaryInteger(v));
			}
			else {
				ans.SetValAtIndex(i, UintToBigBinaryInteger(v));
			}
		}

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

	int32_t DiscreteGaussianGenerator::GenerateInteger(double mean, double stddev, size_t n) {

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
#if defined(_MSC_VER)
		double dbmean = mean.convert_to<double>();
		double dbt = t.convert_to<double>();
#else
		double dbmean = (double)mean;
		double dbt = (double)t;
#endif
		int count = 0;
		std::uniform_int_distribution<int32_t> uniform_int(floor(dbmean - dbt), ceil(dbmean + dbt));
		boost::random::uniform_real_distribution<LargeFloat> uniform_real(0.0, 1.0);

		LargeFloat sigmaFactor = -1 / (2. * stddev * stddev);

		while (true) {
			count++;
			//  pick random int
			int32_t x = uniform_int(GetPRNG());
			//  roll the uniform dice
			LargeFloat dice = uniform_real(GetPRNG());
			//  check if dice land below pdf
			if (dice <= UnnormalizedGaussianPDF(mean, x, sigmaFactor)) {
				// std::cout << "Count: " << count << std::endl;
				return x;
			}
		}
	}
	/**
		*Generates the probability matrix of given distribution, which is used in Knuth-Yao method
	*/
	void DiscreteGaussianGenerator::GenerateProbMatrix(double stddev, double mean) {
		if (probMatrix != nullptr) {
			delete[] probMatrix;
		}
		probMean = mean;
		probMatrixSize = 10 * stddev + 2;
		probMatrix = new uint32_t[probMatrixSize];
		double error = 1;
		for (int i = -5 * stddev + mean;i <= 5 * stddev + mean;i++) {
			double prob = pow(M_E, -pow(i - mean, 2) / (2. * stddev * stddev)) / (stddev * sqrt(2.*M_PI));

			error -= prob;
			probMatrix[int(i + 5 * stddev - mean)] = prob * pow(2, 32);
			//Hamming weights are disabled for now
			/*
			for (int j = 0;j < 32;j++) {
				hammingWeights[j] += ((probMatrix[int(i + m / 2)] >> (31 - j)) & 1);

			}
			*/
		}
		//std::cout << "Error probability: "<< error << std::endl;
		probMatrix[probMatrixSize - 1] = error * pow(2, 32);
		//Hamming weights are disabled for now
		/*
		for (int k = 0;k< 32;k++) {
			hammingWeights[k] += ((probMatrix[probMatrixSize - 1] >> (31 - k)) & 1);
		}
		*/
	}
	/**
	*Generates the probability matrix of given distribution, which is used in Knuth-Yao method (Large Float Version)
	*/
	void DiscreteGaussianGenerator::GenerateProbMatrix(const LargeFloat & stddev, const LargeFloat & mean) {
		if (probMatrix != nullptr) {
			delete[] probMatrix;
		}
#if defined(_MSC_VER)
		double dbmean = mean.convert_to<double>();
		double dbstddev = stddev.convert_to<double>();
#else
		double dbmean = (double)mean;
		double dbstddev = (double)stddev;
#endif
		probMean = dbmean;
		probMatrixSize = 10 * dbstddev + 2;
		probMatrix = new uint32_t[probMatrixSize];
		double error = 1;
		for (int i = -5 * dbstddev + dbmean;i <= 5 * dbstddev + dbmean;i++) {
			double prob = pow(M_E, -pow(i - dbmean, 2) / (2. * dbstddev * dbstddev)) / (dbstddev * sqrt(2.*M_PI));

			error -= prob;
			probMatrix[int(i + 5 * dbstddev - dbmean)] = prob * pow(2, 32);
			//Hamming weights are disabled for now
			/*
			for (int j = 0;j < 32;j++) {
			hammingWeights[j] += ((probMatrix[int(i + m / 2)] >> (31 - j)) & 1);

			}
			*/
		}
		//std::cout << "Error probability: " << error << std::endl;
		probMatrix[probMatrixSize - 1] = error * pow(2, 32);
		//Hamming weights are disabled for now
		/*
		for (int k = 0;k< 32;k++) {
		hammingWeights[k] += ((probMatrix[probMatrixSize - 1] >> (31 - k)) & 1);
		}
		*/
	}
	/**
	* Returns a generated integer. Uses Knuth-Yao method defined as Algorithm 1 in http://link.springer.com/chapter/10.1007%2F978-3-662-43414-7_19#page-1
	*/
	int32_t DiscreteGaussianGenerator::GenerateIntegerKnuthYao() {
		int32_t S = 0;
		bool discard = true;
		std::uniform_int_distribution<int32_t> uniform_int(INT_MIN, INT_MAX);
		uint32_t seed;
		char counter = 0;
		int32_t MAX_ROW = probMatrixSize - 1;
		while (discard == true) {
			//The distance
			int32_t d = 0;
			//Whether a terminal node is hit or not
			uint32_t hit = 0;
			//Indicator of column
			short col = 0;
			bool scanningInitialized = false;
			//To generate random bit a 32 bit integer is generated in every 32 iterations and each single bit is used in order to save cycles
			while (hit == 0 && col <= 31) {
				if (counter % 32 == 0) {
					seed = uniform_int(GetPRNG());
					counter = 0;
				}
				uint32_t r = seed >> counter;
				d = 2 * d + (~r & 1);
				//if (d < hammingWeights[col] || scanningInitialized){
					//scanningInitialized = true;

				for (int32_t row = MAX_ROW;row > -1 && hit == 0;row--) {
					d -= ((probMatrix[row] >> (31 - col)) & 1);
					if (d == -1) {
						hit = 1;
						//If the terminal node is found on the last row, it means that it hit an error column therefore the sample is discarded
						if (row == MAX_ROW) {
							//std::cout << "Hit error row, discarding sample..." << std::endl;
						}
						else {
							//Result is the row that the terminal node found in
							S = row;
							discard = false;
						}
					}
				}
				//}
				col++;
				counter++;
			}
		}
		//The calculation to understand what integer the column actually corresponds to in probability matrix
		return  S - (MAX_ROW - 1) / 2 + probMean;
	}


} // namespace lbcrypto
