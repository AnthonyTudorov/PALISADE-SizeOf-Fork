#include "discretegaussiangenerator.h"
#include "nbtheory.h"
#include "backend.h"

namespace lbcrypto {

	template<typename IntType, typename VecType>
	DiscreteGaussianGeneratorImpl<IntType,VecType>::DiscreteGaussianGeneratorImpl() : DistributionGenerator() {

		SetStd(1);
		Initialize();
	}

	template<typename IntType, typename VecType>
	DiscreteGaussianGeneratorImpl<IntType,VecType>::DiscreteGaussianGeneratorImpl(float std) : DistributionGenerator() {

		SetStd(std);
		Initialize();
	}

	template<typename IntType, typename VecType>
	void DiscreteGaussianGeneratorImpl<IntType,VecType>::SetStd(float std) {
		m_std = std;
	}

	template<typename IntType, typename VecType>
	float DiscreteGaussianGeneratorImpl<IntType,VecType>::GetStd() const {
		return m_std;
	}

	template<typename IntType, typename VecType>
	void DiscreteGaussianGeneratorImpl<IntType,VecType>::Initialize() {

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

	template<typename IntType, typename VecType>
	sint DiscreteGaussianGeneratorImpl<IntType,VecType>::GenerateInt() const {

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

	template<typename IntType, typename VecType>
	std::shared_ptr<sint> DiscreteGaussianGeneratorImpl<IntType,VecType>::GenerateIntVector(usint size) const {

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

	template<typename IntType, typename VecType>
	usint DiscreteGaussianGeneratorImpl<IntType,VecType>::FindInVector(const std::vector<double> &S, double search) const {
		//STL binary search implementation
		auto lower = std::lower_bound(S.begin(), S.end(), search);
		if (lower != S.end())
			return lower - S.begin();
		else
			throw std::runtime_error("DGG Inversion Sampling. FindInVector value not found: " + std::to_string(search));
	}

	template<typename IntType, typename VecType>
	IntType DiscreteGaussianGeneratorImpl<IntType,VecType>::GenerateInteger(const IntType &modulus) const {

		int32_t val = 0;
		double seed;
		IntType ans;
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
			ans = modulus - IntType(val);
		}
		else
			ans = IntType(val);

		return ans;

	}

	template<typename IntType, typename VecType>
	VecType DiscreteGaussianGeneratorImpl<IntType,VecType>::GenerateVector(const usint size, const IntType &modulus) const {

		std::shared_ptr<sint> result = GenerateIntVector(size);

		VecType ans(size);
		ans.SetModulus(modulus);

		for (usint i = 0; i < size; i++) {
			sint v = (result.get())[i];
			if (v < 0) {
				v *= -1;
				ans.SetValAtIndex(i, modulus - IntType(v));
			}
			else {
				ans.SetValAtIndex(i, IntType(v));
			}
		}

		return ans;
	}

	template<typename IntType, typename VecType>
	IntType DiscreteGaussianGeneratorImpl<IntType,VecType>::GenerateInteger(double mean, double stddev, size_t n, const IntType &modulus) const {

		double t = log2(n)*stddev;

		IntType result;

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
			result = modulus - IntType(x);
		}
		else
			result = IntType(x);

		return result;

	}

	template<typename IntType, typename VecType>
	int32_t DiscreteGaussianGeneratorImpl<IntType,VecType>::GenerateInteger(double mean, double stddev, size_t n) {

		double t = log2(n)*stddev;  //this representation of log_2 is used for Visual Studio

		IntType result;

		std::uniform_int_distribution<int32_t> uniform_int(floor(mean - t), ceil(mean + t));
		std::uniform_real_distribution<double> uniform_real(0.0, 1.0);

		double sigmaFactor = -1 / (2. * stddev * stddev);

		bool flagSuccess = false;
		int32_t x;

		while (!flagSuccess) {
			//  pick random int
			x = uniform_int(GetPRNG());
			//  roll the uniform dice
			double dice = uniform_real(GetPRNG());
			//  check if dice land below pdf
			if (dice <= UnnormalizedGaussianPDFOptimized(mean, sigmaFactor, x)) {
				flagSuccess = true;
			}
		}

		return x;

	}

	/**
		*Generates the probability matrix of given distribution, which is used in Knuth-Yao method
	*/
	template<typename IntType, typename VecType>
	void DiscreteGaussianGeneratorImpl<IntType,VecType>::GenerateProbMatrix(double stddev, double mean) {
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
	* Returns a generated integer. Uses Knuth-Yao method defined as Algorithm 1 in http://link.springer.com/chapter/10.1007%2F978-3-662-43414-7_19#page-1
	*/
	template<typename IntType, typename VecType>
	int32_t DiscreteGaussianGeneratorImpl<IntType,VecType>::GenerateIntegerKnuthYao() {
		int32_t S = 0;
		bool discard = true;
		std::uniform_int_distribution<int32_t> uniform_int(std::numeric_limits<int32_t>::min(), std::numeric_limits<int32_t>::max());
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