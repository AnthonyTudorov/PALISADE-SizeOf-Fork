/*
* @file discretegaussiangenerator.cpp This code provides generation of gaussian distibutions of discrete values.
* Discrete uniform generator relies on the built-in C++ generator for 32-bit unsigned integers defined in <random>.
* @author  TPOC: palisade@njit.edu
*
* @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
* All rights reserved.
* Redistribution and use in source and binary forms, with or without modification,
* are permitted provided that the following conditions are met:
* 1. Redistributions of source code must retain the above copyright notice, this
* list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright notice, this
* list of conditions and the following disclaimer in the documentation and/or other
* materials provided with the distribution.
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
* ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
* OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
* IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
*/
#include "discretegaussiangeneratorgeneric.h"
#include "nbtheory.h"
#include "backend.h"

namespace lbcrypto {

	const double DG_ERROR = 8.27181e-25;
	const int32_t N_MAX = 16384;
	const double SIGMA = std::sqrt(std::log(2 * N_MAX / DG_ERROR) / M_PI);
	//const int32_t PRECISION = 128;
	//const double TAIL_CUT = std::sqrt(log(2)*2*(double)(PRECISION));
	const int32_t STDDEV_COUNT=7;
	//const int32_t DDG_DEPTH = 13;
	const int32_t MIN_TREE_DEPTH = 44;

	//	template<typename IntType, typename VecType>
	//	DiscreteGaussianGeneratorImpl<IntType,VecType>::DiscreteGaussianGeneratorImpl() : DistributionGenerator<IntType,VecType>() {
	//
	//		SetStd(1);
	//		Initialize();
	//	}


	DiscreteGaussianGeneratorGeneric::DiscreteGaussianGeneratorGeneric(float std, BaseSamplerType type) : DistributionGenerator<BigInteger, BigVector>() {
		SetStd(std);
		bType = type;
	}


	void DiscreteGaussianGeneratorGeneric::SetStd(float std) {
		m_std = std;
	}


	float DiscreteGaussianGeneratorGeneric::GetStd() const {
		return m_std;
	}

	/**
	*Generates the probability matrix of given distribution, which is used in Knuth-Yao method
	*/
	void DiscreteGaussianGeneratorGeneric::GenerateProbMatrix(double stddev, double mean, int tCount) {

		if (DDGColumn != nullptr) {
			delete[] DDGColumn;
		}

		probMatrixSize = 2*STDDEV_COUNT * stddev +1;
		tableCount = tCount;

		probMatrix.resize(tableCount);
		firstNonZero.resize(tableCount);
		DDGTree.resize(tableCount);
		hammingWeights.resize(tableCount);

		for (unsigned int a = 0;a < tableCount;a++) {
			hammingWeights[a].resize(64,0);
		}

		for (unsigned a = 0;a < tableCount;a++) {
			probMatrix[a].resize(probMatrixSize);
		}

		probMean.resize(tableCount);
		m_std = stddev;
		for (unsigned int b = 0; b < tableCount;b++) {
			probMean[b] = (mean + b) / (tableCount);
			for (int i = -1* STDDEV_COUNT * stddev;i <= STDDEV_COUNT * stddev;i++) {
				double prob = pow(M_E, -pow((i+probMean[b]) - probMean[b], 2) / (2. * stddev * stddev)) / (stddev * sqrt(2.*M_PI));
				probMatrix[b][i+STDDEV_COUNT * stddev] = prob * /*(1<<64)*/ pow(2,64);
			}
			for (int i = 0;i < probMatrixSize;i++) {
				for (int j = 0;j < 64;j++) {
					hammingWeights[b][j] += ((probMatrix[b][i] >> (63 - j)) & 1);
				}
			}
			GenerateDDGTree(b);
		}
	}

	/**
	* Returns a generated integer. Uses Knuth-Yao method defined as Algorithm 1 in http://link.springer.com/chapter/10.1007%2F978-3-662-43414-7_19#page-1
	* Not used at the moment
	int32_t DiscreteGaussianGeneratorGeneric::GenerateIntegerKnuthYao(int tableID) {
		int32_t S = 0;
		bool discard = true;


		int32_t MAX_ROW = probMatrixSize - 1;
		//The distance

		while (discard == true) {
			int32_t d = 0;
			//Whether a terminal node is hit or not
			uint32_t hit = 0;
			//Indicator of column
			short col = 0;
			//bool start = false;
			//To generate random bit a 32 bit integer is generated in every 32 iterations and each single bit is used in order to save cycles
			while (hit == 0 && col <= 63) {
				if (ky_counter % 31 == 0) {
					ky_seed = (PseudoRandomNumberGenerator::GetPRNG())();
					ky_seed = ky_seed << 1;
				}
				uint32_t r = ky_seed >> (32 - ky_counter);
				d = 2 * d + (~r & 1);
				//if (d < hammingWeights[col] || start){
				//start = true;
				for (int32_t row = MAX_ROW;row > -1 && hit == 0;row--) {
					d -= ((probMatrix[tableID][row] >> (63 - col)) & 1);
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
				ky_counter++;
			}
		}
		if (ky_counter % 31 == 0) {
			ky_seed = (PseudoRandomNumberGenerator::GetPRNG())();
			ky_seed = ky_seed << 1;
			ky_counter = 0;
		}
		int sign = ((ky_seed >> (32 - ky_counter)) & 1) ? 1 : -1;
		ky_counter++;
		return  sign*S + probMean[tableID];
	}
	*/
	void DiscreteGaussianGeneratorGeneric::GenerateDDGTree(int tableID) {

		firstNonZero[tableID] = -1;
		for (int i = 0;i < 64 && firstNonZero[tableID] == -1;i++)
			if (hammingWeights[tableID][i] != 0)
				firstNonZero[tableID] = i;

		uint32_t iNodeCount = 1;
				for (int i = 0; i < firstNonZero[tableID];i++) {
					iNodeCount *= 2;
				}
				unsigned int maxNodeCount = iNodeCount;
				for (int i = firstNonZero[tableID];i < firstNonZero[tableID]+MIN_TREE_DEPTH;i++) {
					iNodeCount *= 2;
					iNodeCount -= hammingWeights[tableID][i];
					if(iNodeCount>=maxNodeCount)
						maxNodeCount = iNodeCount;
				}


		int depth = log2(maxNodeCount);
		uint64_t size = 1<<(depth+1);
		DDGTree[tableID].resize(size);



		for (unsigned int i = 0;i < size;i++) {
			DDGTree[tableID][i].resize(MIN_TREE_DEPTH,-2);
		}
		iNodeCount = 1;
		for (int i = 0; i < firstNonZero[tableID];i++) {
			iNodeCount *= 2;
		}
		for (int i = firstNonZero[tableID];i <firstNonZero[tableID]+MIN_TREE_DEPTH;i++){
			iNodeCount*=2;
			iNodeCount -= hammingWeights[tableID][i];
			for (unsigned int j = 0;j < iNodeCount;j++) {
				DDGTree[tableID][j][i - firstNonZero[tableID]] = -1;
			}
			uint32_t eNodeCount = 0;
			for (int j = 0;j < probMatrixSize && eNodeCount != hammingWeights[tableID][i];j++) {
				if ((probMatrix[tableID][j] >> (63 - i)) & 1) {
					DDGTree[tableID][iNodeCount + eNodeCount][i - firstNonZero[tableID]] = j;
					eNodeCount++;
				}
			}
		}
	}


	int32_t DiscreteGaussianGeneratorGeneric::GenerateIntegerKnuthYaoAlt(int64_t tableID) {
		int32_t ans = 0;
		bool hit = false;

		while (!hit) {
			uint32_t nodeIndex = 0;
			int64_t nodeCount = 1;
			bool error = false;
			for (int i = 0; i <64 && !hit && !error;i++) {
				if (ky_counter % 31 == 0) {
					ky_seed = (PseudoRandomNumberGenerator::GetPRNG())();
					ky_seed = ky_seed << 1;
					ky_counter = 0;
				}

				short bit = (ky_seed >> (32 - ky_counter)) & 1;
				nodeIndex *= 2;
				nodeCount *= 2;
				if (bit) {
					nodeIndex += 1;
				}
				if (firstNonZero[tableID] <= i) {
					if(i<firstNonZero[tableID]+MIN_TREE_DEPTH){
						ans = DDGTree[tableID][nodeIndex][i-firstNonZero[tableID]];
					}
					else{
						//std::vector<short> DDGColumn(nodeCount);
						DDGColumn = new short[nodeCount];
						nodeCount-=hammingWeights[tableID][i];
						for (int j = 0;j < nodeCount;j++) {
							DDGColumn[j] = -1;
						}
						uint32_t eNodeCount = 0;
						for (int j = 0;j < probMatrixSize && eNodeCount != hammingWeights[tableID][i];j++) {
							if ((probMatrix[tableID][j] >> (63 - i)) & 1) {
								DDGColumn[nodeCount + eNodeCount]= j;
								eNodeCount++;
							}
						}
						ans = DDGColumn[nodeIndex];
					}
					if (ans >= 0) {
						hit = true;
					}
					else {
						if (ans == -2 || ans == probMatrixSize - 1) {
							error = true;
						}
					}
				}
				ky_counter++;
				if(DDGColumn!=nullptr){
					delete[] DDGColumn;
					DDGColumn=nullptr;
				}
			}
		}
		/*if (ky_counter % 31 == 0) {
			ky_seed = (PseudoRandomNumberGenerator::GetPRNG())();
			ky_seed = ky_seed << 1;
			ky_counter = 0;
		}
		int32_t sign = ((ky_seed >> (32 - ky_counter)) & 1) ? 1 : -1;
		ky_counter++;*/
		return  /*sign**/(ans-STDDEV_COUNT * m_std) + probMean[tableID];
	}


	int32_t DiscreteGaussianGeneratorGeneric::GenerateInteger(double mean, double stddev) {

		//Replaced it with a binary search

		if (stddev != m_prev_std) {
			m_Sample_max = 0;
			int left = 0, right = (m_Sample_b * m_Sample_k) - 1;
			while (left <= right) {
				int mid = (left + right) / 2;
				if (m_sigma[mid] < stddev) {
					left = mid + 1;
				}
				else {
					m_Sample_max = mid;
					right = mid - 1;
				}

			}

			m_K = std::sqrt((stddev - m_SigmaBar) * (stddev + m_SigmaBar)); // m_sigma[m_Sample_max];
			m_prev_std = stddev;
		}

		double x = SampleI(m_Sample_max);

		double c = mean + m_K * x;

		uint64_t k2 = 1 << m_Sample_k;
		double k2c = k2*c;

		double alpha = k2c - floor(k2c);
		std::bernoulli_distribution Beta(alpha);

		double cPrime = floor(k2c) / k2 + Beta(PseudoRandomNumberGenerator::GetPRNG());

		// cPrime is actually rational \in 2^{-k} Z
		int32_t y = SampleC(cPrime, m_Sample_k);
		return y;
	}

	int32_t DiscreteGaussianGeneratorGeneric::SampleI(int32_t i) {
		if (i == 0) {
			int32_t x;
			if (bType == KNUTH_YAO) {
				x = GenerateIntegerKnuthYaoAlt(0);
			}
			else {
				x = GenerateIntegerPeikert(0);
			}
			return x;
		}
		int32_t x1 = SampleI(i - 1);
		int32_t x2 = SampleI(i - 1);
		int32_t y = m_z[i] * x1 + std::max(1, (m_z[i] - 1)) * x2;
		return y;

	}


	double DiscreteGaussianGeneratorGeneric::SampleC(double c, int32_t k) {
		if (k == 0) {
			return 0;
		}

		double g;
		int64_t a = std::abs(((int64_t)(pow(m_Sample_b, (k - 1)) * c)) % m_Sample_b);
		if (bType == KNUTH_YAO) {
			g = pow(m_Sample_b, -k + 1) * GenerateIntegerKnuthYaoAlt(a) + pow(m_Sample_b, (k - 1)) * c;
		}
		else {

			g = pow(m_Sample_b, -k + 1) * GenerateIntegerPeikert(a) + pow(m_Sample_b, (k - 1)) * c;
		}

		return g + SampleC(c - g, k - 1);

	}

	void DiscreteGaussianGeneratorGeneric::PreCompute(int32_t b, int32_t k, double stddev) {
		m_Sample_b = b;
		m_Sample_k = k;

		m_z.resize((int)(b*k));
		m_sigma.resize((int)(b*k));

		m_sigma[0] = stddev;
		this->SetStd(stddev);
		if (bType == KNUTH_YAO) {
			GenerateProbMatrix(stddev, 0, b);
		}
		else {
			Initialize(b);
		}

		//Smoothing parameter
		double N(std::sqrt(std::log(2 + 2 / DG_ERROR) / M_PI));
		//std::cout << "N = " << sqrt(2)*N << std::endl;
		//std::cin.get();
		for (int i = 1;i < b;i++) {
			m_z[i] = floor(m_sigma[i - 1] / (sqrt(2) * N));
			m_sigma[i] = sqrt((m_z[i] * m_z[i] + std::max((m_z[i] - 1) * (m_z[i] - 1), 1)) * m_sigma[i - 1] * m_sigma[i - 1]);
		}
		m_SigmaBar = 0;
		for (int i = 0;i < m_Sample_k;i++) {
			m_SigmaBar += pow(m_Sample_b, (-2 * i));

		}

		m_SigmaBar = m_sigma[0] * std::sqrt(m_SigmaBar);

	}

	void DiscreteGaussianGeneratorGeneric::Initialize(int b) {


		m_vals.clear();
		m_vals.resize(b);
		//weightDiscreteGaussian
		double acc = 1e-15;
		double variance = m_std * m_std;

		int fin = (int)ceil(m_std * sqrt(-2 * log(acc)));
		//this value of fin (M) corresponds to the limit for double precision
		// usually the bound of m_std * M is used, where M = 20 .. 40 - see DG14 for details
		// M = 20 corresponds to 1e-87
		//double mr = 20; // see DG14 for details
		//int fin = (int)ceil(m_std * mr);
		for (int a = 0; a < b; a++) {
			double cusum = 1.0;

			for (sint x = 1; x <= fin; x++) {
				cusum = cusum + 2 * exp(-(x - (double)a / b) * (x - (double)a / b) / (variance * 2));
			}

			m_a = 1 / cusum;

			//fin = (int)ceil(sqrt(-2 * variance * log(acc))); //not needed - same as above
			double temp;

			for (sint i = 1; i <= fin; i++) {
				temp = m_a * exp(-((double)((i - (double)a / b) * (i - (double)a / b)) / (2 * variance)));
				m_vals[a].push_back(temp);
			}

			// take cumulative summation
			for (usint i = 1; i < m_vals[a].size(); i++) {
				m_vals[a][i] += m_vals[a][i - 1];
			}

			//for (usint i = 0; i<m_vals.size(); i++) {
			//	std::cout << m_vals[i] << std::endl;
			//}

			//std::cout<<m_a<<std::endl;

		}
	}

	int32_t DiscreteGaussianGeneratorGeneric::GenerateIntegerPeikert(int64_t b) const {

		std::uniform_real_distribution<double> distribution(0.0, 1.0);

		usint val = 0;
		double seed;
		int32_t ans = 0;
		try {
			seed = distribution(PseudoRandomNumberGenerator::GetPRNG()) - 0.5; //we need to use the binary uniform generator rathen than regular continuous distribution; see DG14 for details
			if (std::abs(seed) <= m_a / 2) {
				val = 0;
			}
			else if (seed > 0) {
				val = FindInVector(m_vals[b], (std::abs(seed) - m_a / 2));
			}
			else {
				val = -(int)FindInVector(m_vals[b], (std::abs(seed) - m_a / 2));
			}
			ans = val;
		}
		catch (std::runtime_error e) {

		}
		return ans;

	}

	usint DiscreteGaussianGeneratorGeneric::FindInVector(const std::vector<double> &S, double search) const {
		//STL binary search implementation
		auto lower = std::lower_bound(S.begin(), S.end(), search);
		if (lower != S.end())
			return lower - S.begin() + 1;
		else
			throw std::runtime_error("DGG Inversion Sampling. FindInVector value not found: " + std::to_string(search));
	}


} // namespace lbcrypto
