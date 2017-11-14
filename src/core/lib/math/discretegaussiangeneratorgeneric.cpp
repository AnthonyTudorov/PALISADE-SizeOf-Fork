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

/**
 * WARNING FOR PARAMETER SELECTION IN GENERIC SAMPLER
 *
 * MAKE SURE THAT PRECISION - BERNOULLI FLIPS IS ALWAYS DIVISIBLE BY LOG_BASE
 * WHEN CHOOSING A STANDARD DEVIATION SIGMA_B FOR BASE SAMPLER, MAKE SURE THAT SIGMA_B>+=4*SQRT(2)*N WHERE N IS THE SMOOTHING PARAMETER
 * */
#include "discretegaussiangeneratorgeneric.h"
#include "nbtheory.h"
#include "backend.h"

namespace lbcrypto {

//const double DG_ERROR = 8.27181e-25;
//const int32_t N_MAX = 16384;
//const double SIGMA = std::sqrt(std::log(2 * N_MAX / DG_ERROR) / M_PI);
//const int32_t PRECISION = 128;
//const double TAIL_CUT = std::sqrt(log(2)*2*(double)(PRECISION));
//const int32_t DDG_DEPTH = 13;
const int32_t MAX_TREE_DEPTH = 64;

const int32_t PRECISION = 53;
const int32_t BERNOULLI_FLIPS = 23;


BaseSampler::BaseSampler(double mean,double std,BitGenerator* generator,BaseSamplerType type=PEIKERT):b_mean(mean),b_std(std),bg(generator),b_type(type){
	double acc = 1e-17;
	fin = (int) ceil(b_std * sqrt(-2 * log(acc)));
	if(b_type==PEIKERT)
		Initialize(b_mean);
	else
		GenerateProbMatrix(b_std,b_mean);
}
int64_t BaseSampler::GenerateInteger(){
	if(b_type==PEIKERT)
		return GenerateIntegerPeikert();
	else
		//return GenerateIntegerKnuthYao();
		return GenerateIntegerKnuthYaoAlt();
}
/**
 *Generates the probability matrix of given distribution, which is used in Knuth-Yao method
 */
void BaseSampler::GenerateProbMatrix(double stddev, double mean) {

	/*if (DDGColumn != nullptr) {
		delete[] DDGColumn;
	}*/
	std::vector<uint64_t> probMatrix;
	b_matrixSize = 2*fin + 1;
	hammingWeights.resize(64, 0);
	probMatrix.resize(b_matrixSize);
	double* probs = new double[b_matrixSize];
	double S=0;
	b_std = stddev;
	b_mean = mean;
	for (int i = -1 * fin; i <= fin; i++) {
		double prob = pow(M_E,-pow((i - b_mean), 2) / (2. * stddev * stddev));
		S+=prob;
		probs[i+fin]=prob;
	}
	for (int i = 0; i < b_matrixSize; i++) {
		probMatrix[i] = probs[i] * (1.0/S) * /*(1<<64)*/pow(2, 64);
		for (int j = 0; j < 64; j++) {
			hammingWeights[j] += ((probMatrix[i] >> (63 - j)) & 1);
		}

	}
	delete[] probs;
	GenerateDDGTree(probMatrix);
}

/**
 * Returns a generated integer. Uses Knuth-Yao method defined as Algorithm 1 in http://link.springer.com/chapter/10.1007%2F978-3-662-43414-7_19#page-1
 * Not used at the moment
 *
 int64_t BaseSampler::GenerateIntegerKnuthYao() {
	 short d = 0;
	 short hit=0;
	 short col=0;
	 int64_t S;
	 while(hit==0){
		 short r=bg->Generate();
		 d = 2 * d + 1 - r;
		 for(int64_t row = b_matrixSize;row>=0;row--){
			 d = d - ((probMatrix[row]>>(63-col)) & 1);
			 if(d==-1){
				 hit = 1;
				 S = row;
				 break;
			 }
		 }
		 col++;
	 }
	 if(S==b_matrixSize-1)
		 std::cout<<"ERROR ROW HIT"<<std::endl;
	 return S-fin;
 }
*/
void BaseSampler::GenerateDDGTree(const std::vector<uint64_t> & probMatrix) {
	for(unsigned int i =0;i<probMatrix.size();i++){
	}
	firstNonZero = -1;
	for (int i = 0; i < 64 && firstNonZero == -1; i++)
		if (hammingWeights[i] != 0)
			firstNonZero = i;
	endIndex = firstNonZero;
	int32_t iNodeCount = 1;
	for (int i = 0; i < firstNonZero; i++) {
		iNodeCount *= 2;
	}
	bool end = false;
	unsigned int maxNodeCount = iNodeCount;
	for (int i = firstNonZero; i < MAX_TREE_DEPTH && !end; i++) {
		iNodeCount *= 2;
		endIndex++;
		if ((uint32_t)iNodeCount >= maxNodeCount)
			maxNodeCount = iNodeCount;
		iNodeCount -= hammingWeights[i];
		if(iNodeCount<=0){
			end=true;
			if(iNodeCount<0){
				endIndex--;
			}
		}

	}

	uint64_t size = /*1 << (depth + 1)*/maxNodeCount;
	DDGTree.resize(size);

	for (unsigned int i = 0; i < size; i++) {
		DDGTree[i].resize(endIndex-firstNonZero, -2);
	}
	iNodeCount = 1;
	for (int i = 0; i < firstNonZero; i++) {
		iNodeCount *= 2;
	}

	for (int i = firstNonZero; i < endIndex; i++) {
		iNodeCount *= 2;
		iNodeCount -= hammingWeights[i];
		for (unsigned int j = 0; j < (uint32_t)iNodeCount; j++) {
			DDGTree[j][i - firstNonZero] = -1;

		}
		uint32_t eNodeCount = 0;
		for (int j =0; j <  b_matrixSize && eNodeCount != hammingWeights[i];j++) {
			if ((probMatrix[j] >> (63 - i)) & 1) {
				DDGTree[iNodeCount + eNodeCount][i - firstNonZero] = j;
				eNodeCount++;
			}
		}
	}
}

int64_t BaseSampler::GenerateIntegerKnuthYaoAlt() {
	int64_t ans = 0;
	bool hit = false;

	while (!hit) {
		uint32_t nodeIndex = 0;
		int64_t nodeCount = 1;
		bool error = false;
		for (int i = 0; i < MAX_TREE_DEPTH && !hit && !error; i++) {


			short bit = bg->Generate();
			nodeIndex *= 2;
			nodeCount *= 2;
			if (bit) {
				nodeIndex += 1;
			}
			if (firstNonZero <= i) {
				if (i < endIndex) {
					ans = DDGTree[nodeIndex][i - firstNonZero];
				} /*else {
					std::cout<<"Hit active generation"<<std::endl;
					//std::vector<short> DDGColumn(nodeCount);
					DDGColumn = new short[nodeCount];
					nodeCount -= hammingWeights[i];
					for (int j = 0; j < nodeCount; j++) {
						DDGColumn[j] = -1;
					}
					uint32_t eNodeCount = 0;
					for (int j = 0;j < b_matrixSize&& eNodeCount != hammingWeights[i]; j++) {
						if ((probMatrix[j] >> (63 - i)) & 1) {
							DDGColumn[nodeCount + eNodeCount] = j;
							eNodeCount++;
						}
					}
					ans = DDGColumn[nodeIndex];
				}*/
				if (ans >= 0) {
					hit = true;
				} else {
					if (ans == -2) {
						error = true;
					}
				}
			}
			/*if (DDGColumn != nullptr) {
				delete[] DDGColumn;
				DDGColumn = nullptr;
			}*/
		}
	}

	//int64_t sign=bg->Generate()?1:-1;
	return /*sign**/(ans - fin);
}
/*
int32_t DiscreteGaussianGeneratorGeneric::GenerateInteger(double mean,double stddev) {

	//Replaced it with a binary search

	if (stddev != m_prev_std) {
		m_Sample_max = 0;
		int left = 0, right = (m_Sample_b * m_Sample_k) - 1;
		while (left <= right) {
			int mid = (left + right) / 2;
			if (m_sigma[mid] < stddev) {
				left = mid + 1;
			} else {
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
	double k2c = k2 * c;

	double alpha = k2c - floor(k2c);
	std::bernoulli_distribution Beta(alpha);

	double cPrime = floor(k2c) / k2
			+ Beta(PseudoRandomNumberGenerator::GetPRNG());

	// cPrime is actually rational \in 2^{-k} Z
	int32_t y = SampleC(cPrime, m_Sample_k);
	return y;
}
 */
/*
int32_t DiscreteGaussianGeneratorGeneric::SampleI(int32_t i) {
	if (i == 0) {
		int32_t x;
		if (bType == KNUTH_YAO) {
			x = GenerateIntegerKnuthYaoAlt(0);
		} else {
			x = GenerateIntegerPeikert(0);
		}
		return x;
	}
	int32_t x1 = SampleI(i - 1);
	int32_t x2 = SampleI(i - 1);
	int32_t y = m_z[i] * x1 + std::max(1, (m_z[i] - 1)) * x2;
	return y;

}
 */
/*
double DiscreteGaussianGeneratorGeneric::SampleC(double c, int32_t k) {
	if (k == 0) {
		return 0;
	}

	double g;
	int64_t a = std::abs(
			((int64_t) (pow(m_Sample_b, (k - 1)) * c)) % m_Sample_b);
	if (bType == KNUTH_YAO) {
		g = pow(m_Sample_b, -k + 1) * GenerateIntegerKnuthYaoAlt(a)
						+ pow(m_Sample_b, (k - 1)) * c;
	} else {

		g = pow(m_Sample_b, -k + 1) * GenerateIntegerPeikert(a)
						+ pow(m_Sample_b, (k - 1)) * c;
	}

	return g + SampleC(c - g, k - 1);

}

void DiscreteGaussianGeneratorGeneric::PreCompute(int32_t b, int32_t k,
		double stddev) {
	m_Sample_b = b;
	m_Sample_k = k;

	m_z.resize((int) (b * k));
	m_sigma.resize((int) (b * k));

	m_sigma[0] = stddev;
	this->SetStd(stddev);
	if (bType == KNUTH_YAO) {
		GenerateProbMatrix(stddev, 0, b);
	} else {
		Initialize(b);
	}

	//Smoothing parameter
	//std::cout << "N = " << sqrt(2)*N << std::endl;
	//std::cin.get();
	for (int i = 1; i < b; i++) {
		m_z[i] = floor(m_sigma[i - 1] / (sqrt(2) * N));
		m_sigma[i] = sqrt(
				(m_z[i] * m_z[i] + std::max((m_z[i] - 1) * (m_z[i] - 1), 1))
 * m_sigma[i - 1] * m_sigma[i - 1]);
	}
	m_SigmaBar = 0;
	for (int i = 0; i < m_Sample_k; i++) {
		m_SigmaBar += pow(m_Sample_b, (-2 * i));

	}

	m_SigmaBar = m_sigma[0] * std::sqrt(m_SigmaBar);

}
 */
void BaseSampler::Initialize(double mean) {

	m_vals.clear();
	double variance = b_std * b_std;


	//this value of fin (M) corresponds to the limit for double precision
	// usually the bound of m_std * M is used, whe                                re M = 20 .. 40 - see DG14 for details
	// M = 20 corresponds to 1e-87
	//double mr = 20; // see DG14 for details
	//int fin = (int)ceil(m_std * mr);
	double cusum = 0.0;
	for (sint x = -1*fin; x <= fin; x++) {
		cusum = cusum + exp(-(x-mean) * (x-mean)/ (variance * 2));
	}

	b_a = 1 / cusum;

	double temp;

	for (sint i = -1*fin; i <= fin; i++) {
		temp = b_a* exp(-((double) ((i - mean)* (i - mean) / (2 * variance))));
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

int64_t BaseSampler::GenerateIntegerPeikert() const {

	std::uniform_real_distribution<double> distribution(0.0, 1.0);

	int64_t val = 0;
	double seed;
	int32_t ans = 0;
	try{
		seed = distribution(PseudoRandomNumberGenerator::GetPRNG()); //we need to use the binary uniform generator rathen than regular continuous distribution; see DG14 for details
		val = FindInVector(m_vals,seed);
		ans = val;
	}catch (std::runtime_error e) {}
	return ans - fin;
}

usint BaseSampler::FindInVector(const std::vector<double> &S, double search) const {
	//STL binary search implementation
	auto lower = std::lower_bound(S.begin(), S.end(), search);
	if (lower != S.end())
		return lower - S.begin();
	else
		throw std::runtime_error("DGG Inversion Sampling. FindInVector value not found: "+ std::to_string(search));
}


DiscreteGaussianGeneratorGeneric::DiscreteGaussianGeneratorGeneric(BaseSampler** samplers, const double std,const int b, double N) {

	//Precomputations for sigma bar
	int x1, x2;
	base_samplers = samplers;
	log_base = b;
	double base_variance = std * std;
	//SampleI Non-base case
	wide_sampler = samplers[0];
	wide_variance = base_variance;
	for (int i = 1; i < MAX_LEVELS; ++i) {
		x1 = (int) floor(sqrt(wide_variance/(2*N*N)));
		x2 = std::max(x1-1, 1);
		wide_sampler = new SamplerCombiner(wide_sampler, wide_sampler, x1, x2);
		combiners[i-1] = wide_sampler;
		wide_variance = (x1*x1 + x2*x2)*wide_variance;
	}

	k = (int)ceil((double)(PRECISION-BERNOULLI_FLIPS)/log_base);
	mask = (1UL << log_base) - 1;

	// compute rr_sigma2
	sampler_variance = 1;
	long double t = 1.0/ (1UL << (2*log_base));
	long double s = 1;
	for (int i = 1; i < k; ++i) {
		s *= t;
		sampler_variance += s;
	}
	sampler_variance *= base_variance;
}

DiscreteGaussianGeneratorGeneric::~DiscreteGaussianGeneratorGeneric() {
	for (int i = 1; i < MAX_LEVELS; ++i) {
		delete combiners[i-1];
	}
}

// SampleZ
int64_t DiscreteGaussianGeneratorGeneric::GenerateInteger(double center, double std) {

	double variance = std * std;
	//SampleI Base Case
	x = wide_sampler->GenerateInteger();

	// Center perturbation
	c = center + x*(sqrt((variance - sampler_variance)/wide_variance));

	ci = floor(c);
	c -= ci;

	return (int64_t)ci + flipAndRound(c);
}
//Part of SampleC
int64_t DiscreteGaussianGeneratorGeneric::flipAndRound(double center) {

	int64_t c = (int64_t) (center * (1ULL << PRECISION));
	int64_t base_c = (c >> BERNOULLI_FLIPS);
	short randomBit;

	//Rounding the center based on the coin flip
	for (int i = BERNOULLI_FLIPS - 1; i >= 0; --i) {
		randomBit = base_samplers[0]->RandomBit();
		if (randomBit > extractBit(c, i))
			return SampleC((int64_t) base_c);
		if (randomBit < extractBit(c, i))
			return SampleC((int64_t) (base_c + 1));
	}
	return SampleC((int64_t)base_c + 1);
}

// SampleC defined in the UCSD paper
int64_t DiscreteGaussianGeneratorGeneric::SampleC(int64_t center) {
	int64_t c; c = center;
	int64_t sample;
	for (int i = 0; i < k; ++i) {
		sample = base_samplers[mask & c]->GenerateInteger();
		if ( (mask & c) > 0 && c < 0)
			sample -= 1;
		for (int j = 0; j < log_base; ++j) {
			c /= 2;
		}
		c += sample;
	}
	return c;
}

} // namespace lbcrypto
