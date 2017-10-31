/*
 * @file 
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

#include <iostream>

#include "../lib/lattice/dcrtpoly.h"
#include "include/gtest/gtest.h"
#include "include/gtest/gtest-all.cc"

#include "math/backend.h"
#include "utils/inttypes.h"
#include "math/nbtheory.h"
#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "math/distrgen.h"
#include "lattice/poly.h"
#include "utils/utilities.h"

using namespace std;
using namespace lbcrypto;
using namespace testing;

static string lead = "****** ";

class MinimalistPrinter : public EmptyTestEventListener {

public:
	void OnTestProgramStart(const ::testing::UnitTest& unit_test) {
		cout << lead << "Begin Test Run" << endl;
		cout << lead << GetMathBackendParameters() << endl;
	}
	void OnTestIterationStart(const ::testing::UnitTest& unit_test, int iteration) {}
	void OnEnvironmentsSetUpStart(const ::testing::UnitTest& unit_test) {}
	void OnEnvironmentsSetUpEnd(const ::testing::UnitTest& unit_test) {}
	void OnTestCaseStart(const ::testing::TestCase& test_case) {}
	void OnTestStart(const ::testing::TestInfo& test_info) {}

	// Called after a failed assertion or a SUCCEED() invocation.
	void OnTestPartResult(const ::testing::TestPartResult& test_part_result) {}

	void OnTestEnd(const ::testing::TestInfo& test_info) {
		if (test_info.result()->Passed() ) {
			return;
		}

		auto tr = test_info.result();

		for( int i=0; i < tr->total_part_count(); i++ ) {
			auto pr = tr->GetTestPartResult(i);
			if( pr.passed() )
				continue;

			internal::ColoredPrintf(internal::COLOR_GREEN,  "[ RUN      ] ");
			printf("%s.%s\n", test_info.test_case_name(), test_info.name());
			fflush(stdout);

			auto n = pr.file_name();
			if( n != NULL )
				cout << n << ":" << pr.line_number() << "\n";

			cout << pr.summary() << endl;

			internal::ColoredPrintf(internal::COLOR_RED, "[  FAILED  ] ");
			printf("%s.%s\n", test_info.test_case_name(), test_info.name());
			fflush(stdout);
			internal::PrintFullTestCommentIfPresent(test_info);
		}
	}
	void OnTestCaseEnd(const ::testing::TestCase& test_case) {}
	void OnEnvironmentsTearDownStart(const ::testing::UnitTest& unit_test) {}
	void OnEnvironmentsTearDownEnd(const ::testing::UnitTest& /*unit_test*/) {}
	void OnTestIterationEnd(const ::testing::UnitTest& unit_test, int iteration) {}

	void OnTestProgramEnd(const ::testing::UnitTest& unit_test)  {
		cout << lead << "End Test Run of " << unit_test.test_to_run_count() << " cases, "
			<< unit_test.successful_test_count() << " passed, "
			<< unit_test.failed_test_count() << " failed" << endl;
	}


};

int main(int argc, char **argv) {

	::testing::InitGoogleTest(&argc, argv);

	bool terse=false;
	for( int i = 1; i < argc; i++ ) {
		if( string(argv[i]) == "-t" ) {
			terse=true;
		}
	}

	// if there are no filters used, default to omitting VERY_LONG tests
	// otherwise we lose control over which tests we can run
	//::testing::GTEST_FLAG(filter) = "*CRT_polynomial_multiplication_small";

	if (::testing::GTEST_FLAG(filter) == "*") {
		::testing::GTEST_FLAG(filter) = "-*_VERY_LONG";
	}

	::testing::TestEventListeners& listeners =
			::testing::UnitTest::GetInstance()->listeners();

	if( terse ) {
		// Adds a listener to the end.  Google Test takes the ownership.
		delete listeners.Release(listeners.default_result_printer());
		listeners.Append(new MinimalistPrinter);
	}
	else {
		std::cout << GetMathBackendParameters() << std::endl;
	}

	return RUN_ALL_TESTS();
}

