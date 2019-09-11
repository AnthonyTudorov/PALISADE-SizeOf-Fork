/*
 * @file testmain.cpp ; main for Android version of test
 * (because Android does not support stdout)
 * @author  TPOC: contact@palisade-crypto.org
 *
 * @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
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

#include "include/gtest/gtest.h"
#include "src/gtest-all.cc"

#include "math/backend.h"
#include "lattice/backend.h"
#include "utils/inttypes.h"
#include "math/nbtheory.h"
#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "math/distrgen.h"
#include "utils/utilities.h"

using namespace std;
using namespace lbcrypto;
using namespace testing;

#include <android/log.h>

class androidbuf : public std::streambuf {
public:
    enum { bufsize = 1024 }; // ... or some other suitable buffer size
    androidbuf() { this->setp(buffer, buffer + bufsize - 1); }

private:
    int overflow(int c)
    {
        if (c == traits_type::eof()) {
            *this->pptr() = traits_type::to_char_type(c);
            this->sbumpc();
        }
        return this->sync()? traits_type::eof(): traits_type::not_eof(c);
    }

    int sync()
    {
        int rc = 0;
        if (this->pbase() != this->pptr()) {
            char writebuf[bufsize+1];
            memcpy(writebuf, this->pbase(), this->pptr() - this->pbase());
            writebuf[this->pptr() - this->pbase()] = '\0';

            rc = __android_log_write(ANDROID_LOG_INFO, "std", writebuf) > 0;
            this->setp(buffer, buffer + bufsize - 1);
        }
        return rc;
    }

    char buffer[bufsize];
};

static string lead = "****** ";

class MinimalistPrinter : public EmptyTestEventListener {

public:
	MinimalistPrinter() {
		std::cout.rdbuf(new androidbuf);
	}
	~MinimalistPrinter() {
		delete std::cout.rdbuf(0);
	}

	void OnTestProgramStart(const ::testing::UnitTest& unit_test) {
		cout << lead << "PALISADE Version " << GetPALISADEVersion() << endl;
		cout << lead << "Date " <<
				testing::internal::FormatEpochTimeInMillisAsIso8601(unit_test.start_timestamp()) << endl;
	}
	void OnTestIterationStart(const ::testing::UnitTest& unit_test, int iteration) {}
	void OnEnvironmentsSetUpStart(const ::testing::UnitTest& unit_test) {}
	void OnEnvironmentsSetUpEnd(const ::testing::UnitTest& unit_test) {}
	void OnTestCaseStart(const ::testing::TestCase& test_case) {
		cout << test_case.name() << " start" << endl;
	}
	void OnTestStart(const ::testing::TestInfo& test_info) {}

	// Called after a failed assertion or a SUCCEED() invocation.
	void OnTestPartResult(const ::testing::TestPartResult& test_part_result) {}

	void OnTestEnd(const ::testing::TestInfo& test_info) {
		auto tr = test_info.result();
		cout << "** " << test_info.test_case_name() << " " << tr->total_part_count() << endl;

		for( int i=0; i < tr->total_part_count(); i++ ) {
			auto pr = tr->GetTestPartResult(i);
			//if( pr.passed() )
				//continue;

			cout << "[ RUN      ] ";
			cout << test_info.test_case_name() << "." << test_info.name() << endl;

			auto n = pr.file_name();
			if( n != NULL )
				cout << n << ":" << pr.line_number() << "\n";

			cout << pr.summary() << endl;

			if( pr.passed() )
				cout << "[  OK      ] ";
			else
				cout << "[  FAILED  ] ";
			cout << test_info.test_case_name() << test_info.name() << endl;
			internal::PrintFullTestCommentIfPresent(test_info);
		}
	}
	void OnTestCaseEnd(const ::testing::TestCase& test_case) {
		cout << test_case.name() << " end" << endl;
	}
	void OnEnvironmentsTearDownStart(const ::testing::UnitTest& unit_test) {}
	void OnEnvironmentsTearDownEnd(const ::testing::UnitTest& /*unit_test*/) {}
	void OnTestIterationEnd(const ::testing::UnitTest& unit_test, int iteration) {}

	void OnTestProgramEnd(const ::testing::UnitTest& unit_test)  {
		cout << lead << "End " << unit_test.test_to_run_count() << " cases "
				<< unit_test.successful_test_count() << " passed "
				<< unit_test.failed_test_count() << " failed" << endl;

		const int failed_test_count = unit_test.failed_test_count();
		if (failed_test_count == 0) {
			return;
		}

		for (int i = 0; i < unit_test.total_test_case_count(); ++i) {
			const TestCase& test_case = *unit_test.GetTestCase(i);
			if (!test_case.should_run() || (test_case.failed_test_count() == 0)) {
				continue;
			}
			for (int j = 0; j < test_case.total_test_count(); ++j) {
				const TestInfo& test_info = *test_case.GetTestInfo(j);
				if (!test_info.should_run() || test_info.result()->Passed()) {
					continue;
				}
				internal::ColoredPrintf(internal::COLOR_RED, "[  FAILED  ] ");
				printf("%s.%s", test_case.name(), test_info.name());
				internal::PrintFullTestCommentIfPresent(test_info);
				printf("\n");
			}
		}
	}


};

bool TestB2 = false;
bool TestB4 = false;
bool TestB6 = false;
bool TestNative = true;

int testmain(int argc, char *argv[]) {

	::testing::InitGoogleTest(&argc, argv);

	bool terse=false;
	bool beset=false;
	for( int i = 1; i < argc; i++ ) {
		if( string(argv[i]) == "-t" ) {
			terse=true;
		}
		else if( string(argv[i]) == "-all" ) {
			TestB2 = TestB4 = TestB6 = true;
			beset=true;
		}
		else if( string(argv[i]) == "-2" ) {
			TestB2 = true;
			beset=true;
		}
		else if( string(argv[i]) == "-4" ) {
			TestB4 = true;
			beset=true;
		}
		else if( string(argv[i]) == "-6" ) {
			TestB6 = true;
			beset=true;
		}
	}

	// if there are no filters used, default to omitting VERY_LONG tests
	// otherwise we lose control over which tests we can run

	if (::testing::GTEST_FLAG(filter) == "*") {
		::testing::GTEST_FLAG(filter) = "-*_VERY_LONG";
	}

	::testing::TestEventListeners& listeners =
			::testing::UnitTest::GetInstance()->listeners();

	if( !beset ) {
		if( MATHBACKEND == 2 )
			TestB2 = true;
		else if( MATHBACKEND == 4 )
			TestB4 = true;
		else if( MATHBACKEND == 6 )
			TestB6 = true;
	}

	delete listeners.Release(listeners.default_result_printer());
	listeners.Append(new MinimalistPrinter);
	auto ret = RUN_ALL_TESTS();
	return ret;
}

#include <jni.h>
#include <string>

extern "C" JNIEXPORT jstring JNICALL
Java_com_lgs_palisadeunittest_MainActivity_RunUnitTest(
        JNIEnv *env,
        jobject /* this */,
	jstring filter) {

	const char *cstr = env->GetStringUTFChars(filter, NULL);

    char *args[] = {
	(char *)"none",
	(char *)cstr,
	(char *)0
    };
    testmain(2, args);
    std::string hello = "Done";
    return env->NewStringUTF(hello.c_str());
}

