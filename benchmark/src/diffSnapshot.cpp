/*
 * diffSnapshot.cpp
 *
 *  Created on: Mar 5, 2017
 *      Author: gerardryan
 */


// diff the output of two snapshot runs
#include <string>
#include <fstream>
#include <map>
using namespace std;

#include "utils/serializable.h"
#include "utils/serializablehelper.h"
using namespace lbcrypto;

const string ncpu = "num_cpus";
const string mhzper = "mhz_per_cpu";
const string scaleon = "cpu_scaling_enabled";

const string bmname = "name";
const string bmtime = "cpu_time";

bool
parseFile(string filename, int& cpu, int& mhz, bool& scaling, map<string,long>& stats) {
	bool foundContext = false;

	ifstream fs;
	fs.open(filename);
	if( !fs.is_open()) {
		cout << "Could not open " << filename << endl;
		return false;
	}

	lbcrypto::IStreamWrapper is(fs);

	Serialized doc;

	while( fs.good() ) {
		doc.ParseStream<rapidjson::kParseStopWhenDoneFlag>(is);
		if( !fs.good() ) break;

		if( doc.HasParseError() && doc.GetParseError() != rapidjson::kParseErrorDocumentEmpty ) {
			cout << "Parse error " << doc.GetParseError() << " at " << doc.GetErrorOffset() << endl;
			return false;
		}

		auto context = doc.FindMember("context");
		auto benchmarks = doc.FindMember("benchmarks");

		if( context == doc.MemberEnd() ) {
			cout << "Missing context" << endl;
			return false;
		}

		if( benchmarks == doc.MemberEnd() ) {
			cout << "Missing benchmarks" << endl;
			return false;
		}

		if( !foundContext ) {
			cpu = benchmarks->value[ncpu].GetInt64();
			mhz = benchmarks->value[mhzper].GetInt64();
			scaling = benchmarks->value[scaleon].GetBool();

			foundContext = true;
		}

		if( !benchmarks->value.IsArray() ) {
			continue;
		}
		else for( size_t i = 0; i < benchmarks->value.Size(); i++ ) {
			stats[benchmarks->value[i][bmname].GetString()] = benchmarks->value[i][bmtime].GetInt64();
		}
	}

	return true;
}

int main( int argc, char *argv[] )
{
	map<string,long> oldStats;
	int	oldCpu = 0, oldMhz = 0;
	bool oldScaling;

	map<string,long> newStats;
	int	newCpu = 0, newMhz = 0;
	bool newScaling;

	if( argc != 3 ) {
		cout << "Usage is " << argv[0] << " oldfile newfile" << endl;
		return 1;
	}

	if( parseFile(argv[1], oldCpu, oldMhz, oldScaling, oldStats) == false ) {
		cout << "Could not process " << argv[1] << endl;
		return 1;
	}

	if( parseFile(argv[2], newCpu, newMhz, newScaling, newStats) == false ) {
		cout << "Could not process " << argv[2] << endl;
		return 1;
	}

	// first check to see if there's anything in new that is not in old
	for( auto np : newStats ) {
		if( oldStats.find( np.first ) == oldStats.end() ) {
			cout << "Warning: key " << np.first << " in new was not found in old" << endl;
		}
	}

	// now compare every item in old to its corresponding value in new
	for( auto op : oldStats ) {
		auto np = newStats.find( op.first );
		if( np == newStats.end() ) {
			cout << "Warning: key " << op.first << " in old was not found in new" << endl;
		}

		long ov = op.second;
		long nv = np->second;
		long diff = nv - ov;

		double dpc = (diff * 100.0) / ov;
		if( dpc > 1.0 )
			cout << op.first << ": " << dpc << endl;
	}

	return 0;
}

