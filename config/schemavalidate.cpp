#include "rapidjson/document.h"
#include "rapidjson/pointer.h"
#include "rapidjson/reader.h"
#include "rapidjson/writer.h"
#include "rapidjson/filereadstream.h"
#include "rapidjson/filewritestream.h"
#include "rapidjson/error/en.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/schema.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <map>
#include <iterator>
#include <algorithm>

#define RAPIDJSON_NO_SIZETYPEDEFINE

using namespace rapidjson;

#include <iostream>
#include <string>
#include <cstdio>
using namespace std;

void jParseError(Document& sd, char *readBuffer) {
	int off = sd.GetErrorOffset();
	fprintf(stderr, "\nError(offset %d): %s\n", 
		off,
		GetParseError_En(sd.GetParseError()));

	int WIN = 30;
	int st = (off-WIN);
	st = st < 0 ? 0 : st;
	int en = off + WIN;
	en = en > 65536 ? 65536 : en;
	for( int j = st; j < en ; j++ )
		fprintf(stderr, "%c", readBuffer[j]);
	fprintf(stderr, "\n");
}

int
main(int argc, char *argv[])
{
	if( argc < 2 ) {
		cout << "Usage is " << argv[0] << " schema [files-to-test]" << endl;
		return 0;
	}

	FILE *sp = fopen(argv[1], "r");
	char readBuffer[65536];
	FileReadStream is(sp, readBuffer, sizeof(readBuffer));

	Document sd;
	if (sd.ParseStream(is).HasParseError()) {
		jParseError(sd, readBuffer);
		fclose(sp);
		return 1;
	}
	fclose(sp);

	cout << "Parsed document" << endl;

	SchemaDocument schema(sd); // Compile a Document to SchemaDocument

	cout << "Converted to schema" << endl;

	for( int i = 2; i < argc; i++ ) {

		cout << argv[i] << ":" << endl;

		FILE *fp = fopen(argv[i], "r");
		char readBuffer2[65536];
		FileReadStream ts(fp, readBuffer2, sizeof(readBuffer2));

		Document d;
		if (d.ParseStream(ts).HasParseError()) {
			jParseError(d, readBuffer2);
			fclose(fp);
			continue;
		}
		fclose(fp);

		SchemaValidator validator(schema);
		if (!d.Accept(validator)) {
		    // Input JSON is invalid according to the schema
		    // Output diagnostic information
		    StringBuffer sb;
		    validator.GetInvalidSchemaPointer().StringifyUriFragment(sb);
		    cout << "Invalid schema " << sb.GetString() << endl;
		    cout << "Invalid keyword " << validator.GetInvalidSchemaKeyword() << endl;
		    sb.Clear();
		    validator.GetInvalidDocumentPointer().StringifyUriFragment(sb);
		    cout << "Invalid document " << sb.GetString() << endl;
		}

	}

	return 0;
}
