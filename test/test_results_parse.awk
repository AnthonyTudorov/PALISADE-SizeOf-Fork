BEGIN {
	hdr = "******"
	backend=""
	cmd="INSERT INTO test_status (platform,backend,date,cases,passed)"
}

$1 == hdr && $2 == "Date" {
	datestamp = $3
}

$1 == "******" && $2 == "Begin" && $3 == "Backend" {
	backend = $4
}

$1 == "******" && $2 == "End" {
	print cmd, "VALUES ('PLATFORM'",",",backend,",'",datestamp,"',",$5,",",$3,");"
	backend = ""
}

END {
	if( backend != "" )
		print cmd, "VALUES ('PLATFORM'",",",backend,",",datestamp,",0,0);"
}
