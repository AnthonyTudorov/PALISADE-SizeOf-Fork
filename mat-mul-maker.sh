awk '
	BEGIN {
		print "v0.4"
		wire=2;
	}

	{
		for( i=1; i<=NF; i++ ) {
			if( $i == "[" ) continue;
			if( $i == "]" ) continue;
			if( $i == ";" ) continue;
			print ":wire ",wire++,"@ integer",$i
		}
	}
' mat-mul-xy
