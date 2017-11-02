for i in 2 4 6 7
do
	echo "****************************"
	echo Building and testing MATHBACKEND $i
	echo "****************************"
	touch src/core/lib/math/backend.h
	make -j16  BINDIR=bin/backend-$i CPPFLAGS+=-DMATHBACKEND=$i all >/dev/null 2>&1
	if [ $? -eq 0 ];
	then
		(
		export LD_LIBRARY_PATH=bin/backend-$i/lib:$LD_LIBRARY_PATH
		export PATH=bin/backend-$i/lib:$LD_LIBRARY_PATH
		bin/backend-$i/unittest/tests -t
		)
	else
		echo " ******** build failed!!!"
	fi
	echo "****************************"
	echo DONE
	echo "****************************"
done
