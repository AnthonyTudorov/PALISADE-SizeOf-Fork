for i in 2 4 6 7
do
	echo "****************************"
	echo Building and testing MATHBACKEND $i
	echo "****************************"
	touch src/core/lib/math/backend.h
	make -j8  CPPFLAGS+=-DMATHBACKEND=$i all >/dev/null 2>&1  # -DBigIntegerBitLength=128
	if [ $? -eq 0 ];
	then
		make testall
	else
		echo " ******** build failed!!!"
	fi
	echo "****************************"
	echo DONE
	echo "****************************"
done
