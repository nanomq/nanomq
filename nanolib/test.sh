#! /bin/bash
# set n to 1
n=1
#continue until n equals 1000
while [ $n -le 10000 ]
do
	echo "pub topic"
	mosquitto_pub -t "a/b/c" -m "cmessage$n"
	mosquitto_pub -t "a/b/d" -m "dmessage$n"
	n=$((n+1))
done

