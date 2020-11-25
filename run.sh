#!/bin/sh

KIC=$1 KID=$2 MCC=$3 MNC=$4 IMSI=$5 ADM=$6 
IMPI=$7 IMPU=$8 IMSHDOMAIN=$9

if (( ${#1} == 32 & ${#2} == 32 ))
then
   echo "[*]Building the docker"
   docker build -t pysim .
   echo "[*]Running the applet installation"
   docker run --privileged -v /dev/bus/usb:/dev/bus/usb -e KIC=$KIC -e KID=$KID pysim
   if(( "${#MCC}" == 3 & "${#MNC}" == 2 & "${#IMSI}" == 15 & "${#ADM}" == 8 & "${#IMPI}" != 0 & "${#IMPU}" !=0  & "${#IMSHDOMAIN}" != 0   ))
   then
      echo "[*]Running the IMS provisioning process"
      docker run -i --privileged -v /dev/bus/usb:/dev/bus/usb pysim  service pcscd start \
      python /pySim_mod/pySim-prog.py -p 0 -s 8988211900000000004 -x $MCC -y $MNC -i $IMSI -a $ADM --ims-hdomain $IMSHDOMAIN --impi $IMPI --impu $IMPU
      echo "[*]Done"
   else
      echo "[*]At least one of the provisioning params is missing"
      fi
else
   echo "Each key must be 32 bytes"
fi
