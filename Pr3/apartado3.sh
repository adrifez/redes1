#!/bin/bash

tshark -r traza.pcap -T fields -e frame.len > sizes.dat

gcc -g -Wall crearCDF.c -o exe
./exe
rm -rf exe sizes.dat

awk '{numero_paquetes[$1] = numero_paquetes[$1] + 1; n_paquetes = n_paquetes + 1;} END{for (valor in numero_paquetes) print valor" "(numero_paquetes[valor]/n_paquetes);}' ECDFsizes.dat > a3/gnuaux.dat
rm -rf ECDFsizes.dat

cd a3

sort -n gnuaux.dat > gnuord.dat
awk 'BEGIN{FS=" "} {acum=acum+$2; print $1"\t"acum;}' gnuord.dat > gnu.dat

./a3plot.gp

rm -rf gnuaux.dat gnuord.dat gnu.dat
cd ..

echo TERCER APARTADO REALIZADO CON EXITO
printf "\n\n"
