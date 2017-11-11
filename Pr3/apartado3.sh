#!/bin/bash

#Generamos el archivo con los tamanos de los paquetes
tshark -r traza.pcap -T fields -e frame.len > sizes.dat

#Compilamos y ejecutamos crearCDF
gcc -g -Wall crearCDF.c -o exe
./exe
rm -rf exe sizes.dat

#Generamos un fichero de dos columnas, donde la primera es los tamanos de paquetes posibles y la segunda es la probabilidad de que un paquete tenga ese tamano
awk '{numero_paquetes[$1] = numero_paquetes[$1] + 1; n_paquetes = n_paquetes + 1;} END{for (valor in numero_paquetes) print valor" "(numero_paquetes[valor]/n_paquetes);}' ECDFsizes.dat | sort -k1n > a3/gnuord.dat
rm -rf ECDFsizes.dat

cd a3

#Preparamos el fichero ECDF
awk 'BEGIN{FS=" "} {acum=acum+$2; print $1" "acum;}' gnuord.dat > gnu.dat

#Grafica
./a3plot.gp

rm -rf gnuaux.dat gnuord.dat gnu.dat
cd ..

echo TERCER APARTADO REALIZADO CON EXITO
printf "\n\n"