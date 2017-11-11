#!/bin/bash

#Generamos el archivo con los tamanos de los paquetes
tshark -r traza.pcap -T fields -e frame.len > sizes.dat
tshark -r traza.pcap -T fields -e frame.len -Y 'eth.src eq 00:11:88:CC:33:32' > sizes3src.dat
tshark -r traza.pcap -T fields -e frame.len -Y 'eth.dst eq 00:11:88:CC:33:32' > sizes3dst.dat
tshark -r traza.pcap -T fields -e ip.len -Y 'tcp.srcport eq 80' > sizes4src.dat
tshark -r traza.pcap -T fields -e ip.len -Y 'tcp.dstport eq 80' > sizes4dst.dat
tshark -r traza.pcap -T fields -e ip.len -Y 'udp.srcport eq 53'> sizes5src.dat
tshark -r traza.pcap -T fields -e ip.len -Y 'udp.dstport eq 53'> sizes5dst.dat

#Compilamos y ejecutamos crearCDF
gcc -g -Wall crearCDF.c -o exe
./exe
rm -rf exe sizes.dat

#Generamos un fichero de dos columnas, donde la primera es los tamanos de paquetes posibles y la segunda es la probabilidad de que un paquete tenga ese tamano
awk '{numero_paquetes[$1] = numero_paquetes[$1] + 1; n_paquetes = n_paquetes + 1;} END{for (valor in numero_paquetes) print valor" "(numero_paquetes[valor]/n_paquetes);}' ECDFsizes.dat | sort -k1n > a3/gnuord.dat
rm -rf ECDFsizes.dat
awk '{numero_paquetes[$1] = numero_paquetes[$1] + 1; n_paquetes = n_paquetes + 1;} END{for (valor in numero_paquetes) print valor" "(numero_paquetes[valor]/n_paquetes);}' sizes3src.dat | sort -k1n > a3/gnuord3s.dat
awk '{numero_paquetes[$1] = numero_paquetes[$1] + 1; n_paquetes = n_paquetes + 1;} END{for (valor in numero_paquetes) print valor" "(numero_paquetes[valor]/n_paquetes);}' sizes3dst.dat | sort -k1n > a3/gnuord3d.dat
awk '{numero_paquetes[$1] = numero_paquetes[$1] + 1; n_paquetes = n_paquetes + 1;} END{for (valor in numero_paquetes) print valor" "(numero_paquetes[valor]/n_paquetes);}' sizes4src.dat | sort -k1n > a3/gnuord4s.dat
awk '{numero_paquetes[$1] = numero_paquetes[$1] + 1; n_paquetes = n_paquetes + 1;} END{for (valor in numero_paquetes) print valor" "(numero_paquetes[valor]/n_paquetes);}' sizes4dst.dat | sort -k1n > a3/gnuord4d.dat
awk '{numero_paquetes[$1] = numero_paquetes[$1] + 1; n_paquetes = n_paquetes + 1;} END{for (valor in numero_paquetes) print valor" "(numero_paquetes[valor]/n_paquetes);}' sizes5src.dat | sort -k1n > a3/gnuord5s.dat
awk '{numero_paquetes[$1] = numero_paquetes[$1] + 1; n_paquetes = n_paquetes + 1;} END{for (valor in numero_paquetes) print valor" "(numero_paquetes[valor]/n_paquetes);}' sizes5dst.dat | sort -k1n > a3/gnuord5d.dat

rm -rf sizes3src.dat sizes3dst.dat sizes4src.dat sizes4dst.dat sizes5src.dat sizes5dst.dat

cd a3

#Preparamos el fichero ECDF
awk 'BEGIN{FS=" "} {acum=acum+$2; print $1" "acum;}' gnuord.dat > gnu.dat
awk 'BEGIN{FS=" "} {acum=acum+$2; print $1" "acum;}' gnuord3s.dat > gnu3s.dat
awk 'BEGIN{FS=" "} {acum=acum+$2; print $1" "acum;}' gnuord3d.dat > gnu3d.dat
awk 'BEGIN{FS=" "} {acum=acum+$2; print $1" "acum;}' gnuord4s.dat > gnu4s.dat
awk 'BEGIN{FS=" "} {acum=acum+$2; print $1" "acum;}' gnuord4d.dat > gnu4d.dat
awk 'BEGIN{FS=" "} {acum=acum+$2; print $1" "acum;}' gnuord5s.dat > gnu5s.dat
awk 'BEGIN{FS=" "} {acum=acum+$2; print $1" "acum;}' gnuord5d.dat > gnu5d.dat

#Grafica
./a3plot.gp

rm -rf gnuaux.dat gnuord.dat gnu.dat sizes*.dat gnuord*.dat gnu*.dat
cd ..

echo TERCER APARTADO REALIZADO CON EXITO
printf "\n\n"