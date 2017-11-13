#!/bin/bash

#Generamos el archivo de los anchos de banda
tshark -r traza.pcap -qz io,stat,1,"SUM(frame.len)frame.len&&eth.src eq 00:11:88:CC:33:32","SUM(frame.len)frame.len&&eth.dst eq 00:11:88:CC:33:32" > a4/bw.dat

cd a4

#Filtramos las filas que contienen los datos que necesitamos para la grafica
tail -n 136 bw.dat | head -n 135 > aux.dat

#Quitamos "|"
awk 'BEGIN {FS="|";}
{
	print $1" "$2" "$3" "$4;
}' aux.dat > limpio.dat
rm -rf aux.dat

#Limpiamos el fichero para poder representar con gnuplot y pasamos los Bytes a bits
awk 'BEGIN {FS=" ";}
{
	print $1"-"$3" "8*$4" "8*$5;
}' limpio.dat > plot.dat
rm -rf limpio.dat

head -n 46 plot.dat > plot1.dat
head -n 92 plot.dat | tail -n 46 > plot2.dat
head -n 138 plot.dat | tail -n 46 > plot3.dat

#Grafica
./a4plot.gp
rm -rf plot.dat plot1.dat plot2.dat plot3.dat

cd ..

echo CUARTO APARTADO REALIZADO CON EXITO
printf "\n\n"
