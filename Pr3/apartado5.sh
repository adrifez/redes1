#!/bin/bash

#Obtenemos el tiempo en el que llega cada uno
tshark -r traza.pcap -T fields -e frame.time_epoch -Y '(ip.src eq 36.173.217.43)&&tcp' > a5/tcpsrc.dat
tshark -r traza.pcap -T fields -e frame.time_epoch -Y '(ip.dst eq 36.173.217.43)&&tcp' > a5/tcpdst.dat
tshark -r traza.pcap -T fields -e frame.time_epoch -Y '(udp.srcport eq 49714)' > a5/udpsrc.dat
tshark -r traza.pcap -T fields -e frame.time_epoch -Y '(udp.dstport eq 49714)' > a5/udpdst.dat

cd a5

#Calculamos el tiempo trancurrido desde el paquete anterior (si es el primer paquete delta es 0)
awk 'BEGIN{n=0;} {if(n == 0) delta=0; else delta=$1-t_last; t_last=$1; n=n+1; print delta;}' tcpsrc.dat > deltaTS.dat
awk 'BEGIN{n=0;} {if(n == 0) delta=0; else delta=$1-t_last; t_last=$1; n=n+1; print delta;}' tcpdst.dat > deltaTD.dat
awk 'BEGIN{n=0;} {if(n == 0) delta=0; else delta=$1-t_last; t_last=$1; n=n+1; print delta;}' udpsrc.dat > deltaUS.dat
awk 'BEGIN{n=0;} {if(n == 0) delta=0; else delta=$1-t_last; t_last=$1; n=n+1; print delta;}' udpdst.dat > deltaUD.dat

rm -rf tcpsrc.dat tcpdst.dat udpsrc.dat udpdst.dat

#Generamos ficheros de dos columnas, donde la primera es los deltas posibles y la segunda es la probabilidad de que exista ese delta entre dos paquetes
awk '{numero_deltas[$1] = numero_deltas[$1] + 1; n_intervalos = n_intervalos + 1;}
END{for (valor in numero_deltas) print valor" "(numero_deltas[valor]/n_intervalos);}' deltaTS.dat > probTS.dat
awk '{numero_deltas[$1] = numero_deltas[$1] + 1; n_intervalos = n_intervalos + 1;}
END{for (valor in numero_deltas) print valor" "(numero_deltas[valor]/n_intervalos);}' deltaTD.dat > probTD.dat
awk '{numero_deltas[$1] = numero_deltas[$1] + 1; n_intervalos = n_intervalos + 1;}
END{for (valor in numero_deltas) print valor" "(numero_deltas[valor]/n_intervalos);}' deltaUS.dat > probUS.dat
awk '{numero_deltas[$1] = numero_deltas[$1] + 1; n_intervalos = n_intervalos + 1;}
END{for (valor in numero_deltas) print valor" "(numero_deltas[valor]/n_intervalos);}' deltaUD.dat > probUD.dat

rm -rf deltaTS.dat deltaTD.dat deltaUS.dat deltaUD.dat

#Preparamos los ficheros ECDF
export LC_NUMERIC=en_US.utf-8
sort -k1g probTS.dat > probTSo.dat
awk 'BEGIN{FS=" "} {acum=acum+$2; print $1" "acum;}' probTSo.dat > plotTS.dat
sort -k1g probTD.dat > probTDo.dat
awk 'BEGIN{FS=" "} {acum=acum+$2; print $1" "acum;}' probTDo.dat > plotTD.dat
sort -k1g probUS.dat > probUSo.dat
awk 'BEGIN{FS=" "} {acum=acum+$2; print $1" "acum;}' probUSo.dat > plotUS.dat
echo No existen datos para la grafica del flujo UDP origen
sort -k1g probUD.dat > probUDo.dat
awk 'BEGIN{FS=" "} {acum=acum+$2; print $1" "acum;}' probUDo.dat > plotUD.dat

rm -rf probTS.dat probTD.dat probUS.dat probUD.dat
rm -rf probTSo.dat probTDo.dat probUSo.dat probUDo.dat

#Grafica
./a5plot.gp

rm -rf plotTS.dat plotTD.dat plotUS.dat plotUD.dat
cd ..

echo QUINTO APARTADO REALIZADO CON EXITO
printf "\n\n"
