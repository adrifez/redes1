#!/bin/bash

#Obtenemos el tiempo en el que llega cada uno
tshark -r traza.pcap -T fields -e frame.time_epoch -Y '(ip.src eq 36.173.217.43)&&tcp' > a5/tcpsrc.dat
tshark -r traza.pcap -T fields -e frame.time_epoch -Y '(ip.dst eq 36.173.217.43)&&tcp' > a5/tcpdst.dat
tshark -r traza.pcap -T fields -e frame.time_epoch -Y '(udp.srcport eq 49714)' > a5/udpsrc.dat
tshark -r traza.pcap -T fields -e frame.time_epoch -Y '(udp.dstport eq 49714)' > a5/udpdst.dat

#Calculamos el tiempo trancurrido desde el paquete anterior (si es el primer paquete delta es 0)
awk 'BEGIN{n=0;} {if(n == 0) delta=0; else delta=$1-t_last; t_last=$1; n=n+1; print n"\t"delta;}' a5/tcpsrc.dat > a5/deltaTS.dat
awk 'BEGIN{n=0;} {if(n == 0) delta=0; else delta=$1-t_last; t_last=$1; n=n+1; print n"\t"delta;}' a5/tcpdst.dat > a5/deltaTD.dat
awk 'BEGIN{n=0;} {if(n == 0) delta=0; else delta=$1-t_last; t_last=$1; n=n+1; print n"\t"delta;}' a5/udpsrc.dat > a5/deltaUS.dat
awk 'BEGIN{n=0;} {if(n == 0) delta=0; else delta=$1-t_last; t_last=$1; n=n+1; print n"\t"delta;}' a5/udpdst.dat > a5/deltaUD.dat
