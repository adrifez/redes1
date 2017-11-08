#!/bin/bash

#Guardamos ip origen y destino junto con el tamano del paquete
tshark -r traza.pcap -T fields -e frame.len -e ip.src -e ip.dst -Y '(eth.type eq 0x0800||vlan.etype eq 0x0800)' > topip.dat
#Guardamos puerto origen y destino junto con el tamano del paquete
tshark -r traza.pcap -T fields -e frame.len -e tcp.srcport -e tcp.dstport -Y '(ip.proto eq 6)' > toptcp.dat
tshark -r traza.pcap -T fields -e frame.len -e udp.srcport -e udp.dstport -Y '(ip.proto eq 17)' > topudp.dat

#Impresion de lo pedido en el segundo apartado
echo Direcciones IP origen en bytes:
echo Direcciones IP origen en paquetes:
echo Direcciones IP destino en bytes:
echo Direcciones IP destino en paquetes:

echo Puertos TCP origen en bytes:
echo Puertos TCP origen en paquetes:
echo Puertos TCP destino en bytes:
echo Puertos TCP destino en paquetes:

echo Puertos UDP origen en bytes:
echo Puertos UDP origen en paquetes:
echo Puertos UDP destino en bytes:
echo Puertos UDP destino en paquetes:
#awk -v ip="$(wc -l ip.dat)" '{noip=noip+1;} END{total=ip+noip; print (ip*100)/total; print (noip*100/total);}' noip.dat
#echo Del porcentaje de IP tenemos: TCP, UDP y otros respectivamente
#awk -v ip="$(wc -l ip.dat)" '{if($1 == 6) tcp=tcp+1; else if($1 == 17) udp=udp+1; else otros=otros+1;} END{print (tcp*100)/ip; print (udp*100)/ip; print (otros*100)/ip;}' ip.dat