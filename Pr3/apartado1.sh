#!/bin/bash

#Contamos paquetes IP y no IP
tshark -r traza.pcap -T fields -e ip.proto -Y '(eth.type eq 0x0800||vlan.etype eq 0x0800)' > a1/ip.dat
tshark -r traza.pcap -Y '((eth.type ne 0x0800&&eth.type ne 0x8100)||(eth.type eq 0x8100&&vlan.etype ne 0x0800))' > a1/noip.dat

cd a1

#Obtencion de porcentajes
echo PRIMER APARTADO > porcentajes.dat
echo ------------------------------ >> porcentajes.dat
echo Porcentaje de paquetes IP y no IP:  >> porcentajes.dat
awk -v ip="$(wc -l ip.dat)" '{noip=noip+1;} END{total=ip+noip; print "  - IP: "(ip*100)/total"%"; print "  - No IP: "(noip*100/total)"%";}' noip.dat >> porcentajes.dat
echo ------------------------------  >> porcentajes.dat
echo Del porcentaje de IP tenemos: TCP, UDP y otros respectivamente:  >> porcentajes.dat
awk -v ip="$(wc -l ip.dat)" '{if($1 == 6) tcp=tcp+1; else if($1 == 17) udp=udp+1; else otros=otros+1;} END{print "  - TCP: "(tcp*100)/ip"%"; print "  - UDP: "(udp*100)/ip"%"; print "  - Otros: "(otros*100)/ip"%";}' ip.dat >> porcentajes.dat
echo ------------------------------  >> porcentajes.dat
printf "\n\n"  >> porcentajes.dat

rm -rf ip.dat noip.dat

#Impresion de lo pedido en el primer apartado
head -n 12 porcentajes.dat

cd ..
