#!/bin/bash
#Contamos paquetes IP y no IP
tshark -r traza.pcap -T fields -e ip.proto -Y '(eth.type eq 0x0800||vlan.etype eq 0x0800)' > ip.dat
tshark -r traza.pcap -Y '((eth.type ne 0x0800&&eth.type ne 0x8100)||(eth.type eq 0x8100&&vlan.etype ne 0x0800))' > noip.dat
#Impresion de lo pedido en el primer apartado
echo Porcentaje de paquetes IP y no IP respectivamente
awk -v ip="$(wc -l ip.dat)" '{noip=noip+1;} END{total=ip+noip; print (ip*100)/total; print (noip*100/total);}' noip.dat
echo Del porentaje de IP tenemos: TCP, UDP y otros respectivamente
awk -v ip="$(wc -l ip.dat)" '{if($1 == 6) tcp=tcp+1; else if($1 == 17) udp=udp+1; else otros=otros+1;} END{print (tcp*100)/ip; print (udp*100)/ip; print (otros*100)/ip;}' ip.dat
