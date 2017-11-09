#!/bin/bash

#Guardamos ip origen y destino junto con el tamano del paquete
tshark -r traza.pcap -T fields -e frame.len -e ip.src -e ip.dst -Y '(eth.type eq 0x0800||vlan.etype eq 0x0800)' > a2/topip.dat
#Guardamos puerto origen y destino junto con el tamano del paquete
tshark -r traza.pcap -T fields -e frame.len -e tcp.srcport -e tcp.dstport -Y '(ip.proto eq 6)' > a2/toptcp.dat
tshark -r traza.pcap -T fields -e frame.len -e udp.srcport -e udp.dstport -Y '(ip.proto eq 17)' > a2/topudp.dat


#Generamos tablas con direcciones ip, los bytes transmitidos y el numero de paquetes
awk 'BEGIN {
	FS = " ";
}
{
	numero_bytes[$2] = numero_bytes[$2] + $1;
	numero_paquetes[$2] = numero_paquetes[$2] + 1;
}
END {
	for (valor in numero_bytes) {
		print valor","numero_bytes[valor]","numero_paquetes[valor];
	}
}' a2/topip.dat > a2/ipsrc.dat

awk 'BEGIN {
	FS = " ";
}
{
	numero_bytes[$3] = numero_bytes[$3] + $1;
	numero_paquetes[$3] = numero_paquetes[$3] + 1;
}
END {
	for (valor in numero_bytes) {
		print valor","numero_bytes[valor]","numero_paquetes[valor];
	}
}' a2/topip.dat > a2/ipdst.dat

awk 'BEGIN {
	FS = " ";
}
{
	numero_bytes[$2] = numero_bytes[$2] + $1;
	numero_paquetes[$2] = numero_paquetes[$2] + 1;
}
END {
	for (valor in numero_bytes) {
		print valor","numero_bytes[valor]","numero_paquetes[valor];
	}
}' a2/toptcp.dat > a2/tcpsrc.dat

awk 'BEGIN {
	FS = " ";
}
{
	numero_bytes[$3] = numero_bytes[$3] + $1;
	numero_paquetes[$3] = numero_paquetes[$3] + 1;
}
END {
	for (valor in numero_bytes) {
		print valor","numero_bytes[valor]","numero_paquetes[valor];
	}
}' a2/toptcp.dat > a2/tcpdst.dat

awk 'BEGIN {
	FS = " ";
}
{
	numero_bytes[$2] = numero_bytes[$2] + $1;
	numero_paquetes[$2] = numero_paquetes[$2] + 1;
}
END {
	for (valor in numero_bytes) {
		print valor","numero_bytes[valor]","numero_paquetes[valor];
	}
}' a2/topudp.dat > a2/udpsrc.dat

awk 'BEGIN {
	FS = " ";
}
{
	numero_bytes[$3] = numero_bytes[$3] + $1;
	numero_paquetes[$3] = numero_paquetes[$3] + 1;
}
END {
	for (valor in numero_bytes) {
		print valor","numero_bytes[valor]","numero_paquetes[valor];
	}
}' a2/topudp.dat > a2/udpdst.dat


#Impresion de lo pedido en el segundo apartado
echo Direcciones IP origen en bytes:
awk 'BEGIN {
	FS = ",";
}
{
	
}
END {
	
}' a2/ipsrc.dat

echo Direcciones IP origen en paquetes:
awk 'BEGIN {
	FS = ",";
}
{
	
}
END {
	
}' a2/ipsrc.dat


echo Direcciones IP destino en bytes:
awk 'BEGIN {
	FS = ",";
}
{
	
}
END {
	
}' a2/ipdst.dat

echo Direcciones IP destino en paquetes:
awk 'BEGIN {
	FS = ",";
}
{
	
}
END {
	
}' a2/ipdst.dat

echo Puertos TCP origen en bytes:
echo Puertos TCP origen en paquetes:
echo Puertos TCP destino en bytes:
echo Puertos TCP destino en paquetes:

echo Puertos UDP origen en bytes:
echo Puertos UDP origen en paquetes:
echo Puertos UDP destino en bytes:
echo Puertos UDP destino en paquetes:
