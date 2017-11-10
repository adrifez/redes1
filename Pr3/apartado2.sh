#!/bin/bash

#Guardamos ip origen y destino junto con el tamano del paquete
tshark -r traza.pcap -T fields -e frame.len -e ip.src -e ip.dst -Y '(eth.type eq 0x0800||vlan.etype eq 0x0800)' > a2/ip.dat
#Guardamos puerto origen y destino junto con el tamano del paquete
tshark -r traza.pcap -T fields -e frame.len -e tcp.srcport -e tcp.dstport -Y '(ip.proto eq 6)' > a2/tcp.dat
tshark -r traza.pcap -T fields -e frame.len -e udp.srcport -e udp.dstport -Y '(ip.proto eq 17)' > a2/udp.dat


#Generamos tablas con direcciones ip, los bytes transmitidos y el numero de paquetes
awk 'BEGIN {FS=" ";} {numero_bytes[$2] = numero_bytes[$2] + $1;}
END{
	for (valor in numero_bytes) {
		print valor" "numero_bytes[valor];
	}
}' a2/ip.dat | sort -k2nr | head -n 10 > a2/ipsrcbytes.dat
awk 'BEGIN {FS=" ";} {numero_paquetes[$2] = numero_paquetes[$2] + 1;}
END {
	for (valor in numero_paquetes) {
		print valor" "numero_paquetes[valor];
	}
}' a2/ip.dat | sort -k2nr | head -n 10 > a2/ipsrcpaquetes.dat

awk 'BEGIN {FS=" ";} {numero_bytes[$3] = numero_bytes[$3] + $1;}
END {
	for (valor in numero_bytes) {
		print valor" "numero_bytes[valor];
	}
}' a2/ip.dat | sort -k2nr | head -n 10 > a2/ipdstbytes.dat
awk 'BEGIN {FS=" ";} {numero_paquetes[$3] = numero_paquetes[$3] + 1;}
END {
	for (valor in numero_paquetes) {
		print valor" "numero_paquetes[valor];
	}
}' a2/ip.dat | sort -k2nr | head -n 10 > a2/ipdstpaquetes.dat

rm -rf a2/ip.dat


awk 'BEGIN {FS=" ";} {numero_bytes[$2] = numero_bytes[$2] + $1;}
END{
	for (valor in numero_bytes) {
		print valor" "numero_bytes[valor];
	}
}' a2/tcp.dat | sort -k2nr | head -n 10 > a2/tcpsrcbytes.dat
awk 'BEGIN {FS=" ";} {numero_paquetes[$2] = numero_paquetes[$2] + 1;}
END {
	for (valor in numero_paquetes) {
		print valor" "numero_paquetes[valor];
	}
}' a2/tcp.dat | sort -k2nr | head -n 10 > a2/tcpsrcpaquetes.dat

awk 'BEGIN {FS=" ";} {numero_bytes[$3] = numero_bytes[$3] + $1;}
END {
	for (valor in numero_bytes) {
		print valor" "numero_bytes[valor];
	}
}' a2/tcp.dat | sort -k2nr | head -n 10 > a2/tcpdstbytes.dat
awk 'BEGIN {FS=" ";} {numero_paquetes[$3] = numero_paquetes[$3] + 1;}
END {
	for (valor in numero_paquetes) {
		print valor" "numero_paquetes[valor];
	}
}' a2/tcp.dat | sort -k2nr | head -n 10 > a2/tcpdstpaquetes.dat

rm -rf a2/tcp.dat


awk 'BEGIN {FS=" ";} {numero_bytes[$2] = numero_bytes[$2] + $1;}
END{
	for (valor in numero_bytes) {
		print valor" "numero_bytes[valor];
	}
}' a2/udp.dat | sort -k2nr | head -n 10 > a2/udpsrcbytes.dat
awk 'BEGIN {FS=" ";} {numero_paquetes[$2] = numero_paquetes[$2] + 1;}
END {
	for (valor in numero_paquetes) {
		print valor" "numero_paquetes[valor];
	}
}' a2/udp.dat | sort -k2nr | head -n 10 > a2/udpsrcpaquetes.dat

awk 'BEGIN {FS=" ";} {numero_bytes[$3] = numero_bytes[$3] + $1;}
END {
	for (valor in numero_bytes) {
		print valor" "numero_bytes[valor];
	}
}' a2/udp.dat | sort -k2nr | head -n 10 > a2/udpdstbytes.dat
awk 'BEGIN {FS=" ";} {numero_paquetes[$3] = numero_paquetes[$3] + 1;}
END {
	for (valor in numero_paquetes) {
		print valor" "numero_paquetes[valor];
	}
}' a2/udp.dat | sort -k2nr | head -n 10 > a2/udpdstpaquetes.dat

rm -rf a2/udp.dat

cd a2
./ipsrc.gp
cd ..

#Impresion de lo pedido en el segundo apartado
echo SEGUNDO APARTADO
echo ------------------------------
echo Direcciones IP origen en bytes:
head -n 10 a2/ipsrcbytes.dat
echo ------------------------------
echo Direcciones IP origen en paquetes:
head -n 10 a2/ipsrcpaquetes.dat
echo ------------------------------
echo Direcciones IP destino en bytes:
head -n 10 a2/ipdstbytes.dat
echo ------------------------------
echo Direcciones IP destino en paquetes:
head -n 10 a2/ipdstpaquetes.dat
echo ------------------------------
printf "\n"
echo ------------------------------
echo Puertos TCP origen en bytes:
head -n 10 a2/tcpsrcbytes.dat
echo ------------------------------
echo Puertos TCP origen en paquetes:
head -n 10 a2/tcpsrcpaquetes.dat
echo ------------------------------
echo Puertos TCP destino en bytes:
head -n 10 a2/tcpdstbytes.dat
echo ------------------------------
echo Puertos TCP destino en paquetes:
head -n 10 a2/tcpdstpaquetes.dat
echo ------------------------------
printf "\n"
echo ------------------------------
echo Puertos UDP origen en bytes:
head -n 10 a2/udpsrcbytes.dat
echo ------------------------------
echo Puertos UDP origen en paquetes:
head -n 10 a2/udpsrcpaquetes.dat
echo ------------------------------
echo Puertos UDP destino en bytes:
head -n 10 a2/udpdstbytes.dat
echo ------------------------------
echo Puertos UDP destino en paquetes:
head -n 10 a2/udpdstpaquetes.dat
echo ------------------------------
printf "\n\n"