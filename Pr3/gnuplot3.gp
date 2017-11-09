#!/usr/bin/gnuplot
#chmod +x ejemploGNUplot.gp

# Salida por pantalla simple: sudo apt-get install gnuplot-x11; set term 11
set term dumb

#set data style points
set title "ECDF tamanio paquetes"
set xlabel "Tamanio"
set ylabel "P[tamanio<=Tamanio]"

# Para salida a un archivo tipo portable network graphics
set term jpeg
set output "ECDFtamanios.jpeg"
plot "gnu.dat" using 1:2 with steps title "F(tamanio)"

set output
