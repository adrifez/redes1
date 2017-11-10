#!/usr/bin/gnuplot
#chmod +x a3plot.gp

#set data style points
set title "ECDF de tamano de paquetes"
set xlabel "Tamano"
set ylabel "P(t <= Tamano)"

# Para salida a un archivo tipo portable network graphics
set term pngcairo transparent enhanced font "arial,10" fontscale 1.0 size 600, 400
set output "ECDF_tamano.png"
plot "gnu.dat" using 1:2 with steps title "F(t)"

set output
