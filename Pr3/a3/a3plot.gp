#!/usr/bin/gnuplot
#chmod +x a3plot.gp

#set data style points
set title "ECDF de tamano de paquetes"
set xlabel "Tamano"
set ylabel "P(t <= Tamano)"
set key top left

# Para salida a un archivo tipo portable network graphics
set term pngcairo transparent enhanced font "arial,10" fontscale 1.0 size 600, 400
set output "ECDF_tamano.png"

#Plot
plot "gnu.dat" using 1:2 with lines title "F(t)" lt rgb "red"
set output "ECDF_tamanonvl2src.png"
plot "gnu3s.dat" using 1:2 with lines title "F(t)" lt rgb "blue"
set output "ECDF_tamanonvl2dst.png"
plot "gnu3d.dat" using 1:2 with lines title "F(t)" lt rgb "red"
set output "ECDF_tamanonvl3srchttp.png"
plot "gnu4s.dat" using 1:2 with lines title "F(t)" lt rgb "blue"
set output "ECDF_tamanonvl3dsthttp.png"
plot "gnu4d.dat" using 1:2 with lines title "F(t)" lt rgb "red"
set output "ECDF_tamanonvl3srcdns.png"
plot "gnu5s.dat" using 1:2 with lines title "F(t)" lt rgb "blue"
set output "ECDF_tamanonvl3dstdns.png"
plot "gnu5d.dat" using 1:2 with lines title "F(t)" lt rgb "red"

set output
