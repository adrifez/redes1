#!/usr/bin/gnuplot
#chmod +x a4plot.gp

# Parametros
set boxwidth 0.9 absolute
set style fill solid 1.00 border lt -1
set style histogram clustered gap 1 title textcolor lt -1
set datafile missing '-'
set style data histograms
set xtics border in scale 0,0 nomirror rotate by -45 autojustify
set logscale y

set title "Ancho de banda"
set xlabel "Intervalo(s)"
set ylabel "BW(bits)"

# Para salida a un archivo tipo portable network graphics
set terminal pngcairo transparent enhanced font "arial,10" fontscale 1.0 size 900, 675

# Plot
set output "bw_1.png"
plot 'plot1.dat' using 2:xtic(1) ti "Mandados" fc rgb "red", 'plot1.dat' using 3 ti "Recibidos" fc rgb "blue"
set output "bw_2.png"
plot 'plot2.dat' using 2:xtic(1) ti "Mandados" fc rgb "red", 'plot2.dat' using 3 ti "Recibidos" fc rgb "blue"
set output "bw_3.png"
plot 'plot3.dat' using 2:xtic(1) ti "Mandados" fc rgb "red", 'plot3.dat' using 3 ti "Recibidos" fc rgb "blue"

# Cierra el archivo de salida
set output