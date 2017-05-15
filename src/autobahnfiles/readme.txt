Installation hints:
(-you need boost for the cjet-unit-tests)
-the packet libssl-dev is required for installing the autobahntestsuit
-install the testsuit in a virtual environment as described in the github howTo: https://github.com/crossbario/autobahn-testsuite
-the testset uses as default ws://localhost:9001, localhost=127.0.0.1
-the targtet request_target is /
-the sub_protocol must be NULL
-the websocket-peer must echo the recieved messages back

Doxygen:
-doxygen autobahnTest.qbs
	dabei wird latex und main erstellt, sowie Doxyfile.in
Doxyfile.in configurieren, insbesondere Zielpfad anlegen und ggf latex & pdflatex anschalten
im Latexordner: -make (Darauf achten, dass alle benötigten Latex-Packete installiert sind!)
Ergebnis ist refman.pdf 
für html index.html (ohne make)
