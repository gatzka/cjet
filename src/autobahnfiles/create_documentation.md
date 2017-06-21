## Howto Create a Project Overview with Doxygen
- execute `doxygen autobahnTest.qbs`in the _/cjet/src_ folder. This creates among other files the file _Doxyfile.in_
- choose your settings in _Doxyfile.in_, particularly choose the target directory, enable latex, pdflatex or html
- execute doxygen with your Doxyfile.in
- execute `make` in the latex directory (make sure you have installed all required latex packages!)
- the result is _refman.pdf_
- for html the result is _index.html_ in the _html_ directory (you do not need make)
