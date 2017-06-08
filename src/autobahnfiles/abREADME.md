# cjet - An ANSI C conformant JET implementation - Tested with autobahn testsuite

## License
Copyright (c) 2014 Stephan Gatzka. See the [LICENSE](LICENSE) file for license rights and
limitations (MIT).

## Howto Install Testsuite:
- the packet libssl-dev is required for installing the autobahntestsuit
- install the testsuit in a virtual environment as described in the autobahn testsuite [readme](https://github.com/crossbario/autobahn-testsuite)

## Howto Build cjet
- (you need boost for the cjet-unit-tests)
- See the build instructions in the cjet [readme](https://github.com/gatzka/cjet)

## Required Changes for Using the Testsuite
If you use autobahnTest.qbs, instead of cjet.qbs, with the abXXX files everything is already changed, otherwise consider the following hints:
- the testsuite uses as default address ws://localhost:9001 with localhost = 127.0.0.1
- the targtet `request_target` is `/`
- the `sub_protocol` must be `NULL`
- the websocket peer must echo the received messages back
- for performance tests messages up to 16M must be handled, hence set during build or in the config file e.g.: `generateCjetConfig.maxMessageSize:33554432` `generateCjetConfig.maxWriteBufferSize:16777216` `generateCjetConfig.maxHeapsizeInKByte:65536`
- utf8 checking using utf8\_checker.h is left to the websocket peer.c
- reassembling the fragmented messages is left to the websocket peer as well
- it is advisable to change the output via log.c to the standard output

## Howto Use
- create a directory for the test results
- start the virtual environment in the commandline `source ~/your wstest installation folder/bin/activate`
- start the cjet including the required changes, e.g. with your IDE
- start the testsuite in the virual environemnt with `wstest -m fuzzingclient` due to cjet is a server implementation
The results can be seen by /your result directory/reports/servers/index.html. The testsuite creates a default config file in your result directory after the first execution. There you can do the following settings:
- give your server a name in section `"servers": [{ **"agent": "your_server_name"}"**]`
- change the url in the same section with `"url": "ws://ip:port"`
- choose test cases in section `"cases": [ **"*"** ]`
    - `"*"` for all cases
    - `"1.2.1","5.1"` for single cases
    - `1.*`,`4.1.*` for all sub cases of a category
- same pattern applys to `"exclude-cases"`
The settings will be used in every further run with the same result directory without any changes in the start command.

## Howto Create a Project Survey with Doxygen
- execute `doxygen autobahnTest.qbs`in the src folder. This creates among other files the file Doxyfile.in
- choose your settings in Doxyfile.in, particularly choose the target directory, enable latex, pdflatex or html
- execute doxygen with your Doxyfile.in
- execute `make` in the latex directory (make sure you have installed all required latex packages!)
- the result is refman.pdf
- for html the result is index.html (you do not need make)
