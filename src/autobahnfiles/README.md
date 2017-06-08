# cjet - An ANSI C conformant JET implementation - Test with autobahn testsuite

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
If you use _autobahnTest.qbs_, instead of _cjet.qbs_, with the _abXXX_ files everything is already changed, otherwise consider the following hints:
- the testsuite uses as default address ws://localhost:9001 with localhost = 127.0.0.1
- the targtet `request_target` is `/`
- the `sub_protocol` must be `NULL`
- the websocket peer must echo the received messages back
- for performance tests messages up to 16M must be handled, hence set during build or in the config file e.g.: `generateCjetConfig.maxMessageSize:33554432` `generateCjetConfig.maxWriteBufferSize:16777216` `generateCjetConfig.maxHeapsizeInKByte:65536`
- utf8 checking using _utf8\_checker.h_ is left to the websocket peer
- reassembling the fragmented messages is left to the websocket peer as well
- it is advisable to change the output via log.c to the standard output

## Howto Use
- create a directory for the test results, e.g. _results_
- start the virtual environment in the commandline `source ~/your wstest installation folder/bin/activate`
- start the cjet including the required changes, e.g. with your IDE
- start the testsuite in the virual environemnt with `wstest -m fuzzingclient` due to cjet is a server implementation  
The results can be seen by _~/results/reports/servers/index.html_. The testsuite creates a default config file _~/results/fuzzingclient.json_ after the first execution. There you can do the following settings:
- give your server a name in section `"servers": [{ "agent": "your_server_name"}"]`
- change the url in the same section with `"url": "ws://ip:port"`
- choose test cases in section `"cases": [ "*" ]`
    - `"*"` for all cases
    - `"1.2.1","5.1"` for single cases
    - `"1.*","4.1.*"` for all sub cases of a category
- same pattern applys to `"exclude-cases"`  
The settings will be used in every further run in _results_ without any changes in the start command.

## Howto Create a Project Survey with Doxygen
- execute `doxygen autobahnTest.qbs`in the _/cjet/src_ folder. This creates among other files the file _Doxyfile.in_
- choose your settings in _Doxyfile.in_, particularly choose the target directory, enable latex, pdflatex or html
- execute doxygen with your Doxyfile.in
- execute `make` in the latex directory (make sure you have installed all required latex packages!)
- the result is _refman.pdf_
- for html the result is _index.html_ in the _html_ directory (you do not need make)
