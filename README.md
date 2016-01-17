# cjet - An ANSI C conformant JET implementation

## License
Copyright (c) 2014 Stephan Gatzka. See the [LICENSE](LICENSE) file for license rights and
limitations (MIT).

## Build Status
[![Travis CI](https://travis-ci.org/gatzka/cjet.svg?branch=master)](https://travis-ci.org/gatzka/cjet)
[![Coverity](https://scan.coverity.com/projects/3315/badge.svg)](https://scan.coverity.com/projects/3315)
[![Coverage Status](https://coveralls.io/repos/gatzka/cjet/badge.svg?branch=master&service=github)](https://coveralls.io/github/gatzka/cjet?branch=master)

[![Stories in Backlog](https://badge.waffle.io/gatzka/cjet.png?label=backlog&title=Backlog)](https://waffle.io/gatzka/cjet)
[![Stories in Ready](https://badge.waffle.io/gatzka/cjet.png?label=ready&title=Ready)](https://waffle.io/gatzka/cjet)
[![Stories in progress](https://badge.waffle.io/gatzka/cjet.png?label=in%20progress&title=In%20Progress)](https://waffle.io/gatzka/cjet)

[![Open Hub](https://img.shields.io/badge/Open-Hub-0185CA.svg)](https://www.openhub.net/p/java-scan)
## Howto Build

### CMake
Create a build directory somewhere on you build machine and execute:

- `cmake <path/to/cjet-sources>`
- `make`
- Optionally run `make test` to execute the unit tests.

There are some options available to configure cjet at compile time. You
will find all these options in the file [defaults.cmake](cmake/defaults.cmake).
If you want to override these default values, you need to pass these
options to cmake, e.g. `cmake -DCONFIG_MAX_WRITE_BUFFER_SIZE=51200 -D...
<path/to/cjet-sources>`.

Per default, cjet is always built with hardening compile switches like
`-fpie`, `-fstack-protector` or `-D_FORTIFY_SOURCE=2`. This imposes a
little runtime overhead. You can disable all hardening by calling cmake
with `-DCONFIG_NO_HARDENING=1`.

### QBS
There is a second build method available, [qbs](http://doc.qt.io/qbs/).
Just create a build directory, change to it and run:
```
qbs -f <path/to/cjet-sources>/src/cjet.qbs
```
qbs has the ability to make parallel builds for multiple profiles. So
if you want to build with clang, gcc, arm-gcc, ppc-gcc (these are the names
of your qbs profiles), just run:
```
qbs -f <path/to/cjet-sources>/src/cjet.qbs debug profile:gcc release profile:gcc debug profile:clang release profile:clang debug profile:arm-gcc release profile:arm-gcc debug profile:ppc-gcc release profile:ppc-gcc
```

You can also configure cjet at compile time via qbs. You will find the
cjet spedific in
[generateCjetConfig.qbs](qbs/modules/generateCjetConfig/generateCjetConfig.qbs)
and the Linux specific configurations in
[generateOsConfig.qbs](qbs/modules/generateOsConfig/generateOsConfig.qbs).

You can override these defaults easily when calling qbs, for instance:
```
qbs -f <path/to/cjet-sources>/src/cjet.qbs profile:gcc generateCjetConfig.serverPort:4321 generateOsConfig.maxEpollEvents:11
```
Per default, cjet is always built with hardening compile switches like
`-fpie`, `-fstack-protector` or `-D_FORTIFY_SOURCE=2`. This imposes a
little runtime overhead. You can disable all hardening by calling qbs like:
```
qbs -f <path/to/cjet-sources>/src/cjet.qbs release hardening.enableHardening:false
```

In addition, there is also a qbs project for building und running cjet and all unit tests:
```
qbs -f <path/to/cjet-sources>/all.qbs release profile:gcc [unittest-runner.showCoverageData:true]...
```
You can specify as many additional parallel build by adding more
profiles. If `unittest-runner.showCoverageData:true` is given, the
coverage data is directly displayed in a web browser.

## Howto run
Just execute `cjet.bin` to run cjet in daemon mode. Run `cjet.bin -f` to
run cjet in foreground.

