# cjet - An ANSI C conformant JET implementation

## License
Copyright (c) 2014 Stephan Gatzka. See the [LICENSE](LICENSE) file for license rights and
limitations (MIT).

## Build Status
[![Travis CI](https://travis-ci.org/gatzka/cjet.svg?branch=master)](https://travis-ci.org/gatzka/cjet)

[![Coverity](https://scan.coverity.com/projects/3315/badge.svg)](https://scan.coverity.com/projects/3315)

[![Coverage Status](https://img.shields.io/coveralls/gatzka/cjet.svg)](https://coveralls.io/r/gatzka/cjet?branch=master)

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
if qou want to build with clang, gcc, arm-gcc, ppc-gcc (these are the names
of your qbs profiles), just run:
```
qbs -f <path/to/cjet-sources>/src/cjet.qbs release profile:gcc release profile:clang release profile:arm-gcc release profile:ppc-gcc debug profile:gcc debug profile:clang debug profile:arm-gcc debug profile:ppc-gcc
```

You can also configure cjet at compile time via qbs. You will find the
cjet spedific in
[generateCjetConfig.qbs](qbs/modules/generateCjetConfig/generateCjetConfig.qbs)
and the Linux specific configurations in
[generateOsConfig](qbs/modules/generateOsConfig/generateOsConfig.qbs).

You can override these defaults easily when calling qbs, for instance:
```
qbs -f <path/to/cjet-sources>/src/cjet.qbs profile:gcc generateCjetConfig.serverPort:4321 generateOsConfig.maxEpollEvents
```

## Howto run
Just execute `cjet.bin` to run cjet in daemon mode. Run `cjet.bin -f` to
run cjet in foreground.

