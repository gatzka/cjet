# cjet - An ANSI C conformant JET implementation

## License
Copyright (c) 2014 Stephan Gatzka. See the [LICENSE](LICENSE) file for license rights and
limitations (MIT).

## Build Status

[![Travis CI](https://travis-ci.org/gatzka/cjet.svg?branch=master)](https://travis-ci.org/gatzka/cjet)

[![Coverity](https://scan.coverity.com/projects/3315/badge.svg)](https://scan.coverity.com/projects/3315)

[![Coverage Status](https://img.shields.io/coveralls/gatzka/cjet.svg)](https://coveralls.io/r/gatzka/cjet?branch=master)

## Howto Build
Create a build directory somewhere on you build machine and execute:

- `cmake <path/to/cjet-sources>`
- `make`
- Optionally run `make test` to execute the unit tests.

## Howto run

Just execute `cjet.bin` to run cjet in daemon mode. Run `cjet.bin -f` to
run cjet in foreground.
