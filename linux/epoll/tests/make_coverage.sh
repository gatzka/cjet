#!/bin/bash
lcov --base-directory . --directory . --zerocounters -q
ctest
lcov --quiet --directory . --capture --output-file app.info
lcov --quiet --remove app.info "/usr*" "/opt/boost/*" "*/cjet/json/*" -o app.info.filter
genhtml --quiet app.info.filter -o report  >/dev/null 2>&1
xdg-open report/index.html
