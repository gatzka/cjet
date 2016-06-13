FROM nfnty/arch-mini:latest

MAINTAINER gatzka "https://github.com/gatzka"

#install everything to build cjet
USER root
RUN pacman -Syy
RUN pacman --noconfirm -Su
RUN pacman --noconfirm -S \
  boost \
  boost-libs \
  clang \
  clang-tools-extra \
  cmake \
  doxygen \
  gcc \
  git \
  qtcreator \
  valgrind

#install everything for AUR
RUN pacman --noconfirm -S --needed base-devel perl
RUN useradd --no-create-home --shell=/bin/false yaourt && usermod -L yaourt

RUN mkdir -p /tmp/lcov && chown yaourt /tmp/lcov
USER yaourt
RUN cd /tmp/lcov && curl -L -O https://aur.archlinux.org/cgit/aur.git/snapshot/lcov.tar.gz && tar -xf lcov.tar.gz && cd lcov && makepkg
USER root
RUN pacman --noconfirm -U /tmp/lcov/lcov/lcov*.xz

RUN qbs-setup-toolchains --detect

CMD git clone https://github.com/gatzka/cjet.git /root/cjet && mkdir -p /tmp/cjet/ && cd /tmp/cjet && qbs -f /root/cjet/all.qbs profile:gcc

