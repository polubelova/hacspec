#!/usr/bin/env bash

set -v -e -x

# Update packages.
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update
apt-get install --yes libssl-dev libsqlite3-dev g++ gcc m4 make opam pkg-config python libgmp3-dev cmake curl libtool-bin autoconf wget locales

locale-gen en_US.UTF-8
dpkg-reconfigure locales

su worker

# Prepare build (OCaml packages)
opam init
echo ". /home/worker/.opam/opam-init/init.sh > /dev/null 2> /dev/null || true" >> .bashrc
opam switch -v ${opamv}
opam install ocamlfind batteries sqlite3 fileutils yojson ppx_deriving_yojson zarith pprint menhir ulex process fix wasm stdint

# Get the HACL* code
git clone ${haclrepo} hacl-star
git -C hacl-star checkout ${haclversion}

# Prepare submodules
opam config exec -- make -C hacl-star prepare -j10

# Cleanup.
rm -rf ~/.ccache ~/.cache
apt-get autoremove -y
apt-get clean
apt-get autoclean
