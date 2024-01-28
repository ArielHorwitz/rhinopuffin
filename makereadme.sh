#! /bin/bash

cargo build --release
cd target/release

exec &> README.md
echo '```'
./rhinopuffin --help
echo '```'
exec &> /dev/tty

mv README.md ../..
cat ../../README.md

