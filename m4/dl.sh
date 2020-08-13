#!/bin/sh -e

m4_files="ax_prepend_flag.m4 ax_append_flag.m4 ax_cflags_warn_all.m4
 ax_require_defined.m4 ax_compiler_vendor.m4"

for ax in $m4_files; do
  rm -f "$ax"
  wget -O "$ax" "http://git.savannah.gnu.org/gitweb/?p=autoconf-archive.git;a=blob_plain;f=m4/$ax"
done
