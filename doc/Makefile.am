AUTOMAKE_OPTIONS=foreign
DISTCLEANFILES=*~
man_MANS=stpm-keygen.1 stpm-sign.1 simple-tpm-pk11.7

# Generated manpage files are checked in, and are normally not built.
# That's why there's nothing on the right hand side of this rule.
# To re-generate, delete the target files and run 'make'.
%.1 %.7:
	yodl2man -o $@.tmp $@.yodl
	perl -ne 's/(^|(?<=[^\\\w]))-/\\-/g;print' < $@.tmp > $@
	rm -f $@.tmp
