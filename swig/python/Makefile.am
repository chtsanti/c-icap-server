
AM_CPPFLAGS=-I$(top_srcdir)/ -I$(top_srcdir)/include/ -I$(top_builddir)/include/ $(AX_SWIG_PYTHON_CPPFLAGS)

MODS_LIB_ADD=$(top_builddir)/libicapapi.la

BUILT_SOURCES = c_icap_swigPy.h

pkgpython_PYTHON = c_icap.py
pkgpyexec_LTLIBRARIES = _c_icap.la

_c_icap_la_LIBADD = $(MODS_LIB_ADD)
_c_icap_la_CFLAGS = @MODULES_CFLAGS@
_c_icap_la_LDFLAGS = -module -avoid-version
_c_icap_la_SOURCES = c_icap_wrap.c


c_icap_wrap.c: ../c_icap.i  ../headers.i
	$(SWIG) -outcurrentdir  -python  $(AM_CPPFLAGS) ../c_icap.i

c_icap_swigPy.h:
	$(SWIG) -python -external-runtime $@

.PHONY: local_python_module

local_python_module: c_icap.py c_icap_wrap.c
	test -e $(abs_builddir)/.libs/_c_icap.so && ln -sf $(abs_builddir)/.libs/_c_icap.so _c_icap.so
	$(PYTHON) c_icap.py build_ext --inplace


EXTRA_DIST = c_icap_wrap.c c_icap_swigPy.h c_icap.py

swig_clean:
	rm c_icap_wrap.c c_icap_swigPy.h c_icap.py
