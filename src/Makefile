# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
include Makefile.include

ifeq ($(srctree),)
srctree := $(patsubst %/,%,$(dir $(CURDIR)))
endif

BPF_DIR = $(srctree)/libbpf/src

ifneq ($(OUTPUT),)
  _OUTPUT := $(OUTPUT)
else
  _OUTPUT := $(CURDIR)/
endif
BOOTSTRAP_OUTPUT := $(_OUTPUT)bootstrap/

LIBBPF_OUTPUT := $(_OUTPUT)libbpf/
LIBBPF_DESTDIR := $(LIBBPF_OUTPUT)
LIBBPF_INCLUDE := $(LIBBPF_DESTDIR)include
LIBBPF_HDRS_DIR := $(LIBBPF_INCLUDE)/bpf
LIBBPF := $(LIBBPF_OUTPUT)libbpf.a

LIBBPF_BOOTSTRAP_OUTPUT := $(BOOTSTRAP_OUTPUT)libbpf/
LIBBPF_BOOTSTRAP_DESTDIR := $(LIBBPF_BOOTSTRAP_OUTPUT)
LIBBPF_BOOTSTRAP_INCLUDE := $(LIBBPF_BOOTSTRAP_DESTDIR)include
LIBBPF_BOOTSTRAP_HDRS_DIR := $(LIBBPF_BOOTSTRAP_INCLUDE)/bpf
LIBBPF_BOOTSTRAP := $(LIBBPF_BOOTSTRAP_OUTPUT)libbpf.a

# We need to copy hashmap.h, nlattr.h, relo_core.h and libbpf_internal.h
# which are not otherwise exported by libbpf, but still required by bpftool.
LIBBPF_INTERNAL_HDRS := $(addprefix $(LIBBPF_HDRS_DIR)/,hashmap.h nlattr.h relo_core.h libbpf_internal.h)
LIBBPF_BOOTSTRAP_INTERNAL_HDRS := $(addprefix $(LIBBPF_BOOTSTRAP_HDRS_DIR)/,hashmap.h relo_core.h libbpf_internal.h)

$(LIBBPF_OUTPUT) $(BOOTSTRAP_OUTPUT) $(LIBBPF_BOOTSTRAP_OUTPUT) $(LIBBPF_HDRS_DIR) $(LIBBPF_BOOTSTRAP_HDRS_DIR):
	$(QUIET_MKDIR)mkdir -p $@

$(LIBBPF): $(wildcard $(BPF_DIR)/*.[ch] $(BPF_DIR)/Makefile) | $(LIBBPF_OUTPUT)
	$(Q)$(MAKE) -C $(BPF_DIR) OBJDIR=$(patsubst %/,%,$(LIBBPF_OUTPUT)) \
		DESTDIR="" PREFIX=$(LIBBPF_DESTDIR:/=) $(LIBBPF) install_headers

$(LIBBPF_INTERNAL_HDRS): $(LIBBPF_HDRS_DIR)/%.h: $(BPF_DIR)/%.h | $(LIBBPF_HDRS_DIR)
	$(call QUIET_INSTALL, $@)
	$(Q)install -m 644 -t $(LIBBPF_HDRS_DIR) $<

$(LIBBPF_BOOTSTRAP): $(wildcard $(BPF_DIR)/*.[ch] $(BPF_DIR)/Makefile) | $(LIBBPF_BOOTSTRAP_OUTPUT)
	$(Q)$(MAKE) -C $(BPF_DIR) OBJDIR=$(patsubst %/,%,$(LIBBPF_BOOTSTRAP_OUTPUT)) \
		DESTDIR="" PREFIX=$(LIBBPF_BOOTSTRAP_DESTDIR:/=) \
		ARCH= CROSS_COMPILE= CC="$(HOSTCC)" LD="$(HOSTLD)" AR="$(HOSTAR)" $@ install_headers

$(LIBBPF_BOOTSTRAP_INTERNAL_HDRS): $(LIBBPF_BOOTSTRAP_HDRS_DIR)/%.h: $(BPF_DIR)/%.h | $(LIBBPF_BOOTSTRAP_HDRS_DIR)
	$(call QUIET_INSTALL, $@)
	$(Q)install -m 644 -t $(LIBBPF_BOOTSTRAP_HDRS_DIR) $<

$(LIBBPF)-clean: FORCE | $(LIBBPF_OUTPUT)
	$(call QUIET_CLEAN, libbpf)
	$(Q)$(MAKE) -C $(BPF_DIR) OUTPUT=$(LIBBPF_OUTPUT) clean >/dev/null

$(LIBBPF_BOOTSTRAP)-clean: FORCE | $(LIBBPF_BOOTSTRAP_OUTPUT)
	$(call QUIET_CLEAN, libbpf-bootstrap)
	$(Q)$(MAKE) -C $(BPF_DIR) OUTPUT=$(LIBBPF_BOOTSTRAP_OUTPUT) clean >/dev/null

prefix ?= /usr/local
libdir ?= $(prefix)/lib
bash_compdir ?= /usr/share/bash-completion/completions

CFLAGS += -O2
CFLAGS += -W
CFLAGS += -Wall
CFLAGS += -Wextra
CFLAGS += -Wformat-signedness
CFLAGS += -Wno-unused-parameter
CFLAGS += -Wno-missing-field-initializers
CFLAGS += $(filter-out -Wswitch-enum -Wnested-externs,$(EXTRA_WARNINGS))
CFLAGS += -DPACKAGE='"bpftool"' -D__EXPORTED_HEADERS__ \
	-I$(or $(OUTPUT),.) \
	-I$(LIBBPF_INCLUDE) \
	-I$(srctree)/src/kernel/bpf/ \
	-I$(srctree)/include \
	-I$(srctree)/include/uapi
ifneq ($(BPFTOOL_VERSION),)
CFLAGS += -DBPFTOOL_VERSION='"$(BPFTOOL_VERSION)"'
endif
ifneq ($(EXTRA_CFLAGS),)
CFLAGS += $(EXTRA_CFLAGS)
endif
ifneq ($(EXTRA_LDFLAGS),)
LDFLAGS += $(EXTRA_LDFLAGS)
endif

HOST_CFLAGS := $(subst -I$(LIBBPF_INCLUDE),-I$(LIBBPF_BOOTSTRAP_INCLUDE),\
		$(subst $(CLANG_CROSS_FLAGS),,$(CFLAGS)))
HOST_LDFLAGS := $(LDFLAGS)

INSTALL ?= install
RM ?= rm -f

FEATURE_USER = .bpftool

# Skip optional dependencies: LLVM (JIT disasm), libbfd (fallback
# disasm), libcrypto (program signing).
SKIP_LLVM ?=
SKIP_LIBBFD ?=
SKIP_CRYPTO ?=
ifneq ($(SKIP_CRYPTO),1)
  CRYPTO_LIBS := -lcrypto
endif

FEATURE_TESTS := clang-bpf-co-re
FEATURE_TESTS += llvm
FEATURE_TESTS += libcap
FEATURE_TESTS += libbfd
FEATURE_TESTS += libbfd-liberty
FEATURE_TESTS += libbfd-liberty-z
FEATURE_TESTS += disassembler-four-args
FEATURE_TESTS += disassembler-init-styled
FEATURE_TESTS += libelf-zstd

FEATURE_DISPLAY := clang-bpf-co-re
FEATURE_DISPLAY += llvm
FEATURE_DISPLAY += libcap
FEATURE_DISPLAY += libbfd
FEATURE_DISPLAY += libbfd-liberty
FEATURE_DISPLAY += libbfd-liberty-z

check_feat := 1
NON_CHECK_FEAT_TARGETS := clean uninstall doc doc-clean doc-install doc-uninstall
ifdef MAKECMDGOALS
ifeq ($(filter-out $(NON_CHECK_FEAT_TARGETS),$(MAKECMDGOALS)),)
  check_feat := 0
endif
endif

ifeq ($(check_feat),1)
include Makefile.feature
endif

LIBS = $(LIBBPF) -lelf $(CRYPTO_LIBS) -lz
LIBS_BOOTSTRAP = $(LIBBPF_BOOTSTRAP) -lelf $(CRYPTO_LIBS) -lz

ifeq ($(feature-libelf-zstd),1)
LIBS += -lzstd
LIBS_BOOTSTRAP += -lzstd
endif

ifeq ($(feature-libcap), 1)
CFLAGS += -DUSE_LIBCAP
LIBS += -lcap
endif

include $(wildcard $(OUTPUT)*.d)

all: $(OUTPUT)bpftool

SRCS := $(wildcard *.c)
# llvm_disasm.c is compiled separately into the bpftool-llvm.so plugin.
SRCS := $(filter-out llvm_disasm.c,$(SRCS))

ifeq ($(feature-llvm),1)
ifneq ($(SKIP_LLVM),1)
HAS_LLVM := 1
endif
endif

ifeq ($(HAS_LLVM),1)
  # The libLLVM-based JIT disassembler is built as a separate plugin,
  # bpftool-llvm.so, which is the only object that links against libLLVM.
  # bpftool loads it lazily with dlopen() (see jit_disasm.c), so the bpftool
  # binary itself keeps no dependency on the large libLLVM shared object.
  CFLAGS  += -DHAVE_LLVM_SUPPORT
  CFLAGS  += -DLLVM_PLUGIN_DIR='"$(libdir)/bpftool"'
  # dlopen() lives in libc on modern glibc, but keep -ldl for portability.
  LIBS    += -ldl

  # Flags used to build the plugin itself (the only part that needs libLLVM).
  LLVM_CONFIG_LIB_COMPONENTS := mcdisassembler all-targets
  # llvm-config always adds -D_GNU_SOURCE, which llvm_disasm.c already defines;
  # filter it out to avoid a redefinition warning.
  LLVM_PLUGIN_CFLAGS := $(filter-out -D_GNU_SOURCE,$(shell $(LLVM_CONFIG) --cflags))

  # Embed libLLVM into the plugin statically when requested with
  # LLVM_LINK_STATIC=1, or when this LLVM install only ships static libraries
  # ("llvm-config --shared-mode" reports "static"). Otherwise link the shared
  # libLLVM, which is the only runtime dependency of the plugin.
  ifeq ($(shell $(LLVM_CONFIG) --shared-mode),static)
    LLVM_LINK_STATIC := 1
  endif
  ifeq ($(LLVM_LINK_STATIC),1)
    LLVM_PLUGIN_LIBS := $(shell $(LLVM_CONFIG) --link-static --libs $(LLVM_CONFIG_LIB_COMPONENTS))
    LLVM_PLUGIN_LIBS += $(shell $(LLVM_CONFIG) --link-static --system-libs $(LLVM_CONFIG_LIB_COMPONENTS))
    LLVM_PLUGIN_LIBS += -lstdc++
  else
    LLVM_PLUGIN_LIBS := $(shell $(LLVM_CONFIG) --libs $(LLVM_CONFIG_LIB_COMPONENTS))
  endif
  LLVM_PLUGIN_LDFLAGS := $(shell $(LLVM_CONFIG) --ldflags)
else
  ifneq ($(SKIP_LIBBFD),1)
  # Fall back on libbfd
  ifeq ($(feature-libbfd),1)
    LIBS += -lbfd -ldl -lopcodes
  else ifeq ($(feature-libbfd-liberty),1)
    LIBS += -lbfd -ldl -lopcodes -liberty
  else ifeq ($(feature-libbfd-liberty-z),1)
    LIBS += -lbfd -ldl -lopcodes -liberty -lz
  endif

  # If one of the above feature combinations is set, we support libbfd
  ifneq ($(filter -lbfd,$(LIBS)),)
    CFLAGS += -DHAVE_LIBBFD_SUPPORT

    # Libbfd interface changed over time, figure out what we need
    ifeq ($(feature-disassembler-four-args), 1)
      CFLAGS += -DDISASM_FOUR_ARGS_SIGNATURE
    endif
    ifeq ($(feature-disassembler-init-styled), 1)
      CFLAGS += -DDISASM_INIT_STYLED
    endif
  endif
  endif # SKIP_LIBBFD
endif
ifeq ($(filter -DHAVE_LLVM_SUPPORT -DHAVE_LIBBFD_SUPPORT,$(CFLAGS)),)
  # No support for JIT disassembly
  SRCS := $(filter-out jit_disasm.c,$(SRCS))
endif

ifeq ($(SKIP_CRYPTO),1)
  CFLAGS += -DBPFTOOL_WITHOUT_CRYPTO
  HOST_CFLAGS += -DBPFTOOL_WITHOUT_CRYPTO
  SRCS := $(filter-out sign.c,$(SRCS))
endif

BPFTOOL_BOOTSTRAP := $(BOOTSTRAP_OUTPUT)bpftool

BOOTSTRAP_OBJS = $(addprefix $(BOOTSTRAP_OUTPUT),main.o common.o json_writer.o gen.o btf.o $(if $(CRYPTO_LIBS),sign.o))
$(BOOTSTRAP_OBJS): $(LIBBPF_BOOTSTRAP)

OBJS = $(patsubst %.c,$(OUTPUT)%.o,$(SRCS)) $(OUTPUT)disasm.o
$(OBJS): $(LIBBPF) $(LIBBPF_INTERNAL_HDRS)

VMLINUX_BTF_PATHS ?= $(if $(O),$(O)/vmlinux)				\
		     $(if $(KBUILD_OUTPUT),$(KBUILD_OUTPUT)/vmlinux)	\
		     ../../../vmlinux					\
		     /sys/kernel/btf/vmlinux				\
		     /boot/vmlinux-$(shell uname -r)
VMLINUX_BTF ?= $(abspath $(firstword $(wildcard $(VMLINUX_BTF_PATHS))))

bootstrap: $(BPFTOOL_BOOTSTRAP)

ifneq ($(VMLINUX_BTF)$(VMLINUX_H),)
ifeq ($(feature-clang-bpf-co-re),1)

BUILD_BPF_SKELS := 1

ifeq ($(VMLINUX_H),)
$(OUTPUT)vmlinux.h: $(VMLINUX_BTF) $(BPFTOOL_BOOTSTRAP)
	$(QUIET_GEN)$(BPFTOOL_BOOTSTRAP) btf dump file $< format c > $@
else
$(OUTPUT)vmlinux.h: $(VMLINUX_H)
	$(Q)cp "$(VMLINUX_H)" $@
endif

$(OUTPUT)%.bpf.o: skeleton/%.bpf.c $(OUTPUT)vmlinux.h $(LIBBPF_BOOTSTRAP)
	$(QUIET_CLANG)$(CLANG) \
		-Wno-microsoft-anon-tag \
		-fms-extensions \
		-I$(or $(OUTPUT),.) \
		-I$(srctree)/include/uapi/ \
		-I$(LIBBPF_BOOTSTRAP_INCLUDE) \
		-g -O2 -Wall -fno-stack-protector \
		--target=bpf -c $< -o $@
	$(Q)$(LLVM_STRIP) -g $@

$(OUTPUT)%.skel.h: $(OUTPUT)%.bpf.o $(BPFTOOL_BOOTSTRAP)
	$(QUIET_GEN)$(BPFTOOL_BOOTSTRAP) gen skeleton $< > $@

$(OUTPUT)prog.o: $(OUTPUT)profiler.skel.h

$(OUTPUT)pids.o: $(OUTPUT)pid_iter.skel.h

endif
endif

CFLAGS += $(if $(BUILD_BPF_SKELS),,-DBPFTOOL_WITHOUT_SKELETONS)

$(OUTPUT)disasm.o: $(srctree)/src/kernel/bpf/disasm.c
	$(QUIET_CC)$(CC) $(CFLAGS) -c -MMD $< -o $@

$(BPFTOOL_BOOTSTRAP): $(BOOTSTRAP_OBJS) $(LIBBPF_BOOTSTRAP)
	$(QUIET_LINK)$(HOSTCC) $(HOST_CFLAGS) $(HOST_LDFLAGS) $(BOOTSTRAP_OBJS) $(LIBS_BOOTSTRAP) -o $@

$(OUTPUT)bpftool: $(OBJS) $(LIBBPF)
	$(QUIET_LINK)$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) $(LIBS) -o $@

ifeq ($(HAS_LLVM),1)
all: $(OUTPUT)bpftool-llvm.so

$(OUTPUT)llvm_disasm.o: llvm_disasm.c
	$(QUIET_CC)$(CC) $(CFLAGS) $(LLVM_PLUGIN_CFLAGS) -fPIC -c -MMD $< -o $@

# The plugin is a shared object by definition, so drop a global -static (e.g.
# from EXTRA_LDFLAGS for a static bpftool) which would conflict with -shared.
# Embedding libLLVM statically is controlled separately (see LLVM_LINK_STATIC).
$(OUTPUT)bpftool-llvm.so: $(OUTPUT)llvm_disasm.o
	$(QUIET_LINK)$(CC) $(CFLAGS) $(filter-out -static,$(LDFLAGS)) \
		$(LLVM_PLUGIN_LDFLAGS) -shared -o $@ $< $(LLVM_PLUGIN_LIBS)
endif

$(BOOTSTRAP_OUTPUT)%.o: %.c $(LIBBPF_BOOTSTRAP_INTERNAL_HDRS) | $(BOOTSTRAP_OUTPUT)
	$(QUIET_CC)$(HOSTCC) $(HOST_CFLAGS) -c -MMD $< -o $@

$(OUTPUT)%.o: %.c
	$(QUIET_CC)$(CC) $(CFLAGS) -c -MMD $< -o $@

feature-detect-clean:
	$(call QUIET_CLEAN, feature-detect)
	$(Q)$(MAKE) -C $(srctree)/tools/build/feature/ clean >/dev/null

clean: $(LIBBPF)-clean $(LIBBPF_BOOTSTRAP)-clean
	$(call QUIET_CLEAN, bpftool)
	$(Q)$(RM) -- $(OUTPUT)bpftool $(OUTPUT)bpftool-llvm.so $(OUTPUT)*.o $(OUTPUT)*.d
	$(Q)$(RM) -- $(OUTPUT)*.skel.h $(OUTPUT)vmlinux.h
	$(Q)$(RM) -r -- $(LIBBPF_OUTPUT) $(BOOTSTRAP_OUTPUT)
	$(call QUIET_CLEAN, core-gen)
	$(Q)$(RM) -- $(OUTPUT)FEATURE-DUMP.bpftool
	$(Q)$(RM) -r -- $(OUTPUT)feature/

ifeq ($(HAS_LLVM),1)
install-bin: $(OUTPUT)bpftool-llvm.so
endif
install-bin: $(OUTPUT)bpftool
	$(call QUIET_INSTALL, bpftool)
	$(Q)$(INSTALL) -m 0755 -d $(DESTDIR)$(prefix)/sbin
	$(Q)$(INSTALL) $(OUTPUT)bpftool $(DESTDIR)$(prefix)/sbin/bpftool
ifeq ($(HAS_LLVM),1)
	$(call QUIET_INSTALL, bpftool-llvm.so)
	$(Q)$(INSTALL) -m 0755 -d $(DESTDIR)$(libdir)/bpftool
	$(Q)$(INSTALL) -m 0755 $(OUTPUT)bpftool-llvm.so $(DESTDIR)$(libdir)/bpftool/bpftool-llvm.so
endif

install: install-bin
	$(Q)$(INSTALL) -m 0755 -d $(DESTDIR)$(bash_compdir)
	$(Q)$(INSTALL) -m 0644 $(srctree)/bash-completion/bpftool $(DESTDIR)$(bash_compdir)

uninstall:
	$(call QUIET_UNINST, bpftool)
	$(Q)$(RM) -- $(DESTDIR)$(prefix)/sbin/bpftool
	$(Q)$(RM) -- $(DESTDIR)$(libdir)/bpftool/bpftool-llvm.so
	$(Q)$(RM) -- $(DESTDIR)$(bash_compdir)/bpftool

doc:
	$(call descend,$(srctree)/docs)

doc-clean:
	$(call descend,$(srctree)/docs,clean)

doc-install:
	$(call descend,$(srctree)/docs,install)

doc-uninstall:
	$(call descend,$(srctree)/docs,uninstall)

FORCE:

.SECONDARY:
.PHONY: all FORCE bootstrap clean install-bin install uninstall
.PHONY: doc doc-clean doc-install doc-uninstall
.DEFAULT_GOAL := all

# Delete partially updated (corrupted) files on error
.DELETE_ON_ERROR:
