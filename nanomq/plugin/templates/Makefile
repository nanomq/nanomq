NAME ?= my_stream_plugin
OUT  ?= $(NAME).so

# 指向 NanoMQ 的 include 目录（含 nano_sdk.h）
NMQ_INCLUDE ?= ../../include
SKILL_INCLUDE ?= ../../skill/include
SKILL_SRC ?= ../../skill/src
NMQ_PLUGIN ?= ..

CFLAGS ?= -O2 -Wall -Wextra -fPIC
LDLIBS ?= -lpthread

all: $(OUT)

$(OUT): skeleton.c
	gcc $(CFLAGS) -shared \
	  -I"$(NMQ_INCLUDE)" -I"$(SKILL_INCLUDE)" \
	  $< \
	  "$(SKILL_SRC)/nano_skill_time.c" \
	  "$(SKILL_SRC)/nano_skill_window.c" \
	  "$(SKILL_SRC)/nano_skill_batch.c" \
	  "$(SKILL_SRC)/nano_skill_dbc_stub.c" \
	  $(LDLIBS) \
	  -o $@

can_pipeline_sample.so: $(NMQ_PLUGIN)/can_pipeline_sample.c
	gcc $(CFLAGS) -shared \
	  -I"$(NMQ_INCLUDE)" -I"$(SKILL_INCLUDE)" \
	  "$<" \
	  "$(SKILL_SRC)/nano_skill_time.c" \
	  "$(SKILL_SRC)/nano_skill_window.c" \
	  "$(SKILL_SRC)/nano_skill_batch.c" \
	  "$(SKILL_SRC)/nano_skill_dbc_stub.c" \
	  $(LDLIBS) \
	-o $@

clean:
	rm -f $(OUT) can_pipeline_sample.so

.PHONY: all clean

