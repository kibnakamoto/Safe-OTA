BUILD ?= ./build
CC ?= gcc
CFLAGS = -std=c11 -O2 -Wall -Wextra -Werror -Isrc
SRC = src/sha256.c src/flash.c src/ota.c tests/test_ota.c

test: $(BUILD)/test_ota
	$(BUILD)/test_ota

$(BUILD)/test_ota: $(SRC) | $(BUILD)
	$(CC) $(CFLAGS) $(SRC) -o $@

asan: | $(BUILD)
	$(CC) $(CFLAGS) -g -fsanitize=address,undefined $(SRC) -o $(BUILD)/test_asan
	$(BUILD)/test_asan

# Mutation testing: each mutant removes one safety property; the tests must catch it.
mutants: | $(BUILD)
	@for m in A C D; do \
	  $(CC) $(CFLAGS) -DMUT_$$m $(SRC) -o $(BUILD)/mut_$$m || exit 1; \
	  if $(BUILD)/mut_$$m >/dev/null 2>&1; then echo "mutant $$m SURVIVED: tests too weak"; exit 1; \
	  else echo "mutant $$m killed"; fi; \
	done

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD)
.PHONY: test asan mutants clean
