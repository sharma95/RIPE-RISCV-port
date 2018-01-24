# Makefile for RIPE-RISCV-port
# @author John Wilander & Nick Nikiforakis
# ported by Aman Sharma & Nicholas Rifel

#Depending on how you test your system you may want to comment, or uncomment
#the following
CFLAGS=-fno-stack-protector -z execstack -std=gnu11 -static

# RISCV GCC compiler - TODO: auto-detect the right gcc or make it an input
NEWLIBERR=$(shell which riscv64-unknown-elf-gcc > /dev/null; echo $$?)
ifeq "$(NEWLIBERR)" "0"
	CC=riscv64-unknown-elf-gcc
else
	CC=riscv64-unknown-linux-gnu-gcc
endif

all: attack_generator

clean:
	rm ./build/*

# ATTACK GENERATOR COMPILE
attack_generator: ./source/attack_generator.c
	mkdir -p build
	${CC} ${CFLAGS} ./source/attack_generator.c -o ./build/attack_generator 
