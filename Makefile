# Makefile for RIPE-RISCV-port
# @author John Wilander & Nick Nikiforakis
# ported by Aman Sharma & Nicholas Rifel

#Depending on how you test your system you may want to comment, or uncomment
#the following
CFLAGS=-fno-stack-protector

# RISCV GCC compiler - TODO: auto-detect the right gcc or make it an input
CC=riscv64-unknown-elf-gcc

all: attack_generator

clean:
	rm ./build/*

# ATTACK GENERATOR COMPILE
attack_generator: ./source/attack_generator.c
	${CC} ${CFLAGS} ./source/attack_generator.c -z execstack -static -fno-stack-protector -g -O0 -o ./build/attack_generator 
