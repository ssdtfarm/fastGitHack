all:
	gcc -std=gnu99 -lz githack.c -g -o main
clean:
	rm -rf main
