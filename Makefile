all:
	gcc -std=gnu99 -lz githack.c -g -o fastGitHack
install:
	mv fastGitHack /bin/
clean:
	rm -rf /bin/fastGitHack
