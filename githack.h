#ifndef GITHACK_H
#define GITHACK_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <zlib.h>
#include <sys/mman.h>
#include <sys/wait.h>

#define FALSE 0
#define TRUE 1
#define BUFFER_SIZE 1024
#define ENTRY_SIZE 62

typedef struct _magic_head
{
    unsigned char signature[4];
    unsigned char version[4];
    unsigned char file_num[4];
} Magic_head;

struct cache_time
{
    unsigned char sec[4];
    unsigned char nsec[4];
};

struct _stage
{
    int stage_one;
    int stage_two;
};

struct _flags
{
    int assume_valid;
    int extended;
    struct _stage stage;
};

struct _extra_flags
{
    int reserved;
    int skip_worktree;
    int intent_to_add;
    int unused;
};

struct url_combo
{
    char protocol[10];
    char host[BUFFER_SIZE];
    char *uri;
};

typedef struct _entry_body {
    struct cache_time sd_ctime;
    struct cache_time sd_mtime;
    unsigned char dev[4];
    unsigned char ino[4];
    unsigned char file_mode[4];
    unsigned char uid[4];
    unsigned char gid[4];
    unsigned char size[4];
    unsigned char sha1[20];
    unsigned char ce_flags[2];
} __attribute__ ((packed)) Entry_body;

struct ce_body
{
    Entry_body *entry_body;
    int entry_len;
    char *name;
};

int hex2dec (unsigned char *hex, int len);

char* sha12hex (unsigned char *sha1);

int signature_check (Magic_head * magic_head);

int version_check (Magic_head * magic_head);

void init_check (FILE * file, Magic_head * magic_head);

int sed2bed (int value);

void pad_entry (FILE * file, int entry_len);

char* get_name (FILE * file, int namelen, int *entry_len);

void handle_version3orlater (FILE * file, int *entry_len);

int get_ip_from_host (char *ipbuf, const char *host, int maxlen);

void parse_http_url (char *http_url, struct url_combo *url_combo);

int* http_get (char *http_url);

void touch_file_et(int *sockfd, const char *filename, int filesize);

int create_dir (const char *sPathName);

void split_pathname (int *sockfd,struct ce_body* ce_body);

void touch_index_file (int *sockfd);

void mk_dir (char *path);

void concat_object_url(Entry_body *entry_body, char *object_url, char *url);

#endif /* GITHACK_H */
