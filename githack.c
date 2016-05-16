#include "githack.h"

int
hex2dec (unsigned char *hex, int len)
{
    char    result[BUFFER_SIZE];
    char    *format = (char *) calloc (sizeof (char), BUFFER_SIZE);
    memset (format, '\0', BUFFER_SIZE);
    char *format_prefix = "0x";
    strcat (format, format_prefix);
    for (int i = 0; i < len; i++) {
        strcat (format, "%02x");
    }
    snprintf (result, BUFFER_SIZE, format, hex[0], hex[1], hex[2], hex[3]);
    free (format);
    return (int) strtol (result, NULL, 16);
}

char *
sha12hex (unsigned char *sha1)
{
    char *result = (char *) calloc (sizeof (char), 41);
    snprintf (result, 41, "%02x%02x%02x%02x%02x%02x%02x%02x"
            "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            sha1[0], sha1[1], sha1[2], sha1[3], sha1[4],
            sha1[5], sha1[6], sha1[7], sha1[8], sha1[9],
            sha1[10], sha1[11], sha1[12], sha1[13], sha1[14],
            sha1[15], sha1[16], sha1[17], sha1[18], sha1[19]);
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
        *entry_len += namelen; }
    return name;
}

void
handle_version3orlater (FILE * file, int *entry_len)
{
    struct _extra_flags extra_flag;
    unsigned char extra_flag_buf[2];
    fread (extra_flag_buf, 1, 2, file);
    //1-bit reserved for future
    extra_flag.reserved = hex2dec (extra_flag_buf, 2) & (0x0001 << 15);
    //1-bit skip-worktree flag (used by sparse checkout)
    extra_flag.skip_worktree = hex2dec (extra_flag_buf, 2) & (0x0001 << 14);
    //1-bit intent-to-add flag (used by "git add -N")
    extra_flag.intent_to_add = hex2dec (extra_flag_buf, 2) & (0x0001 << 13);
    //13-bit unused, must be zero
    extra_flag.unused = hex2dec(extra_flag_buf, 2) & (0xFFFF >> 3);
    assert(extra_flag.unused == 0);
    entry_len += 2;
}

int
get_ip_from_host (char *ipbuf, const char *host, int maxlen)
{
    struct sockaddr_in sa;
    bzero(&sa, sizeof(sa));
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

void 
setnonblocking(int sockfd)  
{  
    int     opts;  
    opts = fcntl (sockfd, F_GETFL);  
    if (opts < 0)  
    {  
        perror("fcntl(sock,GETFL)");  
        exit(-1);  
    }  
    opts |= O_NONBLOCK;  
    if (fcntl (sockfd, F_SETFL, opts) <0)  
    {  
        perror("fcntl(sock,SETFL,opts)");  
        exit(-1);  
    }     
}

void 
setblocking(int sockfd)  
{  
    int     opts;  
    opts = fcntl(sockfd, F_GETFL);  
    if (opts<0)  
    {  
        perror("fcntl(sock,GETFL)");  
        exit(-1);  
    }  
    opts &=  ~O_NONBLOCK;  
    if (fcntl (sockfd, F_SETFL, opts) < 0)  
    {  
        perror("fcntl(sock,SETFL,opts)");  
        exit(-1);  
    }     
}


int
http_get (char *http_url)
{
    struct url_combo url_combo;
    int sockfd;
    struct sockaddr_in address;
    char ip[128];
    char http_header_raw[BUFFER_SIZE];
    parse_http_url (http_url, &url_combo);
    //char *filename = strrchr(url_combo.uri, '/') + 1;
    memset (http_header_raw, '\0', BUFFER_SIZE);
    strcat (http_header_raw, "GET ");
    strncat (http_header_raw, url_combo.uri, 100);
    strcat (http_header_raw, " HTTP/1.1");
    strcat (http_header_raw, "\r\nHost: ");
    strncat (http_header_raw, url_combo.host, 100);
    strcat (http_header_raw, "\r\nReferer: ");
    strncat (http_header_raw, url_combo.protocol, 10);
    strncat (http_header_raw, url_combo.host, 100);
    strcat (http_header_raw, "\r\nUser-Agent:Mozilla/5.0 (X11; Linux x86_64) \
            AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.80 Safari/537.36");
    strcat (http_header_raw, "\r\nConnection: Close\r\n\r\n");
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) {
        perror("create socket");
        exit(-1);
    }
    bzero(&address, sizeof(address));
    address.sin_family = AF_INET;
    memset(ip, '\0', 128);
    get_ip_from_host(ip, url_combo.host, 128);
    if (inet_pton (AF_INET, ip, &address.sin_addr) <= 0)
    {
        perror("inet_pton");
        exit(-1);
    }
    address.sin_port = htons(80);
    setnonblocking(sockfd);
    int ret = connect(sockfd,  (struct sockaddr *)&address, sizeof(address));
    if (ret < 0) {
        if(errno == EINPROGRESS) {
            /*skip*/
        }else {
            perror("connect fail'\n");
            exit(0);
        }
    }
    fd_set wset;
    struct timeval tval;
    FD_ZERO(&wset);
    FD_SET(sockfd, &wset);
    tval.tv_sec = 0;
    tval.tv_usec = 2000 * 1000; //300毫秒
    int ready_n;
    if ((ready_n = select(sockfd + 1, NULL, &wset, NULL, &tval)) == 0) {
        close(sockfd); /* timeout */
        errno = ETIMEDOUT;
        perror("select timeout");
        exit(-1);
    }
    if (FD_ISSET(sockfd, &wset)) {
        int error;
        socklen_t len = sizeof (error);
        if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
            perror("getsockopt error.");
        }else{
            int ret;
            ret = write (sockfd, http_header_raw, strlen (http_header_raw));
            if(ret < 0){
                if(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN){
                    return sockfd;
                }
            }
            if(ret > 0) {
                return sockfd;
            }
        }
    }
    return -1;
}


void 
touch_file_et(int sockfd, const char *filename, int filesize){
    if(!filesize) {
        return;
    }
    char filepath[BUFFER_SIZE * 10] = { '\0' };
    strncat (filepath, filename, BUFFER_SIZE * 10 - 1);
    int i = 0;
    char ch;
    unsigned char buf[filesize * 100];
    unsigned long j = 0l;
    int ret;
    //setnonblocking(sockfd);
    while ((ret = read (sockfd, &ch, 1)) != 0)
    {
        if(ret < 0) {
            if(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN){
                continue;
            }else{
                perror("read");
                exit(-1);
            }
        }
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
            //write (fd, &ch, 1);
            buf[j++] = ch;
        }
    }
    char blob_header_tmp[100];
    snprintf(blob_header_tmp, 100, "blob %d", filesize);
    char *blob_header = blob_header_tmp;
    char* text = (char *) malloc(filesize + strlen(blob_header) + 1);
    unsigned long tlen = filesize + strlen(blob_header) + 1;
    if(uncompress(text, &tlen, buf, j+1) != Z_OK){
        //printf("uncompress failed!\n");
        printf("%s \033[31m[failed]\033[0m\n", filename);
        free(text);
        return;
    }
    printf("%s \033[35m[ok]\033[0m\n", filename);
    FILE *file = fopen(filename, "wb+");
    //char* blob = strchr(text, '\0') + 1;
    //for(unsigned long i = 0l;i < strlen(blob); i++) {
    //        write(fd, &blob[i], 1);
    //}
    fwrite(text + strlen(blob_header) + 1, 1, filesize, file);
    fclose(file);
    free(text);
    //free(buf);
    //close (fd);
}

int
create_dir (const char *sPathName)
{
    char DirName[256] = {'\0'};
    strncpy (DirName, sPathName, 254);
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
create_all_path_dir(struct ce_body *ce_body){
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
            perror ("mkdir error ");
            exit(-1);
        }
    }
}

void
touch_index_file (int sockfd)
{
    int fd = open ("index", O_RDWR | O_CREAT,
            S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    int i = 0;
    char ch;
    int ret;
    while ((ret = read (sockfd, &ch, 1)) != 0)
    {
        if(ret < 0) {
            if(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN){
                continue;
            }else{
                perror("read");
                exit(-1);
            }
        }
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
    close(fd);
}

int
force_rm_dir(const char *path)
{
    DIR *d = opendir(path);
    size_t path_len = strlen(path);
    int r = -1;
    if (d)
    {
        struct dirent *p;
        r = 0;
        while (!r && (p=readdir(d)))
        {
            int r2 = -1;
            char *buf;
            size_t len;
            /* Skip the names "." and ".." as we don't want to recurse on them. */
            if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, ".."))
            {
                continue;
            }
            len = path_len + strlen(p->d_name) + 2;
            buf = malloc(len);
            if (buf)
            {
                struct stat statbuf;
                snprintf(buf, len, "%s/%s", path, p->d_name);
                if (!stat(buf, &statbuf))
                {
                    if (S_ISDIR(statbuf.st_mode))
                    {
                        r2 = force_rm_dir(buf);
                    }
                    else
                    {
                        r2 = unlink(buf);
                    }
                }
                free(buf);
            }
            r = r2;
        }
        closedir(d);
    }
    if (!r)
    {
        r = rmdir(path);
    }
    return r;
}


void
mk_dir (char *path)
{
    char c;
    if (access (path, F_OK) == 0) {
        /*force remote dir*/
        printf("please input y(yes) to force remove exists dir or n(no) to exit process to continue. ");
        c = getchar();
        if(c != 'y') {
            printf("process exit");
            exit(0);
        }
        printf("force remove exists dir %s\n", path);
        force_rm_dir(path);
        printf("remove dir finish\n");
    }
    if (mkdir (path, 0755) == -1)
    {
        perror ("mkdir error");
        exit (-1);
    }
}

void
concat_object_url(Entry_body *entry_body, char *object_url, char *url) {
    strncat (object_url, url, 300);
    strcat (object_url, "/objects/");
    //printf("%s\n", sha12hex(entry_body->sha1));
    char dir[3];
    char *file_name = sha12hex (entry_body->sha1) + 2;
    strncpy (dir, sha12hex (entry_body->sha1), 2);
    dir[2] = '\0';
    strcat (object_url, dir);
    strcat (object_url, "/");
    strncat (object_url, file_name, 500);
}

int 
check_argv(int argc, char *argv[]) {
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
    int index_socckfd, ent_num;
    struct url_combo url_combo;
    if (check_argv (argc, argv) == -1) {
        exit(-1);
    }
    snprintf(index_url, BUFFER_SIZE, "%s/index", argv[1]);
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
        Entry_body *entry_body = (Entry_body *) malloc (sizeof (Entry_body));
        struct ce_body *ce_body = (struct ce_body*) malloc(sizeof (struct ce_body));
        //entry->id = i;
        //entry->entry_body = entry_body;
        //printf("%ld\n", sizeof(Entry_body));
        fread (entry_body, sizeof(Entry_body), 1, index);

        //printf("%.24s\n", ctime(&tim));
        //printf("%d\n", hex2dec(entry_body->gid, 4));
        //printf("%d\n", hex2dec(entry_body->uid, 4));
        //printf("%d\n", hex2dec(entry_body->size, 4));
        //printf("%d\n", hex2dec(entry_body->ino, 4));
        //printf("%d\n", (hex2dec(entry_body->file_mode, 4) & 0xF000) >> 12);
        //printf("%o\n", hex2dec(entry_body->file_mode, 4) & 0x1FF);
        //printf("%s\n", sha12hex(entry_body->sha1));
        //printf("%s\n", file_url);
        struct _flags file_flags;
        file_flags.assume_valid = hex2dec (entry_body->ce_flags, 2) & (0x0001 << 15);
        file_flags.extended = hex2dec (entry_body->ce_flags, 2) & (0x0001 << 14);
        if(hex2dec(magic_head->version, 4) == 2) {
            assert(file_flags.extended == 0);
        }
        file_flags.stage.stage_one =
            hex2dec (entry_body->ce_flags, 2) & (0x0001 << 13);
        file_flags.stage.stage_two =
            hex2dec (entry_body->ce_flags, 2) & (0x0001 << 12);
        int namelen = hex2dec (entry_body->ce_flags, 2) & (0xFFFF >> 4);
        int entry_len = ENTRY_SIZE;
        if (file_flags.extended && hex2dec (magic_head->version, 4) >= 3)
        {
            handle_version3orlater (index, &entry_len);
        }
        ce_body->name = get_name (index, namelen, &entry_len);
        ce_body->entry_len = entry_len;
        pad_entry (index, ce_body->entry_len);
        create_all_path_dir(ce_body);
        int pid;
        //if(process_num > 20) {
        //    while(wait(NULL) != -1) {}
        //    process_num = 0;
        //}
        if ((pid = fork ()) == -1)
        {
            perror ("fork");
        }
        //process_num++;
        if (pid == 0)
        {
            ce_body->entry_body = entry_body;
            char object_url[BUFFER_SIZE] = {'\0'};
            concat_object_url (entry_body, object_url, argv[1]);
            int sockfd2 = http_get (object_url);
            if(sockfd2 <= 0) {
                printf("%s [NOT FOUND]\n", ce_body->name);
                close (sockfd2);
                exit(0);
            }
            //split_pathname (sockfd2, ce_body);
            touch_file_et (sockfd2, ce_body->name, hex2dec((ce_body->entry_body->size), 4));
            //change_file_ac_time(entry_body, ce_body->name);
            free(entry_body);
            free(ce_body);
            close (sockfd2);
            exit(0);
        }
        //touch_file(sockfd2, ce_body.name);
    }
    fclose (index);
    /*remove index file*/
    unlink("index");
    free (magic_head);
    /*wait all child process*/
    while(wait(NULL) != -1){}
}
