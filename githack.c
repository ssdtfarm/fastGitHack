#include "githack.h"



int
hex2dec (unsigned char *hex, int len)
{
    char    result[BUFFER_SIZE];
    char    *format; 
    char    *format_prefix = "0x";

    format = (char *) calloc (sizeof (char), BUFFER_SIZE);
    memset (format, '\0', BUFFER_SIZE);
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
    char    *result;

    result = (char *) calloc (sizeof (char), 41);
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
    int     version;

    version = hex2dec (magic_head->version, 4);
    return version == 2 || version == 3 || version == 4 ? TRUE : FALSE;
}

void
init_check (int sockfd, Magic_head * magic_head)
{
    read (sockfd, magic_head, sizeof (Magic_head));
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
pad_entry (int sockfd, int entry_len)
{
    char pad;
    int padlen; 

    padlen = (8 - (entry_len % 8)) ? (8 - (entry_len % 8)) : 8;
    for (int i = 0; i < padlen; i++)
    {
        readn (sockfd, &pad, 1);
        assert (pad == '\0');
    }

}

char *
get_name (int sockfd, int namelen, int *entry_len)
{
    char    *name;

    name = (char *) calloc (sizeof (char), 0xFFF);
    if (namelen < 0xFFF)
    {
        readn (sockfd, name, namelen);
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
handle_version3orlater (int sockfd, int *entry_len)
{
    struct _extra_flags     extra_flag;
    unsigned char           extra_flag_buf[2];

    readn (sockfd, extra_flag_buf, 2);
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
    struct hostent      *he;
    struct sockaddr_in  sa;

    bzero (&sa, sizeof(sa));
    sa.sin_family = AF_INET;

    if (inet_aton (host, &sa.sin_addr) == 0)
    {
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
    int     protocol_len;

    protocol_len = strchr (http_url, '/') - http_url + 2;
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

ssize_t
writen(int fd, const void *vptr, size_t n)
{
    size_t         nleft;
    ssize_t        nwritten;
    const char*    ptr;

    ptr = vptr;
    nleft = n;
    while (nleft > 0) {
        if ( (nwritten = write(fd, ptr, nleft)) <= 0) {
            if (nwritten < 0 && errno == EINTR)
                nwritten = 0; /*and call write() again*/
            else
                return(-1);
        }

        nleft -= nwritten;
        ptr += nwritten;
    }
    return(n);
}

ssize_t
readline(int fd, void *vptr, size_t maxlen)
{
    ssize_t n, rc;
    char    c,*ptr;
    ptr = vptr;
    for (n = 1; n < maxlen; n++) {
    again:
        if ( ( rc = read(fd, &c , 1)) == 1) {
            *ptr++ = c;
            if (c == '\n')
                break;
        } else if (rc == 0) {
            *ptr = 0;
            return(n - 1);
        } else {
            if (errno == EINTR)
                goto again;
            return(-1);
        }
    }
    
    *ptr = 0;
    return(n);
}

ssize_t
readn(int fd, void *vptr, size_t n)
{
    char    *ptr;
    size_t  nleft;
    ssize_t nread;

    ptr = vptr;
    nleft = n;
    while (nleft > 0) {
        if ( (nread = read(fd, ptr, nleft)) < 0) {
            if (errno == EINTR) 
                nread = 0; /*and call read() again*/
            else
                return(-1);
        } else if (nread == 0)
            break;          /*EOF*/
        nleft -= nread;
        ptr   += nread;
    }
    return(n - nleft);
}


int
http_get (char *http_url, int port)
{
    fd_set  wset;
    int     ready_n;
    int     sockfd;
    char    ip[128] = {'\0'};
    struct  timeval tval;
    struct  url_combo url_combo;
    struct  sockaddr_in address;
    char    http_header_raw[BUFFER_SIZE];

    parse_http_url (http_url, &url_combo);
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
    address.sin_port = htons(port);
    get_ip_from_host(ip, url_combo.host, 128);
    if (inet_pton (AF_INET, ip, &address.sin_addr) <= 0)
    {
        perror("inet_pton");
        exit(-1);
    }

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

    FD_ZERO(&wset);
    FD_SET(sockfd, &wset);
    tval.tv_sec = 0;
    tval.tv_usec = 2000 * 1000; //300毫秒

    if ((ready_n = select (sockfd + 1, NULL, &wset, NULL, &tval)) == 0) {
        close(sockfd); /* timeout */
        errno = ETIMEDOUT;
        perror("select timeout");
        exit(-1);
    }

    if (FD_ISSET(sockfd, &wset)) {
        int         error;
        int         nwrite;
        socklen_t   len;

        len = sizeof (error);
        if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
            perror("getsockopt error.");
        }else{
            if ( (nwrite = writen (sockfd, http_header_raw, strlen (http_header_raw))) == -1){
                perror("write");
                exit(-1);
            }
            if(nwrite > 0) {
                return sockfd;
            }
        }
    }
    return -1;
}


int 
touch_file_et(int sockfd, const char *filename, int filesize){
    int             nread, i = 0;
    char            ch;
    char            *blob_header,*text;
    unsigned char   buf[filesize * 100];
    unsigned long   tlen, j = 0l;
    char            filepath[BUFFER_SIZE * 10] = { '\0' };
    char            blob_header_tmp[100];

    if (!filesize) {
        return 0;
    }
    strncat (filepath, filename, BUFFER_SIZE * 10 - 1);
    //setnonblocking(sockfd);
    while ((nread = read (sockfd, &ch, 1)) != 0)
    {
        if(nread < 0) {
            if(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN){
                nread = 0;
                continue; /*and call read() again*/
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

    snprintf(blob_header_tmp, 100, "blob %d", filesize);
    blob_header = blob_header_tmp;
    text = (char *) malloc(filesize + strlen(blob_header) + 1);
    tlen = filesize + strlen(blob_header) + 1;
    if(uncompress(text, &tlen, buf, j+1) != Z_OK){
        //printf("uncompress failed!\n");
        printf("%s \033[31m[FAILED]\033[0m\n", filename);
        free(text);
        return 0;
    }

    printf("%s \033[35m[OK]\033[0m\n", filename);

    FILE *file = fopen(filename, "wb+");
    fwrite(text + strlen(blob_header) + 1, 1, filesize, file);
    fclose(file);
    free(text);
    return 1;
}

int
create_dir (const char *sPathName)
{
    char    DirName[256] = {'\0'};
    int i, len = strlen (DirName);

    strncpy (DirName, sPathName, 254);
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
    char    *result;
    char    dir[BUFFER_SIZE] = { '\0' };

    result = strrchr (ce_body->name, '/');
    if (result)
    {
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
parse_index_file (int sockfd, char *url)
{
    char    ch;
    int     ret, i = 0;

    //int fd = open ("index", O_RDWR | O_CREAT,
    //        S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
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
        if (ch == '\r' || ch == '\n'){
            if (++i == 4)
                goto handle_http_body;
        }
        else{
            i = 0;
        }
    }

    handle_http_body:
    {
        int         ent_num, i; 
        Magic_head  *magic_head; 

        magic_head = (Magic_head *) malloc (sizeof (Magic_head));
        init_check(sockfd, magic_head);
        ent_num = hex2dec (magic_head->file_num, 4);
        printf("find %d files, downloading~\n", ent_num);
        for (i = 1; i <= ent_num; i++)
        {
            int             namelen, entry_len = ENTRY_SIZE;
            struct _flags   file_flags;
            Entry_body      *entry_body; 
            struct ce_body  *ce_body; 

            entry_body  = (Entry_body *) malloc (sizeof (Entry_body));
            ce_body = (struct ce_body*) malloc(sizeof (struct ce_body));
            readn (sockfd, entry_body, sizeof(Entry_body));
            file_flags.assume_valid = hex2dec (entry_body->ce_flags, 2) & (0x0001 << 15);
            file_flags.extended = hex2dec (entry_body->ce_flags, 2) & (0x0001 << 14);
            if(hex2dec(magic_head->version, 4) == 2) {
                assert(file_flags.extended == 0);
            }
            file_flags.stage.stage_one =
                hex2dec (entry_body->ce_flags, 2) & (0x0001 << 13);
            file_flags.stage.stage_two =
                hex2dec (entry_body->ce_flags, 2) & (0x0001 << 12);
            namelen = hex2dec (entry_body->ce_flags, 2) & (0xFFFF >> 4);
            if (file_flags.extended && hex2dec (magic_head->version, 4) >= 3)
            {
                handle_version3orlater (sockfd, &entry_len);
            }

            ce_body->name = get_name (sockfd, namelen, &entry_len);
            ce_body->entry_len = entry_len;
            pad_entry (sockfd, ce_body->entry_len);
            create_all_path_dir(ce_body);

            int pid;
            if ((pid = fork ()) == -1)
            {
                perror ("fork");
            }
            if (pid == 0)
            {
                int     sockfd2;
                char    object_url[BUFFER_SIZE] = {'\0'};

                free (magic_head);

                ce_body->entry_body = entry_body;
                concat_object_url (entry_body, object_url, url);
                sockfd2 = http_get (object_url, default_port);
                if(sockfd2 <= 0) {
                    printf("%s \033[31m[NOT FOUND]\033[0m\n", ce_body->name);
                    goto end;
                }
                touch_file_et (sockfd2, ce_body->name, hex2dec((ce_body->entry_body->size), 4));

                end:
                    free (entry_body);
                    free (ce_body);
                    close (sockfd2);
                    exit(0);
            }
            free (entry_body);
            free (ce_body);
        }    
        free (magic_head);
        while(wait(NULL) != -1){}
    }
}

int
force_rm_dir(const char *path)
{
    DIR     *d;
    size_t  path_len, len;
    int     r = -1, r2 = -1;
    struct  dirent *p;
    char    *buf;

    d = opendir(path);
    path_len = strlen(path);
    if (d)
    {
        r = 0;
        while (!r && (p=readdir(d)))
        {
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
    char    c;

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
    char    dir[3] = {'\0'};

    strncat (object_url, url, 300);
    strcat (object_url, "/objects/");
    //printf("%s\n", sha12hex(entry_body->sha1));
    char *file_name = sha12hex (entry_body->sha1) + 2;
    strncpy (dir, sha12hex (entry_body->sha1), 2);
    strcat (object_url, dir);
    strcat (object_url, "/");
    strncat (object_url, file_name, 500);
}

int 
check_argv(int argc, char *argv[]) {
    if (argc < 2 || argc > 3)
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
    int     index_socckfd;
    struct  url_combo url_combo;
    char    index_url[BUFFER_SIZE];

    if (argc == 3) {
        default_port = atoi(argv[2]);
    }

    if (check_argv (argc, argv) == -1) {
        exit(-1);
    }

    snprintf (index_url, BUFFER_SIZE, "%s/index", argv[1]);
    parse_http_url (argv[1], &url_combo);
    mk_dir (url_combo.host);
    assert (chdir (url_combo.host) == 0);

    index_socckfd = http_get (index_url, default_port);
    parse_index_file (index_socckfd, argv[1]);
}
