#include "zlib.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <curl/curl.h>
#define BUFFER_SIZE 1024 * 1024
//structure of tree
 typedef struct{
        char mode[7];
        char name[256];
        unsigned char sha[20];
    }TreeEntry;
TreeEntry entries[1000];
     int entry_count=0;

     //structur of a refernece entry 
     typedef struct ref_entry {
    char sha[41];
    char ref_name[256];
} ref_entry;

int get_ref_maps(struct ref_entry *entries, FILE *fp) {
    int i = 0;
    char len_hex[5] = {0};

    while (fread(len_hex, 1, 4, fp) == 4) {
        int pkt_len = (int)strtol(len_hex, NULL, 16);
        if (pkt_len == 0)
            continue; // skip flush packets

        int data_len = pkt_len - 4;
        if (data_len <= 0) continue;

        char *payload = malloc(data_len + 1);
        if (!payload) {
            perror("malloc failed");
            exit(1);
        }

        fread(payload, 1, data_len, fp);
        payload[data_len] = '\0';

        // --- Debug print ---
        printf("Raw packet (%d bytes): ", pkt_len);
        for (int k = 0; k < data_len; k++) {
            unsigned char c = payload[k];
            if (c >= 32 && c <= 126)
                putchar(c);
            else
                printf("\\x%02x", c);
        }
        printf("\n");
        // --------------------

        // Skip service announcement
        if (strncmp(payload, "# service=", 10) == 0) {
            free(payload);
            continue;
        }

        // Skip short/invalid packets
        if (data_len < 41) {
            free(payload);
            continue;
        }

        // Extract SHA
        strncpy(entries[i].sha, payload, 40);
        entries[i].sha[40] = '\0';

        // Find first space
        char *space = strchr(payload, ' ');
        if (!space) {
            free(payload);
            continue;
        }

        char *ref = space + 1;

        // Handle null separator for capabilities
        char *null_sep = strchr(ref, '\0');
        if (null_sep) *null_sep = '\0';

        // Clean ref name
        ref[strcspn(ref, "\r\n")] = 0;

        strncpy(entries[i].ref_name, ref, sizeof(entries[i].ref_name) - 1);
        entries[i].ref_name[sizeof(entries[i].ref_name) - 1] = '\0';

        printf("→ Parsed: %s -> %s\n", entries[i].sha, entries[i].ref_name);
        i++;

        free(payload);
    }

    printf("Total refs parsed: %d\n", i);
    return i;
}


//function to write obj
void write_object(const char *unused_hash, const char *type,
                  const void *content, size_t size) {
  // Compute SHA-1 of full buffer
  unsigned char sha1[20];
  SHA1((const unsigned char *)content, size, sha1);

  // Convert SHA to hex
  char hex[41];
  for (int i = 0; i < 20; i++) {
    sprintf(hex + i * 2, "%02x", sha1[i]);
  }
  hex[40] = '\0';

  // Create path: .git/objects/xx/yyyy...
  char dir[64], path[128];
  snprintf(dir, sizeof(dir), ".git/objects/%.2s", hex);
  snprintf(path, sizeof(path), ".git/objects/%.2s/%.38s", hex, hex + 2);

  // Make directory if needed
  mkdir(dir, 0755);

  // Compress content
  unsigned char outbuf[BUFFER_SIZE];
  z_stream zs = {0};
  deflateInit(&zs, Z_DEFAULT_COMPRESSION);
  zs.next_in = (unsigned char *)content;
  zs.avail_in = size;
  zs.next_out = outbuf;
  zs.avail_out = sizeof(outbuf);
  deflate(&zs, Z_FINISH);
  deflateEnd(&zs);

  size_t compressed_size = zs.total_out;

  // Write to file
  FILE *f = fopen(path, "wb");
  if (!f) {
    perror("fopen");
    return;
  }

  fwrite(outbuf, 1, compressed_size, f);
  fclose(f);

}


//function to write a sha blob
char *hash_blob(char *path){
    FILE *fp = fopen(path, "rb");
  if (!fp) {
    perror("fopen");
    return NULL;
  }

  fseek(fp, 0, SEEK_END);
  long fsize = ftell(fp);
  rewind(fp);
  unsigned char *content= malloc(fsize);
  if (fread(content, 1, fsize, fp) != fsize) {
    perror("fread");
    fclose(fp);
    free(content);
    return NULL;
  }
  fclose(fp);

  //build blob:blob<size>\0<data>
 char header[64];
  int header_len = sprintf(header, "blob %ld", fsize);
  size_t total_size = header_len + 1 + fsize;
  unsigned char *full_buf = malloc(total_size);
  memcpy(full_buf, header, header_len);
  full_buf[header_len] = '\0';
  memcpy(full_buf + header_len + 1, content, fsize);

  // Compute SHA-1
  unsigned char sha1[20];
  SHA1(full_buf, total_size, sha1);

  // Save object
  write_object(NULL, "blob", full_buf, total_size);

  // Convert to hex
  char *hex = malloc(41);
  for (int i = 0; i < 20; i++) {
    sprintf(hex + i * 2, "%02x", sha1[i]);
  }
  hex[40] = '\0';

  free(content);
  free(full_buf);

  return hex;

}

//function to compare entries
int compare_entries(const void *a, const void *b) {
  const TreeEntry *ea = a, *eb = b;
  return strcmp(ea->name, eb->name);
}

//function to write tree sha 
char *write_tree(char *path){
 DIR *dir = opendir(".");
     if(!dir){
        perror("error while opening the dir");
        return 0;
     }
     
     struct dirent *entry;
     while((entry=readdir(dir))!=NULL){
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 ||
        strcmp(entry->d_name, ".git") == 0)
      continue;
     char full_path[128];
      snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
     
     struct stat st;
     if(lstat(full_path,&st)==-1){
        perror("lstat");
        continue;
     }
     char *sha1_hex =NULL;
     if(S_ISDIR(st.st_mode)){
        sha1_hex = write_tree(full_path);
        strcpy(entries[entry_count].mode, "40000");
     }else if(S_ISREG(st.st_mode)){
        sha1_hex =hash_blob(full_path);
        strcpy(entries[entry_count].mode,"100644");
     }else{
        continue;
     }

     strcpy(entries[entry_count].name, entry->d_name);
      sscanf(sha1_hex,
           "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx"
           "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
           &entries[entry_count].sha[0], &entries[entry_count].sha[1],
           &entries[entry_count].sha[2], &entries[entry_count].sha[3],
           &entries[entry_count].sha[4], &entries[entry_count].sha[5],
           &entries[entry_count].sha[6], &entries[entry_count].sha[7],
           &entries[entry_count].sha[8], &entries[entry_count].sha[9],
           &entries[entry_count].sha[10], &entries[entry_count].sha[11],
           &entries[entry_count].sha[12], &entries[entry_count].sha[13],
           &entries[entry_count].sha[14], &entries[entry_count].sha[15],
           &entries[entry_count].sha[16], &entries[entry_count].sha[17],
           &entries[entry_count].sha[18], &entries[entry_count].sha[19]);

    free(sha1_hex);
    entry_count++;
      }
      closedir(dir);
      qsort(entries, entry_count, sizeof(TreeEntry), compare_entries);

      //building serlized tree
      char *tree_buf=NULL;
      size_t tree_size =0;
      for(int i=0;i<entry_count;i++){
        char entry_buf[4096];
        size_t entry_len= sprintf(entry_buf,"%s%s",entries[i].mode,entries[i].name);
        tree_buf = realloc(tree_buf, tree_size + entry_len + 1 + 20);
        memcpy(tree_buf + tree_size, entry_buf, entry_len);
    tree_buf[tree_size + entry_len] = '\0';
    memcpy(tree_buf + tree_size + entry_len + 1, entries[i].sha, 20);
    tree_size += entry_len + 1 + 20;
    char header[64];
  int header_len = sprintf(header, "tree %zu", tree_size);
  size_t total_size = header_len + 1 + tree_size;

  char *final_buf = malloc(total_size);
  memcpy(final_buf, header, header_len);
  final_buf[header_len] = '\0';
  memcpy(final_buf + header_len + 1, tree_buf, tree_size);

  // SHA-1 of full buffer
  unsigned char sha1[20];
  SHA1((unsigned char *)final_buf, total_size, sha1);

  // Write to .git/objects
  write_object(NULL, "tree", final_buf, total_size);

  // Convert to hex string
  char *hex = malloc(41);
  for (int i = 0; i < 20; i++) {
    sprintf(hex + i * 2, "%02x", sha1[i]);
  }
  hex[40] = '\0';

  free(tree_buf);
  free(final_buf);

  return hex;
      }
}
//function to decompress packfile
void  decompress_packfile(){
  FILE *fp = fopen("packfile.response","rb");
  char buffer[1024];
  char pack_header[5];
  if(!fp){
    perror("error while opening the packfile response to decompress");
    return ;
  }
  char line[128];
    fgets(line, sizeof(line), fp);
     size_t bytes_read = fread(pack_header, 1, 4, fp); 
     pack_header[4]='\0';
     unsigned char version[5];
     unsigned char count_bytes[4];
     fread (version,1,4,fp);
      fread(count_bytes, 1, 4, fp);
    uint32_t object_count = (count_bytes[0] << 24) |
                            (count_bytes[1] << 16) |
                            (count_bytes[2] << 8)  |
                            (count_bytes[3]);
   char objects[object_count];
for(int i=0;i<object_count;i++){
   unsigned char c;
fread(&c, 1, 1, fp);
int type = (c >> 4) & 7;  // bits 4-6
long size = c & 0x0F;     // lower 4 bits
int shift = 4;
while (c & 0x80) {        // continuation bit set
    fread(&c, 1, 1, fp);
    size |= ((c & 0x7F) << shift);
    shift += 7;
}
printf("Type: %d, Size: %ld\n", type, size);
}
     fclose(fp);
     return;
}

//function for req object from packfile
void req_object_file(char *url,char *sha){
CURL *curl;
CURLcode res;
FILE *fp =fopen("packfile.response","wb");
if(!fp){
    perror("error while creating the file to write the packfile response");
    return;
}
char body[1025];
snprintf(body,sizeof(body),"0032want %s\n00000009done\n", sha);
char final_url[1024];
snprintf(final_url,sizeof(final_url),"%s/git-upload-pack",url);
curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, final_url);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(body));
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER,
                         curl_slist_append(NULL, "Content-Type: application/x-git-upload-pack-request"));

        res = curl_easy_perform(curl);
        if (res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));

        curl_easy_cleanup(curl);
    }
    fclose(fp);
    curl_global_cleanup();
    return ;
}
//funtion for git cloneeeeeeeeeeeeeeeee..................................///////////////////////
int git_clone_cmd(char *url, char *directory) {
    if (mkdir(directory, 0755) != 0) {
        perror("error creating a directory while cloning the initial stage");
        return 0;
    }
    chdir(directory);
    system("mkdir -p .git/objects .git/refs");

    FILE *head = fopen(".git/HEAD", "w");
    fprintf(head, "ref: refs/heads/master\n");
    fclose(head);

    printf("Initialized empty Git repository in %s/.git\n", directory);

    // --- Fetch refs using curl ---
    char final_url[1024];
    snprintf(final_url, sizeof(final_url), "%s/info/refs?service=git-upload-pack", url);

    CURL *curl;
    CURLcode res;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "curl init failed\n");
        return 0;
    }

    FILE *f = fopen("repoDetails.txt", "wb");
    if (!f) {
        perror("error creating the file to write the responses");
        return 0;
    }

    curl_easy_setopt(curl, CURLOPT_URL, final_url);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, f);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");

    res = curl_easy_perform(curl);
    fclose(f);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        return 0;
    }
    curl_easy_cleanup(curl);

    // --- Parse the pkt-lines from the file ---
    FILE *fp = fopen("repoDetails.txt", "rb");
    if (!fp) {
        perror("error while opening the file to read");
        return 0;
    }

    ref_entry *refs = malloc(200 * sizeof(ref_entry)); // up to 200 refs for now
    if (!refs) {
        perror("malloc failed");
        fclose(fp);
        return 1;
    }

    int ref_count = get_ref_maps(refs, fp);
    fclose(fp);

    printf("Successfully mapped %d refs\n", ref_count);
 char *head_sha=NULL;
    for (int j = 0; j < ref_count; j++) {
        if(strcmp(refs[j].ref_name,"refs/heads/main")){
          head_sha= refs[j].sha;
          break;
        }
    }

    free(refs);
    curl_global_cleanup();

    req_object_file(url,head_sha);//performs writing the packfile in packfile.response
    decompress_packfile();
    return 1;
}
/////////////////////////////////////////MAIN FUNC////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[]){
  
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
 
    if (argc < 2) {
        fprintf(stderr, "Usage: ./your_program.sh <command> [<args>]\n");
        return 1;
    }
    //structure of a tree
   

    const char *command = argv[1];
    
    if (strcmp(command, "init") == 0) {
        // You can use print statements as follows for debugging, they'll be visible when running tests.
        fprintf(stderr, "Logs from your program will appear here!\n");

        // TODO: Uncomment the code below to pass the first stage
         
         if (mkdir(".git", 0755) == -1 || 
             mkdir(".git/objects", 0755) == -1 || 
             mkdir(".git/refs", 0755) == -1){
             fprintf(stderr, "Failed to create directories: %s\n", strerror(errno));
             return 1;
             }
         
         FILE *headFile = fopen(".git/HEAD", "w");
         if (headFile == NULL) {
             fprintf(stderr, "Failed to create .git/HEAD file: %s\n", strerror(errno));
             return 1;
         }
         fprintf(headFile, "ref: refs/heads/main\n");
         fclose(headFile);
         printf("Initialized git directory\n");
//todo task 2
         }else if(strcmp(command, "cat-file") == 0) {
    if (argc != 4 || strcmp(argv[2], "-p") != 0) {
      fprintf(stderr, "Usage: ./your_program.sh cat-file -p <hash>\n");
      return 1;
    }

    char blob_sha[41], blob_file_folder[3], blob_file_name[39],
        blob_file_path[256];
    strncpy(blob_sha, argv[3],40);
    blob_file_folder[0] = blob_sha[0];
    blob_file_folder[1] = blob_sha[1];
    blob_file_folder[2] = '\0';
    for (int i = 2; i < 40; i++) {
      blob_file_name[i - 2] = blob_sha[i];
    }
   blob_file_name[38]='\0';
    snprintf(blob_file_path, sizeof(blob_file_path), ".git/objects/%s/%s",
             blob_file_folder, blob_file_name);
    FILE *blob_file = fopen(blob_file_path, "rb");
    if (!blob_file) {
    fprintf(stderr, "Error opening blob file %s: %s\n", blob_file_path, strerror(errno));
    return 1;
}


    unsigned char buf[1024];
    fread(buf, sizeof(unsigned char), sizeof(buf), blob_file);

    unsigned char decompress_buf[1024];
    z_stream stream = {0};
    inflateInit(&stream);
    stream.next_in = buf;
    stream.avail_in = sizeof(buf);
    stream.next_out = decompress_buf;
    stream.avail_out = sizeof(decompress_buf);
    inflate(&stream, Z_FINISH);
    inflateEnd(&stream);
    int i = 0;
    int j = 0;
    char num_of_bytes[64];
    while (decompress_buf[i] != '\0') {
      if (decompress_buf[i] == ' ') {
        while (decompress_buf[j + i] != '\0') {
          num_of_bytes[j] = decompress_buf[j + i];
          j++;
        }
        break;
      }
      i++;
    }
    i = 0;
    int start_pos = strlen((char *)decompress_buf) + 1;
    while (i < atoi(num_of_bytes)) {
      printf("%c", decompress_buf[i + start_pos]);
      i++;
    }
    fclose(blob_file);
    }
    //task 3 of creating sha hash ig

    else if(strcmp(command,"hash-object")==0){
       
        FILE *file = fopen(argv[3],"rb");
        if(file==NULL){
            fprintf(stderr,"Error in opening the file to get its size in has-object command");
            return 1;
        }
        fseek(file,0,SEEK_END);
        long fileSize = ftell(file);
        fclose(file);
        char content[fileSize+1];
        FILE *filePointer ;
        filePointer = fopen(argv[3],"r");
        char ch;
        int i=0;
        while ((ch = fgetc(filePointer)) != EOF) {
        content[i++]=ch;
    }
    content[i]='\0';

     unsigned char hash_input[fileSize+1+6],hash_output[SHA_DIGEST_LENGTH];
    SHA1(hash_input,strlen((char *)hash_input),hash_output);
     char sha1_hex[41];
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
    sprintf(sha1_hex + i * 2, "%02x", sha1_hex[i]);
}
sha1_hex[40]='\0';
printf("%s \n",sha1_hex);
char dir[64], path[128];
snprintf(dir, sizeof(dir), ".git/objects/%.2s", sha1_hex);
snprintf(path, sizeof(path), ".git/objects/%.2s/%s", sha1_hex, sha1_hex + 2);
mkdir(".git/objects", 0755);
mkdir(dir, 0755);

z_stream defstream;
defstream.zalloc = Z_NULL;
defstream.zfree = Z_NULL;
defstream.opaque = Z_NULL;

defstream.avail_in = strlen(content);
defstream.next_in = (Bytef *)content;

Bytef outbuffer[4096];
defstream.avail_out = sizeof(outbuffer);
defstream.next_out = outbuffer;

deflateInit(&defstream, Z_BEST_COMPRESSION);
deflate(&defstream, Z_FINISH);
deflateEnd(&defstream);

size_t compressed_size = sizeof(outbuffer) - defstream.avail_out;

FILE *out = fopen(path, "wb");
fwrite(outbuffer, 1, compressed_size, out);
fclose(out);

printf("complete execution");
    return 0;
    }

    //todo command  $ git ls-tree --name-only 48eba38070f13847b31ffaff672ed1138753198b
    else if(strcmp(command,"ls-tree")==0){
         const char *path = ".git/objects/48/eba38070f13847b31ffaff672ed1138753198b";  // replace with your object path
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("Error opening file");
        return 1;
    }

    // Get file size
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
        unsigned char *compressed_data = malloc(size);
    unsigned char decompressed_data[4096];
    FILE *fb = fopen(".git/objects/48/eba38070f13847b31ffaff672ed1138753198b", "rb");
fread(compressed_data, 1, size, fb);
fclose(fb);

z_stream stream = {0};
inflateInit(&stream);
stream.next_in = compressed_data;
stream.avail_in = size;
stream.next_out = decompressed_data;
stream.avail_out = sizeof(decompressed_data);
inflate(&stream, Z_FINISH);
inflateEnd(&stream);
unsigned char  raw_output[stream.total_out+1];
unsigned char *p = decompressed_data;
while(*p!='\0') p++;
p++;
while(p<decompressed_data+stream.total_out){
    char mode[10];
    int m=0;
    while(*p!=' '){
        mode[m++]=*p++;
    }
    mode[m]='\0';
    p++;
    char filename[256];
    int f=0;
    while(*p!='\0'){
        filename[f++]=*p++;
    }
    filename[f]='\0';
    p++;
     printf("%s\n", filename);
}

raw_output[stream.total_out]='\0';
printf("%s",raw_output);

    }

    //todo writing the git wrte tree 

    else if(strcmp(command,"write-tree")==0){
    entry_count = 0;
    char *root_sha = write_tree(".");
    printf("%s\n", root_sha);
    free(root_sha);
    }

    //todo  ./your_program.sh commit-tree <tree_sha>{f22a7ed96c9ef04f7c7352eb6616f6290fd4bc40} -p <commit_sha>{9cf03288bb5bf2564e33e06b05ccc2a9bb790ee4}-m <message>"
   
    else if(strcmp(argv[1],"commit-tree")==0){
        printf("%d ho ho\n",argc);
        if (argc < 7) {
    fprintf(stderr, "Usage: %s commit-tree <tree_sha> -p <parent_sha> -m <message>\n", argv[0]);
    return 1;
}

    char *git_message = argv[6];
    char *tree_commit = argv[2];
    char *parent_commit = argv[4];
    //mkdir(".git/objects/1c", 0755); 
    FILE *fc = fopen(".git/objects/9c/f03288bb5bf2564e33e06b05ccc2a9bb790ee4","wb");

    if(fc==NULL){
        perror("Error while opening the file during committing");
        return 0;
    }
    fputs("Author is lord punith\nMail:rajpunith430@gmail.com",fc);
   fprintf(fc,"Tree-commit:%s\n",tree_commit);
   fprintf(fc,"Parent-commit:%s\n",git_message);
   fprintf(fc,"Tree-commit:%s\n",parent_commit);
   fclose(fc);

   //getting the hsh for it 
  FILE *file = fopen(".git/objects/9c/f03288bb5bf2564e33e06b05ccc2a9bb790ee4", "rb");
    if (file == NULL) {
        perror("Error opening file during hashing");
        return 1;
    }

    SHA256_CTX sha256_ctx;  // correct struct for SHA-256
    SHA256_Init(&sha256_ctx);

    const int buffer_size = 4096;
    unsigned char buffer[buffer_size];
    size_t bytesRead;

    // read file in chunks and update hash
    while ((bytesRead = fread(buffer, 1, buffer_size, file)) > 0) {
        SHA256_Update(&sha256_ctx, buffer, bytesRead);
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];  // correct length = 32 bytes
    SHA256_Final(hash, &sha256_ctx);

    printf("SHA-256 hash: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    fclose(file);
   }
 
   //CLONING the repositories no matter whatttttttttt
   //Test command  /path/to/your_program.sh clone https://github.com/blah/blah <some_dir>
   else if(strcmp(command,"clone")==0){
    if(argc<4){
        perror("Eroor in argc while cloning ");
        return 0;
    }
    char *url = argv[2];
    char *directory = argv[3];
      git_clone_cmd(url,directory);
   }

    //the shitty wrong unintional exceptional handling
    else {
        fprintf(stderr, "Unknown command %s\n", command);
        return 0;
    }
    
    return 0;
}
 