#include <errno.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <zconf.h>
#include <zlib.h>

int main(int argc, char *argv[]){
  
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    if (argc < 2) {
        fprintf(stderr, "Usage: ./your_program.sh <command> [<args>]\n");
        return 1;
    }
    
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
    return 2;
    }

    else {
        fprintf(stderr, "Unknown command %s\n", command);
        return 1;
    }
    
    return 0;
}
 