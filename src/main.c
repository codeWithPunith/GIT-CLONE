#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <zlib.h>
#define CHUNK 16384 

int main(int argc, char *argv[]) {
    // Disable output buffering
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    if (argc < 2){
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
         }else if(strcmp(command,"git-cat")==0){
       if(argc!=4 || strcmp(argv[2],"-p")!=0){
        fprintf(stderr,"Bro seriously u got the error in the GIT_CAT executio get lost ");
        return 1;
       }
       char blob_sha[41],blob_folderName[3],blob_fileName[39],blob_file_path[256];
       strcpy(argv[3],blob_sha);
       blob_folderName[0]=blob_sha[0];
       blob_folderName[1]=blob_sha[1];
       blob_folderName[2]='\0';
       for(int i=2;i<=40;i++){
        blob_fileName[i-2]=blob_sha[i];
       }
       snprintf(blob_file_path,sizeof(blob_file_path),".git/objects/%s/%s",blob_folderName,blob_fileName);
       FILE *blobFile = fopen(blob_file_path,"r");
       unsigned char buf[1024];
       fread(buf,sizeof(unsigned char),sizeof(buf),blobFile);
       //writing ur code of zlib from here. 
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
    int start_pos = strlen(decompress_buf) + 1;
    while (i < atoi(num_of_bytes)) {
      printf("%c", decompress_buf[i + start_pos]);
      i++;
    }
    fclose(blobFile);
    }else {
        fprintf(stderr, "Unknown command %s\n", command);
        return 1;
    }
    
    return 0;
}
 