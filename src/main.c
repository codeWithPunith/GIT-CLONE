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
   typedef struct ref_entry{
    char sha[41];
    char ref_name[256];
} ref_entry;


//forward function declarations
int get_ref_maps(ref_entry *refs, FILE *fp);
void req_object_file(const char *url, const char *sha);
void decompress_packfile_into_repo(const char *repo_path, const char *packfile_path);
void write_object_to_git_repo(const char *repo_path, unsigned char *data, size_t size, int type);

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

//function to write object to 

// Forward declarations
int get_ref_maps(ref_entry *refs, FILE *fp);
void req_object_file(const char *url, const char *sha);
void decompress_packfile_into_repo(const char *repo_path, const char *packfile_path);
void write_object_to_git_repo(const char *repo_path, unsigned char *data, size_t size, int type);

void write_object_to_git_repo(const char *repo_path,
                              unsigned char *data, size_t size, int type)
{
    const char *type_str[] = {"", "commit", "tree", "blob", "tag"};
    if (type < 1 || type > 4) {
        fprintf(stderr, "write_object_to_git_repo: unsupported type %d\n", type);
        return;
    }

    // build object full bytes: "<type> <size>\0<data>"
    char header[128];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str[type], size);
    size_t full_size = (size_t)header_len + 1 + size;
    unsigned char *full = malloc(full_size);
    if (!full) { perror("malloc"); return; }
    memcpy(full, header, header_len);
    full[header_len] = '\0';
    memcpy(full + header_len + 1, data, size);

    // compute SHA-1 (raw 20 bytes)
    unsigned char sha[20];
    SHA1(full, full_size, sha);

    // hex encode
    char sha_hex[41];
    for (int i = 0; i < 20; ++i) sprintf(sha_hex + i*2, "%02x", sha[i]);
    sha_hex[40] = '\0';

    // build directories: repo_path + "/.git/objects/xx"
    char objects_dir[512];
    char obj_subdir[512];
    char obj_path[1024];
    snprintf(objects_dir, sizeof(objects_dir), "%s/.git/objects", repo_path);
    snprintf(obj_subdir, sizeof(obj_subdir), "%s/%.2s", objects_dir, sha_hex);
    snprintf(obj_path, sizeof(obj_path), "%s/%s", obj_subdir, sha_hex + 2);  // FIX: was %.38s

    // ensure objects_dir exists
    if (mkdir(objects_dir, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "mkdir(%s) failed: %s\n", objects_dir, strerror(errno));
        free(full);
        return;
    }
    // create subdir for this object
    if (mkdir(obj_subdir, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "mkdir(%s) failed: %s\n", obj_subdir, strerror(errno));
        free(full);
        return;
    }

    // if file already exists, skip writing
    FILE *chk = fopen(obj_path, "rb");
    if (chk) { 
        fclose(chk); 
        free(full); 
        printf("object %s already exists\n", sha_hex); 
        return; 
    }

    FILE *out = fopen(obj_path, "wb");
    if (!out) {
        fprintf(stderr, "fopen(%s) failed: %s\n", obj_path, strerror(errno));
        free(full);
        return;
    }

    // compress with zlib (deflate) and write
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    if (deflateInit(&zs, Z_DEFAULT_COMPRESSION) != Z_OK) {  // FIX: Z_DEFAULT_COMPRESSION is more compatible
        fprintf(stderr, "deflateInit failed\n");
        fclose(out);
        free(full);
        return;
    }
    zs.next_in = full;
    zs.avail_in = (uInt)full_size;
    unsigned char outbuf[8192];
    int zret;
    do {
        zs.next_out = outbuf;
        zs.avail_out = sizeof(outbuf);
        zret = deflate(&zs, Z_FINISH);
        size_t wrote = sizeof(outbuf) - zs.avail_out;
        if (wrote) fwrite(outbuf, 1, wrote, out);
    } while (zret == Z_OK);
    deflateEnd(&zs);
    fclose(out);
    free(full);

    printf("WROTE %s -> %s (type=%s size=%zu)\n", sha_hex, obj_path, type_str[type], size);
}

// Structure to hold objects temporarily during pack processing
typedef struct {
    unsigned char *data;
    size_t size;
    int type;
    long offset;  // file offset for OFS_DELTA resolution
    int resolved;
} pack_object;

// Apply OFS delta
unsigned char* apply_ofs_delta(unsigned char *base, size_t base_size,
                               unsigned char *delta, size_t delta_size,
                               size_t *result_size) {
    size_t pos = 0;
    
    // Read base object size from delta
    size_t base_obj_size = 0;
    int shift = 0;
    while (pos < delta_size) {
        unsigned char c = delta[pos++];
        base_obj_size |= ((size_t)(c & 0x7f)) << shift;
        shift += 7;
        if (!(c & 0x80)) break;
    }
    
    // Read result object size
    size_t result_obj_size = 0;
    shift = 0;
    while (pos < delta_size) {
        unsigned char c = delta[pos++];
        result_obj_size |= ((size_t)(c & 0x7f)) << shift;
        shift += 7;
        if (!(c & 0x80)) break;
    }
    
    if (base_obj_size != base_size) {
        fprintf(stderr, "Delta base size mismatch\n");
        return NULL;
    }
    
    // Allocate result buffer
    unsigned char *result = malloc(result_obj_size);
    if (!result) return NULL;
    size_t result_pos = 0;
    
    // Apply delta instructions
    while (pos < delta_size) {
        unsigned char cmd = delta[pos++];
        
        if (cmd & 0x80) {
            // Copy from base
            size_t offset = 0, size = 0;
            if (cmd & 0x01) offset = delta[pos++];
            if (cmd & 0x02) offset |= delta[pos++] << 8;
            if (cmd & 0x04) offset |= delta[pos++] << 16;
            if (cmd & 0x08) offset |= delta[pos++] << 24;
            if (cmd & 0x10) size = delta[pos++];
            if (cmd & 0x20) size |= delta[pos++] << 8;
            if (cmd & 0x40) size |= delta[pos++] << 16;
            if (size == 0) size = 0x10000;
            
            if (offset + size > base_size || result_pos + size > result_obj_size) {
                free(result);
                return NULL;
            }
            memcpy(result + result_pos, base + offset, size);
            result_pos += size;
        } else if (cmd) {
            // Insert new data
            if (pos + cmd > delta_size || result_pos + cmd > result_obj_size) {
                free(result);
                return NULL;
            }
            memcpy(result + result_pos, delta + pos, cmd);
            result_pos += cmd;
            pos += cmd;
        } else {
            free(result);
            return NULL;
        }
    }
    
    *result_size = result_obj_size;
    return result;
}

void decompress_packfile_into_repo(const char *repo_path, const char *packfile_path) {
    FILE *fp = fopen(packfile_path, "rb");
    if (!fp) { 
        fprintf(stderr, "open(%s) failed: %s\n", packfile_path, strerror(errno)); 
        return; 
    }

    // Try to find "PACK" signature in file (pkt-lines or sideband may precede)
    int found = 0;
    unsigned char buf[4096];
    unsigned char look[4] = {0,0,0,0};
    
    while (!found) {
        size_t n = fread(buf, 1, sizeof(buf), fp);
        if (n == 0) break;
        for (size_t i = 0; i < n; ++i) {
            look[0]=look[1]; look[1]=look[2]; look[2]=look[3]; look[3]=buf[i];
            if (memcmp(look, "PACK", 4) == 0) {
                // compute offset of 'P'
                long cur = ftell(fp);
                long offset_in_chunk = (long)i - 3;
                long pack_pos = cur - (long)n + offset_in_chunk;
                if (fseek(fp, pack_pos, SEEK_SET) != 0) { 
                    perror("fseek"); 
                    fclose(fp); 
                    return; 
                }
                found = 1;
                break;
            }
        }
    }
    if (!found) { 
        fprintf(stderr, "PACK signature not found in %s\n", packfile_path); 
        fclose(fp); 
        return; 
    }

    // read 'PACK' (4 bytes), version (4), count (4)
    char sig[4];
    if (fread(sig, 1, 4, fp) != 4 || memcmp(sig, "PACK", 4) != 0) { 
        fprintf(stderr, "bad PACK\n"); 
        fclose(fp); 
        return; 
    }
    
    uint32_t version;
    if (fread(&version, 4, 1, fp) != 1) { 
        fprintf(stderr, "bad version\n"); 
        fclose(fp); 
        return; 
    }
    uint32_t ver_be = ((unsigned char *)&version)[0]<<24 | 
                      ((unsigned char *)&version)[1]<<16 | 
                      ((unsigned char *)&version)[2]<<8 | 
                      ((unsigned char *)&version)[3];
    (void)ver_be;

    unsigned char cntb[4];
    if (fread(cntb, 1, 4, fp) != 4) { 
        fprintf(stderr, "bad count\n"); 
        fclose(fp); 
        return; 
    }
    uint32_t object_count = (cntb[0]<<24) | (cntb[1]<<16) | (cntb[2]<<8) | cntb[3];
    printf("PACK found: objects=%u\n", object_count);

    // iterate objects
    for (uint32_t i = 0; i < object_count; ++i) {
        unsigned char c;
        if (fread(&c, 1, 1, fp) != 1) { 
            fprintf(stderr, "unexpected EOF reading object header\n"); 
            break; 
        }
        int type = (c >> 4) & 7;
        long size = c & 0x0F;
        int shift = 4;
        while (c & 0x80) {
            if (fread(&c, 1, 1, fp) != 1) { 
                fprintf(stderr, "unexpected EOF reading size\n"); 
                goto cleanup; 
            }
            size |= ((long)(c & 0x7F) << shift);
            shift += 7;
        }
        printf("OBJECT %u header: type=%d size=%ld\n", i+1, type, size);

        // For base objects (1..4) decompress stream and write
        if (type >= 1 && type <= 4) {
            z_stream zs;
            memset(&zs, 0, sizeof(zs));
            if (inflateInit(&zs) != Z_OK) { 
                fprintf(stderr, "inflateInit failed\n"); 
                goto cleanup; 
            }

            const size_t IN_BUF = 8192;
            unsigned char inbuf[IN_BUF];
            size_t out_alloc = (size_t)(size > 0 ? size * 2 : 8192);
            unsigned char *outbuf = malloc(out_alloc);
            if (!outbuf) { 
                perror("malloc"); 
                inflateEnd(&zs); 
                goto cleanup; 
            }
            size_t out_len = 0;
            int finished = 0;

            while (!finished) {
                size_t have = fread(inbuf, 1, IN_BUF, fp);
                if (have == 0) {
                    if (feof(fp)) { 
                        fprintf(stderr, "EOF inside compressed stream\n"); 
                        break; 
                    }
                }
                zs.next_in = inbuf;
                zs.avail_in = (uInt)have;

                while (zs.avail_in > 0) {
                    if (out_len + 8192 > out_alloc) {
                        out_alloc *= 2;
                        unsigned char *tmp = realloc(outbuf, out_alloc);
                        if (!tmp) { 
                            perror("realloc"); 
                            free(outbuf); 
                            inflateEnd(&zs); 
                            goto cleanup; 
                        }
                        outbuf = tmp;
                    }
                    zs.next_out = outbuf + out_len;
                    zs.avail_out = (uInt)(out_alloc - out_len);

                    int zret = inflate(&zs, Z_NO_FLUSH);
                    if (zret == Z_NEED_DICT || zret == Z_DATA_ERROR || zret == Z_MEM_ERROR) {
                        fprintf(stderr, "inflate error %d\n", zret);
                        inflateEnd(&zs);
                        free(outbuf);
                        goto cleanup;
                    }
                    size_t produced = (out_alloc - out_len) - zs.avail_out;
                    out_len += produced;

                    if (zret == Z_STREAM_END) {
                        long unread = (long)zs.avail_in;
                        if (unread > 0) { 
                            if (fseek(fp, -unread, SEEK_CUR) != 0) 
                                perror("fseek back"); 
                        }
                        finished = 1;
                        break;
                    }
                }
            }

            inflateEnd(&zs);

            printf("  => decompressed %zu bytes (declared %ld)\n", out_len, size);
            if (out_len > 0) {
                write_object_to_git_repo(repo_path, outbuf, out_len, type);
            }

            free(outbuf);
        } else {
            // delta (6 or 7): skip for now
            printf("  => skipping delta object (type=%d)\n", type);
            z_stream zs;
            memset(&zs, 0, sizeof(zs));
            if (inflateInit(&zs) != Z_OK) { 
                fprintf(stderr,"inflateInit failed (delta)\n"); 
                goto cleanup; 
            }
            const size_t IN_BUF = 8192;
            unsigned char inbuf[IN_BUF], discard[8192];
            int finished = 0;
            while (!finished) {
                size_t have = fread(inbuf, 1, IN_BUF, fp);
                if (have == 0) { 
                    if (feof(fp)) break; 
                }
                zs.next_in = inbuf;
                zs.avail_in = (uInt)have;
                while (zs.avail_in > 0) {
                    zs.next_out = discard;
                    zs.avail_out = sizeof(discard);
                    int zret = inflate(&zs, Z_NO_FLUSH);
                    if (zret == Z_STREAM_END) {
                        long unread = (long)zs.avail_in;
                        if (unread > 0) 
                            if (fseek(fp, -unread, SEEK_CUR) != 0) 
                                perror("fseek back");
                        finished = 1;
                        break;
                    }
                    if (zret == Z_NEED_DICT || zret == Z_DATA_ERROR || zret == Z_MEM_ERROR) {
                        fprintf(stderr,"inflate error (delta) %d\n", zret);
                        inflateEnd(&zs);
                        goto cleanup;
                    }
                }
            }
            inflateEnd(&zs);
        }
    }

cleanup:
    fclose(fp);
}

void req_object_file(const char *url, const char *sha) {
    FILE *fp = fopen("packfile.response", "wb");
    if (!fp) { 
        perror("open packfile.response"); 
        return; 
    }

    char body[1024];
    // Request without deltas - note the extra capabilities
    snprintf(body, sizeof(body), 
             "0054want %s no-progress include-tag ofs-delta\n"
             "0000"
             "0009done\n", sha);
    char final_url[1024];
    snprintf(final_url, sizeof(final_url), "%s/git-upload-pack", url);

    printf("DEBUG: Requesting from URL: %s\n", final_url);
    printf("DEBUG: Request body: %s\n", body);

    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL *curl = curl_easy_init();
    if (curl) {
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/x-git-upload-pack-request");
        
        curl_easy_setopt(curl, CURLOPT_URL, final_url);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(body));
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);  // DEBUG: verbose output

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        else
            printf("DEBUG: curl request succeeded\n");
        
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    fclose(fp);
    curl_global_cleanup();
}

int git_clone_cmd(char *url, char *directory) {
    if (mkdir(directory, 0755) != 0) {
        perror("error creating a directory while cloning the initial stage");
        return 0;
    }
    
    // FIX: Save current directory to restore later
    char original_dir[1024];
    if (getcwd(original_dir, sizeof(original_dir)) == NULL) {
        perror("getcwd");
        return 0;
    }
    
    if (chdir(directory) != 0) {
        perror("chdir");
        return 0;
    }
    
    system("mkdir -p .git/objects .git/refs");

    FILE *head = fopen(".git/HEAD", "w");
    if (!head) {
        perror("fopen .git/HEAD");
        chdir(original_dir);
        return 0;
    }
    fprintf(head, "ref: refs/heads/master\n");
    fclose(head);

    printf("Initialized empty Git repository in %s/.git\n", directory);

    // --- Fetch refs using curl ---And it really works all the above code
    char final_url[1024];
    snprintf(final_url, sizeof(final_url), "%s/info/refs?service=git-upload-pack", url);

    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "curl init failed\n");
        chdir(original_dir);
        return 0;
    }

    FILE *f = fopen("repoDetails.txt", "wb");
    if (!f) {
        perror("error creating the file to write the responses");
        curl_easy_cleanup(curl);
        chdir(original_dir);
        return 0;
    }

    curl_easy_setopt(curl, CURLOPT_URL, final_url);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, f);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");

    CURLcode res = curl_easy_perform(curl);
    fclose(f);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        chdir(original_dir);
        return 0;
    }
    curl_easy_cleanup(curl);

    // --- Parse the pkt-lines from the file ---
    FILE *fp = fopen("repoDetails.txt", "rb");
    if (!fp) {
        perror("error while opening the file to read");
        chdir(original_dir);
        return 0;
    }

    ref_entry *refs = malloc(200 * sizeof(ref_entry));
    if (!refs) {
        perror("malloc failed");
        fclose(fp);
        chdir(original_dir);
        return 1;
    }

    int ref_count = get_ref_maps(refs, fp);
    printf("DEBUG: ref_count = %d\n", ref_count);
    fclose(fp);

    //printf("Successfully mapped %d refs\n", ref_count);
    printf("Ref[0]: %s\n", refs[0].ref_name);

    printf("\n=== Parsed Git References ===\n");
    for (int j = 0; j < ref_count; j++) {
        printf("[%d] %s -> %s\n", j + 1, refs[j].sha, refs[j].ref_name);
    }
    printf("==============================\n");
    fflush(stdout); 
    // FIX: The strcmp logic was inverted
    char *head_sha = NULL;
    for (int j = 0; j < ref_count; j++) {
        if (strcmp(refs[j].ref_name, "refs/heads/main") == 0) {  // FIX: == 0 means equal
            head_sha = refs[j].sha;
            break;
        }
    }
    printf("DEBUGG :must execute id sha is created\n");
    
    // FIX: Also try "master" if "main" not found
    if (!head_sha) {
        for (int j = 0; j < ref_count; j++) {
            if (strcmp(refs[j].ref_name, "refs/heads/master") == 0) {
                head_sha = refs[j].sha;
                break;
            }
        }
    }
    
    if (!head_sha) {
        fprintf(stderr, "Could not find refs/heads/main or refs/heads/master\n");
        fprintf(stderr, "Available refs:\n");
        for (int j = 0; j < ref_count; j++) {
            fprintf(stderr, "  %s -> %s\n", refs[j].ref_name, refs[j].sha);
        }
        free(refs);
        curl_global_cleanup();
        chdir(original_dir);
        return 0;
    }
    
    printf("Found HEAD SHA: %s\n", head_sha);

    printf("Requesting packfile from server...\n");
    req_object_file(url, head_sha);
    
    // Check if packfile was created
    FILE *check = fopen("packfile.response", "rb");
    if (!check) {
        fprintf(stderr, "ERROR: packfile.response not created!\n");
        free(refs);
        curl_global_cleanup();
        chdir(original_dir);
        return 0;
    }
    fseek(check, 0, SEEK_END);
    long fsize = ftell(check);
    fclose(check);
    printf("Packfile size: %ld bytes\n", fsize);
    if (fsize == 0) {
        fprintf(stderr, "ERROR: packfile.response is empty!\n");
        free(refs);
        curl_global_cleanup();
        chdir(original_dir);
        return 0;
    }
    
    // FIX: Pass "." as repo_path since we're already in the directory
    decompress_packfile_into_repo(".", "packfile.response");
    
    free(refs);
    curl_global_cleanup();
    
    // Restore original directory
    chdir(original_dir);
    
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
 