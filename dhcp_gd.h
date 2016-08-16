#ifndef __DHCP_GD_H_
#define __DHCP_GD_H_

#define DEBUG  1


/*package_limit_mac start*/
#define DEBUG  1
#define MAX_HASH_SIZE 10000000

int timeout_time ; 
int timeout_count;

long int array_count; 
extern struct hsearch_data *hash_head;

struct data_t
{
    int  count;
    long start;
};

extern int package_limit_mac(char *mac);

/*package_limit_mac end*/

/*evp_crypt start*/
#include <openssl/evp.h>
/*
    enc:
        0,decrypt
        1,encrypt
*/

extern int do_crypt(const EVP_CIPHER   *cipher_type,
             unsigned char       *in,
             int                 in_len,
             unsigned char       *out,
             int                 *out_len,
             const unsigned char *key,
             const unsigned char *iv, 
             int                 enc);

/*evp_crypt end*/


/*evp_md start*/
/*digest_name : md5 sha1 sha256*/
extern int hash_digest(const char *digest_name,const unsigned char *in,unsigned char *out,unsigned int *out_len);
/*evp_md end*/


/*option60_parse start*/

struct option_t
{
    unsigned char flag;//0x1 3des
    unsigned char r[8];
    unsigned char ts[8];
    unsigned char key[16];
    unsigned char login[128];
};

struct login_key_t
{
    unsigned char r[8];
    unsigned long ts; 
    unsigned  char zero[16];
};
struct password_key_t
{
    unsigned char r[8];
    unsigned  char password[128];
    unsigned long ts; 
};

 int option_parse(unsigned char *message,unsigned int message_len,unsigned char *user);
/*option60_parse end*/

#endif
