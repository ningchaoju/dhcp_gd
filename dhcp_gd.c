#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#define __USE_GNU
#include <search.h>
#include <openssl/evp.h> 

#include "dhcp_gd.h"


typedef struct _ENTRY
{
    unsigned int used;
    ENTRY entry;
}
_ENTRY;

struct hsearch_data *hash_head;
struct  data_t *data[MAX_HASH_SIZE];

void hash_init()
{
    int i;
    for(i=0;i<MAX_HASH_SIZE;i++)
    {
        data[i]=(struct data_t *)calloc(1,sizeof(struct data_t));
        if(data[i]==NULL)
        {
            perror("Failed to calloc:");
            exit(-1);
        }
    }
    timeout_time=60;
    timeout_count=10;
    array_count = -1;
}


int hash_create(unsigned long hash_size,struct hsearch_data **hash_table)
{
    int rv;
    if(*hash_table==NULL) {
        *hash_table = (struct hsearch_data*)calloc(1,sizeof(struct hsearch_data));
        if(*hash_table==NULL)
        {
            perror("Failed to calloc:");
            return -1;
        }
        rv =  hcreate_r(hash_size, *hash_table);  
        if(rv ==0 )
        {   
            perror("cannot create hashtable:"); 
            return -1; 
        }
        return 0;     
    }
    return 0;
}

int hash_search(ENTRY in, ENTRY **out, struct hsearch_data *hash_table)
{
    int rv ;
    rv = hsearch_r(in, FIND, out, hash_table);
    return rv ;
}

int hash_insert(ENTRY in, ENTRY **out, struct hsearch_data *hash_table)
{
    int rv;
    rv  =  hsearch_r(in, ENTER, out, hash_table);
    return rv ;
}

void hash_destroy(struct hsearch_data *hash_table)
{
    int i;
    for(i=0;i<MAX_HASH_SIZE;i++)
    {
        free(data[i]);
    }
    hdestroy_r(hash_table);

}

static void handle_sigint(int signo)
{
    printf("SIGINT signale occur,free memory\n");
    hash_destroy(hash_head);
    exit(-1);
}


static void setup_signals(void)
{
    struct sigaction s;

    memset(&s, 0, sizeof(struct sigaction));
    s.sa_handler = handle_sigint;
    s.sa_flags = 0;
    sigaction(SIGINT, &s, NULL);
}


int first_insert(char *mac,struct hsearch_data *hash_table)
{
    int rv;
    ENTRY in; 
    ENTRY *out=NULL;

    array_count++;
    data[array_count]->count = 1;
    data[array_count]->start = time((time_t*)NULL);

    in.key=mac;
    in.data=(void  *)data[array_count];
    rv = hash_insert(in,&out,hash_table);
    if(rv == 0)
    {
        printf("Failed to insert mac[%s]\n",in.key);
        return -1;
    }
#if 1
    if(DEBUG){
        printf("\tinsert mac=%s\n",out->key);
        printf("\tinsert count=%d\n",((struct data_t *)out->data)->count);
        printf("\tinsert start=%ld\n",((struct data_t *)out->data)->start);
    }
#endif
    return 0;
}

int update_insert(ENTRY *out)
{
#if 1
    if(DEBUG){
        printf("\tsearch mac=%s\n",out->key);
        printf("\tsearch count=%d\n",((struct data_t *)out->data)->count);
        printf("\tsearch start=%ld\n",((struct data_t *)out->data)->start);
    }
#endif

    unsigned int count;
    unsigned long start; 
    long int current_time;

    count = ((struct data_t *)out->data)->count;   
    start = ((struct data_t *)out->data)->start; 
    current_time = time((time_t*)NULL);

    if(current_time - start <= timeout_time)  //<60s
    {
        if(count < timeout_count)
        {
            if(DEBUG){
                printf("\tin %ds,less more %d counts [%d]\n",timeout_time,timeout_count,count);
            }
            (((struct data_t *)out->data)->count)++;    
            if(DEBUG){
                printf("\tupdate mac[less]=%s\n",out->key);
                printf("\tupdate count[less]=%d\n",((struct data_t *)out->data)->count);
                printf("\tupdate start[less]=%ld\n",((struct data_t *)out->data)->start);
            }
        }else
        {
            if(DEBUG){
                printf("\tin %ds, more than %d counts [%d]\n",timeout_time,timeout_count,count);
            }
            (((struct data_t *)out->data)->count)++;    
            if(DEBUG){
                printf("\tupdate mac[more]=%s\n",out->key);
                printf("\tupdate count[more]=%d\n",((struct data_t *)out->data)->count);
                printf("\tupdate start[more]=%ld\n",((struct data_t *)out->data)->start);
            }
            return -1; 
        }

    }else  //>60s
    {
        if(DEBUG){
            printf("\tout %ds,reset data\n",timeout_time);
        }
        (((struct data_t *)out->data)->count) = 1;    
        (((struct data_t *)out->data)->start) = time((time_t*)NULL);
        if(DEBUG){
            printf("\trest mac=%s\n",out->key);
            printf("\treset count=%d\n",((struct data_t *)out->data)->count);
            printf("\treset start=%ld\n",((struct data_t *)out->data)->start);
        }
    }
    return 0;
}


int package_limit_mac(char *mac)
{
    int rv; 
    int find;
    ENTRY in;
    ENTRY *out=NULL;

    setup_signals();

    rv = hash_create(MAX_HASH_SIZE,&hash_head); 
    if(rv != 0)
    {
        return -1;
    }

    memset(&in,0,sizeof(ENTRY));

    in.key=mac;
    find = hash_search(in,&out,hash_head);
    if(find == 0)
    {
        if(DEBUG)
        {
            printf("Not find mac [%s]\n",in.key);
        }
        rv = first_insert(mac,hash_head);
        if(rv != 0)
        {   
            return -1;
        }
    }
    if(find == 1)
    {
        if(DEBUG){
            printf("Find mac [%s]\n",out->key);
        }

        rv = update_insert(out); 
        if(rv != 0)
        {
            return -1;
        }
    }
    return 0;
}








char *password = "ncj390266522";

int hash_digest(const char *digest_name,const unsigned char *in,unsigned char *out,unsigned int *out_len)
{
    EVP_MD_CTX ctx;
    const EVP_MD *md=NULL;

    unsigned char md_value[EVP_MAX_MD_SIZE];
    int md_len, i,rv;


    //使EVP_Digest系列函数支持所有有效的信息摘要算法
    OpenSSL_add_all_digests();

    //根据输入的信息摘要函数的名字得到相应的EVP_MD算法结构
    md = EVP_get_digestbyname(digest_name);
    if(!md) {
        perror("EVP_get_digestbyname:");
        return -1;
    }

    //初始化信息摘要结构ctx，这在调用EVP_DigestInit_ex函数的时候是必须的。
    EVP_MD_CTX_init(&ctx);

    //使用md的算法结构设置ctx结构，impl为NULL，即使用缺省实现的算法（openssl本身提供的信息摘要算法）
    rv = EVP_DigestInit_ex(&ctx, md, NULL);
    if(rv != 1)
    {
        perror("VP_DigestInit_ex");
        return -1;
    }

    //开始真正进行信息摘要运算，可以多次调用该函数，处理更多的数据，这里只调用了1次
    rv = EVP_DigestUpdate(&ctx, in, strlen(in));
    if(rv != 1)
    {
        perror("EVP_DigestUpdate");
        return -1;
    }
    //EVP_DigestUpdate(&ctx, mess2, strlen(mess2));

    //完成信息摘要计算过程，将完成的摘要信息存储在md_value里面,长度信息存储在md_len里面
    rv = EVP_DigestFinal_ex(&ctx, out, out_len);
    if(rv != 1)
    {
        perror("EVP_DigestFinal_ex");
        return -1;
    }

    //使用该函数释放ctx占用的资源，如果使用_ex系列函数，这是必须调用的。
    EVP_MD_CTX_cleanup(&ctx);
    return 0;
}



int do_crypt(const EVP_CIPHER *cipher_type,unsigned char *in,int in_len,unsigned char *out, int *out_len, const unsigned char *key,const unsigned char *iv,int enc)
{
    int rv;
    int temp_len;    

    EVP_CIPHER_CTX ctx;           //EVP算法上下文  

    OpenSSL_add_all_algorithms(); //load all algorithms 
    EVP_CIPHER_CTX_init(&ctx);    //初始化密码算法结构体 

    //设置算法和密钥
    rv = EVP_CipherInit_ex(&ctx,cipher_type, NULL,key,iv,enc);
    if(rv != 1)  
    {  
        perror("Fauled to EVP_CipherInit_ex:");  
        goto out;  
    }  

    rv = EVP_CipherUpdate(&ctx, out, out_len, in, in_len); 
    if(rv != 1)  
    {  
        perror("Fauled to EVP_CipherUpdate:");  
        goto out;  
    } 

    rv = EVP_CipherFinal_ex(&ctx, out + (*out_len),&temp_len); 
    if(rv != 1)  
    {  
        perror("Fauled to EVP_CipherUpdate:");  
        goto out;  
    } 

    *out_len += temp_len;
    EVP_CIPHER_CTX_cleanup(&ctx);    
    return 0; 
out: 
    EVP_CIPHER_CTX_cleanup(&ctx);    
    return -1;  

}


int option_encrypt(unsigned char *message)
{
    unsigned char *user = "390266522@qq.com";
    char *password = "ncj390266522";
    printf("user:\t[%d][%s]\n",strlen(user),user);
    printf("passwd:\t[%d][%s]\n",strlen(password),password);

    int i;
    int rv;
    unsigned char r[16]={0};
    unsigned long ts;
    unsigned char key_password[128]={"12345678"};   
    unsigned char key[64] = {0};
    unsigned int key_len;
    int out_len;
    unsigned char out[1024]={0};


    EVP_CIPHER *cipher_type=NULL;
    cipher_type=EVP_des_ede3_ecb();

    struct option_t option_field;
    memset(&option_field,0,sizeof(option_field));

    option_field.flag = 0x1;
    printf("flag:\t[%x]\n",option_field.flag);

    RAND_pseudo_bytes(r,8);
    memcpy(option_field.r,r,8);
    printf("r:\t[%d][",strlen(option_field.r));
    for(i=0;i<strlen(option_field.r);i++)
    {
        printf("%x",option_field.r[i]);
    }
    printf("]\n");


    ts=time((time_t*)NULL);
    //option_field.ts = ts;
    printf("ts:\t[%d][%ld]\n",sizeof(option_field.ts),option_field.ts);
    rv = hash_digest("md5",key_password,key,&key_len);    
    if(rv != 0)
    {   
        return -1; 
    } 
    memcpy(option_field.key,key,16);
    printf("key:\t[%d[",16);
    for(i = 0; i < 16; i++){
        printf("%02x", option_field.key[i]);
    }   
    printf("]\n");



    struct login_key_t login_key;
    memset(&login_key,0,sizeof(login_key));
    memcpy(login_key.r,r,8);
    login_key.ts=ts;
    memcpy(login_key.zero,"00000000",8);


    rv = do_crypt(cipher_type,user,strlen(user), out, &out_len, (unsigned char*)&login_key,  NULL,1); 
    if(rv!=0)
    {
        return -1;
    }

    memcpy(option_field.login,out,out_len);

    printf("login：\t[%d][",strlen(option_field.login)); 
    for(i=0;i<strlen(option_field.login);i++)  
    {   
        printf("%x",option_field.login[i]);  
    }   
    printf("]\n"); 

    memcpy(message,(unsigned char *)&option_field,sizeof(option_field));

    return 0;
#if 0
#endif
} 



int option_parse(unsigned char *message,unsigned int message_len,unsigned char *user)
{
    int i,rv;
    int out_len;
    EVP_CIPHER *cipher_type=NULL;
    unsigned char out[128]={0};
    unsigned char login_key[32]={0};
    unsigned char login[128]={0};

    if(!message)
    {
        printf("message is NULL\n");
        return -1;
    }

    switch(message[0])
    {
        case 1:
            cipher_type=EVP_des_ede3_ecb();
            break;
        default:
            printf("Unknow flag :[%02x]\n",message[0]);
            return -1;
    }
    for(i=0;i<16;i++)
    {  
        login_key[i] = message[i+1];
    }  
    for(i=16;i<24;i++)
    {   
        login_key[i] = 0x00;
    }  

    for(i=33;i<message_len;i++)
    {
        login[i-33] = message[i];
    }
    
    rv = do_crypt(cipher_type,login,message_len-1-8-8-16, out, &out_len, login_key, NULL,0); 
    if(rv!=0)
    {   
        return -1; 
    } 
    memcpy(user,out,out_len);
    return 0;
}
