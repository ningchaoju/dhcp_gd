#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "dhcp_gd.h"

int main(int argc,char *argv[])
{   
    int rv;
        int i;
    int j;
    int count=100000;
    int times=60;
    unsigned char buf[32]={0};
    unsigned long first_time,last_time;

    hash_init();

    first_time=time((time_t*)NULL);
    for(j=1;j<times+1;j++)
    {
        printf("[%d]times:\n",j);
        //usleep(1000000);
        for(i=1;i<count;i++)
        {
            printf("\n\t[%d]mac:\n\t",i);

            //usleep(100000);
            memset(buf,0,sizeof(buf));
            sprintf(buf,"%04daabbccdd",i); 
            rv = package_limit_mac(buf);
            if(rv != 0)
            {
                printf("\tpackage ls limited!\n");
                //goto out;
            }else{   
                printf("\tpackage ls permit!\n");
            }
        }
    }
    last_time=time((time_t*)NULL);
    
    printf("last_time - first_time = [%ld] - [%d] = [%ld]\n",last_time,first_time,last_time-first_time);    

    hash_destroy(hash_head);
    return 0;
out:    
    hash_destroy(hash_head);
    return -1;
}
