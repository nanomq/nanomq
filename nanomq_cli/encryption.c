#include "encryption.h"

static print_help(void)
{
	printf("./nanomq_cli encrypt <content>\n");
}

int
encrypt_start(int argc, char **argv)
{
    if(argc != 3) {
	    print_help();
	    return -1;
    }
	uint8_t hash[HASHLEN];
	get_encrypt(hash, argv[2]);
    for( int i=0; i<HASHLEN; ++i ) printf( "%02x", hash[i] ); printf( "\n" );
	return 0;
}