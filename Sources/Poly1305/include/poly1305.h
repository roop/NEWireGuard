
#ifndef POLY1305_H
#define POLY1305_H

int crypto_onetimeauth(unsigned char *out,const unsigned char *in,unsigned long long inlen,const unsigned char *k);

#endif
