#include <Security/cssm.h>
#include <stdio.h>
int main(void) {
    printf("CSSM_ALGID_SHA256WithRSA=%u\n", (unsigned)CSSM_ALGID_SHA256WithRSA);
    printf("CSSM_ALGID_SHA1WithRSA=%u\n",   (unsigned)CSSM_ALGID_SHA1WithRSA);
    printf("CSSM_ALGID_RSA=%u\n",            (unsigned)CSSM_ALGID_RSA);
    printf("CSSM_ALGID_NONE=%u\n",           (unsigned)CSSM_ALGID_NONE);
    return 0;
}
