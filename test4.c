#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void build_password(char *out)
{
    static volatile unsigned char enc[] = {
        0x36, 0x3F, 0x2E, 0x37, 0x3F, 0x33, 0x34, 0x6B, 0x68, 0x69
    };
    const unsigned char key = 0x5A;
    size_t n = sizeof(enc) / sizeof(enc[0]);

    for (size_t i = 0; i < n; i++)
        out[i] = (char)(enc[i] ^ key);

    out[n] = '\0';
}

int check_password(const char *input, const char *pw)
{
    return strcmp(input, pw) == 0;
}

int main(void)
{
    char *input = malloc(128);
    char *pw    = malloc(64);
    if (!input || !pw) { free(input); free(pw); return 1; }

    build_password(pw);

    printf("Password: ");
    if (!fgets(input, 128, stdin)) {
        free(input); free(pw);
        return 1;
    }
    input[strcspn(input, "\n")] = '\0';

    int ok = check_password(input, pw);

    if (ok) puts("Access granted.");
    else    puts("Wrong.");

    free(input);
    free(pw);
    return ok ? 0 : 1;
}
