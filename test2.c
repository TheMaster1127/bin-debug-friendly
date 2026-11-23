#include <stdio.h>
#include <string.h>

static void build_password(char *out)
{
    static volatile unsigned char enc[] = {
        0x39, 0x28, 0x3B, 0x39, 0x31, 0x37, 0x3F, 0x6B, 0x68, 0x69
    };
    const unsigned char key = 0x5A;
    size_t n = sizeof(enc) / sizeof(enc[0]);

    for (size_t i = 0; i < n; i++)
        out[i] = (char)(enc[i] ^ key);

    out[n] = '\0';
}

int check_password(const char *input)
{
    char pw[64];
    build_password(pw);
    return strcmp(input, pw) == 0;
}

int main(void)
{
    char input[128];

    printf("Password: ");
    if (!fgets(input, sizeof input, stdin))
        return 1;

    input[strcspn(input, "\n")] = '\0';

    if (check_password(input)) {
        puts("Access granted.");
        return 0;
    }

    puts("Wrong.");
    return 1;
}
