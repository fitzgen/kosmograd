#include "stdio.h"
#include "goodbye.h"

typedef struct {
    int n;
    char *name;
} Target;

void hello(Target t) {
    const char *plural;
    if (t.n == 1) {
        plural = "";
    } else {
        plural = "s";
    }
    printf("Hello, %i %s%s!\n", t.n, t.name, plural);
}

const int N = 10;

void shadow() {
    int s = 2;
    {
        int s = 4;
        {
            int s = 6;
            printf("s = %i\n", s);
        }
        printf("s = %i\n", s);
    }
    printf("s = %i\n", s);
}

int main() {
    Target target;
    target.n = N;
    target.name = "Jeena";
    hello(target);

    shadow();

    int a = 5;
    int b = 10;
    printf("%i + %i = %i\n", a, b, a+b);

    goodbye();

    return 0;
}
