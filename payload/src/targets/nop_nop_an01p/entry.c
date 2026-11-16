/* entry.c —— 给 HWWLZ 的 run_exploit() 套一个独立可执行入口 */
#include <unistd.h>

extern int run_exploit(int argc, char **argv);

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    static char *av[] = { "glhw", 0 };
    write(2, "PROBE-ENTRY\n", 12);
    int r = run_exploit(1, av);
    write(2, "PROBE-RET\n", 10);
    return r;
}
