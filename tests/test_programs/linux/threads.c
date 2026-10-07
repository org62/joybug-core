/* Two worker threads calling the same function, for breakpoint and thread
 * bookkeeping tests. */
#include <pthread.h>
#include <stdio.h>
#include "../portable.h"

volatile int g_sum = 0;

NOINLINE void worker(int id) {
    g_sum += id;
}

static void *thread_main(void *arg) {
    worker((int)(long)arg);
    return NULL;
}

int main(void) {
    pthread_t t1, t2;
    pthread_create(&t1, NULL, thread_main, (void *)1);
    pthread_create(&t2, NULL, thread_main, (void *)2);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    printf("sum=%d\n", g_sum);
    return g_sum == 3 ? 0 : 1;
}
