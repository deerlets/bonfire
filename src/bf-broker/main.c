#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <bonfire.h>

#define BROKER_ADDRESS "tcp://0.0.0.0:30824"
#define BROKER_PUB_ADDRESS "tcp://0.0.0.0:30825"
#define BROKER_SUB_ADDRESS "tcp://0.0.0.0:30826"

static int exit_flag;

static void signal_handler(int sig)
{
    if (sig == SIGINT)
        exit_flag = 1;
}

int main()
{
    signal(SIGINT, signal_handler);

    char cache_file[PATH_MAX] = "";
    struct bonfire_broker *bbrk = bonfire_broker_new(BROKER_ADDRESS);
    bonfire_broker_enable_pubsub(bbrk, BROKER_PUB_ADDRESS, BROKER_SUB_ADDRESS);
    snprintf(cache_file, sizeof(cache_file), "/tmp/bf-broker.%d", getpid());
    bonfire_broker_set_cache_file(bbrk, cache_file);
    while (exit_flag == 0) {
        bonfire_broker_loop(bbrk, 1000);
    }
    bonfire_broker_destroy(bbrk);
}
