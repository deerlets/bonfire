#include <signal.h>
#include <bonfire.h>

#define BROKER_ADDRESS "tcp://0.0.0.0:30824"
#define BROKER_PUB_ADDRESS "tcp://0.0.0.0:30825"
#define BROKER_SUB_ADDRESS "tcp://0.0.0.0:30826"

static int exit_flag;

static void signal_handler(int sig)
{
    if (sig == SIGINT || sig == SIGQUIT)
        exit_flag = 1;
}

int main()
{
    signal(SIGINT, signal_handler);
    signal(SIGQUIT, signal_handler);

    struct bonfire_broker *bbrk = bonfire_broker_new(BROKER_ADDRESS);
    bonfire_broker_enable_pubsub(bbrk, BROKER_PUB_ADDRESS, BROKER_SUB_ADDRESS);
    while (exit_flag == 0) {
        bonfire_broker_loop(bbrk, 1000);
    }
    bonfire_broker_destroy(bbrk);
}
