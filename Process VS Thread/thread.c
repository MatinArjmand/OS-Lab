#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>
#include <pthread.h>

#define BUFFER_SIZE 20000
#define NUMS 1000000

int buffer[BUFFER_SIZE];
int count = 0;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond_full = PTHREAD_COND_INITIALIZER;
pthread_cond_t cond_empty = PTHREAD_COND_INITIALIZER;

void* producer(void* arg) {
    //printf("producer started\n");
    for (int i = 0; i < NUMS; i++) {
        pthread_mutex_lock(&mutex);
        while (count == BUFFER_SIZE) {
            // wait for empty
            pthread_cond_wait(&cond_empty, &mutex);
        }
        buffer[count] = i;
        //printf("produced %d\n", i);
        count++;
        //usleep(100000);
        pthread_cond_signal(&cond_full);
        pthread_mutex_unlock(&mutex);
    }
    return NULL;
}

void* consumer(void* arg) {
    //printf("consumer started\n");
    int sum = 0;
    int consumed_value;
    for (int i = 0; i < NUMS; i++) {
        pthread_mutex_lock(&mutex);
        while (count == 0) {
            // wait for a number to be produced
            pthread_cond_wait(&cond_full, &mutex);
        }
        consumed_value = buffer[count - 1];
        count--;
        //printf("consumed %d\n", consumed_value);
        sum += consumed_value;
        //usleep(100000);
        pthread_cond_signal(&cond_empty);
        pthread_mutex_unlock(&mutex);
    }

    //printf("consumer result: sum = %d\n", sum);
    return NULL;
}

int main() {
    pthread_t prod_thread, cons_thread;

    pthread_mutex_init(&mutex, NULL); 
    pthread_cond_init(&cond_full, NULL);
    pthread_cond_init(&cond_empty, NULL);

    if (pthread_create(&prod_thread, NULL, producer, NULL) != 0) {
        perror("Failed to create producer thread");
        return 1;
    }
    if (pthread_create(&cons_thread, NULL, consumer, NULL) != 0) {
        perror("Failed to create consumer thread");
        return 1;
    }

    // wait for threads
    pthread_join(prod_thread, NULL);
    pthread_join(cons_thread, NULL);

    // destroy mutex and cond variables
    pthread_mutex_destroy(&mutex);
    pthread_cond_destroy(&cond_full);
    pthread_cond_destroy(&cond_empty);

    return 0;
}
