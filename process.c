#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>

#define NUMS 10

int main() {
    int pipefd[2];
    pid_t pid;
    int sum = 0;

    //int numbers[] = {1,2,3,4,5,67,5,3,78,77,66,55,99,14,34,2,56,56};
    //int n_size = sizeof(numbers)/sizeof(numbers[0]);

    //int n_size -  sizeof(numbers)/sizeof(numbers[0]);

    clock_t start_time = clock();

    if (pipe(pipefd) == -1) {
        perror("pipe failed");
        return 1;
    }
    
    pid = fork();
    if (pid < 0) {
        perror("fork fail");
        return 1;
    }

    if (pid > 0) {
        // producer
        printf("producer started\n");
        close(pipefd[0]); // close reading
        for (int i = 0; i < NUMS; i++) {
            write(pipefd[1], &i, sizeof(i));
            printf("write %d\n", i);
            fflush(stdout);
        }
        close(pipefd[1]);
        wait(NULL);
        printf("producer finished\n");

    } else {    // pid = 0
        // consumer
        printf("consumer started\n");
        close(pipefd[1]); // close writing

        int value;
        while (read(pipefd[0], &value, sizeof(value)) > 0) {
            sum += value;
        }
        printf("consumer result: sum = %d\n", sum);

        close(pipefd[0]);
        exit(0);
    }

    clock_t end_time = clock();
    double execution_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    printf("Execution time: %.4f seconds\n", execution_time);

    return 0;
}