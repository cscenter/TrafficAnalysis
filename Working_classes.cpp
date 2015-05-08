#include <signal.h>
#include <stdlib.h>
#include <iostream>
#include "Working_classes.h"

void Working_classes::sigfunc(int sig) {
    char c;
    if(sig != SIGINT)
        return;
    else {
        printf("\nХотите завершить программу (y/n) : ");
        while((c=getchar()) == 'n')
        return;
        exit (0);
    }
}

Working_classes::Working_classes() {
    signal(SIGINT,sigfunc);
}
