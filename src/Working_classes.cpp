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

Working_classes::Working_classes(const std::string& config_xml, const std::string& stage, const std::string& working_mode,
                                 const std::string& learning_type, const std::string& device,
                                 const std::string& result_filename)
                :stat_analysator(config_xml, stage, working_mode, learning_type, device, result_filename) {
    signal(SIGINT,sigfunc);
}
