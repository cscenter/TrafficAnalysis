#ifndef WORKING_CLASSES_H
#define WORKING_CLASSES_H

#include "Signature_analysis.h"
#include "Statistic_analysis.h"


class Working_classes {
    Signature_analysis *sig_analysator;
    Statistic_analysis *stat_analysator;
public:
    Working_classes();
    ~Working_classes() {
        sig_analysator->print_sessions_list();
        delete stat_analysator;
        delete sig_analysator;
    };
    Signature_analysis* get_signature_analysis() { return sig_analysator; };
    Statistic_analysis* get_statistic_analysys() { return stat_analysator; };
    static void sigfunc(int sig);
};

#endif
