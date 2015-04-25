#include "Statistic_data.h"
#include <iostream>

Statistic_data::Statistic_data() {
    data.resize(2);
    for (int i = 0; i < data.size(); i++) {
        data[i].resize(4);
    }
    data[0][0] = 0; //download
    data[0][1] = 0;
    data[0][2] = 1;
    data[0][3] = 0;
    data[1][0] = 0.51;  //browsing
    data[1][1] = 0.17;
    data[1][2] = 0.19;
    data[1][3] = 0.12;
}

int Statistic_data::get_nearest(const std::vector<double> & v) const {

    int min = INT_MAX, nmin;
    for (int i = 0; i < data.size(); i++) {
        double d = 0;
        for (int j = 0; j < v.size(); j++) {
            d += (v[j] - data[i][j]) * (v[i] - data[i][j]);
        }
        if (d < min) {
            nmin = i;
            min = d;
        }
    }
    return nmin;
}