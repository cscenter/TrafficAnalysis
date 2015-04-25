#include <vector>
#include <climits>

class Statistic_data {
private:
    std::vector< std::vector<double> > data;
public:

    Statistic_data();
    int get_nearest(const std::vector<double> & v) const;

};

