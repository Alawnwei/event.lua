#ifndef TIMEUTIL_H
#define TIMEUTIL_H
#include <time.h>

double get_time_millis();
time_t get_today_start(time_t ts);
time_t get_today_over(time_t ts);
time_t get_week_start(time_t ts);
time_t get_week_over(time_t ts);
time_t get_month_start(time_t ts);
time_t get_month_over(time_t ts);

time_t get_day_time(time_t ts, int hour, int min, int sec);
time_t get_day_time_with_sec(time_t ts, int sec);

int get_diff_day(time_t ts0, time_t ts1);
int get_diff_week(time_t ts0, time_t ts1);

#endif