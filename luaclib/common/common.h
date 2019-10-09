#ifndef COMMON_H
#define COMMON_H
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

typedef struct vector2 {
	float x;
	float z;
} vector2_t;


float sqrt_dot2dot(vector2_t* a, vector2_t* b);
float dot2dot(vector2_t* a, vector2_t* b);
float dot2segment(vector2_t* x0, vector2_t* x1, vector2_t* x);

void vector2_rotation(vector2_t* dot, vector2_t* center, float angle);
void move_torward(vector2_t* result, vector2_t* from, float angle, float dt);
void move_forward(vector2_t* result, vector2_t* from, vector2_t* to, float pass);

int capsule_intersect(vector2_t* src, vector2_t* u, float cr, vector2_t* center, float r);
int rectangle_intersect(vector2_t* src, float length, float width, float angle, vector2_t* center, float r);
int sector_intersect(vector2_t* src, float angle, float degree, float l, vector2_t* center, float r);
int segment_intersect(vector2_t* a, vector2_t* b, vector2_t* center, float r);
int circle_intersect(vector2_t* src, float l, vector2_t* center, float r);

int inside_circle(vector2_t* center, float range, vector2_t* dot, float r);
int inside_sector(vector2_t* center, float angle, float degree, float l, vector2_t* dot, float r);
int inside_rectangle(vector2_t* src, float angle, float length, float width, vector2_t* dot, float r);

int in_front_of(vector2_t* src, float angle, vector2_t* dot);
int segment_intersect_segment(vector2_t* cross, vector2_t* p1, vector2_t* p2, vector2_t* p3, vector2_t* p4);

void random_in_circle(vector2_t* result, vector2_t* center, float radius);

void random_in_rectangle(vector2_t* result, vector2_t* center, float length, float width, float angle);
#endif