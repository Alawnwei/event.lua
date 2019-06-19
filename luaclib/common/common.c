#include "common.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <math.h>

#define PI  (3.141592653589793238462643383279502884)

#define rad(angle) ((angle) * (PI/180))
#define deg(radian) ((radian) * (180/PI))

static const vector2_t VECTOR2_ZERO = {0,0};

//https://zhuanlan.zhihu.com/p/23903445
//
static inline void
vector2_add(vector2_t* result, vector2_t* a, vector2_t* b) {
    result->x = a->x + b->x;
    result->z = a->z + b->z;
}

static inline void
vector2_sub(vector2_t* result, vector2_t* a, vector2_t* b) {
    result->x = a->x - b->x;
    result->z = a->z - b->z;
}

static inline float
vector2_dot(vector2_t* a, vector2_t* b) {
    return a->x * b->x + a->z * b->z;
}

static inline float
vector2_magnitude2(vector2_t* u) {
    return u->x * u->x + u->z * u->z;
}

static inline float
vector2_magnitude(vector2_t* u) {
    return sqrt(vector2_magnitude2(u));
}

static inline void
vector2_lerp(vector2_t* result, vector2_t* from, vector2_t* to, float ratio) {
    result->x = from->x + (to->x - from->x) * ratio;
    result->z = from->z + (to->z - from->z) * ratio;
}

static inline float
vector2_angle(vector2_t* a, vector2_t* b) {
    float scalar = sqrt(vector2_magnitude2(a) * vector2_magnitude2(b));
    return rad(acos(vector2_dot(a, b) / scalar));
}

inline void
vector2_rotation(vector2_t* dot, vector2_t* center,float angle) {
    float r = rad(angle);
    float si = sin(r);
    float co = cos(r);

    float x = dot->x;
    float z = dot->z;
    dot->x = (x - center->x) * co - (z - center->z) * si + center->x;
    dot->z = (x - center->x) * si + (z - center->z) * co + center->z;
}

inline float
sqrt_dot2dot(vector2_t* a, vector2_t* b) {
    return (a->x - b->x) * (a->x - b->x) + (a->z - b->z) * (a->z - b->z);
}

inline float
dot2dot(vector2_t* a, vector2_t* b) {
    return sqrt(sqrt_dot2dot(a, b));
}

void
move_torward(vector2_t* result, vector2_t* src, float angle, float dt) {
    float radian = rad(angle);
    result->x = cos(radian) * dt + src->x;
    result->z = sin(radian) * dt + src->z;
}

void
move_forward(vector2_t* result, vector2_t* from, vector2_t* to, float pass) {
    float dt = dot2dot(from, to);
    if (dt == 0) {
        result->x = from->x;
        result->z = from->z;
        return;
    }
    float ratio = pass / dt;
    if (ratio > 1) {
        ratio = 1;
    }

    vector2_lerp(result, from, to, ratio);
}

static inline float
sqrt_dot2segment(vector2_t* x0, vector2_t* u, vector2_t* x) {
    vector2_t vt;

    vector2_sub(&vt, x, x0);

    float t = vector2_dot(&vt, u) / vector2_magnitude2(u);
    if (t < 0) {
        t = 0;
    } else if (t > 1) {
        t = 1;
    }

    vector2_t dot;
    dot.x = x0->x + t * u->x;
    dot.z = x0->z + t * u->z;

    return sqrt_dot2dot(x, &dot);
}

float
dot2segment(vector2_t* x0, vector2_t* x1, vector2_t* x) {
    vector2_t u;
    u.x = x1->x - x0->x;
    u.z = x1->z - x0->z;
    return sqrt(sqrt_dot2segment(x0, &u, x));
}

int
capsule_intersect(vector2_t* src, vector2_t* u, float cr, vector2_t* center, float r) {
    return sqrt_dot2segment(src, u, center) <= (cr + r) * (cr + r);
}

int
rectangle_intersect(vector2_t* src, float length, float width, float angle, vector2_t* center, float r) {
    float radian = rad(angle);

    vector2_t rt_center;
    rt_center.x = src->x + (cos(radian) * (length / 2));
    rt_center.z = src->z + (sin(radian) * (length / 2));

    vector2_t delta_center;
    delta_center.x = center->x - rt_center.x;
    delta_center.z = center->z - rt_center.z;

    vector2_rotation(&delta_center, (vector2_t*)&VECTOR2_ZERO, 360 - angle);

    vector2_t h;
    h.x = length / 2;
    h.z = width / 2;

    vector2_t v;
    v.x = delta_center.x >= 0 ? delta_center.x : -delta_center.x;
    v.z = delta_center.z >= 0 ? delta_center.z : -delta_center.z;

    vector2_t u;
    u.x = v.x - h.x < 0 ? 0 : v.x - h.x;
    u.z = v.z - h.z < 0 ? 0 : v.z - h.z;

    return vector2_magnitude2(&u) <= r * r;
}

int
sector_intersect(vector2_t* src, float angle, float degree, float l, vector2_t* center, float r) {
    vector2_t dt;
    vector2_sub(&dt, center, src);

    float range = l + r;

    float sqrt_magnitude = vector2_magnitude2(&dt);
    if ( sqrt_magnitude > range * range) {
        return 0;
    }

    float radian = rad(angle);

    vector2_t u;
    u.x = cos(radian);
    u.z = sin(radian);

    vector2_t abs_u;
    abs_u.x = -u.z;
    abs_u.z = u.x;

    float px = vector2_dot(&dt, &u);
    float pz = abs(vector2_dot(&dt, &abs_u));

    float theta = rad(degree / 2);
    if (px > sqrt(sqrt_magnitude) * cos(theta)) {
        return 1;
    }

    vector2_t q;
    q.x = l * cos(theta);
    q.z = l * sin(theta);

    vector2_t p;
    p.x = px;
    p.z = pz;

    return sqrt_dot2segment((vector2_t*)&VECTOR2_ZERO, &q, &p) <= r * r;
}

int
circle_intersect(vector2_t* src, float l, vector2_t* center, float r) {
    vector2_t d;
    vector2_sub(&d, src, center);

    float range = l + r;
    if (abs(d.x) <= range && abs(d.z) <= range) {
        return vector2_magnitude2(&d) <= range * range;
    }
    return 0;
}

int
segment_intersect(vector2_t* a, vector2_t* b, vector2_t* center, float r) {
    vector2_t u;
    vector2_sub(&u, b, a);

    return sqrt_dot2segment(a, &u, center) <= (r * r);
}

int
in_front_of(vector2_t* src, float angle, vector2_t* dot) {
    vector2_t delta;
    vector2_sub(&delta, dot, src);

    if (delta.x == 0 && delta.z == 0) {
        return 1;
    }

    float z_angle = deg(atan2(delta.x, delta.z));
    float diff_z_angle = z_angle - angle;

    if (diff_z_angle >= 270) {
        diff_z_angle -= 360;
    } else if (diff_z_angle <= -270) {
        diff_z_angle += 360;
    }

    if (diff_z_angle < -90 || diff_z_angle > 90) {
        return 0;
    }

    return 1;
}

int
inside_circle(vector2_t* center, float l, vector2_t* dot, float r) {
    return circle_intersect(center, l, dot, r);
}

int
inside_sector(vector2_t* center, float angle, float degree, float l, vector2_t* dot, float r) {
    if (in_front_of(center, angle, dot) == 0) {
        return 0;
    }

    vector2_t delta;
    vector2_sub(&delta, dot, center);

    if (delta.x == 0 && delta.z == 0) {
        return 1;
    }

    if (inside_circle(center, l, dot, r) == 0) {
        return 0;
    }

    float z_angle = deg(atan2(delta.x, delta.z));

    float diff_z_angle = z_angle - angle;
    float trans_z_angle = diff_z_angle + degree / 2;

    while (trans_z_angle > 360) {
        trans_z_angle -= 360;
    }

    while (trans_z_angle < 0) {
        trans_z_angle += 360;
    }

    return trans_z_angle <= degree;
}

int
inside_rectangle(vector2_t* src, float angle, float length, float width, vector2_t* dot, float r) {
    if (in_front_of(src, angle, dot) == 0) {
        return 0;
    }
    
    vector2_t delta;
    vector2_sub(&delta, dot, src);

    if (delta.x == 0 && delta.z == 0) {
        return 1;
    }

    float z_angle = deg(atan2(delta.x, delta.z));
    float diff_z_angle = z_angle - angle;

    if (diff_z_angle >= 270) {
        diff_z_angle -= 360;
    } else if (diff_z_angle <= -270) {
        diff_z_angle += 360;
    }

    if (diff_z_angle < -90 || diff_z_angle > 90) {
        return 0;
    }

    float diff_z_radian = deg(abs(diff_z_angle));

    float diff_len = sqrt(vector2_magnitude2(&delta));

    float change_x = diff_len * cos(diff_z_radian);
    float change_z = diff_len * sin(diff_z_radian);

    if ((change_x < 0 || change_x > length) || (change_z < 0 ||  change_z > (width / 2))) {
        return 0;
    }
    return 1;
}

int
segment_intersect_segment(vector2_t* cross, vector2_t* p1, vector2_t* p2, vector2_t* p3, vector2_t* p4) {
    float p0_x = p1->x;
    float p0_z = p1->z;
    float p1_x = p2->x;
    float p1_z = p2->z;
    float p2_x = p3->x;
    float p2_z = p3->z;
    float p3_x = p4->x;
    float p3_z = p4->z;

    float s10_x = p1_x - p0_x;
    float s10_z = p1_z - p0_z;
    float s32_x = p3_x - p2_x;
    float s32_z = p3_z - p2_z;

    float denom = s10_x * s32_z - s32_x * s10_z;
    if (denom == 0)//平行或共线
        return 0; // Collinear

    int demon_positive = denom > 0;

    float s02_x = p0_x - p2_x;
    float s02_z = p0_z - p2_z;
    float s_numer = s10_x * s02_z - s10_z * s02_x;
    if ((s_numer < 0) == demon_positive)
        return 0; // No collision

    float t_numer = s32_x * s02_z - s32_z * s02_x;
    if ((t_numer < 0) == demon_positive)
        return 0; // No collision

    if (fabs(s_numer) > fabs(denom) || fabs(t_numer) > fabs(denom))
        return 0; // No collision
    // Collision detected
    float t = t_numer / denom;
    
    cross->x = p0_x + (t * s10_x);

    cross->z = p0_z + (t * s10_z);

    return 1;
}

void
random_in_circle(vector2_t* result, vector2_t* center, float radius) {
    float angle = rand() % 360;
    float rand_radius = rand() % (int)radius;

    float dx = sin(rad(angle)) * rand_radius;
    float dz = cos(rad(angle)) * rand_radius;

    result->x = center->x + dx;
    result->z = center->z + dz;
}

void
random_in_rectangle(vector2_t* result, vector2_t* center, float length, float width, float angle) {
    float dx = rand() % (int)length - length / 2;
    float dz = rand() % (int)width - width / 2;

    result->x = center->x + dx;
    result->z = center->z + dz;

    if (angle <= 0.1) {
        return;
    }

    vector2_rotation(result, center, 360 - angle);
}
