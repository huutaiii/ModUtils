#pragma once

// #include <glm/glm.hpp>
#include "glm-dx.h"
#include <cmath>
#include <limits>

#ifndef PI
#define PI ((float)(3.141592653589793f))
#endif
#ifndef SMALL_FLOAT
#define SMALL_FLOAT ((float)(0.0001f))
#endif
#ifndef INTERP_MIN_DIST
#define INTERP_MIN_DIST ((float)(1e-8f))
#endif
#ifndef DEG_TO_RAD
#define DEG_TO_RAD ((float)(0.017453292519943295f))
#endif
#ifndef RAD_TO_DEG
#define RAD_TO_DEG ((float)(57.29577951308232f))
#endif

#undef min
#undef max

inline __m128 GLMtoXMM(glm::vec4 v)
{
    return _mm_setr_ps(v.x, v.y, v.z, v.w);
}

inline __m128 GLMtoXMM(glm::vec3 v)
{
    return GLMtoXMM(glm::vec4(v, static_cast<decltype(v.r)>(0)));
}

inline glm::vec4 XMMtoGLM(__m128 m)
{
    float v[4];
    _mm_storer_ps(v, m); // MSVC specific, keeps components in reverse order
    return glm::vec4(v[3], v[2], v[1], v[0]);
}

inline glm::vec4 MemToGLM(void* p)
{
    float* v = (float*)p;
    return glm::vec4(v[0], v[1], v[2], v[3]);
}

inline float RelativeOffsetAlpha(glm::vec3 offset, float max_distance)
{
    return glm::length(offset) / max_distance;
}

template<typename T>
inline T pow2(T x) { return x * x; }

template<typename T>
inline T pow3(T x) { return x * x * x; }

template<typename T>
inline T pow4(T x) { return x * x * x * x; }

template<typename T>
inline T safediv(T x, T y) { return (x == 0 || y == 0) ? 0 : x / y; }

template<typename Tlhs, typename Trhs>
inline decltype(auto) safediv(Tlhs lhs, Trhs rhs) { return rhs == Trhs(0) ? (decltype(lhs * rhs))0 : (lhs / rhs); }

template<typename T>
inline T convnan(T x, T newValue = T(0)) { return isnan(x) ? newValue : x; }

template<typename T>
inline T min(T a, T b) { return a < b ? a : b; }

template<typename T>
inline T max(T a, T b) { return a > b ? a : b; }

template<typename T>
inline T min(T a) { return a; }

template<typename T>
inline T max(T a) { return a; }

template<typename T, typename... Targs>
inline T max(T first, Targs... args)
{
    return max<T>(first, max<T>(args...));
}

template<typename T, typename... Targs>
inline T min(T first, Targs... args)
{
    return min<T>(first, min<T>(args...));
}

template<typename T>
inline T clamp(T x, T a, T b) { return min(b, max(a, x)); }

template<typename T>
inline T saturate(T x) { return clamp(x, T(0), T(1)); }

template<typename Tv, typename Ta>
#pragma warning(suppress : 4244)
inline Tv lerp(Tv x, Tv y, Ta a) { a = clamp(a, Ta(0), Ta(1)); return x * Tv((Ta)1.0 - a) + y * Tv(a); }

// maps range [edge0..edge1] to [0..1] with an in-out curve
template<typename T>
inline T smoothstep(T edge0, T edge1, T x, T replaceNaN = 0) {
    x = clamp((x - edge0) / (edge1 - edge0), (T)0, (T)1);
    if (isnan(replaceNaN) && isnan(x)) return replaceNaN;
    return x * x * (3 - 2 * x);
}

template<typename T>
inline T maprange(T x, T in_min, T in_max, T out_min, T out_max) { return convnan(out_min + (x - in_min) / (in_max - in_min) * (out_max - out_min)); }

template<typename T>
inline T mapclamped(T x, T in_min, T in_max, T out_min, T out_max)
{
    return out_min < out_max ? clamp(maprange(x, in_min, in_max, out_min, out_max)) : clamp(maprange(x, in_min, in_max, out_max, out_min));
}

template<typename T>
inline T oneminus(T x) { return T(1) - x; }

template<typename T>
inline T rcp(T x) { return T(1) / x; }

template<typename T>
inline T safercp(T x) { return safediv<T>(T(1), x); }

template<typename T>
inline T sign(T x) { return T(x >= T(0) ? 1 : -1); }

template<typename T, typename Tresult>
inline Tresult sign(T x) { return Tresult(x >= T(0) ? 1 : -1); }

template<typename T, typename Tresult>
inline Tresult signz(T x) { return x == 0 ? 0 : sign<T, Tresult>(x); }

// clamps x to [-b..-a] or [a..b]
template<typename T>
inline T absclamp(T x, T a, T b) {
#if _DEBUG
    if (a < T(0) || b < T(0))
    {
        throw std::invalid_argument("Endpoints can't be negative");
    }
#endif
    T s = sign<T>(x);
    return s * clamp(abs(x), a, b);
};

// y = (x + bias) * scale
template<typename T>
inline T scalebias(T x, T scale, T bias) { return (x + bias) * scale; }

template<typename T>
inline T hypotenuse(T a, T b) { return std::sqrt(a * a + b * b); }

template<typename T> inline T LinearInterpolation(T x) { return x; }

template<typename T> inline T EaseInSine(T x)
{
    return T(1 - std::cos(PI * x / 2));
}

template<typename T> inline T EaseOutSine(T x)
{
    return T(std::sin(PI * x / 2));
}

template<typename T> inline T EaseInOutSine(T x)
{
    return T(-(std::cos(PI * x) - 1) / 2);
}

template<typename T> inline T EaseInQuad(T x)
{
    return pow2<T>(x);
}

template<typename T> inline T EaseOutQuad(T x)
{
    return T(1) - pow2<T>(T(1) - x);
}

template<typename T> inline T EaseInOutQuad(T x)
{
    return x < T(0.5) ? T(2) * pow2<T>(x) : T(1) - pow2<T>(T(2) - x * T(2)) / T(2);
}

template<typename T> inline T EaseInCubic(T x)
{
    return pow3<T>(x);
}

template<typename T> inline T EaseOutCubic(T x)
{
    return T(1) - pow3<T>(T(1) - x);
}

template<typename T> inline T EaseInOutCubic(T x)
{
    return x < T(0.5) ? T(4) * pow3<T>(x) : T(1) - pow3<T>(T(2) - x * T(2)) / T(2);
}

template<glm::length_t L, typename T, glm::qualifier Q>
inline glm::vec<L, T, Q> InterpToV(glm::vec<L, T, Q> current, glm::vec<L, T, Q> target, float speed, float deltaTime, float minDistance = INTERP_MIN_DIST)
{
    if (speed <= 0.f)
    {
        return target;
    }

    glm::vec<L, T, Q> delta = (target - current);
    if (glm::length(delta) <= minDistance)
    {
        return target;
    }

    glm::vec<L, T, Q> d = delta * clamp(deltaTime * speed, 0.f, 1.f);
    return current + d;
}

//template<glm::length_t L, typename T, glm::qualifier Q>
//inline glm::vec<L, T, Q> InterpToV(glm::vec<L, T, Q> current, glm::vec<L, T, Q> target, glm::vec<L, T, Q> inout_delta, float speed, float deltaTime, float minDistance = 0.0001f)
//{
//    if (speed <= 0.f)
//    {
//        return target;
//    }
//
//    glm::vec<L, T, Q> delta = (target - current);
//    if (glm::length(delta) <= minDistance)
//    {
//        return target;
//    }
//
//    glm::vec<L, T, Q> d = delta * clamp(deltaTime * speed, 0.f, 1.f);
//    d = ClampVecLength(d, glm::length(inout_delta) * 2.f);
//    inout_delta = d;
//    return current + d;
//}

template<glm::length_t L, typename T, glm::qualifier Q>
inline glm::vec<L, T, Q> InterpToVConstant(glm::vec<L, T, Q> current, glm::vec<L, T, Q> target, float speed, float deltaTime, float minDistance = INTERP_MIN_DIST)
{
    if (speed <= 0.f)
    {
        return target;
    }

    glm::vec<L, T, Q> delta = (target - current);
    if (glm::length(delta) <= minDistance)
    {
        return target;
    }

    glm::vec<L, T, Q> d = glm::normalize(delta) * clamp(deltaTime * speed, 0.f, 1.f);
    return current + d;
}

template<glm::length_t L, typename T, glm::qualifier Q>
inline glm::vec<L, T, Q> InterpToV(glm::vec<L, T, Q> current, glm::vec<L, T, Q> target, glm::vec<L, T, Q> speed, float deltaTime, float minDistance = INTERP_MIN_DIST)
{
    if (glm::length(speed) < 0.0001f)
    {
        return target;
    }
    float speedLength = glm::length(speed);

    glm::vec<L, T, Q> deltaInterp = InterpToV(current, target, speedLength, deltaTime, minDistance) - current;
    return current + deltaInterp * (speed / speedLength);
}

template<glm::length_t L, typename T, glm::qualifier Q>
inline glm::vec<L, T, Q> InterpSToV(glm::vec<L, T, Q> current, glm::vec<L, T, Q> target, float speed, float deltaTime, float minDistance = INTERP_MIN_DIST)
{
    if (speed <= 0.f)
    {
        return target;
    }

    glm::vec<L, T, Q> delta = (target - current);
    if (glm::length(delta) <= minDistance)
    {
        return target;
    }

    T deltaL = glm::length(delta);
    glm::vec<L, T, Q> d = glm::normalize(delta) * clamp(deltaL * deltaL * deltaTime * speed, 0.f, deltaL);
    return current + d;
}

template <typename T>
inline T InterpToF(T current, T target, double speed, double deltaTime, double minDistance = INTERP_MIN_DIST)
{
    if (speed <= 0.00001)
    {
        return target;
    }

    T delta = target - current;
    if (abs(delta) <= minDistance)
    {
        return target;
    }

    T deltaInterp = T(delta * saturate(deltaTime * speed));
    return current + deltaInterp;
}

template <typename T>
inline T InterpToFz(T current, T target, double speed, double deltaTime, double minDistance = INTERP_MIN_DIST)
{
    T delta = target - current;
    if (abs(delta) <= minDistance)
    {
        return target;
    }

    T deltaInterp = T(delta * saturate(deltaTime * speed));
    return current + deltaInterp;
}

template <typename T>
inline T InterpToFEaseInOut(T current, T target, T *pDelta, T maxDeltaInc, double speed, double exponent, double deltaTime, double minDistance = INTERP_MIN_DIST)
{
    T delta = target - current;

    // T deltaInterp = T(delta * saturate(deltaTime * speed));
    T deltaInterp = T(std::pow(std::abs(delta), exponent) * saturate(deltaTime * speed));
    // deltaInterp = sign(delta) * min(deltaInterp, std::abs(delta));

    deltaInterp = min(std::abs(deltaInterp), std::abs(delta), T(std::abs(*pDelta) + maxDeltaInc * deltaTime)) * sign(delta);

    *pDelta = deltaInterp;
    return current + (*pDelta);
}

template <typename T>
inline T InterpSToF(T current, T target, double speed, double deltaTime, double minDistance = INTERP_MIN_DIST)
{
    if (speed <= 0.00001)
    {
        return target;
    }

    T delta = target - current;
    if (abs(delta) <= minDistance)
    {
        return target;
    }

    T deltaInterp = T(delta * delta * saturate(deltaTime * speed));
    deltaInterp = sign(delta) * min(deltaInterp, abs(delta));
    return current + deltaInterp;
}

template <typename T>
inline T InterpToFConstant(T current, T target, double speed, double deltaTime, double minDistance = INTERP_MIN_DIST)
{
    if (speed <= 0.00001)
    {
        return target;
    }

    T delta = target - current;
    if (abs(delta) <= minDistance)
    {
        return target;
    }

    if (delta >= 0.f)
    {
        return clamp(T(current + deltaTime * speed), current, target);
    }
    else
    {
        return clamp(T(current - deltaTime * speed), target, current);
    }
}

template <glm::length_t L, typename T, glm::qualifier Q>
inline glm::vec<L, T, Q> ClampVecLength(glm::vec<L, T, Q> vec, T maxlength)
{
    T length = glm::length(vec);
    if (length > 0.0001f)
    {
        return glm::normalize(vec) * min(length, maxlength);
    }
    return glm::vec<L, T, Q>({});
}

template <typename T>
class FDynamicTargetBlend
{
private:
    T Source;
    float Duration;
    float Current = 0;

public:
    float (*Easing)(float) = EaseOutCubic;

    inline FDynamicTargetBlend(T source = T(0), float duration = 1)
        : Source(source), Duration(duration)
    {}
    inline FDynamicTargetBlend(float duration) : Source(T(0)), Duration(duration) {}

    inline void Reset()
    {
        Current = 0;
    }

    inline void Reset(T source)
    {
        Source = source;
        Reset();
    }

    inline void Reset(T source, float duration)
    {
        Duration = duration;
        Reset(source);
    }

    inline T Update(T target, float deltaTime, float alphaOverride = std::numeric_limits<float>::quiet_NaN())
    {
        Current += deltaTime;
        if (!std::isnan(alphaOverride))
        {
            return lerp(Source, target, alphaOverride);
        }
        return lerp(Source, target, Duration <= 0 ? 1 : saturate(Easing(saturate(safediv(Current, Duration)))));
    }
};
