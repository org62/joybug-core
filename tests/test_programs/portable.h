/* Shared by the test programs that build with both MSVC and GCC/Clang. */
#ifndef JOYBUG_PORTABLE_H
#define JOYBUG_PORTABLE_H
#ifdef _MSC_VER
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif
#endif
