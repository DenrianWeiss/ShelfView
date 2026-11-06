#ifndef BC_PACK_JNI_UTIL_H
#define BC_PACK_JNI_UTIL_H
#define CHECK_NULL(value) do { if ((value) == 0) return; } while (0)
#define CHECK_NULL_RETURN(value, result) do { if ((value) == 0) return (result); } while (0)
#endif
