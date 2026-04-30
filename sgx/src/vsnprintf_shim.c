/* Shim for __vsnprintf_chk to work in SGX environment
 * This redirects the fortified vsnprintf to the regular vsnprintf
 */

#include <stdarg.h>
#include <stddef.h>

/* Forward declaration - vsnprintf is provided by the SGX runtime */
int vsnprintf(char *str, size_t size, const char *format, va_list ap);

/* Fortified vsnprintf - just call the regular version */
int __vsnprintf_chk(char *str, size_t maxlen, int flag, size_t slen, const char *format, va_list ap) {
    (void)flag;  /* Unused in SGX */
    (void)slen;  /* Unused in SGX */
    return vsnprintf(str, maxlen, format, ap);
}
