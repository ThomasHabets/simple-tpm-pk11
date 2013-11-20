// Internal include to not pollute non-namespace parts.

#define BEGIN_NAMESPACE(x) namespace x {
#define END_NAMESPACE(x) }

#define TSCALL(x, ...) {                                        \
                TSS_RESULT res;                                 \
                if (TSS_SUCCESS != (res = x(__VA_ARGS__))) {    \
                        throw #x"(): " + parseError(res);       \
                }                                               \
        }
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
