#include<opencryptoki/pkcs11.h>

class Session {
public:
  Session(int slot);

  void FindObjectsInit(CK_ATTRIBUTE_PTR filters, int nfilters);
  int FindObjects(CK_OBJECT_HANDLE_PTR obj, int maxobj); 
  void GetAttributeValue(CK_OBJECT_HANDLE hObject,
                         CK_ATTRIBUTE_PTR pTemplate, CK_ULONG usCount);

  void SignInit(CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
  void Sign(CK_BYTE_PTR pData, CK_ULONG usDataLen,
            CK_BYTE_PTR pSignature, CK_ULONG_PTR pusSignatureLen);
private:
  int slot_;
  int findpos_;
};
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
