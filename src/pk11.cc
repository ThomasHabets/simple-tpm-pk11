/**
 *
 *
 * This file contains the PKCS#11 API, meaning C_GetFunctionList and the C
 * callbacks it supplies.
 *
 * In this file is the glue between the trousers C API and the rest of the
 * simple-tpm-pk11 code which is C++.
 */
#include<ctime>
#include<cstdio>
#include<cstring>
#include<functional>
#include<iostream>
#include<fstream>
#include<string>
#include<syslog.h>
#include<vector>

#include"tss/tspi.h"

#include"session.h"
#include"common.h"
#include"internal.h"

using stpm::xctime;

BEGIN_NAMESPACE();

CK_FUNCTION_LIST funclist;
const std::string config_dir = ".simple-tpm-pk11";

// TODO: allocate and free sessions properly.
std::vector<Session> sessions;

Config get_config();

void
log_error(const std::string& msg)
{
  try {
    auto cfg = get_config();
    *cfg.logfile_ << ctime(nullptr) << msg << "\n";
  } catch(...) {
    std::cerr << "PK11 ERROR> " << msg << std::endl;
  }
  syslog(LOG_ERR, "%s", msg.c_str());
}

bool
debug_env()
{
  const char *dbg{getenv("SIMPLE_TPM_PK11_DEBUG")};
  return !!dbg;
}

void
log_debug(const std::string& msg)
{
  auto cfg = get_config();
  if (cfg.debug_) {
    *cfg.logfile_ << xctime() << " DEBUG " << msg << std::endl;
  }
}

Config
get_config()
{
  const char *home{getenv("HOME")};
  if (home == nullptr) {
    throw std::string(__func__) + "(): getenv(HOME) failed.";
  }
  auto ret = Config{std::string{home} + "/" + config_dir + "/config"};
  if (debug_env()) {
    ret.debug_ = true;
  }
  return ret;
}

CK_RV
C_GetInfo(CK_INFO_PTR pInfo)
{
  log_debug("GetInfo()");
  memset(pInfo, 0, sizeof(CK_INFO));
  pInfo->cryptokiVersion.major = 0;
  pInfo->cryptokiVersion.minor = 1;
  // TODO: flags
  strcpy((char*)pInfo->manufacturerID, "habets");
  strcpy((char*)pInfo->libraryDescription, "habets descr");
  pInfo->libraryVersion.major = 0;
  pInfo->libraryVersion.minor = 1;
  return CKR_OK;
}

CK_RV
C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
              CK_ULONG_PTR pusCount)
{
  log_debug("GetSlotList()");
  if (*pusCount) {
    *pSlotList = 0x1234;
  }
  *pusCount = 1;
  return CKR_OK;
}

CK_RV
C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags,
              CK_VOID_PTR pApplication,
              CK_RV  (*Notify) (CK_SESSION_HANDLE hSession,
                                CK_NOTIFICATION event, CK_VOID_PTR pApplication),
              CK_SESSION_HANDLE_PTR phSession)
{
  log_debug("OpenSession()");
  try {
    sessions.emplace_back(get_config());
    *phSession = sessions.size() - 1;
    return CKR_OK;
  } catch (const std::string& msg) {
    log_error(msg);
  } catch (const char* msg) {
    log_error(msg);
  } catch (...) {
    log_error("Unknown exception");
  }
  return CKR_FUNCTION_FAILED;
}

CK_RV
C_CloseSession(CK_SESSION_HANDLE hSession)
{
  log_debug("CloseSession()");
  return CKR_OK;
}

CK_RV
C_Login(CK_SESSION_HANDLE hSession,
        CK_USER_TYPE userType, CK_CHAR_PTR pPin,
        CK_ULONG usPinLen)
{
  log_debug("Login()");
  return CKR_OK;
}

CK_RV
C_Logout(CK_SESSION_HANDLE hSession)
{
  log_debug("Logout()");
  return CKR_OK;
}


CK_RV
C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
  strcpy((char*)pInfo->label, "token label");
  strcpy((char*)pInfo->manufacturerID, "manuf id");
  strcpy((char*)pInfo->model, "model");
  strcpy((char*)pInfo->serialNumber, "serial");
  //pInfo->flags
  pInfo->ulMaxSessionCount = 1000;
  pInfo->ulSessionCount = 0;
  pInfo->ulMaxRwSessionCount = 1000;
  pInfo->ulRwSessionCount = 0;
  pInfo->ulMaxPinLen = 64;
  pInfo->ulMinPinLen = 6;
  pInfo->ulTotalPublicMemory = 1000000;
  pInfo->ulFreePublicMemory = 1000000;
  pInfo->ulTotalPrivateMemory = 1000000;
  pInfo->ulFreePrivateMemory = 1000000;
  pInfo->hardwareVersion.major = 0;
  pInfo->firmwareVersion.major = 0;
  strcpy((char*)pInfo->utcTime, "bleh");
  return CKR_OK;
}

CK_RV
C_Finalize(CK_VOID_PTR pReserved)
{
  log_debug("Finalize()");
  return CKR_OK;
}

CK_RV
C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR filters,
                  CK_ULONG nfilters)
{
  log_debug("FindObjectsInit()");
  sessions[hSession].FindObjectsInit(filters, nfilters);
  return CKR_OK;
}

CK_RV
C_FindObjects(CK_SESSION_HANDLE hSession,
              CK_OBJECT_HANDLE_PTR phObject, CK_ULONG usMaxObjectCount,
              CK_ULONG_PTR nfound)
{
  log_debug("FindObjects()");
  *nfound = sessions[hSession].FindObjects(phObject, usMaxObjectCount);
  return CKR_OK;
}

CK_RV
C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
  log_debug("FindObjectsFinal()");
  return CKR_OK;
}

CK_RV
wrap_exceptions(const std::string& name, std::function<void()> f)
{
  log_debug(name + "()");
  try {
    f();
    return CKR_OK;
  } catch (const PK11Error& e) {
    log_error(name + "(): " + e.msg);
    return e.code;
  } catch (const std::string& msg) {
    log_error(name + "(): " + msg);
  } catch (const char* msg) {
    log_error(name + "(): " + msg);
  } catch (...) {
    log_error(name + "(): Unknown exception");
  }
  return CKR_FUNCTION_FAILED;
}


CK_RV
C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG usCount)
{
  return wrap_exceptions(__func__, [&]{
      sessions[hSession].GetAttributeValue(hObject, pTemplate, usCount);
  });
}

CK_RV
C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
           CK_OBJECT_HANDLE hKey)
{
  log_debug("SignInit()");
  sessions[hSession].SignInit(pMechanism, hKey);
  return CKR_OK;
}

CK_RV
C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
       CK_ULONG usDataLen, CK_BYTE_PTR pSignature,
       CK_ULONG_PTR pusSignatureLen)
{
  log_debug("Sign()");
  try {
    sessions[hSession].Sign(pData, usDataLen,
                            pSignature, pusSignatureLen);
  } catch (const std::string& msg) {
    std::cerr << msg << std::endl;
  }
  return CKR_OK;
}

CK_RV
C_Initialize(CK_VOID_PTR pInitArgs)
{
  return CKR_OK;
}

__attribute__((constructor))
void cons()
{
#define F(x) funclist.C_##x = C_##x
  F(GetInfo);
  F(Initialize);
  F(Finalize);
  F(GetSlotList);
  F(GetTokenInfo);
  F(Login);
  F(Logout);
  F(OpenSession);
  F(CloseSession);
  F(FindObjectsInit);
  F(FindObjects);
  F(FindObjectsFinal);
  F(GetAttributeValue);
  F(SignInit);
  F(Sign);
#undef F
}

END_NAMESPACE();

extern "C" CK_RV
C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
  *ppFunctionList = &funclist;
  return CKR_OK;
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
