/**
 * Copyright 2013 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 *
 *
 * This file contains the PKCS#11 API, meaning C_GetFunctionList and the C
 * callbacks it supplies.
 *
 * In this file is the glue between the trousers C API and the rest of the
 * simple-tpm-pk11 code which is C++.
 */
#include<cstdio>
#include<cstring>
#include<ctime>
#include<fstream>
#include<functional>
#include<iostream>
#include<sstream>
#include<string>
#include<syslog.h>
#include<vector>

#include"tss/tspi.h"

#include"common.h"
#include"internal.h"
#include"session.h"

using stpm::xctime;

BEGIN_NAMESPACE();

CK_FUNCTION_LIST funclist;
const std::string config_dir = ".simple-tpm-pk11";
const char* env_debug = "SIMPLE_TPM_PK11_DEBUG";
const char* env_config = "SIMPLE_TPM_PK11_CONFIG";

// TODO: allocate and free sessions properly.
std::vector<Session> sessions;

Config get_config();

void
log_error(const std::string& msg)
{
  try {
    auto cfg = get_config();
    stpm::do_log(cfg.logfile_.get(), xctime() + " " + msg);
  } catch(...) {
    std::cerr << "PK11 ERROR> " << msg << std::endl;
  }
  syslog(LOG_ERR, "%s", msg.c_str());
}

bool
debug_env()
{
  const char *dbg{getenv(env_debug)};
  return !!dbg;
}

void
log_debug(const std::string& msg)
{
  try {
    auto cfg = get_config();
    if (cfg.debug_ || debug_env()) {
      stpm::do_log(cfg.logfile_.get(), xctime() + " DEBUG " + msg);
    }
  } catch (...) {
    if (debug_env()) {
      std::cerr << xctime() << " DEBUG " << msg << std::endl;
    }
  }
}

Config
get_config()
{
  const char* home{getenv("HOME")};
  if (home == nullptr) {
    throw std::runtime_error(std::string(__func__) + "(): "
                             + "getenv(HOME) failed.");
  }

  std::string config_path{std::string{home} + "/" + config_dir + "/config"};
  const char* conf_env{getenv(env_config)};
  if (conf_env) {
    config_path = conf_env;
  }

  auto ret = Config{config_path};
  if (debug_env()) {
    ret.debug_ = true;
  }
  return ret;
}

CK_RV
wrap_exceptions(const std::string& name, std::function<void()> f)
{
  log_debug(name + "()");
  try {
    f();
    return CKR_OK;
  } catch (const PK11Error& e) {
    log_error(name + "(): " + e.what());
    return e.code;
  } catch (const std::exception& e) {
    log_error(name + "(): " + e.what());
  } catch (...) {
    log_error(name + "(): Unknown exception");
  }
  return CKR_FUNCTION_FAILED;
}

CK_RV
C_GetInfo(CK_INFO_PTR pInfo)
{
  return wrap_exceptions(__func__, [&]{
      memset(pInfo, 0, sizeof(CK_INFO));
      pInfo->cryptokiVersion.major = 0;
      pInfo->cryptokiVersion.minor = 1;
      // TODO: flags
      strcpy((char*)pInfo->manufacturerID, "simple-tpm-pk11 manufacturer");
      strcpy((char*)pInfo->libraryDescription, "simple-tpm-pk11 library");

      // TODO: take these version numbers from somewhere canonical.
      pInfo->libraryVersion.major = 0;
      pInfo->libraryVersion.minor = 1;
  });
}

CK_RV
C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
              CK_ULONG_PTR pusCount)
{
  return wrap_exceptions(__func__, [&]{
      if (*pusCount) {
        *pSlotList = 0x1234;
      }
      *pusCount = 1;
  });
}

CK_RV
C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags,
              CK_VOID_PTR pApplication,
              CK_RV  (*Notify) (CK_SESSION_HANDLE hSession,
                                CK_NOTIFICATION event, CK_VOID_PTR pApplication),
              CK_SESSION_HANDLE_PTR phSession)
{
  return wrap_exceptions(__func__, [&]{
    sessions.emplace_back(get_config());
    *phSession = sessions.size() - 1;
  });
}

CK_RV
C_CloseSession(CK_SESSION_HANDLE hSession)
{
  return wrap_exceptions(__func__, [&]{});
}

CK_RV
C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
  return wrap_exceptions(__func__, [&]{
    pInfo->slotID = 0;
    pInfo->state = CKS_RW_USER_FUNCTIONS; /* ? */
    pInfo->flags = CKF_SERIAL_SESSION;
    pInfo->ulDeviceError = 0;
  });
}

CK_RV
C_Login(CK_SESSION_HANDLE hSession,
        CK_USER_TYPE userType, CK_CHAR_PTR pPin,
        CK_ULONG usPinLen)
{
  return wrap_exceptions(__func__, [&]{
      sessions[hSession].Login(userType, std::string{pPin, pPin+usPinLen});
  });
}

CK_RV
C_Logout(CK_SESSION_HANDLE hSession)
{
  return wrap_exceptions(__func__, [&]{});
}

CK_RV
C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
  return wrap_exceptions(__func__, [&]{
      // TODO: fill these out from slot.
      strcpy((char*)pInfo->slotDescription, "Simple-TPM-PK11 slot");
      strcpy((char*)pInfo->manufacturerID, "manuf id");

      pInfo->flags = 0;
      pInfo->hardwareVersion = { 0, 0 };
      pInfo->firmwareVersion = { 0, 0 };
  });
}


CK_RV
C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
  return wrap_exceptions(__func__, [&]{
      // TODO: fill these out from token.
      strcpy((char*)pInfo->label, "Simple-TPM-PK11 token");
      strcpy((char*)pInfo->manufacturerID, "manuf id");
      strcpy((char*)pInfo->model, "model");
      strcpy((char*)pInfo->serialNumber, "serial");

      pInfo->flags = 0;
      auto config = get_config();

      std::string kfs;
      try {
        kfs = stpm::slurp_file(config.keyfile_);
      } catch (...) {
        throw PK11Error(CKR_GENERAL_ERROR,
                        "Failed to read key file '" + config.keyfile_ + "'");
      }
      const stpm::Key key = stpm::parse_keyfile(kfs);

      if (stpm::auth_required(config.set_srk_pin_ ? &config.srk_pin_ : NULL,
                              key)) {
        pInfo->flags |= CKF_LOGIN_REQUIRED;
      }
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
      strcpy((char*)pInfo->utcTime, "bleh");  // TODO.
  });
}

CK_RV
C_GetMechanismList(CK_SLOT_ID slotId, CK_MECHANISM_TYPE_PTR pMechanismList,
		   CK_ULONG_PTR pulCount)
{
  return wrap_exceptions(__func__, [&]{
      // TODO: We don't support any mechanisms.  This is a blatent lie, because
      // we do let you sign things.
      *pulCount = 0;
  });
}

CK_RV
C_Finalize(CK_VOID_PTR pReserved)
{
  return wrap_exceptions(__func__, [&]{});
}

CK_RV
C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR filters,
                  CK_ULONG nfilters)
{
  return wrap_exceptions(__func__, [&]{
      sessions[hSession].FindObjectsInit(filters, nfilters);
  });
}

CK_RV
C_FindObjects(CK_SESSION_HANDLE hSession,
              CK_OBJECT_HANDLE_PTR phObject, CK_ULONG usMaxObjectCount,
              CK_ULONG_PTR nfound)
{
  return wrap_exceptions(__func__, [&]{
      *nfound = sessions[hSession].FindObjects(phObject, usMaxObjectCount);
  });
}

CK_RV
C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
  return wrap_exceptions(__func__, [&]{});
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
  return wrap_exceptions(__func__, [&]{
      sessions[hSession].SignInit(pMechanism, hKey);
  });
}

CK_RV
C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
       CK_ULONG usDataLen, CK_BYTE_PTR pSignature,
       CK_ULONG_PTR pusSignatureLen)
{
  return wrap_exceptions(__func__, [&]{
    sessions[hSession].Sign(pData, usDataLen,
                            pSignature, pusSignatureLen);
  });
}

CK_RV
C_Initialize(CK_VOID_PTR pInitArgs)
{
  return wrap_exceptions(__func__, [&]{});
}

CK_RV
C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
  return wrap_exceptions(__func__, [&]{
      // No random number generation is supported.
      throw PK11Error(CKR_RANDOM_NO_RNG, "Not supported.");
  });
}

__attribute__((constructor))
void cons()
{
#define F(x) funclist.C_##x = C_##x
  F(GetInfo);
  F(Initialize);
  F(Finalize);
  F(GetSlotList);
  F(GetSlotInfo);
  F(GetTokenInfo);
  F(GetMechanismList);
  F(Login);
  F(Logout);
  F(OpenSession);
  F(CloseSession);
  F(GetSessionInfo);
  F(FindObjectsInit);
  F(FindObjects);
  F(FindObjectsFinal);
  F(GetAttributeValue);
  F(SignInit);
  F(Sign);
  F(SeedRandom);
#undef F
}

END_NAMESPACE();

extern "C" CK_RV
C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
  return wrap_exceptions(__func__, [&]{
      *ppFunctionList = &funclist;
  });
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
