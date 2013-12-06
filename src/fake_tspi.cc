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
#include"tss/tspi.h"
int foobar;

TSPICALL
Tspi_Context_Create(TSS_HCONTEXT* phContext)
{
  return TSS_SUCCESS;
}

TSPICALL
Tspi_SetAttribUint32(TSS_HOBJECT hObject,
                     TSS_FLAG    attribFlag,
                     TSS_FLAG    subFlag,
                     UINT32      ulAttrib)
{
  return TSS_SUCCESS;
}

TSPICALL
Tspi_GetAttribUint32(TSS_HOBJECT hObject,
                     TSS_FLAG    attribFlag,
                     TSS_FLAG    subFlag,
                     UINT32*     pulAttrib)
{
  switch (subFlag) {
  case TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE:
    *pulAttrib = 0;
    break;
  default:
    *pulAttrib = 123;
  }
  return TSS_SUCCESS;
}

TSPICALL
Tspi_GetAttribData(TSS_HOBJECT hObject,
                   TSS_FLAG    attribFlag,
                   TSS_FLAG    subFlag,
                   UINT32*     pulAttribDataSize,
                   BYTE**      prgbAttribData)
{
  static BYTE buf[10];
  *pulAttribDataSize = 10;
  *prgbAttribData = buf;
  return TSS_SUCCESS;
}

TSPICALL
Tspi_Context_Connect(TSS_HCONTEXT hContext,
                     TSS_UNICODE*        wszDestination)
{
  return TSS_SUCCESS;
}

TSPICALL
Tspi_Key_CreateKey(TSS_HKEY  hKey,
                   TSS_HKEY  hWrappingKey,
                   TSS_HPCRS hPcrComposite)
{
  return TSS_SUCCESS;
}

TSPICALL
Tspi_Context_CreateObject(TSS_HCONTEXT hContext,
                          TSS_FLAG     objectType,
                          TSS_FLAG     initFlags,
                          TSS_HOBJECT* phObject)
{
  return TSS_SUCCESS;
}

TSPICALL
Tspi_Context_GetTpmObject(TSS_HCONTEXT hContext,
                          TSS_HTPM*    phTPM)
{
  return TSS_SUCCESS;
}

TSPICALL
Tspi_TPM_StirRandom(TSS_HTPM hTPM,
                    UINT32   ulEntropyDataLength,
                    BYTE*    rgbEntropyData)
{
  return TSS_SUCCESS;
}

TSPICALL
Tspi_Context_LoadKeyByBlob(TSS_HCONTEXT hContext,
                           TSS_HKEY     hUnwrappingKey,
                           UINT32       ulBlobLength,
                           BYTE*        rgbBlobData,
                           TSS_HKEY*    phKey)
{
  return TSS_SUCCESS;
}

TSPICALL
Tspi_Context_LoadKeyByUUID(TSS_HCONTEXT hContext,
                           TSS_FLAG     persistentStorageType,
                           TSS_UUID     uuidData,
                           TSS_HKEY*    phKey)
{
  return TSS_SUCCESS;
}

TSPICALL
Tspi_Policy_SetSecret(TSS_HPOLICY hPolicy,
                      TSS_FLAG    secretMode,
                      UINT32      ulSecretLength,
                      BYTE*       rgbSecret)
{
  return TSS_SUCCESS;
}

TSPICALL
Tspi_Policy_AssignToObject(TSS_HPOLICY hPolicy,
                           TSS_HOBJECT hObject)
{
  return TSS_SUCCESS;
}

TSPICALL
Tspi_Hash_Sign(TSS_HHASH hHash,
               TSS_HKEY  hKey,
               UINT32*   pulSignatureLength,
               BYTE**    prgbSignature)
{
  static BYTE sign[] = {0x12, 0x34, 0x56, 0x78};
  *pulSignatureLength = sizeof(sign);
  *prgbSignature = sign;
  return TSS_SUCCESS;
}

TSPICALL
Tspi_Hash_SetHashValue(TSS_HHASH hHash,
                       UINT32    ulHashValueLength,
                       BYTE*     rgbHashValue)
{
  return TSS_SUCCESS;
}

TSPICALL
Tspi_Hash_UpdateHashValue(TSS_HHASH hHash,
                          UINT32    ulDataLength,
                          BYTE*     rgbData)
{
  return TSS_SUCCESS;
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
