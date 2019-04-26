package org.cryptomator.cryptolib.sgx;

public enum SgxStatus {
    SGX_SUCCESS,

    SGX_ERROR_UNEXPECTED,      /* Unexpected error */
    SGX_ERROR_INVALID_PARAMETER,      /* The parameter is incorrect */
    SGX_ERROR_OUT_OF_MEMORY,      /* Not enough memory is available to complete this operation */
    SGX_ERROR_ENCLAVE_LOST,      /* Enclave lost after power transition or used in child process created by linux:fork() */
    SGX_ERROR_INVALID_STATE,      /* SGX API is invoked in incorrect order or state */
    SGX_ERROR_FEATURE_NOT_SUPPORTED,   /* Feature is not supported on this platform */



    SGX_ERROR_INVALID_FUNCTION,      /* The ecall/ocall index is invalid */
    SGX_ERROR_OUT_OF_TCS,      /* The enclave is out of TCS */
    SGX_ERROR_ENCLAVE_CRASHED,      /* The enclave is crashed */
    SGX_ERROR_ECALL_NOT_ALLOWED,      /* The ECALL is not allowed at this time, e.g. ecall is blocked by the dynamic entry table, or nested ecall is not allowed during initialization */
    SGX_ERROR_OCALL_NOT_ALLOWED,      /* The OCALL is not allowed at this time, e.g. ocall is not allowed during exception handling */
    SGX_ERROR_STACK_OVERRUN,      /* The enclave is running out of stack */

    SGX_ERROR_UNDEFINED_SYMBOL,      /* The enclave image has undefined symbol. */
    SGX_ERROR_INVALID_ENCLAVE,      /* The enclave image is not correct. */
    SGX_ERROR_INVALID_ENCLAVE_ID,      /* The enclave id is invalid */
    SGX_ERROR_INVALID_SIGNATURE,      /* The signature is invalid */
    SGX_ERROR_NDEBUG_ENCLAVE,      /* The enclave is signed as product enclave, and can not be created as debuggable enclave. */
    SGX_ERROR_OUT_OF_EPC,      /* Not enough EPC is available to load the enclave */
    SGX_ERROR_NO_DEVICE,      /* Can't open SGX device */
    SGX_ERROR_MEMORY_MAP_CONFLICT,      /* Page mapping failed in driver */
    SGX_ERROR_INVALID_METADATA,      /* The metadata is incorrect. */
    SGX_ERROR_DEVICE_BUSY,      /* Device is busy, mostly EINIT failed. */
    SGX_ERROR_INVALID_VERSION,      /* Metadata version is inconsistent between uRTS and sgx_sign or uRTS is incompatible with current platform. */
    SGX_ERROR_MODE_INCOMPATIBLE,      /* The target enclave 32/64 bit mode or sim/hw mode is incompatible with the mode of current uRTS. */
    SGX_ERROR_ENCLAVE_FILE_ACCESS,     /* Can't open enclave file. */
    SGX_ERROR_INVALID_MISC,     /* The MiscSelct/MiscMask settings are not correct.*/
    SGX_ERROR_INVALID_LAUNCH_TOKEN,    /* The launch token is not correct.*/

    SGX_ERROR_MAC_MISMATCH,      /* Indicates verification error for reports, sealed datas, etc */
    SGX_ERROR_INVALID_ATTRIBUTE,      /* The enclave is not authorized */
    SGX_ERROR_INVALID_CPUSVN,      /* The cpu svn is beyond platform's cpu svn value */
    SGX_ERROR_INVALID_ISVSVN,      /* The isv svn is greater than the enclave's isv svn */
    SGX_ERROR_INVALID_KEYNAME,      /* The key name is an unsupported value */

    SGX_ERROR_SERVICE_UNAVAILABLE,   /* Indicates aesm didn't respond or the requested service is not supported */
    SGX_ERROR_SERVICE_TIMEOUT,   /* The request to aesm timed out */
    SGX_ERROR_AE_INVALID_EPIDBLOB,   /* Indicates epid blob verification error */
    SGX_ERROR_SERVICE_INVALID_PRIVILEGE,   /* Enclave has no privilege to get launch token */
    SGX_ERROR_EPID_MEMBER_REVOKED,   /* The EPID group membership is revoked. */
    SGX_ERROR_UPDATE_NEEDED,   /* SGX needs to be updated */
    SGX_ERROR_NETWORK_FAILURE,   /* Network connecting or proxy setting issue is encountered */
    SGX_ERROR_AE_SESSION_INVALID,   /* Session is invalid or ended by server */
    SGX_ERROR_BUSY,   /* The requested service is temporarily not availabe */
    SGX_ERROR_MC_NOT_FOUND,   /* The Monotonic Counter doesn't exist or has been invalided */
    SGX_ERROR_MC_NO_ACCESS_RIGHT,   /* Caller doesn't have the access right to specified VMC */
    SGX_ERROR_MC_USED_UP,   /* Monotonic counters are used out */
    SGX_ERROR_MC_OVER_QUOTA,   /* Monotonic counters exceeds quota limitation */
    SGX_ERROR_KDF_MISMATCH,   /* Key derivation function doesn't match during key exchange */
    SGX_ERROR_UNRECOGNIZED_PLATFORM,   /* EPID Provisioning failed due to platform not recognized by backend server*/

    SGX_ERROR_NO_PRIVILEGE,   /* Not enough privilege to perform the operation */

    /* SGX Protected Code Loader Error codes*/
    SGX_ERROR_PCL_ENCRYPTED,   /* trying to encrypt an already encrypted enclave */
    SGX_ERROR_PCL_NOT_ENCRYPTED,   /* trying to load a plain enclave using sgx_create_encrypted_enclave */
    SGX_ERROR_PCL_MAC_MISMATCH,   /* section mac result does not match build time mac */
    SGX_ERROR_PCL_SHA_MISMATCH,   /* Unsealed key MAC does not match MAC of key hardcoded in enclave binary */
    SGX_ERROR_PCL_GUID_MISMATCH,   /* GUID in sealed blob does not match GUID hardcoded in enclave binary */

    /* SGX errors are only used in the file API when there is no appropriate EXXX (EINVAL, EIO etc.) error code */
    SGX_ERROR_FILE_BAD_STATUS,    /* The file is in bad status, run sgx_clearerr to try and fix it */
    SGX_ERROR_FILE_NO_KEY_ID,    /* The Key ID field is all zeros, can't re-generate the encryption key */
    SGX_ERROR_FILE_NAME_MISMATCH,    /* The current file name is different then the original file name (not allowed, substitution attack) */
    SGX_ERROR_FILE_NOT_SGX_FILE, /* The file is not an SGX file */
    SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE,    /* A recovery file can't be opened, so flush operation can't continue (only used when no EXXX is returned)  */
    SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE, /* A recovery file can't be written, so flush operation can't continue (only used when no EXXX is returned)  */
    SGX_ERROR_FILE_RECOVERY_NEEDED,    /* When openeing the file, recovery is needed, but the recovery process failed */
    SGX_ERROR_FILE_FLUSH_FAILED,    /* fflush operation (to disk) failed (only used when no EXXX is returned) */
    SGX_ERROR_FILE_CLOSE_FAILED,    /* fclose operation (to disk) failed (only used when no EXXX is returned) */


    SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED; /* The ioctl for enclave_create unexpectedly failed with EINTR. */

    public static String toHex(int status) {
        return Integer.toHexString(status);
    }

    public String getDescription() {
        switch (this) {
            case SGX_SUCCESS:
                return "Sucess";

            case SGX_ERROR_UNEXPECTED:
                return "Unexpected error";

            case SGX_ERROR_INVALID_PARAMETER:
                return "The parameter is incorrect";

            case SGX_ERROR_OUT_OF_MEMORY:
                return "Not enough memory is available to complete this operation";

            case SGX_ERROR_ENCLAVE_LOST:
                return "Enclave lost after power transition or used in child process created by linux:fork()";

            case SGX_ERROR_INVALID_STATE:
                return "SGX API is invoked in incorrect order or state";

            case SGX_ERROR_FEATURE_NOT_SUPPORTED:
                return "Feature is not supported on this platform";

            case SGX_ERROR_INVALID_FUNCTION:
                return "The ecall/ocall index is invalid";

            case SGX_ERROR_OUT_OF_TCS:
                return "The enclave is out of TCS";

            case SGX_ERROR_ENCLAVE_CRASHED:
                return "The enclave is crashed";

            case SGX_ERROR_ECALL_NOT_ALLOWED:
                return "The ECALL is not allowed at this time, e.g. ecall is blocked by the dynamic entry table, or nested ecall is not allowed during initialization";

            case SGX_ERROR_OCALL_NOT_ALLOWED:
                return "The OCALL is not allowed at this time, e.g. ocall is not allowed during exception handling";

            case SGX_ERROR_STACK_OVERRUN:
                return "The enclave is running out of stack";

            case SGX_ERROR_UNDEFINED_SYMBOL:
                return "The enclave image has undefined symbol";

            case SGX_ERROR_INVALID_ENCLAVE:
                return "The enclave image is not correct";

            case SGX_ERROR_INVALID_ENCLAVE_ID:
                return "The enclave id is invalid";

            case SGX_ERROR_INVALID_SIGNATURE:
                return "The signature is invalid";

            case SGX_ERROR_NDEBUG_ENCLAVE:
                return "The enclave is signed as product enclave, and can not be created as debuggable enclave";

            case SGX_ERROR_OUT_OF_EPC:
                return "Not enough EPC is available to load the enclave";

            case SGX_ERROR_NO_DEVICE:
                return "Can't open SGX device";

            case SGX_ERROR_MEMORY_MAP_CONFLICT:
                return "Page mapping failed in driver";

            case SGX_ERROR_INVALID_METADATA:
                return "The metadata is incorrect";

            case SGX_ERROR_DEVICE_BUSY:
                return "Device is busy, mostly EINIT failed";

            case SGX_ERROR_INVALID_VERSION:
                return "Metadata version is inconsistent between uRTS and sgx_sign or uRTS is incompatible with current platform";

            case SGX_ERROR_MODE_INCOMPATIBLE:
                return "The target enclave 32/64 bit mode or sim/hw mode is incompatible with the mode of current uRTS";

            case SGX_ERROR_ENCLAVE_FILE_ACCESS:
                return "Can't open enclave file";

            case SGX_ERROR_INVALID_MISC:
                return "The MiscSelct/MiscMask settings are not correct";

            case SGX_ERROR_INVALID_LAUNCH_TOKEN:
                return "The launch token is not correct";

            case SGX_ERROR_MAC_MISMATCH:
                return "Indicates verification error for reports, sealed datas, etc";

            case SGX_ERROR_INVALID_ATTRIBUTE:
                return "The enclave is not authorized";

            case SGX_ERROR_INVALID_CPUSVN:
                return "The cpu svn is beyond platform's cpu svn value";

            case SGX_ERROR_INVALID_ISVSVN:
                return "The isv svn is greater than the enclave's isv svn";

            case SGX_ERROR_INVALID_KEYNAME:
                return "The key name is an unsupported value";

            case SGX_ERROR_SERVICE_UNAVAILABLE:
                return "Indicates aesm didn't respond or the requested service is not supported";

            case SGX_ERROR_SERVICE_TIMEOUT:
                return "The request to aesm timed out";

            case SGX_ERROR_AE_INVALID_EPIDBLOB:
                return "Indicates epid blob verification error";

            case SGX_ERROR_SERVICE_INVALID_PRIVILEGE:
                return "Enclave has no privilege to get launch token";

            case SGX_ERROR_EPID_MEMBER_REVOKED:
                return "The EPID group membership is revoked";

            case SGX_ERROR_UPDATE_NEEDED:
                return "SGX needs to be updated";

            case SGX_ERROR_NETWORK_FAILURE:
                return "Network connecting or proxy setting issue is encountered";

            case SGX_ERROR_AE_SESSION_INVALID:
                return "Session is invalid or ended by server";

            case SGX_ERROR_BUSY:
                return "The requested service is temporarily not availabe";

            case SGX_ERROR_MC_NOT_FOUND:
                return "The Monotonic Counter doesn't exist or has been invalided";

            case SGX_ERROR_MC_NO_ACCESS_RIGHT:
                return "Caller doesn't have the access right to specified VMC";

            case SGX_ERROR_MC_USED_UP:
                return "Monotonic counters are used out";

            case SGX_ERROR_MC_OVER_QUOTA:
                return "Monotonic counters exceeds quota limitation";

            case SGX_ERROR_KDF_MISMATCH:
                return "Key derivation function doesn't match during key exchange";

            case SGX_ERROR_UNRECOGNIZED_PLATFORM:
                return "EPID Provisioning failed due to platform not recognized by backend server";

            case SGX_ERROR_NO_PRIVILEGE:
                return "Not enough privilege to perform the operation";

            case SGX_ERROR_PCL_ENCRYPTED:
                return "Trying to encrypt an already encrypted enclave";

            case SGX_ERROR_PCL_NOT_ENCRYPTED:
                return "Trying to load a plain enclave using sgx_create_encrypted_enclave";

            case SGX_ERROR_PCL_MAC_MISMATCH:
                return "Section mac result does not match build time mac";

            case SGX_ERROR_PCL_SHA_MISMATCH:
                return "Unsealed key MAC does not match MAC of key hardcoded in enclave binary";

            case SGX_ERROR_PCL_GUID_MISMATCH:
                return "GUID in sealed blob does not match GUID hardcoded in enclave binary";

            case SGX_ERROR_FILE_BAD_STATUS:
                return "The file is in bad status, run sgx_clearerr to try and fix it";

            case SGX_ERROR_FILE_NO_KEY_ID:
                return "The Key ID field is all zeros, can't re-generate the encryption key";

            case SGX_ERROR_FILE_NAME_MISMATCH:
                return "The current file name is different then the original file name (not allowed, substitution attack)";

            case SGX_ERROR_FILE_NOT_SGX_FILE:
                return "The file is not an SGX file";

            case SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE:
                return "A recovery file can't be opened, so flush operation can't continue (only used when no EXXX is returned) ";

            case SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE:
                return "A recovery file can't be written, so flush operation can't continue (only used when no EXXX is returned)";

            case SGX_ERROR_FILE_RECOVERY_NEEDED:
                return "When openeing the file, recovery is needed, but the recovery process failed";

            case SGX_ERROR_FILE_FLUSH_FAILED:
                return "fflush operation (to disk) failed (only used when no EXXX is returned)";

            case SGX_ERROR_FILE_CLOSE_FAILED:
                return "fclose operation (to disk) failed (only used when no EXXX is returned)";

            case SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED:
                return "The ioctl for enclave_create unexpectedly failed with EINTR";

            default:
                return this.toString();

        }
    }

    public static SgxStatus fromInt(int status) {
        switch (status) {
            case 0:
                return SGX_SUCCESS;
            case 1:
                return SGX_ERROR_UNEXPECTED;
            case 2:
                return SGX_ERROR_INVALID_PARAMETER;
            case 3:
                return SGX_ERROR_OUT_OF_MEMORY;
            case 4:
                return SGX_ERROR_ENCLAVE_LOST;
            case 5:
                return SGX_ERROR_INVALID_STATE;
            case 8:
                return SGX_ERROR_FEATURE_NOT_SUPPORTED;
            case 4097:
                return SGX_ERROR_INVALID_FUNCTION;
            case 4099:
                return SGX_ERROR_OUT_OF_TCS;
            case 4102:
                return SGX_ERROR_ENCLAVE_CRASHED;
            case 4103:
                return SGX_ERROR_ECALL_NOT_ALLOWED;
            case 4104:
                return SGX_ERROR_OCALL_NOT_ALLOWED;
            case 4105:
                return SGX_ERROR_STACK_OVERRUN;
            case 8192:
                return SGX_ERROR_UNDEFINED_SYMBOL;
            case 8193:
                return SGX_ERROR_INVALID_ENCLAVE;
            case 8194:
                return SGX_ERROR_INVALID_ENCLAVE_ID;
            case 8195:
                return SGX_ERROR_INVALID_SIGNATURE;
            case 8196:
                return SGX_ERROR_NDEBUG_ENCLAVE;
            case 8197:
                return SGX_ERROR_OUT_OF_EPC;
            case 8198:
                return SGX_ERROR_NO_DEVICE;
            case 8199:
                return SGX_ERROR_MEMORY_MAP_CONFLICT;
            case 8201:
                return SGX_ERROR_INVALID_METADATA;
            case 8204:
                return SGX_ERROR_DEVICE_BUSY;
            case 8205:
                return SGX_ERROR_INVALID_VERSION;
            case 8206:
                return SGX_ERROR_MODE_INCOMPATIBLE;
            case 8207:
                return SGX_ERROR_ENCLAVE_FILE_ACCESS;
            case 8208:
                return SGX_ERROR_INVALID_MISC;
            case 8209:
                return SGX_ERROR_INVALID_LAUNCH_TOKEN;
            case 12289:
                return SGX_ERROR_MAC_MISMATCH;
            case 12290:
                return SGX_ERROR_INVALID_ATTRIBUTE;
            case 12291:
                return SGX_ERROR_INVALID_CPUSVN;
            case 12292:
                return SGX_ERROR_INVALID_ISVSVN;
            case 12293:
                return SGX_ERROR_INVALID_KEYNAME;
            case 16385:
                return SGX_ERROR_SERVICE_UNAVAILABLE;
            case 16386:
                return SGX_ERROR_SERVICE_TIMEOUT;
            case 16387:
                return SGX_ERROR_AE_INVALID_EPIDBLOB;
            case 16388:
                return SGX_ERROR_SERVICE_INVALID_PRIVILEGE;
            case 16389:
                return SGX_ERROR_EPID_MEMBER_REVOKED;
            case 16390:
                return SGX_ERROR_UPDATE_NEEDED;
            case 16391:
                return SGX_ERROR_NETWORK_FAILURE;
            case 16392:
                return SGX_ERROR_AE_SESSION_INVALID;
            case 16394:
                return SGX_ERROR_BUSY;
            case 16396:
                return SGX_ERROR_MC_NOT_FOUND;
            case 16397:
                return SGX_ERROR_MC_NO_ACCESS_RIGHT;
            case 16398:
                return SGX_ERROR_MC_USED_UP;
            case 16399:
                return SGX_ERROR_MC_OVER_QUOTA;
            case 16401:
                return SGX_ERROR_KDF_MISMATCH;
            case 16402:
                return SGX_ERROR_UNRECOGNIZED_PLATFORM;
            case 20482:
                return SGX_ERROR_NO_PRIVILEGE;
            case 24577:
                return SGX_ERROR_PCL_ENCRYPTED;
            case 24578:
                return SGX_ERROR_PCL_NOT_ENCRYPTED;
            case 24579:
                return SGX_ERROR_PCL_MAC_MISMATCH;
            case 24580:
                return SGX_ERROR_PCL_SHA_MISMATCH;
            case 24581:
                return SGX_ERROR_PCL_GUID_MISMATCH;
            case 28673:
                return SGX_ERROR_FILE_BAD_STATUS;
            case 28674:
                return SGX_ERROR_FILE_NO_KEY_ID;
            case 28675:
                return SGX_ERROR_FILE_NAME_MISMATCH;
            case 28676:
                return SGX_ERROR_FILE_NOT_SGX_FILE;
            case 28677:
                return SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE;
            case 28678:
                return SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE;
            case 28679:
                return SGX_ERROR_FILE_RECOVERY_NEEDED;
            case 28680:
                return SGX_ERROR_FILE_FLUSH_FAILED;
            case 28681:
                return SGX_ERROR_FILE_CLOSE_FAILED;
            case 61441:
                return SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED;
            default:
                return SGX_ERROR_UNEXPECTED;
        }
    }
}
