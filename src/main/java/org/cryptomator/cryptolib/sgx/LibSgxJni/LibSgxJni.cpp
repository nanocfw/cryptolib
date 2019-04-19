#include "LibSgxJni.h"

static __inline void native_cpuid(unsigned int *eax, unsigned int *ebx, unsigned int *ecx, unsigned int *edx)
{
	// ecx is often an input as well as an output.

#if !defined(_MSC_VER)

	asm volatile("cpuid"
		: "=a" (*eax),
		"=b" (*ebx),
		"=c" (*ecx),
		"=d" (*edx)
		: "0" (*eax), "2" (*ecx));

#else
	int registers[4] = {0,0,0,0};

	__cpuidex(registers, *eax, *ecx);
	*eax = registers[0];
	*ebx = registers[1];
	*ecx = registers[2];
	*edx = registers[3];

#endif
}

JNIEXPORT jboolean JNICALL Java_org_cryptomator_cryptolib_sgx_SgxJNI_jni_1sgx_1is_1enabled(JNIEnv * env, jobject obj)
{
	if (SGX_STATUS == 0 || SGX_STATUS == 1)
		return SGX_STATUS;

	unsigned eax, ebx, ecx, edx;
	eax = 1; // processor info and feature bits

	native_cpuid(&eax, &ebx, &ecx, &edx);

	eax = 7;
	ecx = 0;
	native_cpuid(&eax, &ebx, &ecx, &edx);

	//CPUID.(EAX=07H, ECX=0H):EBX.SGX = 1,

	SGX_STATUS = (ebx >> 2) & 0x1;
	return SGX_STATUS = 1;
}

JNIEXPORT jint JNICALL Java_org_cryptomator_cryptolib_sgx_SgxJNI_jni_1initialize_1enclave(JNIEnv *env, jobject obj)
{
	sgx_launch_token_t token = {0};
	int updated = 0;
	sgx_enclave_id_t* eid;
	sgx_status_t ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, eid, NULL);
	if (ret == SGX_SUCCESS)
	{
	    jlong jid = *eid;
	    jclass clazz = env -> GetObjectClass(obj);
            jfieldID fidenclave = env -> GetFieldID(clazz, "FEnclaveID", "J");

            env -> SetLongField(obj, fidenclave, jid);
	}
	return (long) ret;
}

JNIEXPORT jint JNICALL Java_org_cryptomator_cryptolib_sgx_SgxJNI_jni_1sgx_1destroy_1enclave(JNIEnv *env, jobject obj, jlong enclave_id)
{
	sgx_status_t ret = sgx_destroy_enclave((sgx_enclave_id_t) enclave_id);
	return (long) ret;
}

JNIEXPORT jbyteArray JNICALL Java_org_cryptomator_cryptolib_sgx_SgxJNI_jni_1sgx_1seal_1data(JNIEnv *env, jobject obj, jlong enclave_id, jbyteArray data_in, jlong data_size)
{
	byte *data;
	env -> GetByteArrayRegion (data_in, 0, data_size, reinterpret_cast<jbyte*>(data));

	uint32_t sealed_data_size;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;

	ret = ecall_get_sealed_data_size((sgx_enclave_id_t) enclave_id, data_size, &sealed_data_size);

	if (ret != SGX_SUCCESS)
		return NULL;

    byte *sealed_data;
	sealed_data = (byte*) malloc(sealed_data_size);

	ret = ecall_seal_data((sgx_enclave_id_t) enclave_id, data, data_size, sealed_data, sealed_data_size);

	free(data);

    jbyteArray data_out = env -> NewByteArray (sealed_data_size);
    env -> SetByteArrayRegion (data_out, 0, sealed_data_size, reinterpret_cast<jbyte*>(sealed_data));

    free(sealed_data);

    return data_out;
}

JNIEXPORT jbyteArray JNICALL Java_org_cryptomator_cryptolib_sgx_SgxJNI_jni_1sgx_1unseal_1data(JNIEnv *env, jobject obj, jlong enclave_id, jbyteArray data_in, jlong data_size)
{
    byte *data;
    env -> GetByteArrayRegion (data_in, 0, data_size, reinterpret_cast<jbyte*>(data));

	uint32_t unsealed_data_size;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;

	ret = ecall_get_unsealed_data_size((sgx_enclave_id_t) enclave_id, data, data_size, &unsealed_data_size);

	if (ret != SGX_SUCCESS)
		return NULL;

	byte *unsealed_data;
	unsealed_data = (byte*) malloc(unsealed_data_size);

	ret = ecall_unseal_data((sgx_enclave_id_t) enclave_id, data, data_size, unsealed_data, unsealed_data_size);

	free(data);

    jbyteArray data_out = env -> NewByteArray (unsealed_data_size);
    env -> SetByteArrayRegion (data_out, 0, unsealed_data_size, reinterpret_cast<jbyte*>(unsealed_data));

    free(unsealed_data);

    return data_out;
}
