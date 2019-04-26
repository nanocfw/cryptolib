package org.cryptomator.cryptolib.sgx;


import org.cryptomator.cryptolib.sgx.SgxStatus;

import java.nio.ByteBuffer;

public class SgxJNI {

    private long FEnclaveID;
    private static boolean FLibraryLoaded = false;

    public boolean IsLibraryLoaded() {
        return FLibraryLoaded;
    }

    public void InitializeEnclave() {
        if (!FLibraryLoaded)
            throw new ExceptionInInitializerError("Não foi possível carregar a biblioteca SgxLib.");

        if (!jni_sgx_is_enabled())
            throw new ExceptionInInitializerError("SGX não é suportado pelo hardware ou está desabilitado.");

        int ret = 1;
        try {
            ret = jni_initialize_enclave();
        } catch (Exception ex) {
            System.out.println(ex);
        }
        if (ret != 0)
            throw new ExceptionInInitializerError("Erro ao inicializar o enclave: " + System.lineSeparator() +
                    "Código: " + SgxStatus.toHex(ret) + " - " +
                    "Descrição: " + SgxStatus.fromInt(ret).getDescription());

        String teste = "HelloWorld!";
        byte[] b = teste.getBytes();
        ByteBuffer bf = ByteBuffer.wrap(b);
        bf = SgxEncryptData(bf);
        bf = SgxDecryptData(bf);
        String teste2 = new String(bf.array());
        if (!teste2.equals(teste))
            throw new ExceptionInInitializerError("Erro ao selar/deselar os dados");
    }

    public byte[] SgxEncryptBytes(byte[] data) {
        if (data.length == 0)
            return new byte[]{};
        return jni_sgx_seal_data(FEnclaveID, data);
    }

    public ByteBuffer SgxEncryptData(ByteBuffer buffIn) {
        int dataLength = buffIn.remaining();
        byte[] data = new byte[dataLength];
        buffIn.get(data, buffIn.position(), dataLength);

        byte[] encData = this.SgxEncryptBytes(data);

        ByteBuffer result = ByteBuffer.wrap(encData);
        return result;
    }

    public byte[] SgxDecryptBytes(byte[] data) {
        if (data.length == 0)
            return new byte[]{};

        return jni_sgx_unseal_data(FEnclaveID, data);
    }

    public ByteBuffer SgxDecryptData(ByteBuffer buffIn) {
        int dataLength = buffIn.remaining();
        byte[] data = new byte[dataLength];
        buffIn.get(data, buffIn.position(), dataLength);

        byte[] encData = this.SgxDecryptBytes(data);

        ByteBuffer result = ByteBuffer.wrap(encData);
        return result;
    }

    public void DestroyEnclave() {
        jni_sgx_destroy_enclave(FEnclaveID);
    }

    static {
        try {
            System.loadLibrary("Sgx");
            FLibraryLoaded = true;
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    private native boolean jni_sgx_is_enabled();

    private native int jni_initialize_enclave();

    private native byte[] jni_sgx_seal_data(long enclave_id, byte[] data_in);

    private native byte[] jni_sgx_unseal_data(long enclave_id, byte[] data_in);

    private native int jni_sgx_destroy_enclave(long enclave_id);
}
