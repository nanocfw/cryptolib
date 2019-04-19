package org.cryptomator.cryptolib.sgx;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.cryptomator.cryptolib.sgx.SgxJNI;

import java.nio.ByteBuffer;

public class FileHeaderSgxCryptorImpl implements FileHeaderCryptor {

    private final SgxJNI FSgxLib;

    FileHeaderSgxCryptorImpl(SgxJNI sgxLib) {
        FSgxLib = sgxLib;
    }

    @Override
    public FileHeader create() {
        return new FileHeaderSgxImpl();
    }

    @Override
    public int headerSize() {
        return 8;
    }

    @Override
    public ByteBuffer encryptHeader(FileHeader header) {
        ByteBuffer result = ByteBuffer.allocate(8);
        return result;
    }

    @Override
    public FileHeader decryptHeader(ByteBuffer ciphertextHeaderBuf) throws AuthenticationFailedException {
       return new FileHeaderSgxImpl();
    }
}
