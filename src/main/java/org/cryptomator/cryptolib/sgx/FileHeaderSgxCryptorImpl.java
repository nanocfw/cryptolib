package org.cryptomator.cryptolib.sgx;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;

import java.nio.ByteBuffer;

public class FileHeaderSgxCryptorImpl implements FileHeaderCryptor {

    @Override
    public FileHeader create() {
        return new FileHeaderSgxImpl();
    }

    @Override
    public int headerSize() {
        return Constants.FILE_HEADER_SIZE;
    }

    @Override
    public ByteBuffer encryptHeader(FileHeader header) {
        ByteBuffer result = ByteBuffer.allocate(Constants.FILE_HEADER_SIZE);
        return result;
    }

    @Override
    public FileHeader decryptHeader(ByteBuffer ciphertextHeaderBuf) throws AuthenticationFailedException {
       return new FileHeaderSgxImpl();
    }
}
