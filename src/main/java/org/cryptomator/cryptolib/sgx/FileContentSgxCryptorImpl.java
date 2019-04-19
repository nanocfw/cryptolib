package org.cryptomator.cryptolib.sgx;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.sgx.SgxJNI;

import java.nio.ByteBuffer;

import static org.cryptomator.cryptolib.sgx.Constants.*;

public class FileContentSgxCryptorImpl implements FileContentCryptor {

    private final SgxJNI FSgxLib;

    FileContentSgxCryptorImpl(SgxJNI sgxLib) {
        FSgxLib = sgxLib;
    }

    @Override
    public int cleartextChunkSize() {
        return SGX_PAYLOAD_SIZE;
    }

    @Override
    public int ciphertextChunkSize() {
        return SGX_CHUNK_SIZE;
    }

    @Override
    public ByteBuffer encryptChunk(ByteBuffer cleartextChunk, long chunkNumber, FileHeader header) {
        if (cleartextChunk.remaining() == 0 || cleartextChunk.remaining() > SGX_PAYLOAD_SIZE)
            throw new IllegalArgumentException("Invalid chunk");


        return FSgxLib.SgxEncryptData(cleartextChunk);
    }

    @Override
    public ByteBuffer decryptChunk(ByteBuffer ciphertextChunk, long chunkNumber, FileHeader header, boolean authenticate) throws AuthenticationFailedException {
        if (ciphertextChunk.remaining() < SGX_ADD_BYTES || ciphertextChunk.remaining() > SGX_CHUNK_SIZE)
            throw new IllegalArgumentException("Invalid chunk size: " + ciphertextChunk.remaining() + ", expected range [" + (SGX_ADD_BYTES) + ", " + SGX_CHUNK_SIZE + "]");

        return FSgxLib.SgxDecryptData(ciphertextChunk);
    }
}
