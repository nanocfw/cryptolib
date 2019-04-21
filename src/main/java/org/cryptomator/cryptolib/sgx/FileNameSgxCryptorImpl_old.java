package org.cryptomator.cryptolib.sgx;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.cryptomator.cryptolib.common.MessageDigestSupplier;

import java.nio.charset.Charset;

public class FileNameSgxCryptorImpl_old implements FileNameCryptor {

    private final SgxJNI FSgxLib;
    private static final Charset UTF_8 = Charset.forName("UTF-8");
    private static final BaseEncoding BASE32 = BaseEncoding.base32();

    FileNameSgxCryptorImpl_old(SgxJNI sgxLib) {
        FSgxLib = sgxLib;
    }

    @Override
    public String hashDirectoryId(String cleartextDirectoryId) {
        byte[] cleartextBytes = cleartextDirectoryId.getBytes(UTF_8);
        byte[] encryptedBytes = FSgxLib.SgxEncryptBytes(cleartextBytes);
        byte[] hashedBytes = MessageDigestSupplier.SHA1.get().digest(encryptedBytes);
        return BASE32.encode(hashedBytes);
    }

    @Override
    public String encryptFilename(String cleartextName, byte[]... associatedData) {
        return encryptFilename(BASE32, cleartextName, associatedData);
    }

    @Override
    public String encryptFilename(BaseEncoding encoding, String cleartextName, byte[]... associatedData) {
        byte[] cleartextBytes = cleartextName.getBytes(UTF_8);
        byte[] encryptedBytes = cleartextBytes; //FSgxLib.SgxEncryptBytes(cleartextBytes);
        return encoding.encode(encryptedBytes);
    }

    @Override
    public String decryptFilename(String ciphertextName, byte[]... associatedData) throws AuthenticationFailedException {
        return decryptFilename(BASE32, ciphertextName, associatedData);
    }

    @Override
    public String decryptFilename(BaseEncoding encoding, String ciphertextName, byte[]... associatedData) throws AuthenticationFailedException {
        byte[] encryptedBytes = encoding.decode(ciphertextName);
        byte[] cleartextBytes = encryptedBytes;//FSgxLib.SgxDecryptBytes(encryptedBytes);
        return new String(cleartextBytes, UTF_8);
    }
}
