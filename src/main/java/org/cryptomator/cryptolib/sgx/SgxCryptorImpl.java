package org.cryptomator.cryptolib.sgx;

import org.cryptomator.cryptolib.api.*;
import org.cryptomator.cryptolib.common.AesKeyWrap;
import org.cryptomator.cryptolib.common.MacSupplier;
import org.cryptomator.cryptolib.common.Scrypt;
import org.cryptomator.cryptolib.v1.Constants;
import org.cryptomator.cryptolib.v1.FileNameCryptorImpl;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.cryptomator.cryptolib.v1.Constants.*;
import static org.cryptomator.cryptolib.v1.Constants.DEFAULT_SCRYPT_BLOCK_SIZE;

public class SgxCryptorImpl implements Cryptor {

    private final SecretKey encKey;
    private final SecretKey macKey;
    private final SecureRandom random;
    private final FileContentSgxCryptorImpl fileContentCryptor;
    private final FileHeaderSgxCryptorImpl fileHeaderCryptor;
    private final FileNameCryptorImpl fileNameCryptor;
    private final SgxJNI sgxLib;

    public SgxCryptorImpl(SecretKey encKey, SecretKey macKey, SecureRandom random) {
        this.encKey = encKey;
        this.macKey = macKey;
        this.random = random;
        this.sgxLib = new SgxJNI();
        this.sgxLib.InitializeEnclave();
        this.fileHeaderCryptor = new FileHeaderSgxCryptorImpl();
        this.fileContentCryptor = new FileContentSgxCryptorImpl(sgxLib);
        this.fileNameCryptor = new FileNameCryptorImpl(encKey, macKey);
    }

    @Override
    public FileContentSgxCryptorImpl fileContentCryptor() {
        assertNotDestroyed();
        return this.fileContentCryptor;
    }

    @Override
    public FileHeaderSgxCryptorImpl fileHeaderCryptor() {
        assertNotDestroyed();
        return this.fileHeaderCryptor;
    }

    @Override
    public FileNameCryptorImpl fileNameCryptor() {
        assertNotDestroyed();
        return this.fileNameCryptor;
    }

    @Override
    public boolean isDestroyed() {
        // SecretKey did not implement Destroyable in Java 7:
        if (encKey instanceof Destroyable && macKey instanceof Destroyable) {
            return ((Destroyable) encKey).isDestroyed() || ((Destroyable) macKey).isDestroyed() || sgxLib == null || !sgxLib.IsLibraryLoaded();
        } else {
            return false;
        }
    }

    @Override
    public void close() {
        destroy();
    }

    @Override
    public void destroy() {
        destroyQuietly(encKey);
        destroyQuietly(macKey);
        if (sgxLib != null)
            sgxLib.DestroyEnclave();
    }

    @Override
    public KeyFile writeKeysToMasterkeyFile(CharSequence passphrase, int vaultVersion) {
        return writeKeysToMasterkeyFile(passphrase, new byte[0], vaultVersion);
    }

    @Override
    public KeyFile writeKeysToMasterkeyFile(CharSequence passphrase, byte[] pepper, int vaultVersion) {
        assertNotDestroyed();
        final byte[] salt = new byte[DEFAULT_SCRYPT_SALT_LENGTH];
        random.nextBytes(salt);
        final byte[] saltAndPepper = new byte[salt.length + pepper.length];
        System.arraycopy(salt, 0, saltAndPepper, 0, salt.length);
        System.arraycopy(pepper, 0, saltAndPepper, salt.length, pepper.length);

        final byte[] kekBytes = Scrypt.scrypt(passphrase, saltAndPepper, DEFAULT_SCRYPT_COST_PARAM, DEFAULT_SCRYPT_BLOCK_SIZE, KEY_LEN_BYTES);
        final byte[] wrappedEncryptionKey;
        final byte[] wrappedMacKey;
        try {
            final SecretKey kek = new SecretKeySpec(kekBytes, Constants.ENC_ALG);
            wrappedEncryptionKey = AesKeyWrap.wrap(kek, encKey);
            wrappedMacKey = AesKeyWrap.wrap(kek, macKey);
        } finally {
            Arrays.fill(kekBytes, (byte) 0x00);
        }

        final Mac mac = MacSupplier.HMAC_SHA256.withKey(macKey);
        final byte[] versionMac = mac.doFinal(ByteBuffer.allocate(Integer.SIZE / Byte.SIZE).putInt(vaultVersion).array());

        final SgxKeyFileImpl keyfile = new SgxKeyFileImpl();
        keyfile.setVersion(vaultVersion);
        keyfile.cryptorName = "SGX";
        keyfile.scryptSalt = salt;
        keyfile.scryptCostParam = DEFAULT_SCRYPT_COST_PARAM;
        keyfile.scryptBlockSize = DEFAULT_SCRYPT_BLOCK_SIZE;
        keyfile.encryptionMasterKey = wrappedEncryptionKey;
        keyfile.macMasterKey = wrappedMacKey;
        keyfile.versionMac = versionMac;
        return keyfile;
    }

    private void destroyQuietly(SecretKey key) {
        try {
            if (key instanceof Destroyable && !((Destroyable) key).isDestroyed()) {
                ((Destroyable) key).destroy();
            }
        } catch (DestroyFailedException e) {
            // ignore
        }
    }

    private void assertNotDestroyed() {
        if (isDestroyed()) {
            throw new IllegalStateException("Cryptor destroyed.");
        }
    }
}
