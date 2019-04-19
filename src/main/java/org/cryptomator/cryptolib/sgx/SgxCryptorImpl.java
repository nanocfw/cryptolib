package org.cryptomator.cryptolib.sgx;

import org.cryptomator.cryptolib.api.*;
import org.cryptomator.cryptolib.sgx.SgxJNI;

public class SgxCryptorImpl implements Cryptor {

    private final FileContentSgxCryptorImpl fileContentCryptor;
    private final FileHeaderSgxCryptorImpl fileHeaderCryptor;
    private final FileNameSgxCryptorImpl fileNameCryptor;
    private final SgxJNI sgxLib;

    public SgxCryptorImpl() {
        this.sgxLib = new SgxJNI();
        this.sgxLib.InitializeEnclave();
        this.fileHeaderCryptor = new FileHeaderSgxCryptorImpl(sgxLib);
        this.fileContentCryptor = new FileContentSgxCryptorImpl(sgxLib);
        this.fileNameCryptor = new FileNameSgxCryptorImpl(sgxLib);
    }

    @Override
    public FileContentSgxCryptorImpl fileContentCryptor() {
        return this.fileContentCryptor;
    }

    @Override
    public FileHeaderSgxCryptorImpl fileHeaderCryptor() {
        return this.fileHeaderCryptor;
    }

    @Override
    public FileNameSgxCryptorImpl fileNameCryptor() {
        return this.fileNameCryptor;
    }

    @Override
    public KeyFile writeKeysToMasterkeyFile(CharSequence passphrase, int vaultVersion) {
        return writeKeysToMasterkeyFile(passphrase, null, vaultVersion);
    }

    @Override
    public KeyFile writeKeysToMasterkeyFile(CharSequence passphrase, byte[] pepper, int vaultVersion) {
        SgxKeyFileImpl keyFile = new SgxKeyFileImpl();
        keyFile.setVersion(vaultVersion);
        keyFile.cryptorName = "SGX";
        return keyFile;
    }

    @Override
    public void destroy() {
        if (sgxLib != null)
            sgxLib.DestroyEnclave();
    }

    @Override
    public void close() {
        destroy();
    }

    @Override
    public boolean isDestroyed() {
      return (sgxLib == null || !sgxLib.IsLibraryLoaded());
    }
}
