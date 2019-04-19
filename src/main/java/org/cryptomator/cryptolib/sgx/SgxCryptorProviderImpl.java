package org.cryptomator.cryptolib.sgx;

import org.cryptomator.cryptolib.api.*;

public class SgxCryptorProviderImpl implements CryptorProvider {

    @Override
    public Cryptor createNew() {
        return new SgxCryptorImpl();
    }

    @Override
    public Cryptor createFromKeyFile(KeyFile keyFile, CharSequence passphrase, int expectedVaultVersion) throws UnsupportedVaultFormatException, InvalidPassphraseException {
        return createNew();
    }

    @Override
    public Cryptor createFromKeyFile(KeyFile keyFile, CharSequence passphrase, byte[] pepper, int expectedVaultVersion) throws UnsupportedVaultFormatException, InvalidPassphraseException {
        return createNew();
    }
}
