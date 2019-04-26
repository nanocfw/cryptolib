/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib;

import java.security.SecureRandom;

import org.cryptomator.cryptolib.api.*;
import org.cryptomator.cryptolib.common.ReseedingSecureRandom;
import org.cryptomator.cryptolib.sgx.SgxCryptorProviderImpl;
import org.cryptomator.cryptolib.v1.CryptorProviderImpl;

import static com.google.common.base.Preconditions.checkArgument;

public final class Cryptors {

	/**
	 * @param seeder A native (if possible) SecureRandom used to seed internal CSPRNGs.
	 * @return A version 1 CryptorProvider
	 */
	public static CryptorProvider version1(SecureRandom seeder) {
		SecureRandom csprng = ReseedingSecureRandom.create(seeder);
		return new CryptorProviderImpl(csprng);
	}

	public static CryptorProvider sgx(SecureRandom seeder)
	{
		SecureRandom csprng = ReseedingSecureRandom.create(seeder);
		return new SgxCryptorProviderImpl(csprng);
	}

	/**
	 * Calculates the size of the cleartext resulting from the given ciphertext decrypted with the given cryptor.
	 * 
	 * @param ciphertextSize Length of encrypted payload. Not including the {@link FileHeader#getFilesize() length of the header}.
	 * @param cryptor The cryptor which defines the cleartext/ciphertext ratio
	 * @return Cleartext length of a <code>ciphertextSize</code>-sized ciphertext decrypted with <code>cryptor</code>.
	 */
	public static long cleartextSize(long ciphertextSize, Cryptor cryptor) {
		checkArgument(ciphertextSize >= 0, "expected ciphertextSize to be positive, but was %s", ciphertextSize);
		long cleartextChunkSize = cryptor.fileContentCryptor().cleartextChunkSize();
		long ciphertextChunkSize = cryptor.fileContentCryptor().ciphertextChunkSize();
		long overheadPerChunk = ciphertextChunkSize - cleartextChunkSize;
		long numFullChunks = ciphertextSize / ciphertextChunkSize; // floor by int-truncation
		long additionalCiphertextBytes = ciphertextSize % ciphertextChunkSize;
		if (additionalCiphertextBytes > 0 && additionalCiphertextBytes <= overheadPerChunk) {
			throw new IllegalArgumentException("Method not defined for input value " + ciphertextSize);
		}
		long additionalCleartextBytes = (additionalCiphertextBytes == 0) ? 0 : additionalCiphertextBytes - overheadPerChunk;
		assert additionalCleartextBytes >= 0;
		return cleartextChunkSize * numFullChunks + additionalCleartextBytes;
	}

	/**
	 * Calculates the size of the ciphertext resulting from the given cleartext encrypted with the given cryptor.
	 *
	 * @param cleartextSize Length of a unencrypted payload.
	 * @param cryptor The cryptor which defines the cleartext/ciphertext ratio

	 * @return Ciphertext length of a <code>cleartextSize</code>-sized cleartext encrypted with <code>cryptor</code>.
	 *         Not including the {@link FileHeader#getFilesize() length of the header}.
	 */
	public static long ciphertextSize(long cleartextSize, Cryptor cryptor) {
		checkArgument(cleartextSize >= 0, "expected cleartextSize to be positive, but was %s", cleartextSize);
		long cleartextChunkSize = cryptor.fileContentCryptor().cleartextChunkSize();
		long ciphertextChunkSize = cryptor.fileContentCryptor().ciphertextChunkSize();
		long overheadPerChunk = ciphertextChunkSize - cleartextChunkSize;
		long numFullChunks = cleartextSize / cleartextChunkSize; // floor by int-truncation
		long additionalCleartextBytes = cleartextSize % cleartextChunkSize;
		long additionalCiphertextBytes = (additionalCleartextBytes == 0) ? 0 : additionalCleartextBytes + overheadPerChunk;
		assert additionalCiphertextBytes >= 0;
		return ciphertextChunkSize * numFullChunks + additionalCiphertextBytes;
	}

	/**
	 * Reencrypts a masterkey with a new passphrase.
	 * 
	 * @param cryptoProvider A suitable CryptorProvider instance, i.e. same version as the original masterkey has been created with.
	 * @param masterkey The original JSON representation of the masterkey
	 * @param oldPassphrase The old passphrase
	 * @param newPassphrase The new passphrase
	 * @return A JSON representation of the masterkey, now encrypted with <code>newPassphrase</code>
	 * @throws InvalidPassphraseException If the wrong <code>oldPassphrase</code> has been supplied for the <code>masterkey</code>
	 * @since 1.1.0
	 * @see #changePassphrase(CryptorProvider, byte[], byte[], CharSequence, CharSequence)
	 */
	public static byte[] changePassphrase(CryptorProvider cryptoProvider, byte[] masterkey, CharSequence oldPassphrase, CharSequence newPassphrase) throws InvalidPassphraseException {
		return changePassphrase(cryptoProvider, masterkey, new byte[0], oldPassphrase, newPassphrase);
	}

	/**
	 * Reencrypts a masterkey with a new passphrase.
	 * 
	 * @param cryptoProvider A suitable CryptorProvider instance, i.e. same version as the original masterkey has been created with.
	 * @param masterkey The original JSON representation of the masterkey
	 * @param pepper An application-specific pepper added to the salt during key-derivation (if applicable)
	 * @param oldPassphrase The old passphrase
	 * @param newPassphrase The new passphrase
	 * @return A JSON representation of the masterkey, now encrypted with <code>newPassphrase</code>
	 * @throws InvalidPassphraseException If the wrong <code>oldPassphrase</code> has been supplied for the <code>masterkey</code>
	 * @since 1.1.4
	 */
	public static byte[] changePassphrase(CryptorProvider cryptoProvider, byte[] masterkey, byte[] pepper, CharSequence oldPassphrase, CharSequence newPassphrase) throws InvalidPassphraseException {
		final KeyFile keyFile = KeyFile.parse(masterkey);
		try (Cryptor cryptor = cryptoProvider.createFromKeyFile(keyFile, oldPassphrase, pepper, keyFile.getVersion())) {
			return cryptor.writeKeysToMasterkeyFile(newPassphrase, pepper, keyFile.getVersion()).serialize();
		}
	}

}
