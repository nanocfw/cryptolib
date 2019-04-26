package org.cryptomator.cryptolib.sgx;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import org.cryptomator.cryptolib.api.KeyFile;

public class SgxKeyFileImpl extends KeyFile {
    @Expose
    @SerializedName("cryptorName")
    String cryptorName;

    @Expose
    @SerializedName("scryptSalt")
    byte[] scryptSalt;

    @Expose
    @SerializedName("scryptCostParam")
    int scryptCostParam;

    @Expose
    @SerializedName("scryptBlockSize")
    int scryptBlockSize;

    @Expose
    @SerializedName("primaryMasterKey")
    byte[] encryptionMasterKey;

    @Expose
    @SerializedName("hmacMasterKey")
    byte[] macMasterKey;

    @Expose
    @SerializedName("versionMac")
    byte[] versionMac;
}
