package org.cryptomator.cryptolib.sgx;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import org.cryptomator.cryptolib.api.KeyFile;

public class SgxKeyFileImpl extends KeyFile {
    @Expose
    @SerializedName("cryptorName")
    String cryptorName;
}
