package org.cryptomator.cryptolib.sgx;

import org.cryptomator.cryptolib.api.FileHeader;

public class FileHeaderSgxImpl implements FileHeader {

    private long filesize = -1L;

    @Override
    public long getFilesize() {
        return this.filesize;
    }

    @Override
    public void setFilesize(long filesize) {
        this.filesize = filesize;
    }
}
