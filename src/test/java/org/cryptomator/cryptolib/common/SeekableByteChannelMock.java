/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.common;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;

public class SeekableByteChannelMock implements SeekableByteChannel {

	boolean open = true;
	private final ByteBuffer buf;

	public SeekableByteChannelMock(ByteBuffer buf) {
		this.buf = buf;
	}

	@Override
	public boolean isOpen() {
		return open;
	}

	@Override
	public void close() throws IOException {
		open = false;
	}

	@Override
	public int read(ByteBuffer dst) throws IOException {
		if (!buf.hasRemaining()) {
			return -1;
		} else {
			int num = Math.min(buf.remaining(), dst.remaining());
			ByteBuffer limitedSrc = buf.asReadOnlyBuffer();
			limitedSrc.limit(limitedSrc.position() + num);
			dst.put(limitedSrc);
			buf.position(limitedSrc.position());
			return num;
		}
	}

	@Override
	public int write(ByteBuffer src) throws IOException {
		int num = Math.min(buf.remaining(), src.remaining());
		ByteBuffer limitedSrc = src.asReadOnlyBuffer();
		limitedSrc.limit(limitedSrc.position() + num);
		buf.put(limitedSrc);
		return num;
	}

	@Override
	public long position() throws IOException {
		return buf.position();
	}

	@Override
	public SeekableByteChannel position(long newPosition) throws IOException {
		assert newPosition < Integer.MAX_VALUE;
		buf.position((int) newPosition);
		return this;
	}

	@Override
	public long size() throws IOException {
		return buf.limit();
	}

	@Override
	public SeekableByteChannel truncate(long size) throws IOException {
		assert size < Integer.MAX_VALUE;
		if (size < buf.position()) {
			buf.position((int) size);
		}
		buf.limit((int) size);
		return this;
	}

}
