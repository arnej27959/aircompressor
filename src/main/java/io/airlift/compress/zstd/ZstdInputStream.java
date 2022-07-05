/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.airlift.compress.zstd;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import static io.airlift.compress.zstd.Constants.COMPRESSED_BLOCK;
import static io.airlift.compress.zstd.Constants.MAGIC_NUMBER;
import static io.airlift.compress.zstd.Constants.MAX_BLOCK_SIZE;
import static io.airlift.compress.zstd.Constants.RAW_BLOCK;
import static io.airlift.compress.zstd.Constants.RLE_BLOCK;
import static io.airlift.compress.zstd.Constants.SIZE_OF_BLOCK_HEADER;
import static io.airlift.compress.zstd.Constants.SIZE_OF_BYTE;
import static io.airlift.compress.zstd.Constants.SIZE_OF_INT;
import static io.airlift.compress.zstd.Util.fail;
import static sun.misc.Unsafe.ARRAY_BYTE_BASE_OFFSET;

/**
 * Take a compressed InputStream and decompress it as needed
 * @author arnej27959
 */
public class ZstdInputStream
        extends InputStream
{
    public static final int DEFAULT_BUFFER_SIZE = 8 * 1024;
    public static final int BUFFER_SIZE_MASK = ~(DEFAULT_BUFFER_SIZE - 1);
    private final InputStream inputStream;
    private byte[] inputBuffer;
    private int inputPosition;
    private int inputEnd;
    private byte[] outputBuffer;
    private int outputPosition;
    private int outputEnd;
    private boolean isClosed;
    private boolean seenEof;
    private boolean lastBlock;
    private boolean singleSegmentFlag;
    private boolean contentChecksumFlag;
    private int skipBytes;
    private int windowSize;
    private int blockMaximumSize = MAX_BLOCK_SIZE;
    private int curBlockSize;
    private int curBlockType = -1;
    private FrameHeader curHeader;
    private ZstdBlockDecompressor blockDecompressor;
    private long evictedInput;

    public ZstdInputStream(InputStream inp, int initialBufferSize)
    {
        this.inputStream = inp;
        this.inputBuffer = new byte[initialBufferSize];
        this.outputBuffer = new byte[initialBufferSize];
    }

    public ZstdInputStream(InputStream inp)
    {
        this(inp, DEFAULT_BUFFER_SIZE);
    }

    @Override
    public int available()
    {
        return outputAvailable();
    }

    @Override
    public int read() throws IOException
    {
        throwIfClosed();
        if (ensureGotOutput()) {
            int b = outputBuffer[outputPosition++];
            return (b & 0xFF);
        }
        else {
            return -1;
        }
    }

    @Override
    public int read(byte[] b) throws IOException
    {
        return read(b, 0, b.length);
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException
    {
        throwIfClosed();
        if (ensureGotOutput()) {
            len = Math.min(outputAvailable(), len);
            System.arraycopy(outputBuffer, outputPosition, b, off, len);
            outputPosition += len;
            return len;
        }
        else {
            return -1;
        }
    }

    @Override
    public void close() throws IOException
    {
        throwIfClosed();
        if (!seenEof) {
            inputStream.close();
        }
        isClosed = true;
    }

    private void check(boolean condition, String reason)
    {
        Util.verify(condition, curInputFilePosition(), reason);
    }

    private boolean ensureGotOutput() throws IOException
    {
        while ((outputAvailable() == 0) && !seenEof) {
            if (ensureGotFrameHeader() && ensureGotBlock()) {
                decompressBlock();
            }
        }
        if (outputAvailable() > 0) {
            return true;
        }
        else {
            check(seenEof, "unable to decode to EOF");
            check(inputAvailable() == 0, "leftover input at end");
            check(curHeader == null, "unfinished frame at end");
            return false;
        }
    }

    private void readMoreInput() throws IOException
    {
        ensureInputSpace(1024);
        int got = inputStream.read(inputBuffer, inputEnd, inputSpace());
        if (got == -1) {
            seenEof = true;
        }
        else {
            inputEnd += got;
        }
    }

    private ByteBuffer inputBB()
    {
        ByteBuffer bb = ByteBuffer.wrap(inputBuffer, inputPosition, inputAvailable());
        bb.order(ByteOrder.LITTLE_ENDIAN);
        return bb;
    }

    private boolean ensureGotFrameHeader() throws IOException
    {
        if (curHeader != null) {
            return true;
        }
        // a skip frame is minimum 8 bytes
        // a data frame is minimum 4 + 2 + 3 = 9 bytes, but we only
        // need 5 bytes to know the size of the frame header
        if (inputAvailable() < 8) {
            readMoreInput();
            // retry from start
            return false;
        }
        ByteBuffer bb = inputBB();
        int magic = bb.getInt();
        if ((magic >= 0x184D2A50) && (magic <= 0x184D2A5F)) {
            inputPosition += SIZE_OF_INT;
            skipBytes = bb.getInt();
            inputPosition += SIZE_OF_INT;
            while (skipBytes > 0) {
                if (skipBytes < inputAvailable()) {
                    inputPosition += skipBytes;
                    skipBytes = 0;
                    // retry from start
                    return false;
                }
                else {
                    skipBytes -= inputAvailable();
                    inputPosition = 0;
                    inputEnd = 0;
                    readMoreInput();
                }
            }
        }
        if (magic == MAGIC_NUMBER) {
            int fhDesc = 0xFF & bb.get();
            int frameContentSizeFlag = (fhDesc & 0b11000000) >> 6;
            singleSegmentFlag =        (fhDesc & 0b00100000) != 0;
            contentChecksumFlag =      (fhDesc & 0b00000100) != 0;
            int dictionaryIdFlag =     (fhDesc & 0b00000011)     ;
            // 4 byte magic + 1 byte fhDesc
            int fhSize = SIZE_OF_INT + SIZE_OF_BYTE;
            // add size of frameContentSize
            if (frameContentSizeFlag == 0) {
                fhSize += (singleSegmentFlag ? 1 : 0);
            }
            else {
                fhSize += 1 << frameContentSizeFlag;
            }
            // add size of window descriptor
            fhSize += (singleSegmentFlag ? 0 : 1);
            // add size of dictionary id
            fhSize += (1 << dictionaryIdFlag) >> 1;
            if (fhSize > inputAvailable()) {
                readMoreInput();
                // retry from start
                return false;
            }
            inputPosition += SIZE_OF_INT;
            curHeader = readFrameHeader();
            inputPosition += fhSize - SIZE_OF_INT;
            startFrame();
            return true;
        }
        else {
            throw fail(curInputFilePosition(), "bad magic: " + magic);
        }
    }

    private void startFrame()
    {
        blockDecompressor = new ZstdBlockDecompressor(curHeader);
        check(outputPosition == outputEnd, "orphan output present");
        outputPosition = 0;
        outputEnd = 0;
        if (singleSegmentFlag) {
            windowSize = (int) curHeader.contentSize;
            blockMaximumSize = windowSize;
            ensureOutputSpace(windowSize);
        }
        else {
            windowSize = curHeader.windowSize;
            blockMaximumSize = Math.min(windowSize, MAX_BLOCK_SIZE);
            ensureOutputSpace(blockMaximumSize + windowSize);
        }
    }

    private boolean ensureGotBlock() throws IOException
    {
        check(curHeader != null, "no current frame");
        if (curBlockType == -1) {
            // must have a block now
            if (inputAvailable() < SIZE_OF_BLOCK_HEADER) {
                readMoreInput();
                // retry from start
                return false;
            }
            int blkHeader = nextByte() << 16 | nextByte() << 8 | nextByte();
            lastBlock =    (blkHeader & 0b001) != 0;
            curBlockType = (blkHeader & 0b110) >> 1;
            curBlockSize = blkHeader >> 3;
            ensureInputSpace(curBlockSize + SIZE_OF_INT);
        }
        if (inputAvailable() < curBlockSize + (contentChecksumFlag ? SIZE_OF_INT : 0)) {
            readMoreInput();
            // retry from start
            return false;
        }
        return true;
    }

    int nextByte()
    {
        int r = 0xFF & inputBuffer[inputPosition];
        inputPosition++;
        return r;
    }

    long inputAddress()
    {
        return ARRAY_BYTE_BASE_OFFSET + inputPosition;
    }

    long inputLimit()
    {
        return ARRAY_BYTE_BASE_OFFSET + inputEnd;
    }

    long outputAddress()
    {
        return ARRAY_BYTE_BASE_OFFSET + outputEnd;
    }

    long outputLimit()
    {
        return ARRAY_BYTE_BASE_OFFSET + outputBuffer.length;
    }

    int decodeRaw()
    {
        check(inputAddress() + curBlockSize <= inputLimit(), "Not enough input bytes");
        check(outputAddress() + curBlockSize <= outputLimit(), "Not enough output space");
        return blockDecompressor.decodeRawBlock(inputBuffer, inputAddress(), curBlockSize, outputBuffer, outputAddress(), outputLimit());
    }

    int decodeRle()
    {
        check(inputAddress() + 1 <= inputLimit(), "Not enough input bytes");
        check(outputAddress() + curBlockSize <= outputLimit(), "Not enough output space");
        return blockDecompressor.decodeRleBlock(curBlockSize, inputBuffer, inputAddress(), outputBuffer, outputAddress(), outputLimit());
    }

    int decodeCompressed()
    {
        check(inputAddress() + curBlockSize <= inputLimit(), "Not enough input bytes");
        check(outputAddress() + blockMaximumSize <= outputLimit(), "Not enough output space");
        return blockDecompressor.decodeCompressedBlock(
                inputBuffer, inputAddress(),
                curBlockSize,
                outputBuffer, outputAddress(), outputLimit(),
                windowSize, ARRAY_BYTE_BASE_OFFSET);
    }

    private void decompressBlock()
    {
        check(outputPosition == outputEnd, "orphan output present");
        switch (curBlockType) {
            case RAW_BLOCK:
                ensureOutputSpace(curBlockSize);
                outputEnd += decodeRaw();
                inputPosition += curBlockSize;
                break;
            case RLE_BLOCK:
                ensureOutputSpace(curBlockSize);
                outputEnd += decodeRle();
                inputPosition += 1;
                break;
            case COMPRESSED_BLOCK:
                check(curBlockSize < blockMaximumSize, "compressed block must be smaller than Block_Maximum_Size");
                ensureOutputSpace(blockMaximumSize);
                outputEnd += decodeCompressed();
                inputPosition += curBlockSize;
                break;
            default:
                throw fail(curInputFilePosition(), "Invalid block type " + curBlockType);
        }
        curBlockType = -1;
        if (lastBlock) {
            curHeader = null;
            blockDecompressor = null;
            if (contentChecksumFlag) {
                check(inputAvailable() >= SIZE_OF_INT, "missing checksum data");
                inputPosition += SIZE_OF_INT;
            }
        }
    }

    private int inputAvailable()
    {
        return inputEnd - inputPosition;
    }

    private int inputSpace()
    {
        return inputBuffer.length - inputEnd;
    }

    private long curInputFilePosition()
    {
        return evictedInput + inputPosition;
    }

    private void ensureInputSpace(int size)
    {
        if (inputSpace() < size) {
            evictedInput += inputPosition;
            if (size < inputPosition) {
                System.arraycopy(inputBuffer, inputPosition, inputBuffer, 0, inputAvailable());
                inputEnd = inputAvailable();
                inputPosition = 0;
            }
            else {
                int newSize = (inputBuffer.length * 2 + size) & BUFFER_SIZE_MASK;
                byte[] newBuf = new byte[newSize];
                System.arraycopy(inputBuffer, inputPosition, newBuf, 0, inputAvailable());
                inputBuffer = newBuf;
                inputEnd = inputAvailable();
                inputPosition = 0;
            }
        }
    }

    private int outputAvailable()
    {
        return outputEnd - outputPosition;
    }

    private int outputSpace()
    {
        return outputBuffer.length - outputEnd;
    }

    private void ensureOutputSpace(int size)
    {
        if (outputSpace() < size) {
            check(outputAvailable() == 0, "logic error");
            byte[] newBuf;
            if (windowSize * 4 + size < outputPosition) {
                // plenty space in old buffer
                newBuf = outputBuffer;
            }
            else {
                int newSize = (outputBuffer.length
                               + windowSize * 4
                               + size
                               + DEFAULT_BUFFER_SIZE) & BUFFER_SIZE_MASK;
                newBuf = new byte[newSize];
            }
            // keep up to one window of old data
            int sizeToKeep = Math.min(outputPosition, windowSize);
            System.arraycopy(outputBuffer, outputPosition - sizeToKeep, newBuf, 0, sizeToKeep);
            outputEnd = sizeToKeep;
            outputPosition = sizeToKeep;
        }
    }

    private void throwIfClosed() throws IOException
    {
        if (isClosed) {
            throw new IOException("Input stream is already closed");
        }
    }

    private FrameHeader readFrameHeader()
    {
        long base = ARRAY_BYTE_BASE_OFFSET + inputPosition;
        long limit = ARRAY_BYTE_BASE_OFFSET + inputEnd;
        return ZstdFrameDecompressor.readFrameHeader(inputBuffer, base, limit);
    }
}
