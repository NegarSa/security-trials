import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.sql.Timestamp;
import java.util.Arrays;

public class SecureOutputStream extends OutputStream{
    private OutputStream notSec;
    private BlockCipher blockCipher;
    private byte[] MessageBuffer;
    private int Index;
    private HashFunction hashFunction;

    SecureOutputStream(byte[] symmetricKey, OutputStream outputStream){
        blockCipher = new BlockCipher(symmetricKey);
        notSec = outputStream;
        Index = 0;
        MessageBuffer = new byte[8];
        hashFunction = new HashFunction();
    }
    public void write(int in){ // Buffer the output until we can encrypt it
                                // i.e. either the end of a message (\n)
                                // or the end of a block (8 bytes)
                                // And then send the encrypted message
        MessageBuffer[Index++] = (byte)in;
        boolean sendHash = false;
        try {
            if(in == '\n') {
                for (int i = Index; i < 8; i++) MessageBuffer[i] = 0;
                Index = 8;
                sendHash = true;
            }
            if (Index == 8){ // Full block => encrypt
                byte[] encrypted = new byte[8];
                blockCipher.encrypt(MessageBuffer, 0, encrypted, 0);
                for (int i = 0; i < 8; i++) notSec.write(encrypted[i]);
                Index = 0;

                hashFunction.update(MessageBuffer);
                if(sendHash){
                    // Add current time in seconds
                    hashFunction.update(new Timestamp((int)System.currentTimeMillis() / 1000).toString().getBytes());

                    byte[] hash = hashFunction.digest();
                    hashFunction.reset();
                    for (byte b : hash) {
                        notSec.write(b);
                    }
                }
            }
        }
        catch(IOException x) {x.printStackTrace();}
    }
    public void write(byte[] in){
        int len = in.length;
        byte[] out = new byte[len];
        for (int i = 0; i + 7 < len; i+=8) {
            blockCipher.encrypt(in, i, out, i);
        }
        try {
            System.out.println("out+ " + Arrays.toString(out));
            notSec.write(out);
        }
        catch (IOException x) {
            x.printStackTrace();
        }
    }
    public void close() throws IOException {notSec.close();}
    public void flush() throws IOException {notSec.flush();}
}
