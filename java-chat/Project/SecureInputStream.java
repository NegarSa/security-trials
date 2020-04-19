import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.io.IOException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.util.Arrays;

public class SecureInputStream extends InputStream{
    private BlockCipher blockCipher;
    private InputStream notSec;
    private byte[] MessageBuffer;
    private int Index;
    private HashFunction hashFunction;

    SecureInputStream(byte[] symmetricKey, InputStream inputStream){
        blockCipher = new BlockCipher(symmetricKey);
        notSec = inputStream;
        Index = 0;
        MessageBuffer = new byte[8];
        hashFunction = new HashFunction();
    }
    public int read(){
        boolean checkHash = false;
        if(Index == 8){ // Read the next block, decrypt and buffer them
            Index = 0;
            byte[] Message = new byte[8];
            byte[] hash = new byte[20];
            try {
                for (int i = 0; i < 8; i++) {
                    int tmp = notSec.read();
                    if(tmp == -1) break;
                    Message[i] = (byte)tmp;

                    if((char)tmp == '\n') {
                        for (int j = 0; j < 20; j++) {
                            hash[i] = (byte)notSec.read();
                            checkHash = true;
                        }
                    }
                }
                blockCipher.decrypt(Message, 0, MessageBuffer, 0);
                hashFunction.update(MessageBuffer);
                if(checkHash){
                    hashFunction.update(new Timestamp((int)System.currentTimeMillis() / 1000).toString().getBytes());
                    byte[] hashed = hashFunction.digest();
                    // If they are equal, there is no problem
                    if(!Arrays.equals(hashed, hash))  return -2;
                }
            }
            catch (IOException x){x.printStackTrace();}
        }
        return MessageBuffer[Index++]; // Already decrypted
    }
    public int read(byte[] out){ // Read an entire block of input and decrypt it
                                // This way we don't need buffering
        try {
            byte[] mes = new byte[8];
            int numBytes = 0;
            for (int i = 0; i < 8; i++) {
                int temp = (byte)notSec.read();
                System.out.println(temp);
                if (temp == -1){
                    numBytes = i;
                    break;
                }
                mes[i] = (byte)temp;
                if (temp == '\n'){
                    numBytes = i + 1;
                    break;
                }
            }
            //int numBytes = notSec.read(mes, 0, 8);
            System.out.println("in + " + Arrays.toString(mes));
            if (numBytes == -1 || numBytes == 0) return -1;

            blockCipher.decrypt(mes, 0, out, 0);
            System.out.println("mes + "+ Arrays.toString(out) + new String(out));
            return numBytes;
        }
        catch (IOException x){
            x.printStackTrace();
        }
        return -1;
    }

    public void close() throws IOException {
        notSec.close();
    }
}

