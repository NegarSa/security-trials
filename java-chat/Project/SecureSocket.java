// This file implements a secure (encrypted) version of the Socket class.
// (Actually, it is insecure as written, and students will fix the insecurities
// as part of their homework.)
//
// This class is meant to work in tandem with the SecureServerSocket class.
// The idea is that if you have a program that uses java.net.Socket and
// java.net.ServerSocket, you can make that program secure by replacing 
// java.net.Socket by this class, and java.net.ServerSocket by 
// SecureServerSocket.
//
// Like the ordinary Socket interface, this one differentiates between the
// client and server sides of a connection.  A server waits for connections
// on a SecureServerSocket, and a client uses this class to connect to a 
// server.
// 
// A client makes a connection like this:
//        String          serverHostname = ...
//        int             serverPort = ...
//        byte[]          myPrivateKey = ...
//        byte[]          serverPublicKey = ...
//        SecureSocket sock;
//        sock = new SecureSocket(serverHostname, serverPort,
//                                   myPrivateKey, serverPublicKey);
// 
// The keys are in a key-exchange protocol (which students will write), to
// establish a shared secret key that both the client and server know.
//
// Having created a SecureSocket, a program can get an associated
// InputStream (for receiving data that arrives on the socket) and an
// associated OutputStream (for sending data on the socket):
//
//         InputStream inStream = sock.getInputStream();
//         OutputStream outStream = sock.getOutputStream();


import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.io.IOException;
import java.net.UnknownHostException;
import java.util.Arrays;


public class SecureSocket {
    private Socket       sock;
    private SecureInputStream  in;
    private SecureOutputStream out;

    public SecureSocket(String hostname, int port,
                        byte[] clientPrivateKey, byte[] serverPublicKey)
            throws IOException, UnknownHostException {
        // this constructor is called by a client who wants to make a secure
        // socket connection to a server

        sock = new Socket(hostname, port);

        byte[] symmetricKey = keyExchange(clientPrivateKey, serverPublicKey, false);

        setupStreams(sock, symmetricKey, false);
    }

    public SecureSocket(Socket s, byte[] myPrivateKey) throws IOException {
        // don't call this yourself
        // this is meant to be called by SecureServerSocket

        sock = s;

        byte[] symmetricKey = keyExchange(myPrivateKey, null, true);

        setupStreams(sock, symmetricKey, true);
    }

    private byte[] keyExchange(byte[] myPrivateKey,
                               byte[] hisPublicKey,  // null if I am server
                               boolean iAmClient ) throws IOException {

        InputStream instream = sock.getInputStream();
        OutputStream outstream = sock.getOutputStream();

        if(iAmClient){ // server
            RSA my_serverRSA = new RSA(Config.getAsString("serverkey.txt", "Pub"),
                    Config.getAsString("serverkey.txt", "Pri"));

            byte[] clientpub = new byte[5000];
            int num = instream.read(clientpub, 0, clientpub.length); // server gets client pub key
            if(num != clientpub.length)    throw new RuntimeException();

            RSA clientRSA = new RSA(Arrays.toString(clientpub));

            byte[] nonceServer = Util.getRandomByteArray(16);
            byte[] enNonce = clientRSA.encryptWithPublic(nonceServer);
            outstream.write(enNonce, 0, enNonce.length); // Server sends its nonce, encrypted with client pub key
            outstream.flush();

            byte[] clientNonce_rec = new byte[32];
            num = instream.read(clientNonce_rec, 0, clientNonce_rec.length);
            if(num != clientNonce_rec.length)    throw new RuntimeException();
            byte[] key = my_serverRSA.decryptWithPrivate(clientNonce_rec);

            byte[] nonceClient_dec = new byte[16];
            System.arraycopy(key, 0, nonceClient_dec,16, 16);

            BlockCipher cipher = new BlockCipher(key);
            byte[] nonceClient_dec_enc = new byte[16];
            cipher.encrypt(nonceClient_dec, 0, nonceClient_dec_enc, 0);

            // server sends nonce client encrypted with shared key
            outstream.write(nonceClient_dec_enc, 0, nonceClient_dec_enc.length);
            outstream.flush();
            return key;

        }else{ // client
            RSA myRSA = new RSA(); // generate a key pair
            RSA serverRSA = new RSA(Arrays.toString(hisPublicKey));

            byte[] mypub = myRSA.getPublicKey().getBytes();
            outstream.write(mypub, 0, mypub.length); // client sends its pub key
            outstream.flush();

            byte[] serverNonce_rec = new byte[16];
            int num = instream.read(serverNonce_rec, 0, serverNonce_rec.length); // client gets server nonce
            if(num != serverNonce_rec.length)    throw new RuntimeException();
            byte[] nonceServer_dec = myRSA.decryptWithPrivate(serverNonce_rec);

            byte[] nonceClient = Util.getRandomByteArray(16);
            byte[] key = new byte[32];
            System.arraycopy(nonceServer_dec, 0, key, 0, 16);
            System.arraycopy(nonceClient, 0, key,16, 16);

            byte[] enNonce = serverRSA.encryptWithPublic(key);
            outstream.write(enNonce, 0, enNonce.length); // client sends its nonce
            outstream.flush();

            BlockCipher cipher = new BlockCipher(key);
            byte[] rec_nonce = new byte[16];
            byte[] rec_nonce_dec = new byte[16];
            num = instream.read(rec_nonce, 0, rec_nonce.length);
            if(num != rec_nonce.length)    throw new RuntimeException();
            cipher.decrypt(rec_nonce, 0, rec_nonce_dec, 0);

            if (Arrays.equals(rec_nonce_dec, nonceClient)){
                return key;
            }
            else{
                throw new RuntimeException("Not valid!");
            }

        }
    }

    private void setupStreams(Socket ssock,
                              byte[] symmetricKey, boolean iAmClient )
            throws IOException {
        // Assignment 2: replace this with something that creates streams that
        //               use crypto in a way that makes them secure

        // This is hopelessly insecure; streams are totally unprotected from
        // eavesdropping or tampering.
        in = new SecureInputStream(symmetricKey, sock.getInputStream());
        out = new SecureOutputStream(symmetricKey, sock.getOutputStream());
    }

    public SecureInputStream getInputStream() throws IOException {
        return in;
    }

    public SecureOutputStream getOutputStream() throws IOException {
        return out;
    }

    public void close() throws IOException {
        in.close();
        out.close();
        sock.close();
    }
}
