
package com.mikaros.asymmetriccryptography;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import org.apache.commons.codec.binary.Base64;

/**
 *
 * @author MikoG
 */
public class AsymmetricCryptography {
    
    //
    private Cipher cipher;
    
    public AsymmetricCryptography() throws NoSuchAlgorithmException, NoSuchPaddingException{
        //instanciamos con algoritmo RSA
        this.cipher = Cipher.getInstance("RSA");
    }
    
    public PublicKey getPublic(String filename) throws Exception{
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
    
    public PrivateKey getPrivate(String filename) throws Exception{
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }
    
    //encriptamso el archivo
    public void encryptFile(byte[] input, File output, PrivateKey key)
        throws IOException, GeneralSecurityException{
        this.cipher.init(Cipher.ENCRYPT_MODE, key);
        //mandamos a llamar la funcion escribir en el archivo para mostrar salida encriptada
        writeToFile(output, this.cipher.doFinal(input));
    }
    // fun desencriptar archivo
    public void decryptFile(byte[] input, File output, PublicKey key) 
        throws IOException, GeneralSecurityException{
            this.cipher.init(Cipher.DECRYPT_MODE, key);
            //llamamos write to file para mostrar salida desencriptada
            writeToFile(output, this.cipher.doFinal(input));
    }
    
    //escribimos en el archivo
    private void writeToFile(File output, byte[] toWrite) 
        throws IllegalBlockSizeException, BadPaddingException, IOException{
            FileOutputStream fos = new FileOutputStream(output);
            //escribimos dentro del archivo
            fos.write(toWrite);
            fos.flush();
            //cerramos el archivo
            fos.close();
    }
    
    //fun encriptacion de texto
    public String encryptText(String msg, PrivateKey key) 
            throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, 
            UnsupportedEncodingException, InvalidKeyException, BadPaddingException{
        
        this.cipher.init(Cipher.ENCRYPT_MODE, key);
        return Base64.encodeBase64String(cipher.doFinal(msg.getBytes("UTF-8")));
    }
    //fun desencriptar texto
    public String decryptText(String msg, PublicKey key) 
            throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, 
            UnsupportedEncodingException, InvalidKeyException, BadPaddingException{
        
        this.cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(Base64.decodeBase64(msg)), "UTF-8");
        
    }
    
    
    //fun get file Bytes
    public byte[] getFileInBytes(File f) throws IOException{
        FileInputStream fis = new FileInputStream(f);
        byte[] fbytes = new byte[(int) f.length()];
        //leemoss
        fis.read(fbytes);
        //cerramos
        fis.close();
        return fbytes;
    }
    
    
    public static void main(String[] args) throws Exception{
            //src/main/java/com/mikaros/asymmetriccryptography/KeyPair/publicKey
        
        String path = "src/main/java/com/mikaros/asymmetriccryptography/KeyPair/";
            
        AsymmetricCryptography ac = new AsymmetricCryptography();
        //variables de llaves y su ruta
        PrivateKey privatekKey = ac.getPrivate(path + "privatekey");
        PublicKey publicKey = ac.getPublic(path + "publicKey");
        
        //mensaje a encriptar
        String msg = "Cryptography is fun!! c:";
        //mensaje encriptado
        String encrypted_msg = ac.encryptText(msg, privatekKey);
        //mensaje desencripotado
        String decrypted_msg = ac.decryptText(encrypted_msg, publicKey);
        
        System.out.println("Mensaje Original: `" + msg + "`" +
                "\n Encrypted: " + encrypted_msg  + 
                "\n Decrypted: " + decrypted_msg);
        
        //Cracion de archivos automatico
        //obtencion de archivo de texto con mensaje
        if(new File(path + "text.txt").exists() ){
            //encriptacion de archivo y generacion 
            ac.encryptFile(ac.getFileInBytes(new File(path + "text.txt")),new File(path +  "text_encrypted.txt"), privatekKey);
            //desencriptacion de archivo y salida
            ac.decryptFile(ac.getFileInBytes(new File(path + "text_encrypted.txt")), new File(path + "text_decrypted.txt"), publicKey);
        }else{
            //advertencia 
            System.out.println("Es necesario crear el archivo text.txt dentro de KEYPAIR");
        }
        
    }
    
    
    
}
