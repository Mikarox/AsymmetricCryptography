package com.mikaros.asymmetriccryptography;

//imports para manipualcion de archivos
import java.io.File;
import java.io.FileOutputStream;
//import IO Exeption
import java.io.IOException;

//imports para Generacion y manipulacion de llaves de seguridad
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 *
 * @author MikoG
 */
public class GenerateKeys {
    
    //
    private KeyPairGenerator keyGen;
    private KeyPair pair;
    
    private PrivateKey privateKey;
    private PublicKey publicKey;
    
    /* 
       Funcion Generate Keys
        Instancia e Incializacion
    */
    
    public GenerateKeys(int keylength) throws NoSuchAlgorithmException, NoSuchProviderException{
        //Instanciamos el generador con el algoritmo RSA
        this.keyGen = KeyPairGenerator.getInstance("RSA");
        //Inicializamos el generador
        this.keyGen.initialize(keylength);
    }
    
    public void createKeys(){
        //generamos la llave par
        this.pair = this.keyGen.generateKeyPair();
        //Generamso la llaveprivada
        this.privateKey = pair.getPrivate();
        //generamos la lalve publica
        this.publicKey =  pair.getPublic();
        
    }
    
    // Fun get private
    public PrivateKey getPrivateKey(){
        return this.privateKey;
    }
    // Fun get public key
     public PublicKey getPublicKey(){
        return this.publicKey;
    }
     
     //Funcion para escribir las llaves en un archivo
     public void writeToFile(String path, byte[] key) throws IOException{
         //Optenemos el archivo y lo abrimos de la ruta
         File f = new File(path);
         f.getParentFile().mkdir();
         
         FileOutputStream fos = new FileOutputStream(f);
         //escribimos la llave en el archivo
         fos.write(key);
         fos.flush();
         //cerramos el archivo IMPORTANTE
         fos.close();                
     }
     
     //fun main
     
     public static void main(String[] args){
         GenerateKeys gk;
         //uso de try para atrapar cualquier tipo de error
         try{
             //generamos una llave con densidad/longitud de 1024 caracteres
             gk = new GenerateKeys(1024);
             //llamamos a la funcion crear llaves
             gk.createKeys();
             //Escribimos la llave en el archivo
             gk.writeToFile("KeyPair/publicKey", gk.getPublicKey().getEncoded());
             //escribimso la llave privada en el archivo
             gk.writeToFile("KeyPair/privatekey", gk.getPrivateKey().getEncoded());             
         }catch(NoSuchAlgorithmException | NoSuchProviderException e){
             System.err.println(e.getMessage());
         }catch(IOException e){
             System.err.println(e.getMessage());
         }
     }
     
     
    
}
