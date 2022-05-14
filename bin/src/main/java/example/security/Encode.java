package example.security;

import org.mindrot.jbcrypt.*;
import java.io.IOException;
import javax.xml.bind.DatatypeConverter;

public class Encode {

  final Encryption encrypt = new Encryption();

  public String hashpw(String pass){
    String stored = BCrypt.hashpw(pass, BCrypt.gensalt());

    try {

      byte[] newHash = encrypt.do_RSAEncryption(stored);

      return DatatypeConverter.printHexBinary(newHash);

    } catch (Exception e) {

      return null;

    }
  }

  public boolean verify(String pass, String hash){

    try{

      String newHash = encrypt.do_RSADecryption(DatatypeConverter.parseHexBinary(hash));

      return BCrypt.checkpw(pass, newHash);

    } catch (Exception e) {

      System.out.println("Encode verify error");

      e.printStackTrace();

      return false;
    }
  }
}
