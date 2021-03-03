import java.security.SecureRandom;
import MilagroLib.*;
import Protocols.MQV;
import java.util.Arrays;

public class Driver_MQV {

    //print bytes
    private static void printBinary(byte[] array) {
        int i;
        for (i = 0; i < array.length; i++) {
            System.out.printf("%02x", array[i]);
        }
        System.out.println();
    }

    public static void main(String[] args)
    {
        byte[] keyA, keyB;
        SecureRandom random = new SecureRandom();
    	RAND rng = new RAND();        
        byte[] RAW = new byte[100];

        //random number generator
        random.nextBytes(RAW);
    	rng.clean();
    	rng.seed(100,RAW);

        //declare two parties
        System.out.println("\nMQV process starting...");
        MQV Alice = new MQV(rng);
        MQV Bob = new MQV(rng);

        //generate principal keys
        Alice.generateKeys();
        Bob.generateKeys();
        
        //calculate keys
        keyA = Alice.calculateKey(Bob.getPublicEphemeralKey(), Bob.getPublicLongtermKey());
        keyB = Bob.calculateKey(Alice.getPublicEphemeralKey(), Alice.getPublicLongtermKey());
        
        //display both parties keys
        System.out.print("\nAlice key: ");
        printBinary(keyA);
        System.out.print("Bobby key: ");
        printBinary(keyB);
        
        //success if both keys are same
        if (Arrays.equals(keyA, keyB)) {
            System.out.print("\nMQV Key share Sucessful!\n");
        } else {
            System.out.print("\nMQV Key share Failed!\n");
        }
    }
}