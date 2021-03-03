import java.security.SecureRandom;
import java.util.Arrays;
import MilagroLib.*;
import Protocols.IBAKA;

public class Driver_IBAKA {

    //verify partial private key 
    private static void verifyS(ECP pkS_, ECP lpk_, ECP gen_, BIG S_, BIG hash_){
        ECP testS = new ECP();
        testS = pkS_.mul(hash_);
        testS.add(lpk_);

        if (testS.toString().equals(gen_.mul(S_).toString())) {
            System.out.println("Verfication Sucessful!");
        } else {
            System.out.println("Verfication Failed!");
        }
    }

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
        BIG hashA, hashB;
        byte[] keyA, keyB;
        SecureRandom random = new SecureRandom();
    	RAND rng = new RAND();        
        byte[] RAW = new byte[100];
        byte[] AliceID = new byte[128];
        byte[] BobID = new byte[128];

        //random number generator
        random.nextBytes(RAW);
        random.nextBytes(AliceID);
        random.nextBytes(BobID);
    	rng.clean();
    	rng.seed(100,RAW);

        //declare two parties
        System.out.println("\nIBAKA process starting...");
        IBAKA Alice = new IBAKA(rng);
        IBAKA Bob = new IBAKA(rng);

        //get parameters from KGC
        Alice.KGC(AliceID); 
        Bob.KGC(BobID);
        
        hashA = IBAKA.hashing(AliceID, Alice.getPublicLongtermKey(), Alice.getHash1(), Alice.getOrder());
        hashB = IBAKA.hashing(BobID, Bob.getPublicLongtermKey(), Bob.getHash1(), Bob.getOrder());
        
        //verify partial private keys given by KGC
        System.out.print("\nAlice SA: ");
        verifyS(Alice.getPublicKGCKey(), Alice.getPublicLongtermKey(), Alice.getGen(), Alice.getS(), hashA);
        System.out.print("Bobby SB: ");
        verifyS(Bob.getPublicKGCKey(), Bob.getPublicLongtermKey(), Bob.getGen(), Bob.getS(), hashB);
        
        //generate ephemeral keys
        Alice.generateEphemeralKey();
        Bob.generateEphemeralKey();
        
        //calculate keys
        keyA = Alice.calculateKey(hashB, Bob.getPublicLongtermKey(), Bob.getPublicEphemeralKey());
        keyB = Bob.calculateKey(hashA, Alice.getPublicLongtermKey(), Alice.getPublicEphemeralKey());
       
        //display both parties keys
        System.out.print("\nAlice key: ");
        printBinary(keyA);
        System.out.print("Bobby key: ");
        printBinary(keyB);

        //success if both keys are same
        if (Arrays.equals(keyA, keyB)) {
            System.out.print("\nIBAKA Key share Sucessful!\n");
        } else {
            System.out.print("\nIBAKA Key share Failed!\n");
        }
    } 
}