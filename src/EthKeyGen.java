import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;

import org.ethereum.crypto.ECKey;
import org.ethereum.crypto.jce.ECKeyPairGenerator;
import org.ethereum.crypto.jce.SpongyCastleProvider;
import org.ethereum.util.ByteUtil;
import org.spongycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.spongycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.util.encoders.Hex;

public class EthKeyGen {

    private static final SecureRandom secureRandom = new SecureRandom();
    private static final Provider provider = SpongyCastleProvider.getInstance();
    private static final KeyPairGenerator keyPairGen = ECKeyPairGenerator.getInstance(provider, secureRandom);

    private static int MIN_SAME = 5;
    
    public static void main(String[] args) {
		if (args.length != 3) {
			System.out.println("Example: $java -jar xx.jar 2 10000 8, 2:number of threads, 10000: max number of key pair every thread('0' represent no limit), 8: min same char");
			return;
		}

		final int threads = Integer.valueOf(args[0]);
		long args1 = Long.valueOf(args[1]);
		final long maxPerThread = args1 <= 0 ? Long.MAX_VALUE : args1;
		MIN_SAME = Integer.valueOf(args[2]);
		
		for (int i = 0; i < threads; i++) {
			new Thread(new Runnable() {
				@Override
				public void run() {
					long start = System.currentTimeMillis();

				    SecureRandom secureRandom = new SecureRandom();
				    Provider provider = SpongyCastleProvider.getInstance();
				    KeyPairGenerator keyPairGen = ECKeyPairGenerator.getInstance(provider, secureRandom);
				    
			    	for (long i = 0; i < maxPerThread; i++) {
			    		generateGood(keyPairGen);
					}
			    	System.out.println("elapse-time:" + (System.currentTimeMillis() - start) + "ms");
				}
			}).start();
		}
	}

    private static void generateGood(KeyPairGenerator keyPairGen) {
    	KeyPair keyPair = keyPairGen.generateKeyPair();
    	PrivateKey privKey = keyPair.getPrivate();
    	ECPoint pub;
    	PublicKey pubKey = keyPair.getPublic();
        if (pubKey instanceof BCECPublicKey) {
            pub = ((BCECPublicKey) pubKey).getQ();
        } else if (pubKey instanceof ECPublicKey) {
            pub = ECKey.extractPublicKey((ECPublicKey) pubKey);
        } else {
            throw new AssertionError(
                "Expected Provider " + provider.getName() +
                " to produce a subtype of ECPublicKey, found " + pubKey.getClass());
        }
        String hexAddr = Hex.toHexString(ECKey.computeAddress(pub));
        if (!isGoodAddress(hexAddr, MIN_SAME)) {
        	return;
        }
        String hexPriv = Hex.toHexString(ByteUtil.bigIntegerToBytes(((BCECPrivateKey) privKey).getD(), 32));
    	System.out.println(hexAddr + ":" + hexPriv);
    }

    public static String[] generate() {
    	KeyPair keyPair = keyPairGen.generateKeyPair();
    	PrivateKey privKey = keyPair.getPrivate();
    	ECPoint pub;
    	PublicKey pubKey = keyPair.getPublic();
        if (pubKey instanceof BCECPublicKey) {
            pub = ((BCECPublicKey) pubKey).getQ();
        } else if (pubKey instanceof ECPublicKey) {
            pub = ECKey.extractPublicKey((ECPublicKey) pubKey);
        } else {
            throw new AssertionError(
                "Expected Provider " + provider.getName() +
                " to produce a subtype of ECPublicKey, found " + pubKey.getClass());
        }
        String hexAddr = Hex.toHexString(ECKey.computeAddress(pub));
        String hexPriv = Hex.toHexString(ByteUtil.bigIntegerToBytes(((BCECPrivateKey) privKey).getD(), 32));
    	return new String[]{hexAddr, hexPriv};
    }

    public static boolean isGoodAddress(String hexAddr, int minSame) {
        int length = hexAddr.length();
        boolean good = false;
        char last = 'g';
        int same = 1;
        for (int i = 0; i < length; i++) {
			char c = hexAddr.charAt(i);
			if (c == last) {
				same += 1;
			} else {
				same = 1;
			}
			last = c;
			// 超过MIN_SAME个字符相同保留
			if (same >= minSame) {
				good = true;
				break;
			}
		}
        char firstChar = hexAddr.charAt(0);
        if (!good 
        		// 快速过滤，优化性能
        		&& (firstChar == '0' || firstChar == '1') 
        		// 保留以“12345678”、“01234567”开头的
        		&& (hexAddr.startsWith("123456789") || hexAddr.startsWith("012345678"))) {
        	good = true;
        }
        return good;
    }
}
