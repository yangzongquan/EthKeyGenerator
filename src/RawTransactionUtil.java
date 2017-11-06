import java.math.BigInteger;

import org.ethereum.core.Transaction;
import org.ethereum.crypto.ECKey;
import org.ethereum.util.ByteUtil;
import org.spongycastle.util.encoders.Hex;

public class RawTransactionUtil {
	
	public static void main(String[] args) {
		
		if (args == null || args.length != 8) {
			printHelp();
			return;
		}
		// 检查privKey
		String hexPrivKey = args[0];
		if (isEmpty(hexPrivKey) || (hexPrivKey.length() != 64 && hexPrivKey.length() != 66)) {
			System.err.println("Invlid privKey");
			return;
		}
		if (hexPrivKey.startsWith("0x")) {
			hexPrivKey = hexPrivKey.substring(2, hexPrivKey.length());
		}
		if (hexPrivKey.length() != 64) {
			System.err.println("Invlid privKey");
			return;
		}
		// 检查nonce
		long nonce = -1;
		try {
			nonce = Long.valueOf(args[1]);
		} catch (NumberFormatException e) {
		}
		if (nonce < 0) {
			System.err.println("Invlid nonce");
			return;
		}
		// 检查gasPrice
		long gasPrice = -1;
		try {
			gasPrice = Long.valueOf(args[2]);
		} catch (NumberFormatException e) {
		}
		if (gasPrice < 0) {
			System.err.println("Invlid gasPrice");
			return;
		}
		// 检查gasPrice
		long gasLimit = -1;
		try {
			gasLimit = Long.valueOf(args[3]);
		} catch (NumberFormatException e) {
		}
		if (gasLimit < 0) {
			System.err.println("Invlid gasLimit");
			return;
		}
		// 检查gasPrice
		String hexTo = args[4];
		if (isEmpty(hexTo) || (hexTo.length() != 40 && hexTo.length() != 42)){
			System.err.println("Invlid hexTo");
			return;
		}
		if (hexTo.startsWith("0x")) {
			hexTo = hexTo.substring(2, hexTo.length());
		}
		if (hexTo.length() != 40) {
			System.err.println("Invlid hexTo");
			return;
		}
		// 检查value
		long value = -1;
		try {
			value = Long.valueOf(args[5]);
		} catch (NumberFormatException e) {
		}
		if (value < 0) {
			System.err.println("Invlid value");
			return;
		}
		// 处理hexData
		String hexData = args[6];
		if (!isEmpty(hexData) && hexData.startsWith("0x")){
			hexData = hexData.substring(2, hexData.length());
		}
		// 处理netId
		int netId;
		try {
			netId = Integer.valueOf(args[7]);
		} catch (NumberFormatException e) {
			System.err.println("Invlid netId");
			return;
		}
		
		System.out.println("params->\n     nonce:" + nonce + ", gasPrice:" + gasPrice 
				+ ", gasLimit:" + gasLimit + ", value:" + value + ", netId:" + netId 
				+ ", hexTo:" + hexTo + ", hexData:" + hexData);
		
		String rawData = genRawTransData(hexPrivKey, nonce, gasPrice, gasLimit, hexTo, value, hexData, netId);
		
		System.out.println("rawData: " + rawData);
		
//		System.out.println(
//				genRawTransData("c6f5caefed455c26db5c9ecaed24e5489bc4542215448b0373ff8e0780c39818", 
//				1, 1000000000, 200000, "7cd8b22babfbf2b1d17e7e1aae54e7b505b1dc72", 1, null, 1));
	}

	private static void printHelp() {
		System.out.println("生成原始交易数据。用于在geth控制台中，调用方法'eth.sendRawTransaction(signedTransactionData [, callback])'的signedTransactionData参数：\n"
				+ "参数：\n"
				+ "    1. String hexPrivKey 32位私钥的十六进制格式，如：0xc6f5caefed455c26db5c9ecaed24e5489bc4542215448b0373ff8e0780c39818。\n"
				+ "    2. long nonce 随机数，或者叫序列号，后来交易必须比先前交易大，不能重复。通常通过“geth console” -> eth.getTransactionCount(eth.accounts[3]) 获得。\n"
				+ "    3. long gasPrice gas价格，eth.gasPrice是当前一段时间内的市场均价，设置为“eth.gasPrice/10”一般能交易成功。\n"
				+ "    4. long gasLimit gas消耗限制，eth.estimateGas可以评估出消耗的gas。\n"
				+ "    5. String hexTo 接收方地址。\n"
				+ "    6. long value 发送的以太坊，单位：wei。\n"
				+ "    7. String hexData ABI合约调用的编码数据，参考http://solidity.readthedocs.io/en/latest/abi-spec.html#examples。\n"
				+ "    8. int netId chainId, mainnet:1, privtenet: xx, 通过 geth console -> admin.nodeInfo -> network 查看。\n"
				+ "返回：\n"
				+ "    返回signedTransactionData，如：'0xa8...'。\n"
				+ "示例：\n"
				+ "    java -jar ./RawUtil.jar \"0xc6f5ca...\" 0 1000000000 200000 \"0x7cd8b22bab...\" 1000000000000000000 \"\" 1\n"
				+ "    说明：\n"
				+ "         \"0xc6f5ca...\" 表示私钥，未输入完整。\n"
				+ "         \"0x7cd8b22bab...\" 表示接收方地址，未输入完整。\n"
				+ "         1000000000000000000 一个以太坊。");
	}

	/**
	 * 生成RawTransactionData。
	 * 
	 * @param hexPrivKey 私钥，无"0x"前缀。
	 * @param nonce 随机数，或者叫序列号，后来交易必须比先前交易大，不能重复。通常通过“geth console” -> eth.getTransactionCount(eth.accounts[3]) 获得。
	 * @param gasPrice gas价格，eth.gasPrice是当前一段时间内的市场均价，设置为“eth.gasPrice/10”一般能交易成功。
	 * @param gasLimit gas消耗限制，eth.estimateGas可以评估出消耗的gas。
	 * @param hexTo 接收方地址，无"0x"前缀。
	 * @param value 发送的以太坊，单位：wei。
	 * @param hexData ABI合约调用的编码数据，参考http://solidity.readthedocs.io/en/latest/abi-spec.html#examples。
	 * @param netId chainId, mainnet:1, privtenet: xx, 通过 geth console -> admin.nodeInfo -> network 查看。
	 * @return 返回RawTransactionData，如："0xa8..."。
	 */
	public static final String genRawTransData(String hexPrivKey, long nonce, long gasPrice, long gasLimit, String hexTo, long value, String hexData, int netId) {
	    byte[] senderPrivateKey = Hex.decode(hexPrivKey);
	    byte[] fromAddress = ECKey.fromPrivate(senderPrivateKey).getAddress();

	    System.out.println("from: 0x" + Hex.toHexString(fromAddress));

	    Transaction tx = new Transaction(
	            ByteUtil.bigIntegerToBytes(BigInteger.valueOf(nonce)), // nonce, 通过 geth console -> eth.getTransactionCount(eth.accounts[3]) 获得
	            ByteUtil.longToBytesNoLeadZeroes(gasPrice), // gasPrice
	            ByteUtil.longToBytesNoLeadZeroes(gasLimit), // gasLimits
	            Hex.decode(hexTo), // to
	            ByteUtil.bigIntegerToBytes(BigInteger.valueOf(value)), // value, unit: wei
	            (hexData == "" || hexData == null) ? new byte[0] : Hex.decode(hexData), //data, new byte[0]: no data
	            netId); // chainId, mainnet:1, privtenet: xx, 通过 geth console -> admin.nodeInfo -> network 查看

	    tx.sign(ECKey.fromPrivate(senderPrivateKey));

	    return "0x" + Hex.toHexString(tx.getEncoded());
	}
	
	public static boolean isEmpty(String s) {
		if (s == null || s.length() == 0) {
			return true;
		}
		return false;
	}
}
