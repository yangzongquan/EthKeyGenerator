import java.math.BigInteger;

import org.ethereum.core.Transaction;
import org.ethereum.crypto.ECKey;
import org.ethereum.util.ByteUtil;
import org.spongycastle.util.encoders.Hex;

public class RawTransactionUtil {
	
	public static void main(String[] args) {
		System.out.println(
				genRawTransData("c6f5caefed455c26db5c9ecaed24e5489bc4542215448b0373ff8e0780c39818", 
				1, 1000000000, 200000, "7cd8b22babfbf2b1d17e7e1aae54e7b505b1dc72", 1, null, 1));
	}

	/**
	 * 生成RawTransactionData。
	 * 
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
	    System.out.println(Hex.toHexString(fromAddress));

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
}
