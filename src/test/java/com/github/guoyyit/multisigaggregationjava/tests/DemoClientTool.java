package com.github.guoyyit.multisigaggregationjava.tests;

import com.github.guoyyit.multisigaggregationjava.core.Hex;
import com.github.guoyyit.multisigaggregationjava.signer.LocalSigner;
import com.github.guoyyit.multisigaggregationjava.config.ServiceProperties;
import com.github.guoyyit.multisigaggregationjava.store.FileStore;

import java.util.List;

/**
 * 仅用于手工演示：在本地生成签名方材料，或计算承诺/随机数/部分签名。
 * 参数：gen <keyId> | commitment <keyId> <sessionId> <saltHex> |
 *       nonce <keyId> <sessionId> |
 *       partial <keyId> <sessionId> <messageHex> <pubHexCsv> <nonceHexCsv>
 */
public class DemoClientTool {

    public static void main(String[] args) {
        ServiceProperties properties = new ServiceProperties();
        String dir = System.getenv().getOrDefault("MULTISIG_DATA_DIR", "data");
        properties.setStoreDir(dir);
        FileStore store = new FileStore(properties);
        store.initialize();
        switch (args[0]) {
            case "gen" -> {
                LocalSigner signer = LocalSigner.loadOrGenerate(args[1], store);
                System.out.println("PUB=" + signer.publicKeyHex());
                System.out.println("POP=" + signer.proofOfPossessionHex());
            }
            case "commitment" -> {
                LocalSigner signer = LocalSigner.load(args[1], store);
                System.out.println(signer.commitment(args[2], args[3]));
            }
            case "nonce" -> {
                LocalSigner signer = LocalSigner.load(args[1], store);
                System.out.println(signer.nonce(args[2]));
            }
            case "partial" -> {
                LocalSigner signer = LocalSigner.load(args[1], store);
                List<String> pubs = List.of(args[4].split(","));
                List<String> nonces = List.of(args[5].split(","));
                System.out.println(signer.partialSignature(args[2], args[3], pubs, nonces));
            }
            default -> throw new IllegalArgumentException("unknown command");
        }
    }
}
