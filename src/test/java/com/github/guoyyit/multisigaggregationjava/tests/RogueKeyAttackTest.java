package com.github.guoyyit.multisigaggregationjava.tests;

import com.github.guoyyit.multisigaggregationjava.core.ErrorCode;
import com.github.guoyyit.multisigaggregationjava.core.Hex;
import com.github.guoyyit.multisigaggregationjava.core.Musig;
import com.github.guoyyit.multisigaggregationjava.core.Schnorr;
import com.github.guoyyit.multisigaggregationjava.core.ServiceException;
import com.github.guoyyit.multisigaggregationjava.signer.LocalSigner;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RogueKeyAttackTest extends ServiceTestBase {

    private final SecureRandom random = new SecureRandom();

    @Test
    void registrationWithoutValidProofOfPossessionIsRejected(@TempDir Path tempDir) {
        Context context = startContext(tempDir);
        try {
            LocalSigner victim = LocalSigner.generate("victim", context.fileStore());
            BigInteger attackerSecret = Schnorr.randomScalar(random);
            ECPoint rogue = Schnorr.scalarBaseMult(attackerSecret);

            ServiceException missing = assertThrows(ServiceException.class,
                    () -> context.keyService().register(
                            "rogue", "attacker",
                            Hex.encode(Schnorr.compress(rogue)), null));
            assertEquals(ErrorCode.POP_MISSING, missing.errorCode());

            byte[] forgedProof = Schnorr.signSchnorr(
                    attackerSecret, "wrong-message".getBytes(), random);
            ServiceException invalid = assertThrows(ServiceException.class,
                    () -> context.keyService().register(
                            "rogue", "attacker",
                            Hex.encode(Schnorr.compress(rogue)),
                            Hex.encode(forgedProof)));
            assertEquals(ErrorCode.POP_INVALID, invalid.errorCode());

            context.keyService().register("victim", "victim-owner",
                    victim.publicKeyHex(), victim.proofOfPossessionHex());
            ServiceException cannotAssumeVictimKey = assertThrows(ServiceException.class,
                    () -> context.keyService().register(
                            "rogue-victim", "attacker",
                            victim.publicKeyHex(), victim.proofOfPossessionHex()));
            assertEquals(ErrorCode.DUPLICATE_KEY_ID, cannotAssumeVictimKey.errorCode());
        } finally {
            context.close();
        }
    }

    @Test
    void keyAggCoefficientNeutralizesClassicRogueKeyConstruction(@TempDir Path tempDir) {
        Context context = startContext(tempDir);
        try {
            LocalSigner victim = LocalSigner.generate("victim", context.fileStore());
            context.keyService().register("victim", "victim-owner",
                    victim.publicKeyHex(), victim.proofOfPossessionHex());

            ECPoint victimPoint = Schnorr.parsePoint(Hex.decode(victim.publicKeyHex()));
            List<ECPoint> sorted = Musig.sortPoints(List.of(victimPoint, victimPoint));

            BigInteger coefficient = Musig.coefficient(sorted, victimPoint);
            assertTrue(coefficient.signum() > 0,
                    "所有参与方都绑定非平凡系数，攻击者无法把他人系数消成 1");

            BigInteger attackerX = Schnorr.randomScalar(random);
            ECPoint classicRogue = Schnorr.scalarBaseMult(attackerX)
                    .subtract(victimPoint)
                    .normalize();
            List<ECPoint> rogueSet = Musig.sortPoints(List.of(victimPoint, classicRogue));
            ECPoint aggregate = Musig.aggregatePoint(rogueSet);
            assertTrue(!aggregate.equals(Schnorr.scalarBaseMult(attackerX)),
                    "经典 rogue-key 构造无法让聚合公钥退化为攻击者单独公钥");
        } finally {
            context.close();
        }
    }
}
