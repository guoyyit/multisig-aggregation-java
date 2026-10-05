package com.github.guoyyit.multisigaggregationjava.tests;

import com.github.guoyyit.multisigaggregationjava.core.ErrorCode;
import com.github.guoyyit.multisigaggregationjava.core.ServiceException;
import com.github.guoyyit.multisigaggregationjava.model.KeyStatus;
import com.github.guoyyit.multisigaggregationjava.model.PublicKeyRecord;
import com.github.guoyyit.multisigaggregationjava.signer.LocalSigner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConcurrencyDeterminismTest extends ServiceTestBase {

    @Test
    void registerThenRevokeYieldsRevokedAndReregisterIsRejected(@TempDir Path tempDir) {
        Context context = startContext(tempDir);
        try {
            LocalSigner signer = LocalSigner.generate("seq-a", context.fileStore());
            context.keyService().register(
                    "seq-a", "owner", signer.publicKeyHex(), signer.proofOfPossessionHex());
            context.keyService().revoke("seq-a", "orderly shutdown");
            assertEquals(KeyStatus.REVOKED,
                    context.keyService().get("seq-a").orElseThrow().status(),
                    "先注册后撤销必须得到已撤销状态");

            ServiceException reRegister = assertThrows(ServiceException.class,
                    () -> context.keyService().register("seq-a", "owner",
                            signer.publicKeyHex(), signer.proofOfPossessionHex()));
            assertEquals(ErrorCode.DUPLICATE_KEY_ID, reRegister.errorCode(),
                    "注册不得覆盖已撤销状态");
            assertEquals(KeyStatus.REVOKED,
                    context.keyService().get("seq-a").orElseThrow().status());
        } finally {
            context.close();
        }
    }

    @Test
    void revokeOfUnknownKeyIsRejectedAndLaterRegisterSucceeds(@TempDir Path tempDir) {
        Context context = startContext(tempDir);
        try {
            ServiceException revokeFirst = assertThrows(ServiceException.class,
                    () -> context.keyService().revoke("seq-b", "too early"));
            assertEquals(ErrorCode.KEY_NOT_FOUND, revokeFirst.errorCode(),
                    "先撤销不存在的 keyId 必须被明确拒绝");

            LocalSigner signer = LocalSigner.generate("seq-b", context.fileStore());
            context.keyService().register(
                    "seq-b", "owner", signer.publicKeyHex(), signer.proofOfPossessionHex());
            assertEquals(KeyStatus.ACTIVE,
                    context.keyService().get("seq-b").orElseThrow().status(),
                    "被拒绝的撤销不得影响后续注册");
        } finally {
            context.close();
        }
    }

    @Test
    void concurrentSamePublicKeyRegistrationsAllowExactlyOne(@TempDir Path tempDir)
            throws Exception {
        Context context = startContext(tempDir);
        String winner;
        try {
            LocalSigner signer = LocalSigner.generate("shared", context.fileStore());
            String pub = signer.publicKeyHex();
            String pop = signer.proofOfPossessionHex();
            int contenders = 8;
            ExecutorService pool = Executors.newFixedThreadPool(contenders);
            CountDownLatch ready = new CountDownLatch(contenders);
            CountDownLatch go = new CountDownLatch(1);
            Map<String, Object> outcomes = new ConcurrentHashMap<>();
            List<Future<?>> futures = new java.util.ArrayList<>();
            for (int i = 0; i < contenders; i++) {
                String keyId = "dup-" + i;
                futures.add(pool.submit(() -> {
                    ready.countDown();
                    try {
                        go.await();
                        context.keyService().register(keyId, "owner", pub, pop);
                        outcomes.put(keyId, "OK");
                    } catch (ServiceException ex) {
                        outcomes.put(keyId, ex.errorCode());
                    } catch (InterruptedException ex) {
                        Thread.currentThread().interrupt();
                        outcomes.put(keyId, ex);
                    }
                }));
            }
            assertTrue(ready.await(10, TimeUnit.SECONDS));
            go.countDown();
            for (Future<?> future : futures) {
                future.get(10, TimeUnit.SECONDS);
            }
            pool.shutdown();

            long successes = outcomes.values().stream().filter("OK"::equals).count();
            assertEquals(1, successes, "同一公钥并发注册时至多一个成功");
            long duplicates = outcomes.values().stream()
                    .filter(ErrorCode.DUPLICATE_PUBLIC_KEY::equals).count();
            assertEquals(contenders - 1, duplicates,
                    "其余注册必须得到明确且可区分的拒绝原因 DUPLICATE_PUBLIC_KEY");
            winner = outcomes.entrySet().stream()
                    .filter(e -> "OK".equals(e.getValue()))
                    .findFirst().orElseThrow().getKey();
        } finally {
            context.close();
        }

        Context restarted = startContext(tempDir);
        try {
            List<PublicKeyRecord> all = restarted.keyService().list(null);
            assertEquals(1, all.size(), "磁盘上同一公钥不得被登记两次");
            assertEquals(winner, all.get(0).keyId(),
                    "重启后磁盘状态必须与接口返回的胜出者一致");
            assertEquals(KeyStatus.ACTIVE, all.get(0).status());
        } finally {
            restarted.close();
        }
    }

    @Test
    void concurrentRegisterAndRevokeSettleInRealOrderAndSurviveRestart(
            @TempDir Path tempDir) throws Exception {
        Context context = startContext(tempDir);
        Map<String, KeyStatus> expected = new ConcurrentHashMap<>();
        try {
            int rounds = 12;
            for (int round = 0; round < rounds; round++) {
                String keyId = "race-" + round;
                LocalSigner signer = LocalSigner.generate(keyId, context.fileStore());
                String pub = signer.publicKeyHex();
                String pop = signer.proofOfPossessionHex();
                ExecutorService pool = Executors.newFixedThreadPool(2);
                CountDownLatch ready = new CountDownLatch(2);
                CountDownLatch go = new CountDownLatch(1);
                Map<String, Object> outcomes = new ConcurrentHashMap<>();
                Runnable registerTask = () -> {
                    ready.countDown();
                    try {
                        go.await();
                        context.keyService().register(keyId, "owner", pub, pop);
                        outcomes.put("register", "OK");
                    } catch (ServiceException ex) {
                        outcomes.put("register", ex.errorCode());
                    } catch (InterruptedException ex) {
                        Thread.currentThread().interrupt();
                    }
                };
                Runnable revokeTask = () -> {
                    ready.countDown();
                    try {
                        go.await();
                        context.keyService().revoke(keyId, "race");
                        outcomes.put("revoke", "OK");
                    } catch (ServiceException ex) {
                        outcomes.put("revoke", ex.errorCode());
                    } catch (InterruptedException ex) {
                        Thread.currentThread().interrupt();
                    }
                };
                Future<?> f1 = pool.submit(registerTask);
                Future<?> f2 = pool.submit(revokeTask);
                assertTrue(ready.await(10, TimeUnit.SECONDS));
                go.countDown();
                f1.get(10, TimeUnit.SECONDS);
                f2.get(10, TimeUnit.SECONDS);
                pool.shutdown();

                assertEquals("OK", outcomes.get("register"),
                        "注册在锁串行化下必须总是成功");
                Object revokeOutcome = outcomes.get("revoke");
                assertTrue("OK".equals(revokeOutcome)
                                || ErrorCode.KEY_NOT_FOUND == revokeOutcome,
                        "撤销只允许成功或明确拒绝，不得出现半写入: " + revokeOutcome);
                KeyStatus finalStatus = "OK".equals(revokeOutcome)
                        ? KeyStatus.REVOKED : KeyStatus.ACTIVE;
                assertEquals(finalStatus,
                        context.keyService().get(keyId).orElseThrow().status(),
                        "最终状态必须与真实执行顺序一致");
                expected.put(keyId, finalStatus);
            }
        } finally {
            context.close();
        }

        Context restarted = startContext(tempDir);
        try {
            for (Map.Entry<String, KeyStatus> entry : expected.entrySet()) {
                assertEquals(entry.getValue(),
                        restarted.keyService().get(entry.getKey()).orElseThrow().status(),
                        "重启后磁盘状态必须与接口返回一致: " + entry.getKey());
            }
        } finally {
            restarted.close();
        }
    }
}
