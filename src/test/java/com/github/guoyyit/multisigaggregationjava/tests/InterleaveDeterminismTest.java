package com.github.guoyyit.multisigaggregationjava.tests;

import com.github.guoyyit.multisigaggregationjava.core.ErrorCode;
import com.github.guoyyit.multisigaggregationjava.core.ServiceException;
import com.github.guoyyit.multisigaggregationjava.model.KeyStatus;
import com.github.guoyyit.multisigaggregationjava.model.ProofStatus;
import com.github.guoyyit.multisigaggregationjava.signer.LocalSigner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.RepeatedTest;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;

class InterleaveDeterminismTest extends ServiceTestBase {

    @Test
    void registerThenRevokeEndsRevokedAndRevokeThenRegisterIsRejected(@TempDir Path tempDir) {
        Context context = startContext(tempDir);
        try {
            LocalSigner first = LocalSigner.generate("order-1", context.fileStore());
            context.keyService().register("order-1", "o",
                    first.publicKeyHex(), first.proofOfPossessionHex());
            context.keyService().revoke("order-1", null);
            assertEquals(KeyStatus.REVOKED,
                    context.keyService().get("order-1").orElseThrow().status());

            // 先撤销（对不存在 keyId 写墓碑），再注册必须被明确拒绝。
            context.keyService().revoke("order-2", "preemptive");
            LocalSigner second = LocalSigner.generate("order-2", context.fileStore());
            ServiceException rejected = assertThrowsService(() ->
                    context.keyService().register("order-2", "o",
                            second.publicKeyHex(), second.proofOfPossessionHex()));
            assertEquals(ErrorCode.KEY_REVOKED, rejected.errorCode());
            assertEquals(KeyStatus.REVOKED,
                    context.keyService().get("order-2").orElseThrow().status());
            assertEquals(ProofStatus.NOT_APPLICABLE,
                    context.keyService().get("order-2").orElseThrow().proofStatus());
        } finally {
            context.close();
        }
    }

    @RepeatedTest(20)
    void concurrentRegisterAndRevokeSameKeyIsDeterministic(@TempDir Path tempDir)
            throws Exception {
        Context context = startContext(tempDir);
        try {
            LocalSigner signer = LocalSigner.generate("race", context.fileStore());
            ExecutorService pool = Executors.newFixedThreadPool(2);
            CountDownLatch start = new CountDownLatch(1);

            Callable<String> registerTask = () -> {
                start.await();
                try {
                    context.keyService().register("race", "o",
                            signer.publicKeyHex(), signer.proofOfPossessionHex());
                    return "REGISTERED";
                } catch (ServiceException ex) {
                    return ex.errorCode().code();
                }
            };
            Callable<String> revokeTask = () -> {
                start.await();
                context.keyService().revoke("race", null);
                return "REVOKED";
            };

            Future<String> r1 = pool.submit(registerTask);
            Future<String> r2 = pool.submit(revokeTask);
            start.countDown();
            String registerOutcome = r1.get();
            r2.get();
            pool.shutdown();

            KeyStatus finalStatus = context.keyService().get("race").orElseThrow().status();
            if ("REGISTERED".equals(registerOutcome)) {
                assertEquals(KeyStatus.REVOKED, finalStatus,
                        "注册成功后撤销，最终必须为 REVOKED");
            } else {
                assertEquals(ErrorCode.KEY_REVOKED.code(), registerOutcome,
                        "撤销先发生时注册必须被明确拒绝");
                assertEquals(KeyStatus.REVOKED, finalStatus,
                        "不得出现注册覆盖撤销或半写入状态");
            }
        } finally {
            context.close();
        }
    }

    @RepeatedTest(20)
    void samePublicKeyConcurrentRegistrationsAtMostOneSucceeds(@TempDir Path tempDir)
            throws Exception {
        Context context = startContext(tempDir);
        try {
            LocalSigner shared = LocalSigner.generate("shared", context.fileStore());
            int count = 8;
            ExecutorService pool = Executors.newFixedThreadPool(count);
            CountDownLatch start = new CountDownLatch(1);
            List<Future<String>> futures = new ArrayList<>();
            for (int index = 0; index < count; index++) {
                final String keyId = "dup-" + index;
                futures.add(pool.submit(() -> {
                    start.await();
                    try {
                        context.keyService().register(keyId, "o",
                                shared.publicKeyHex(), shared.proofOfPossessionHex());
                        return "OK";
                    } catch (ServiceException ex) {
                        return ex.errorCode().code();
                    }
                }));
            }
            start.countDown();

            int success = 0;
            int rejected = 0;
            for (Future<String> future : futures) {
                if ("OK".equals(future.get())) {
                    success++;
                } else {
                    rejected++;
                    assertEquals(ErrorCode.DUPLICATE_PUBLIC_KEY.code(), future.get(),
                            "失败原因必须可区分：同一公钥材料冲突");
                }
            }
            pool.shutdown();

            assertEquals(1, success, "同一公钥至多注册成功一次");
            assertEquals(count - 1, rejected);
            long activeWithPub = context.keyService().list(KeyStatus.ACTIVE).stream()
                    .filter(record -> record.pubHex().equals(shared.publicKeyHex()))
                    .count();
            assertEquals(1, activeWithPub, "不得出现同一公钥被登记两次");
        } finally {
            context.close();
        }
    }

    @Test
    void finalStateOnDiskMatchesAfterRestart(@TempDir Path tempDir) throws Exception {
        Context context = startContext(tempDir);
        try {
            LocalSigner signer = LocalSigner.generate("persist-race",
                    context.fileStore());
            ExecutorService pool = Executors.newFixedThreadPool(2);
            CountDownLatch start = new CountDownLatch(1);
            Future<?> register = pool.submit(() -> {
                try {
                    start.await();
                    context.keyService().register("persist-race", "o",
                            signer.publicKeyHex(), signer.proofOfPossessionHex());
                } catch (ServiceException expected) {
                    // 撤销先发生时注册被拒绝，属于合法交错结果。
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                }
            });
            Future<?> revoke = pool.submit(() -> {
                try {
                    start.await();
                    context.keyService().revoke("persist-race", null);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                }
            });
            start.countDown();
            register.get();
            revoke.get();
            pool.shutdown();
            assertEquals(KeyStatus.REVOKED,
                    context.keyService().get("persist-race").orElseThrow().status());
        } finally {
            context.close();
        }

        Context restarted = startContext(tempDir);
        try {
            assertEquals(KeyStatus.REVOKED,
                    restarted.keyService().get("persist-race").orElseThrow().status(),
                    "重启后磁盘最终状态必须与接口返回一致");
        } finally {
            restarted.close();
        }
    }

    private static ServiceException assertThrowsService(Callable<?> callable) {
        try {
            callable.call();
        } catch (ServiceException ex) {
            return ex;
        } catch (Exception ex) {
            throw new AssertionError("期望 ServiceException", ex);
        }
        throw new AssertionError("期望 ServiceException");
    }
}
