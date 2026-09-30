package com.github.guoyyit.multisigaggregationjava.tests;

import com.github.guoyyit.multisigaggregationjava.config.MultisigConfig;
import com.github.guoyyit.multisigaggregationjava.config.SchedulingConfig;
import com.github.guoyyit.multisigaggregationjava.service.AggregationService;
import com.github.guoyyit.multisigaggregationjava.service.KeyService;
import com.github.guoyyit.multisigaggregationjava.service.RecoveryService;
import com.github.guoyyit.multisigaggregationjava.service.SessionService;
import com.github.guoyyit.multisigaggregationjava.service.SessionSweeper;
import com.github.guoyyit.multisigaggregationjava.store.AuditLog;
import com.github.guoyyit.multisigaggregationjava.store.FileStore;
import com.github.guoyyit.multisigaggregationjava.store.KeyRepository;
import com.github.guoyyit.multisigaggregationjava.store.SessionRepository;
import com.github.guoyyit.multisigaggregationjava.web.AggregateController;
import com.github.guoyyit.multisigaggregationjava.web.AuditController;
import com.github.guoyyit.multisigaggregationjava.web.KeyController;
import com.github.guoyyit.multisigaggregationjava.web.SessionController;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;

import java.io.Closeable;
import java.nio.file.Path;

abstract class ServiceTestBase {

    protected Context startContext(Path tempDir) {
        AnnotationConfigApplicationContext spring = new AnnotationConfigApplicationContext();
        System.setProperty("multisig.store-dir", tempDir.resolve("data").toString());
        System.setProperty("multisig.session-ttl-seconds", "2");
        System.setProperty("multisig.sweep-millis", "3600000");
        spring.register(MultisigConfig.class, FileStore.class, KeyRepository.class,
                SessionRepository.class, AuditLog.class, KeyService.class,
                AggregationService.class, SessionService.class, RecoveryService.class,
                SessionSweeper.class, SchedulingConfig.class,
                KeyController.class, SessionController.class,
                AggregateController.class, AuditController.class);
        spring.refresh();
        return new Context(spring);
    }

    record Context(AnnotationConfigApplicationContext spring) implements Closeable {
        org.springframework.context.ApplicationContext applicationContext() {
            return spring;
        }

        FileStore fileStore() {
            return spring.getBean(FileStore.class);
        }

        KeyService keyService() {
            return spring.getBean(KeyService.class);
        }

        SessionService sessionService() {
            return spring.getBean(SessionService.class);
        }

        AggregationService aggregation() {
            return spring.getBean(AggregationService.class);
        }

        AuditLog auditLog() {
            return spring.getBean(AuditLog.class);
        }

        @Override
        public void close() {
            spring.close();
        }
    }
}
