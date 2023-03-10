package org.dependencytrack.common;

import alpine.Config;

import java.time.Duration;

public enum ConfigKey implements Config.Key {

    SNYK_THREAD_POOL_SIZE("snyk.thread.pool.size", 10),
    POLICY_EXECUTOR_THREAD_POOL_SIZE("policy.executor.thread.pool.size", 5),
    SNYK_RETRY_MAX_ATTEMPTS("snyk.retry.max.attempts", 10),
    SNYK_RETRY_EXPONENTIAL_BACKOFF_MULTIPLIER("snyk.retry.exponential.backoff.multiplier", 2),
    SNYK_RETRY_EXPONENTIAL_BACKOFF_INITIAL_DURATION_SECONDS("snyk.retry.exponential.backoff.initial.duration.seconds", 1),
    SNYK_RETRY_EXPONENTIAL_BACKOFF_MAX_DURATION_SECONDS("snyk.retry.exponential.backoff.max.duration.seconds", 60),
    OSSINDEX_REQUEST_MAX_PURL("ossindex.request.max.purl", 128),
    OSSINDEX_RETRY_EXPONENTIAL_BACKOFF_MAX_ATTEMPTS("ossindex.retry.backoff.max.attempts", 10),
    OSSINDEX_RETRY_EXPONENTIAL_BACKOFF_MULTIPLIER("ossindex.retry.backoff.multiplier", 2),
    OSSINDEX_RETRY_EXPONENTIAL_BACKOFF_MAX_DURATION("ossindex.retry.backoff.max.duration", Duration.ofMinutes(10).toMillis()),
    REPO_META_ANALYZER_CACHE_STAMPEDE_BLOCKER_ENABLED("repo.meta.analyzer.cacheStampedeBlocker.enabled", true),
    REPO_META_ANALYZER_CACHE_STAMPEDE_BLOCKER_LOCK_BUCKETS("repo.meta.analyzer.cacheStampedeBlocker.lock.buckets", 1000),
    REPO_META_ANALYZER_CACHE_STAMPEDE_BLOCKER_MAX_ATTEMPTS("repo.meta.analyzer.cacheStampedeBlocker.max.attempts", 10),
    SYSTEM_REQUIREMENT_CHECK_ENABLED("system.requirement.check.enabled", true),
    KAFKA_APPLICATION_ID("kafka.application.id", "dependencytrack-apiserver"),
    KAFKA_BOOTSTRAP_SERVERS("kafka.bootstrap.servers", null),
    KAFKA_AUTO_OFFSET_RESET("kafka.auto.offset.reset", "earliest"),
    KAFKA_NUM_STREAM_THREADS("kafka.num.stream.threads", 1),
    KAFKA_TOPIC_PREFIX("api.topic.prefix", "");

    private final String propertyName;
    private final Object defaultValue;

    ConfigKey(final String propertyName, final Object defaultValue) {
        this.propertyName = propertyName;
        this.defaultValue = defaultValue;
    }

    @Override
    public String getPropertyName() {
        return propertyName;
    }

    @Override
    public Object getDefaultValue() {
        return defaultValue;
    }

}
