package com.templateproject.common.exceptions;

public class RedisLocakTimeoutException extends RuntimeException {
    public RedisLocakTimeoutException() {
        super("레디스 락 타임아웃");
    }
}
