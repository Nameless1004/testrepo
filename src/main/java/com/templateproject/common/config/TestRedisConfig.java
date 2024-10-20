package com.templateproject.common.config;

import org.redisson.Redisson;
import org.redisson.api.RedissonClient;
import org.redisson.config.Config;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Profile("test")  // 'test' 프로파일에서만 활성화
@Configuration
public class TestRedisConfig {

    @Value("${spring.data.redis.host}")
    private String redishost;

    @Value("${spring.data.redis.port}")
    private int port;
    private static final String REDISSON_HOST_PREFIX = "redis://";

    @Bean
    public RedissonClient redissonClient() {

        Config config = new Config();
        config.useSingleServer().setAddress(REDISSON_HOST_PREFIX+redishost+":"+port);
        return Redisson.create(config);
    }
}
