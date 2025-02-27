package com.ruoyi.lock.domain;

import com.fasterxml.jackson.annotation.*;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class MqttMessage {
    @JsonProperty("device_id")
    private String deviceId;
    private String timestamp;
    private OperateType operate;
    private final Map<String, String> dynamicParams = new HashMap<>();

    @JsonAnySetter
    public void addDynamicParam(String key, String value) {
        dynamicParams.put(key, value);
    }

    @JsonAnyGetter
    public Map<String, String> getDynamicParams() {
        return dynamicParams;
    }

    // Enum definition for operate types
    public enum OperateType {
        OPEN("door_open_once"),
        IDLE("door_idle"),
        EVENT("door_event"),
        OTA("kit_ota"),
        ADD("add_whitelist_user"),
        DELETE("del_whitelist_user");



        private final String value;

        OperateType(String value) {
            this.value = value;
        }

        @JsonValue
        public String getValue() {
            return value;
        }

        @JsonCreator
        public static OperateType fromValue(String value) {
            for (OperateType type : OperateType.values()) {
                if (type.value.equalsIgnoreCase(value)) {
                    return type;
                }
            }
            throw new IllegalArgumentException("Invalid operate value: " + value);
        }
    }

    // Getters and Setters
    public String getDeviceId() {
        return deviceId;
    }

    public void setDeviceId(String deviceId) {
        this.deviceId = deviceId;
    }

    public String getTimestamp() {
        if (timestamp == null) {
            timestamp = Instant.now().toString();
        }
        return timestamp;
    }

    // 保持setter不变以允许手动设置
    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    public OperateType getOperate() {
        return operate;
    }

    public void setOperate(OperateType operate) {
        this.operate = operate;
    }
}