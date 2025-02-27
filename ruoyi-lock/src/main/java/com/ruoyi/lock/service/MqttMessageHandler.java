package com.ruoyi.lock.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ruoyi.lock.domain.MqttMessage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.integration.annotation.ServiceActivator;
import org.springframework.stereotype.Service;
import org.springframework.messaging.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class MqttMessageHandler {

    private static final Logger logger = LoggerFactory.getLogger(MqttMessageHandler.class);

    @Autowired
    private ObjectMapper objectMapper;

    @ServiceActivator(inputChannel = "mqttInputChannel")
    public void handleMessage(Message<?> message) {
        String topic = (String) message.getHeaders().get("mqtt_receivedTopic");
        String payload = (String) message.getPayload();
        logger.info("Received message from topic {}: {}", topic, payload);

        try {
            // 解析消息
            MqttMessage mqttMessage = objectMapper.readValue(payload, MqttMessage.class);
            handleDoorEvent(mqttMessage);
        } catch (Exception e) {
            logger.error("Error processing MQTT message", e);
        }
    }

    private void handleDoorEvent(MqttMessage mqttMessage) {
        // 处理门锁事件
        logger.info("Handling door event: {}", mqttMessage.toString());
        // 根据业务需求进行处理，例如记录事件、更新状态等
        MqttMessage.OperateType operate = mqttMessage.getOperate();
        // 根据操作类型处理消息
        switch (operate) {
            case EVENT:

                break;
            case ADD:

                break;
            default:
                logger.warn("Unknown operation: {}", operate);
        }
    }
}
