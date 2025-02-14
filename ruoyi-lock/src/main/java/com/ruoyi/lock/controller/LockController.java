package com.ruoyi.lock.controller;

import com.ruoyi.common.annotation.Anonymous;
import com.ruoyi.common.annotation.Log;
import com.ruoyi.common.core.domain.AjaxResult;
import com.ruoyi.common.core.domain.entity.SysDept;
import com.ruoyi.common.core.domain.entity.SysUser;
import com.ruoyi.common.core.redis.RedisCache;
import com.ruoyi.common.enums.BusinessType;
import com.ruoyi.common.enums.OperatorType;
import com.ruoyi.common.utils.SecurityUtils;
import com.ruoyi.common.utils.uuid.UUID;
import com.ruoyi.lock.domain.Devices;
import com.ruoyi.lock.domain.FreedormLockSchedule;
import com.ruoyi.lock.dto.AddTimingRequest;
import com.ruoyi.lock.dto.DeleteTimingRequest;
import com.ruoyi.lock.dto.ExistingTimingResponse;
import com.ruoyi.lock.mapper.FreedormLockSchedulesMapper;
import com.ruoyi.lock.service.IDevicesService;
import com.ruoyi.lock.service.ILockService;
import com.ruoyi.lock.service.MqttGateway;
import com.ruoyi.lock.domain.MqttMessage;
import com.ruoyi.system.service.impl.SysDeptServiceImpl;
import com.ruoyi.system.service.impl.SysUserServiceImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.validation.Valid;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static com.ruoyi.lock.service.impl.LockServiceImpl.isOverlapping;

@RestController
@RestControllerAdvice
@RequestMapping("/lock")
public class LockController {

    private static final Logger logger = LoggerFactory.getLogger(LockController.class);

    private static final String VISITOR_CODE_PREFIX = "visitor_code:";

    @Autowired
    private MqttGateway mqttGateway;

    @Autowired
    private ILockService lockService;

    @Autowired
    private IDevicesService devicesService;

    @Autowired
    private FreedormLockSchedulesMapper schedulesMapper;

    @Autowired
    private SysUserServiceImpl sysUserServiceImpl;

    @Autowired
    private SysDeptServiceImpl sysDeptServiceImpl;

    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    @PostMapping("/doorOpenOnce")
    @PreAuthorize("@ss.hasRole('dm')")
    @Log(title = "门锁操作", businessType = BusinessType.OPEN)
    public AjaxResult doorOpenOnce(@RequestBody Map<String, Object> requestBody){
        String deviceId;
        if (!requestBody.containsKey("deviceId")) {
            deviceId = SecurityUtils.getLoginUser().getUser().getDept().getDeviceId();
        } else if (!requestBody.containsKey("duration")) {
            return AjaxResult.error("请求参数缺失");
        }
        deviceId = (String) requestBody.get("deviceId");
        int duration = (int) requestBody.get("duration");
        Map<String, Object> data = new HashMap<>();
        data.put("duration", duration);

        MqttMessage<Map<String, Object>> message = new MqttMessage<>();
        message.setOperate("door_open_once");
        message.setTimestamp(System.currentTimeMillis() / 1000);
        message.setData(data);

        String topic = "/" + deviceId + "/server2client";
        mqttGateway.sendToMqtt(topic, message);
        logger.info("Sending message to topic {}: {}", topic, message);
        return AjaxResult.success("门锁操作成功");
    }

    /**
     * 新增定时开门时间段
     */
    @PostMapping("/timing/add")
    public AjaxResult addTiming(@Valid @RequestBody AddTimingRequest request){
        Devices devices = new Devices();
        devices.setDeptId(SecurityUtils.getDeptId());
         List<Devices> devicesList = devicesService.selectDevicesList(devices);
        if (devicesList.isEmpty()) {
            return AjaxResult.error("设备不存在或无权限访问");
        }
        devices = devicesList.get(0);
        for (Integer day : request.getDaysOfWeek()) {
            if (day < 1 || day > 7) {
               return AjaxResult.error("dayOfWeek 必须在1到7之间");
            }
            // 检查是否有重叠的时间段
            List<FreedormLockSchedule> existingSchedules = schedulesMapper.findByDeviceIdAndDayOfWeek(devices.getDeviceId(), day);
            for (FreedormLockSchedule existingSchedule : existingSchedules) {
                if (isOverlapping(existingSchedule.getStartTime(), existingSchedule.getEndTime(),
                        request.getStartTime().toString(), request.getEndTime().toString())) {
                    return AjaxResult.error("与现有时间段重叠，设备ID: " + devices.getDeviceId() + ", 星期: " + day);
                }
            }
        }
        lockService.addTiming(request, devices);
        logger.info("Added timing for deviceId: {}", devices.getDeviceId());
        return AjaxResult.success("定时开门时间段添加成功");
    }

    /**
     * 删除定时开门时间段
     */
    @DeleteMapping("/timing/delete")
    public AjaxResult deleteTiming(@Valid @RequestBody DeleteTimingRequest request){
        lockService.deleteTiming(request);
        logger.info("Deleted timing for deviceId: {}", request.getDeviceId());
        return AjaxResult.success("定时开门时间段删除成功");
    }

    /**
     * 查询某个门锁已有的时间段
     * GET 请求，传递 deviceId 作为查询参数
     */
    @GetMapping("/timing/existing")
    public AjaxResult getExistingTimings(@RequestParam("deviceId") String deviceId){
        List<ExistingTimingResponse> existingTimings = lockService.getExistingTimings(deviceId);
        logger.info("Fetched existing timings for deviceId: {}", deviceId);
        return AjaxResult.success(existingTimings);
    }

    /**
     * 生成访客码
     * POST /lock/generateVisitorCode
     * 请求参数：
     * - validTimeMinutes：有效时间，以分为单位
     * - maxUsage：可用次数
     */
    @PostMapping("/generateVisitorCode")
    @PreAuthorize("@ss.hasRole('dm')")
    public AjaxResult generateVisitorCode(
            @RequestParam("validTimeMinutes") @Min(value = 1, message = "有效时间必须大于0") Integer validTimeMinutes,
            @RequestParam("maxUsage") @Min(value = 1, message = "可用次数必须至少为1") Integer maxUsage) {

        // 生成唯一的访客码
        String visitorCode = UUID.randomUUID().toString().replace("-", "").substring(0, 8).toUpperCase();

        // 获取当前用户的deviceId
//        String deviceId = SecurityUtils.getLoginUser().getUser().getDept().getDeviceId();
        long userId = SecurityUtils.getUserId();
        SysUser user = sysUserServiceImpl.selectUserById(userId);
        SysDept dept = sysDeptServiceImpl.selectDeptById(user.getDeptId());
        String deviceId = dept.getDeviceId();
        // 定义 Redis 键
        String redisKey = VISITOR_CODE_PREFIX + visitorCode;

        // 使用 Redis Hash 存储访客码信息
        Map<String, Object> visitorCodeInfo = new HashMap<>();
        visitorCodeInfo.put("usageCount", maxUsage); // 存储可用次数
        visitorCodeInfo.put("deviceId", deviceId);   // 存储设备 ID

        // 获取 HashOperations
        HashOperations<String, Object, Object> hashOps = redisTemplate.opsForHash();

        // 存储访客码信息到 Redis Hash，并设置过期时间
        hashOps.putAll(redisKey, visitorCodeInfo);
        redisTemplate.expire(redisKey, validTimeMinutes, TimeUnit.MINUTES); // 设置统一的过期时间

        logger.info("生成访客码: {}，设备ID: {}，有效时间: {} 分钟，可用次数: {}",
                visitorCode, deviceId, validTimeMinutes, maxUsage);

        // 返回访客码
        Map<String, String> response = new HashMap<>();
        response.put("visitorCode", visitorCode);
        return AjaxResult.success("访客码生成成功", response);
    }


    /**
     * 验证访客码并执行开门操作
     * GET /api/lock/validateVisitorCode/{visitorCode}
     */
    @Anonymous
    @GetMapping("/validateVisitorCode/{visitorCode}")
    public AjaxResult validateVisitorCode(
            @PathVariable("visitorCode") @NotBlank(message = "访客码不能为空") String visitorCode) {
        visitorCode = visitorCode.toUpperCase();
        String redisKey = VISITOR_CODE_PREFIX + visitorCode;

        // 获取 HashOperations
        HashOperations<String, Object, Object> hashOps = redisTemplate.opsForHash();

        // 检查访客码是否存在 (检查 Redis Key 是否存在)
        Boolean exists = redisTemplate.hasKey(redisKey);
        if (exists == null || !exists) {
            logger.warn("无效或已过期的访客码: {}", visitorCode);
            return AjaxResult.error("无效或已过期的访客码");
        }

        // 从 Redis Hash 中获取访客码信息
        Map<Object, Object> visitorCodeInfo = hashOps.entries(redisKey);
        int usageCount = Integer.parseInt(visitorCodeInfo.get("usageCount").toString()); // 获取剩余次数
        String deviceId = (String) visitorCodeInfo.get("deviceId"); // 获取设备 ID

        // 原子性减少可用次数
        usageCount--; // 在内存中减少

        if (usageCount < 0) {
            // 清理缓存
            redisTemplate.delete(redisKey);
            logger.warn("访客码已达到最大使用次数: {}", visitorCode);
            return AjaxResult.error("访客码已达到最大使用次数");
        }

        // 更新 Redis Hash 中的剩余次数
        hashOps.put(redisKey, "usageCount", usageCount);

        if (deviceId == null) { // 理论上 deviceId 不应该为 null，除非数据异常
            redisTemplate.delete(redisKey); // 数据异常时清理缓存
            logger.error("设备ID信息缺失: {}", visitorCode);
            return AjaxResult.error("访客码验证失败");
        }

        // 次数用尽后删除缓存
        if (usageCount == 0) {
            redisTemplate.delete(redisKey);
            logger.info("访客码已用完并删除: {}", visitorCode);
        } else {
            logger.info("访客码剩余次数: {}，访客码: {}", usageCount, visitorCode);
        }

        // 执行开门操作
        doorOpenOnceAction(deviceId, 5); // 假设开门持续5秒
        return AjaxResult.success("开门操作已执行");
    }

    /**
     * 辅助方法：执行开门操作
     */
    @Log(title = "访客码开门操作", businessType = BusinessType.OPEN, operatorType = OperatorType.GUEST)
    private void doorOpenOnceAction(String deviceId, int duration) {
        // 构建消息数据
        Map<String, Object> data = new HashMap<>();
        data.put("duration", duration);

        MqttMessage<Map<String, Object>> message = new MqttMessage<>();
        message.setOperate("door_open_once");
        message.setTimestamp(System.currentTimeMillis() / 1000);
        message.setData(data);

        String topic = "/" + deviceId + "/server2client";
        mqttGateway.sendToMqtt(topic, message);
        logger.info("发送开门消息到主题 {}: {}", topic, message);
    }
    // 添加其他操作类型的接口，例如 doorOpenTimer、doorLock 等
}
