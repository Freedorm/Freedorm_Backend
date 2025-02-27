package com.ruoyi.lock.service.impl;

import com.ruoyi.lock.domain.Devices;
import com.ruoyi.lock.domain.FreedormLockSchedule;
import com.ruoyi.lock.dto.AddTimingRequest;
import com.ruoyi.lock.dto.DeleteTimingRequest;
import com.ruoyi.lock.dto.ExistingTimingResponse;
import com.ruoyi.lock.mapper.FreedormLockSchedulesMapper;
import com.ruoyi.lock.service.ILockService;
import com.ruoyi.lock.service.MqttGateway;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class LockServiceImpl implements ILockService {

    @Autowired
    private FreedormLockSchedulesMapper schedulesMapper;

    @Autowired
    private MqttGateway mqttGateway;

    @Override
    @Transactional(rollbackFor = Exception.class)
    public void addTiming(AddTimingRequest request, Devices device) {
        for (Integer day : request.getDaysOfWeek()) {
            // 创建新的时间表记录
            FreedormLockSchedule schedule = new FreedormLockSchedule();
            schedule.setDeviceId(device.getDeviceId());
            schedule.setDayOfWeek(day);
            schedule.setStartTime(request.getStartTime().toString());
            schedule.setEndTime(request.getEndTime().toString());

            // 插入数据库
            schedulesMapper.insertFreedormLockSchedule(schedule);
        }
    }

    /**
     * 检查两个时间段是否重叠
     *
     * @param existingStart 现有时间段的开始时间（格式："HH:mm:ss"）
     * @param existingEnd   现有时间段的结束时间（格式："HH:mm:ss"）
     * @param newStart      新时间段的开始时间（格式："HH:mm:ss"）
     * @param newEnd        新时间段的结束时间（格式："HH:mm:ss"）
     * @return 如果重叠则返回 true，否则返回 false
     */
    public static boolean isOverlapping(String existingStart, String existingEnd, String newStart, String newEnd) {
        return !newStart.equals(existingEnd) && !newEnd.equals(existingStart) &&
               newStart.compareTo(existingEnd) < 0 && existingStart.compareTo(newEnd) < 0;
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    public void deleteTiming(DeleteTimingRequest request) {
        for (Integer day : request.getDaysOfWeek()) {
            // 检查 day 是否在1-7之间
            if (day < 1 || day > 7) {
                throw new IllegalArgumentException("dayOfWeek 必须在1到7之间");
            }

            // 创建时间表记录，用于删除
            FreedormLockSchedule schedule = new FreedormLockSchedule();
            schedule.setDeviceId(request.getDeviceId());
            schedule.setDayOfWeek(day);
            schedule.setStartTime(request.getStartTime().toString());
            schedule.setEndTime(request.getEndTime().toString());

            // 删除记录
            int deletedRows = schedulesMapper.deleteFreedormLockSchedule(schedule);
            if (deletedRows == 0) {
                throw new NoSuchElementException("未找到对应的时间段记录，deviceId: " + request.getDeviceId() + ", dayOfWeek: " + day);
            }
        }
    }

    @Override
    public List<ExistingTimingResponse> getExistingTimings(String deviceId) {
        // 查询数据库中该设备的所有时间段
        List<FreedormLockSchedule> schedules = schedulesMapper.findByDeviceId(deviceId);
        if (schedules == null || schedules.isEmpty()) {
            return Collections.emptyList();
        }

        // 将时间段按 startTime 和 endTime 分组，并收集对应的 daysOfWeek
        Map<String, List<Integer>> grouped = schedules.stream()
                .collect(Collectors.groupingBy(
                        schedule -> schedule.getStartTime() + "|" + schedule.getEndTime(),
                        Collectors.mapping(FreedormLockSchedule::getDayOfWeek, Collectors.toList())
                ));

        // 构建响应列表
        List<ExistingTimingResponse> responseList = new ArrayList<>();
        for (Map.Entry<String, List<Integer>> entry : grouped.entrySet()) {
            String[] times = entry.getKey().split("\\|");
            String startTime = times[0];
            String endTime = times[1];
            List<Integer> daysOfWeek = entry.getValue();

            ExistingTimingResponse response = new ExistingTimingResponse();
            response.setDeviceId(deviceId);
            response.setDaysOfWeek(daysOfWeek);
            response.setStartTime(startTime);
            response.setEndTime(endTime);

            responseList.add(response);
        }

        return responseList;
    }
}
