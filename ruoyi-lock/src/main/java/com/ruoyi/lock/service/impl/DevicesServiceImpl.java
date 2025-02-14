package com.ruoyi.lock.service.impl;

import java.util.List;

import com.ruoyi.common.core.domain.entity.SysDept;
import com.ruoyi.common.core.domain.entity.SysUser;
import com.ruoyi.common.utils.SecurityUtils;
import com.ruoyi.lock.dto.BindDeviceRequest;
import com.ruoyi.system.service.ISysDeptService;
import com.ruoyi.system.service.ISysUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.ruoyi.lock.mapper.DevicesMapper;
import com.ruoyi.lock.domain.Devices;
import com.ruoyi.lock.service.IDevicesService;
import org.springframework.transaction.annotation.Transactional;

/**
 * 设备Service业务层处理
 *
 * @author Maxing
 * @date 2025-01-04
 */
@Service
public class DevicesServiceImpl implements IDevicesService
{
    @Autowired
    private DevicesMapper devicesMapper;

    @Autowired
    private ISysDeptService deptService;

    @Autowired
    private ISysUserService userService;

    /**
     * 查询设备
     *
     * @param deviceId 设备主键
     * @return 设备
     */
    @Override
    public Devices selectDevicesByDeviceId(String deviceId)
    {
        return devicesMapper.selectDevicesByDeviceId(deviceId);
    }

    /**
     * 查询设备列表
     *
     * @param devices 设备
     * @return 设备
     */
    @Override
    public List<Devices> selectDevicesList(Devices devices)
    {
        return devicesMapper.selectDevicesList(devices);
    }

    /**
     * 新增设备
     *
     * @param devices 设备
     * @return 结果
     */
    @Override
    public int insertDevices(Devices devices)
    {
        return devicesMapper.insertDevices(devices);
    }

    /**
     * 修改设备
     *
     * @param devices 设备
     * @return 结果
     */
    @Override
    public int updateDevices(Devices devices)
    {
        return devicesMapper.updateDevices(devices);
    }

    /**
     * 批量删除设备
     *
     * @param deviceIds 需要删除的设备主键
     * @return 结果
     */
    @Override
    public int deleteDevicesByDeviceIds(String[] deviceIds)
    {
        return devicesMapper.deleteDevicesByDeviceIds(deviceIds);
    }

    /**
     * 删除设备信息
     *
     * @param deviceId 设备主键
     * @return 结果
     */
    @Override
    public int deleteDevicesByDeviceId(String deviceId)
    {
        return devicesMapper.deleteDevicesByDeviceId(deviceId);
    }

    private void enable_device(String deviceId) {
        Devices device = selectDevicesByDeviceId(deviceId);
        device.setIsEnabled(0);
        updateDevices(device);
    }

    @Override
    public Boolean deviceIsOnline(String deviceId) {
        return selectDevicesByDeviceId(deviceId).getIsEnabled() == 0;
    }

    @Override
    @Transactional
    public Boolean bindDevice(BindDeviceRequest request) {
        Devices device = selectDevicesByDeviceId(request.getDeviceId());
        SysUser user = SecurityUtils.getLoginUser().getUser();
        if (device.getDeptId() == null || device.getIsEnabled() == 1) {
            SysDept dept = new SysDept();
            dept.setDeptName(user.getNickName() + "的设备");
            dept.setParentId(200L);
            dept.setOrderNum(0);
            dept.setLeader(user.getNickName());
            dept.setDeviceId(device.getDeviceId());
            user.setDeptId(deptService.insertDeptWithReturn(dept));
            Long[] roleIds;
            if (user.getRoleIds() == null) {
                roleIds = new Long[0];
            }else {
                roleIds = user.getRoleIds();
            }
            Long[] newRoleIds = new Long[roleIds.length + 1];
            System.arraycopy(roleIds, 0, newRoleIds, 0, roleIds.length);
            newRoleIds[roleIds.length] = 100L;
            user.setRoleIds(newRoleIds);
            userService.updateUser(user);
            device.setDeptId(dept.getDeptId());
            device.setIsEnabled(0);
            updateDevices(device);
        } else {
            user.setDeptId(device.getDeptId());
            userService.updateUser(user);
        }
        return true;
    }

    @Override
    public boolean unbindDevice() {
        SysUser user = SecurityUtils.getLoginUser().getUser();
        user.setDeptId(null);
        userService.updateUser(user);
        return true;
    }
}
