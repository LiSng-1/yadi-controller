"""
雅迪一线通控制器协议 - Saleae Logic 2 High Level Analyzer
协议规范：
- 帧格式：12字节，起始位+12×8数据位，空闲低电平
- 帧结构：[SYNC=0x08][DEV_ID=0x61][DATA2-DATA10][CHECKSUM]
- 校验和：DATA0-DATA10累加和低8位
"""

from typing import Optional, Dict, Any, List
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame


# 帧解析结果类型定义
RESULT_TYPES = {
    'sync': {'format': '同步: {{data.value}}'},
    'device_id': {'format': '设备编码: {{data.value}}'},
    'data2': {'format': 'DATA2: 单撑断电={{data.side_stand}}, 启动保护={{data.start_protect}}'},
    'data3': {'format': 'DATA3: 霍尔故障={{data.hall_fault}}, 转把={{data.throttle_fault}}, 控制器={{data.controller_fault}}, 欠压={{data.under_voltage}}, 巡航={{data.cruise}}, 助力={{data.assist}}, 缺相={{data.phase_loss}}'},
    'data4': {'format': 'DATA4: 速度档位={{data.speed_gear}}, 电机运行={{data.motor_running}}, 刹车={{data.brake}}, 滑行充电={{data.coast_charge}}, 防飞车={{data.anti_runaway}}'},
    'data5': {'format': 'DATA5: 70%电流={{data.current_70}}, 一键通={{data.一键通}}, EKK备用={{data.ekk}}, 过流={{data.over_current}}, 堵转={{data.stall}}, 倒车={{data.reverse}}, 电子刹车={{data.e_brake}}, 限速={{data.speed_limit}}'},
    'data6': {'format': '运行电流: {{data.current}}A'},
    'data7': {'format': '速度(高字节): {{data.speed_high}}'},
    'data8': {'format': '速度(低字节): {{data.speed_low}}'},
    'speed': {'format': '速度计数: {{data.speed}} (0.5s内霍尔变化数)'},
    'checksum': {'format': '校验和: {{data.calculated}}/{{data.received}} {{data.status}}'},
    'frame_complete': {'format': '完整帧 - 速度档位={{data.speed_gear}}, 电流={{data.current}}A, 速度={{data.speed}}'},
    'error': {'format': '错误: {{data.message}}'}
}


class Hla(HighLevelAnalyzer):
    """
    雅迪协议HLA实现
    基于Async Serial分析仪输出的字节流进行帧同步和解析
    """
    
    def __init__(self):
        """初始化分析仪状态"""
        # 结果类型注册
        self.result_types = RESULT_TYPES
        
        # 状态机
        self.state = 'IDLE'  # IDLE, SYNC_RECEIVED, COLLECTING
        
        # 帧缓冲区
        self.frame_buffer: List[int] = []
        self.frame_start_time = None
        
        # 调试计数器
        self.frame_count = 0
        self.error_count = 0
        
    def decode(self, frame: AnalyzerFrame) -> Optional[AnalyzerFrame]:
        """
        处理Async Serial分析仪的每一帧输出
        frame.type: 'data' 包含单个字节
        frame.data['data']: 字节值 (0-255)
        """
        if frame.type != 'data':
            return None
            
        # 获取当前字节
        byte_value = frame.data['data'][0] if isinstance(frame.data['data'], (bytes, bytearray)) else frame.data['data']
        current_time = frame.start_time
        
        # 状态机处理
        if self.state == 'IDLE':
            # 等待同步字节0x08
            if byte_value == 0x08:
                self.state = 'SYNC_RECEIVED'
                self.frame_buffer = [byte_value]
                self.frame_start_time = current_time
                return AnalyzerFrame('sync', current_time, current_time, {
                    'value': f'0x{byte_value:02X}'
                })
                
        elif self.state == 'SYNC_RECEIVED':
            # 等待设备编码0x61
            self.frame_buffer.append(byte_value)
            if byte_value == 0x61:
                self.state = 'COLLECTING'
                return AnalyzerFrame('device_id', self.frame_start_time, current_time, {
                    'value': f'0x{byte_value:02X}'
                })
            else:
                # 同步错误，重置
                self.state = 'IDLE'
                self.error_count += 1
                return AnalyzerFrame('error', self.frame_start_time, current_time, {
                    'message': f'设备编码错误: 期望0x61, 收到0x{byte_value:02X}'
                })
                
        elif self.state == 'COLLECTING':
            # 收集数据字节 (DATA2-DATA10)
            self.frame_buffer.append(byte_value)
            
            # 根据当前字节位置返回对应的解析结果
            byte_index = len(self.frame_buffer) - 1
            
            # DATA2 (索引2)
            if byte_index == 2:
                return self._parse_data2(byte_value, frame)
            # DATA3 (索引3)
            elif byte_index == 3:
                return self._parse_data3(byte_value, frame)
            # DATA4 (索引4)
            elif byte_index == 4:
                return self._parse_data4(byte_value, frame)
            # DATA5 (索引5)
            elif byte_index == 5:
                return self._parse_data5(byte_value, frame)
            # DATA6 (索引6)
            elif byte_index == 6:
                return self._parse_data6(byte_value, frame)
            # DATA7 (索引7)
            elif byte_index == 7:
                return self._parse_data7(byte_value, frame)
            # DATA8 (索引8)
            elif byte_index == 8:
                return self._parse_data8(byte_value, frame)
            # DATA9 (索引9)
            elif byte_index == 9:
                return self._parse_data9(byte_value, frame)
            # DATA10 (索引10)
            elif byte_index == 10:
                return self._parse_data10(byte_value, frame)
            # DATA11 校验和 (索引11)
            elif byte_index == 11:
                self.frame_buffer.append(byte_value)
                result = self._verify_and_complete(frame)
                self.state = 'IDLE'  # 重置状态机
                return result
                
        return None
    
    def _parse_data2(self, byte_value: int, frame: AnalyzerFrame) -> AnalyzerFrame:
        """解析DATA2: 单撑断电、启动保护等"""
        side_stand = bool((byte_value >> 2) & 0x01)
        start_protect = bool(byte_value & 0x01)
        
        return AnalyzerFrame('data2', frame.start_time, frame.end_time, {
            'side_stand': side_stand,
            'start_protect': start_protect,
            'raw': f'0x{byte_value:02X}'
        })
    
    def _parse_data3(self, byte_value: int, frame: AnalyzerFrame) -> AnalyzerFrame:
        """解析DATA3: 故障和状态标志"""
        return AnalyzerFrame('data3', frame.start_time, frame.end_time, {
            'hall_fault': bool((byte_value >> 6) & 0x01),
            'throttle_fault': bool((byte_value >> 5) & 0x01),
            'controller_fault': bool((byte_value >> 4) & 0x01),
            'under_voltage': bool((byte_value >> 3) & 0x01),
            'cruise': bool((byte_value >> 2) & 0x01),
            'assist': bool((byte_value >> 1) & 0x01),
            'phase_loss': bool(byte_value & 0x01),
            'raw': f'0x{byte_value:02X}'
        })
    
    def _parse_data4(self, byte_value: int, frame: AnalyzerFrame) -> AnalyzerFrame:
        """解析DATA4: 速度档位、电机状态等"""
        # 速度档位: bit7 + bit1-0
        speed_gear = ((byte_value >> 7) << 2) | ((byte_value >> 1) & 0x03)
        
        return AnalyzerFrame('data4', frame.start_time, frame.end_time, {
            'speed_gear': speed_gear,
            'motor_running': bool((byte_value >> 6) & 0x01),
            'brake': bool((byte_value >> 5) & 0x01),
            'coast_charge': bool((byte_value >> 3) & 0x01),
            'anti_runaway': bool((byte_value >> 2) & 0x01),
            'raw': f'0x{byte_value:02X}'
        })
    
    def _parse_data5(self, byte_value: int, frame: AnalyzerFrame) -> AnalyzerFrame:
        """解析DATA5: 各种使能标志"""
        return AnalyzerFrame('data5', frame.start_time, frame.end_time, {
            'current_70': bool((byte_value >> 7) & 0x01),
            '一键通': bool((byte_value >> 6) & 0x01),
            'ekk': bool((byte_value >> 5) & 0x01),
            'over_current': bool((byte_value >> 4) & 0x01),
            'stall': bool((byte_value >> 3) & 0x01),
            'reverse': bool((byte_value >> 2) & 0x01),
            'e_brake': bool((byte_value >> 1) & 0x01),
            'speed_limit': bool(byte_value & 0x01),
            'raw': f'0x{byte_value:02X}'
        })
    
    def _parse_data6(self, byte_value: int, frame: AnalyzerFrame) -> AnalyzerFrame:
        """解析DATA6: 运行电流"""
        # 有符号数：bit7为符号位，bit6-0为绝对值
        if byte_value & 0x80:
            current = -(byte_value & 0x7F)
        else:
            current = byte_value & 0x7F
            
        return AnalyzerFrame('data6', frame.start_time, frame.end_time, {
            'current': current,
            'raw': f'0x{byte_value:02X}'
        })
    
    def _parse_data7(self, byte_value: int, frame: AnalyzerFrame) -> AnalyzerFrame:
        """解析DATA7: 速度高字节"""
        return AnalyzerFrame('data7', frame.start_time, frame.end_time, {
            'speed_high': byte_value,
            'raw': f'0x{byte_value:02X}'
        })
    
    def _parse_data8(self, byte_value: int, frame: AnalyzerFrame) -> AnalyzerFrame:
        """解析DATA8: 速度低字节"""
        return AnalyzerFrame('data8', frame.start_time, frame.end_time, {
            'speed_low': byte_value,
            'raw': f'0x{byte_value:02X}'
        })
    
    def _parse_data9(self, byte_value: int, frame: AnalyzerFrame) -> AnalyzerFrame:
        """解析DATA9: 保留字节"""
        return AnalyzerFrame('data9', frame.start_time, frame.end_time, {
            'reserved': byte_value,
            'raw': f'0x{byte_value:02X}'
        })
    
    def _parse_data10(self, byte_value: int, frame: AnalyzerFrame) -> AnalyzerFrame:
        """解析DATA10: 保留字节"""
        return AnalyzerFrame('data10', frame.start_time, frame.end_time, {
            'reserved': byte_value,
            'raw': f'0x{byte_value:02X}'
        })
    
    def _verify_and_complete(self, frame: AnalyzerFrame) -> AnalyzerFrame:
        """
        验证校验和并返回完整帧解析
        在最后一帧时调用
        """
        if len(self.frame_buffer) != 12:
            return AnalyzerFrame('error', self.frame_start_time, frame.end_time, {
                'message': f'帧长度错误: 期望12, 收到{len(self.frame_buffer)}'
            })
            
        # 计算校验和 (DATA0-DATA10)
        calc_checksum = sum(self.frame_buffer[:11]) & 0xFF
        received_checksum = self.frame_buffer[11]
        
        checksum_ok = (calc_checksum == received_checksum)
        self.frame_count += 1
        
        # 发送校验和结果
        checksum_frame = AnalyzerFrame('checksum', self.frame_start_time, frame.end_time, {
            'calculated': f'0x{calc_checksum:02X}',
            'received': f'0x{received_checksum:02X}',
            'status': '✓ 通过' if checksum_ok else '✗ 错误'
        })
        
        # 在Logic 2中，decode函数一次只能返回一个帧
        # 为了显示完整信息，我们返回一个综合帧
        if checksum_ok:
            # 从缓冲区提取数据
            data6 = self.frame_buffer[6]
            if data6 & 0x80:
                current = -(data6 & 0x7F)
            else:
                current = data6 & 0x7F
                
            data4 = self.frame_buffer[4]
            speed_gear = ((data4 >> 7) << 2) | ((data4 >> 1) & 0x03)
            
            data7 = self.frame_buffer[7]
            data8 = self.frame_buffer[8]
            speed = (data7 << 8) | data8
            
            return AnalyzerFrame('frame_complete', self.frame_start_time, frame.end_time, {
                'speed_gear': speed_gear,
                'current': current,
                'speed': speed,
                'frame_count': self.frame_count,
                'checksum_ok': checksum_ok
            })
        else:
            return checksum_frame
