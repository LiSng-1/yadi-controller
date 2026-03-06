class YadiProtocolParser:
    def __init__(self):
        self.protocol_version = "1.0"
    
    def parse_frame(self, raw_data):
        """解析雅迪控制器协议帧"""
        if len(raw_data) < 10:
            return None
        
        frame = {
            "start_byte": raw_data[0],
            "length": raw_data[1],
            "command": raw_data[2],
            "data": raw_data[3:-2],
            "checksum": raw_data[-2],
            "end_byte": raw_data[-1]
        }
        
        if not self._verify_checksum(raw_data):
            return None
        
        return frame
    
    def _verify_checksum(self, data):
        """验证校验和"""
        checksum = 0
        for i in range(1, len(data) - 2):
            checksum ^= data[i]
        return checksum == data[-2]
    
    def parse_status_data(self, data):
        """解析状态数据"""
        if len(data) < 8:
            return None
        
        status = {
            "battery_voltage": (data[0] << 8 | data[1]) / 10.0,
            "current": (data[2] << 8 | data[3]) / 10.0,
            "speed": data[4],
            "temperature": data[5] - 40,
            "mileage": (data[6] << 8 | data[7]) / 10.0
        }
        
        return status
    
    def build_command(self, command, data):
        """构建命令帧"""
        frame = [0xAA, len(data) + 3, command]
        frame.extend(data)
        
        # 计算校验和
        checksum = 0
        for i in range(1, len(frame)):
            checksum ^= frame[i]
        frame.append(checksum)
        frame.append(0x55)
        
        return frame
    
    def parse_response(self, response):
        """解析响应帧"""
        frame = self.parse_frame(response)
        if not frame:
            return None
        
        if frame["command"] == 0x01:
            return self.parse_status_data(frame["data"])
        elif frame["command"] == 0x02:
            return {"success": frame["data"][0] == 0x01}
        elif frame["command"] == 0x03:
            return {"version": "".join([chr(b) for b in frame["data"]])}
        else:
            return frame

if __name__ == "__main__":
    parser = YadiProtocolParser()
    
    # 测试解析状态数据
    test_data = [0xAA, 0x0B, 0x01, 0x0C, 0x80, 0x00, 0x78, 0x20, 0x28, 0x00, 0x64, 0x3F, 0x55]
    result = parser.parse_response(test_data)
    print("测试解析结果:")
    print(result)