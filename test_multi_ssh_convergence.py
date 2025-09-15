#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
多SSH会话并行监控测试脚本
"""

import time
import logging
import yaml
import threading
import concurrent.futures
from pathlib import Path
from src.ssh_manager import SSHManager
from src.rstp_analyzer import RSTPAnalyzer

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def load_config():
    """加载配置文件"""
    config_path = Path(__file__).parent / 'config.yaml'
    with open(config_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def multi_ssh_convergence_monitor(analyzers, timeout=60.0, num_sessions=5):
    """多SSH会话并行监控收敛状态"""
    logger.info(f"开始多SSH会话并行监控，会话数: {num_sessions}")
    
    convergence_result = {
        'converged': False,
        'convergence_time': timeout,
        'first_session': None,
        'session_results': []
    }
    
    # 创建线程锁和事件
    convergence_lock = threading.Lock()
    convergence_event = threading.Event()
    start_time = time.time()
    
    def monitor_single_session(session_id, analyzer):
        """单个SSH会话监控函数"""
        session_start = time.time()
        logger.info(f"会话 {session_id} 开始监控")
        
        try:
            # 为每个会话创建独立的SSH连接
            ssh_manager = SSHManager(
                f"{analyzer.node.config.name}_session_{session_id}",
                analyzer.node.config.ip,
                analyzer.node.config.username,
                analyzer.node.config.password
            )
            
            # 连接SSH
            if not ssh_manager.connect():
                logger.error(f"会话 {session_id} SSH连接失败")
                return {'session_id': session_id, 'success': False, 'error': 'SSH连接失败'}
            
            # 创建独立的分析器实例
            session_analyzer = RSTPAnalyzer(ssh_manager)
            
            # 监控收敛状态
            check_interval = 0.1  # 100ms检测间隔
            stable_count = 0
            required_stable = 3  # 需要连续3次稳定
            
            while not convergence_event.is_set() and (time.time() - start_time) < timeout:
                try:
                    # 获取当前收敛状态
                    state = session_analyzer.get_convergence_state()
                    
                    if state and state.get('converged', False):
                        stable_count += 1
                        logger.debug(f"会话 {session_id} 检测到稳定状态 ({stable_count}/{required_stable})")
                        
                        if stable_count >= required_stable:
                            # 检测到收敛
                            convergence_time = time.time() - start_time
                            
                            with convergence_lock:
                                if not convergence_result['converged']:
                                    convergence_result['converged'] = True
                                    convergence_result['convergence_time'] = convergence_time
                                    convergence_result['first_session'] = session_id
                                    logger.info(f"🎉 会话 {session_id} 首先检测到收敛! 时间: {convergence_time:.3f}秒")
                                    convergence_event.set()
                            
                            return {
                                'session_id': session_id,
                                'success': True,
                                'convergence_time': convergence_time,
                                'detection_time': time.time() - session_start
                            }
                    else:
                        stable_count = 0
                    
                    time.sleep(check_interval)
                    
                except Exception as e:
                    logger.warning(f"会话 {session_id} 监控异常: {e}")
                    # 尝试重连
                    if not ssh_manager.is_connected():
                        logger.info(f"会话 {session_id} 尝试重连...")
                        ssh_manager.connect()
                    time.sleep(check_interval)
            
            # 超时或被其他会话中断
            return {
                'session_id': session_id,
                'success': False,
                'timeout': True,
                'detection_time': time.time() - session_start
            }
            
        except Exception as e:
            logger.error(f"会话 {session_id} 发生错误: {e}")
            return {
                'session_id': session_id,
                'success': False,
                'error': str(e),
                'detection_time': time.time() - session_start
            }
        
        finally:
            try:
                ssh_manager.close()
            except:
                pass
    
    # 使用线程池并行执行多个会话
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_sessions) as executor:
        # 为每个分析器创建多个监控会话
        futures = []
        for analyzer in analyzers:
            for session_id in range(num_sessions):
                future = executor.submit(monitor_single_session, f"{analyzer.node.config.name}_{session_id}", analyzer)
                futures.append(future)
        
        # 等待所有会话完成或收敛检测完成
        for future in concurrent.futures.as_completed(futures, timeout=timeout + 10):
            try:
                result = future.result()
                convergence_result['session_results'].append(result)
                
                if result.get('success') and result.get('convergence_time'):
                    logger.info(f"会话 {result['session_id']} 完成: {result}")
            except Exception as e:
                logger.error(f"获取会话结果失败: {e}")
    
    total_time = time.time() - start_time
    logger.info(f"多SSH会话并行监控完成，总耗时: {total_time:.3f}秒")
    
    return convergence_result

def test_multi_ssh_convergence():
    """测试多SSH会话并行监控功能"""
    logger.info("开始测试多SSH会话并行监控功能...")
    
    try:
        # 加载配置
        config = load_config()
        
        # 创建SSH管理器
        dut_ssh = SSHManager(
            "DUT",
            config['vms']['dut']['ip'],
            config['vms']['dut']['username'],
            config['vms']['dut']['password']
        )
        
        # 连接SSH
        if not dut_ssh.connect():
            logger.error("无法连接到DUT")
            return False
        
        # 创建分析器
        analyzer = RSTPAnalyzer(dut_ssh)
        
        logger.info("=== 开始多SSH会话并行监控测试 ===")
        start_time = time.time()
        
        # 调用新的多SSH会话并行监控功能
        result = multi_ssh_convergence_monitor([analyzer], timeout=60, num_sessions=5)
        
        total_time = time.time() - start_time
        
        # 输出测试结果
        logger.info("============================================================")
        logger.info("多SSH会话并行监控测试结果:")
        logger.info(f"收敛状态: {'已收敛' if result['converged'] else '未收敛'}")
        logger.info(f"收敛时间: {result['convergence_time']:.3f}秒")
        logger.info(f"首先检测的会话: {result['first_session']}")
        logger.info(f"总测试时间: {total_time:.3f}秒")
        logger.info(f"会话结果数量: {len(result['session_results'])}")
        
        # 显示各会话的详细结果
        for session_result in result['session_results']:
            logger.info(f"  会话 {session_result['session_id']}: {session_result}")
        
        if result['converged']:
            logger.info("✅ 多SSH会话并行监控测试成功")
            success = True
        else:
            logger.error("❌ 多SSH会话并行监控测试超时")
            success = False
        
        logger.info("============================================================")
        
        return success
        
    except Exception as e:
        logger.error(f"测试过程中发生错误: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False
    
    finally:
        # 清理资源
        try:
            dut_ssh.close()
        except:
            pass

if __name__ == "__main__":
    success = test_multi_ssh_convergence()
    if success:
        print("\n🎉 多SSH会话并行监控功能测试通过!")
    else:
        print("\n❌ 多SSH会话并行监控功能测试失败!")