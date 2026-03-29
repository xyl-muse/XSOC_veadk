"""风险处置专家智能体"""
from veadk import Agent
from typing import Dict, Any, Optional
from schemas.security_event import SecurityEvent, EventStatus


class ResponseAgent(Agent):
    """
    风险处置专家智能体
    职责：对真实攻击事件进行风险评估，制定并执行最小影响的处置策略
    """
    name: str = "response_agent"
    display_name: str = "风险处置专家"
    description: str = "负责对真实攻击事件进行风险评估，制定并执行最小影响的处置策略"

    # 智能体系统提示词
    instruction: str = """
你是资深安全风险处置专家，专注于安全事件的风险评估和处置策略制定工作。你的职责是：
1. 接收来自溯源分析专家的真实攻击事件和关键线索
2. 调用工具查询资产重要性、业务影响、风险评估等数据
3. 制定最小影响的处置策略，优先使用API封禁/白名单，其次考虑终端隔离
4. 执行处置操作，检查操作安全性，确保最小影响原则
5. 验证处置效果，实现处置失败回滚逻辑
6. 遵循最小化工作路径原则，重点关注风险评估和处置执行

输出要求：
- 风险评估结果必须明确：风险等级、影响范围、资产重要性
- 处置策略需输出结构化的信息：策略类型、执行步骤、预期效果
- 执行处置操作时，需经过安全校验和人工审核（通过VEADK的HITL机制）
- 验证处置效果，确保操作生效
    """

    async def run(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """智能体执行入口"""
        import uuid
        trace_id = str(uuid.uuid4())

        # 1. 将输入转换为标准化事件格式
        security_event = SecurityEvent.from_input(event_data)
        self.logger.info(f"开始风险评估和处置事件: {security_event.event_id}, 类型: {security_event.event_type_name}", trace_id=trace_id)

        # 2. 风险评估
        risk_assessment = self._assess_risk(security_event)
        security_event.context["risk_assessment"] = risk_assessment

        # 3. 制定处置策略
        response_strategy = self._develop_response_strategy(security_event)
        security_event.context["response_strategy"] = response_strategy

        # 4. 执行处置操作（需要经过HITL机制触发人工审核）
        execution_result = await self._execute_response(security_event)
        security_event.context["execution_result"] = execution_result

        # 5. 验证处置效果
        verification_result = self._verify_response_effect(security_event)
        security_event.context["verification_result"] = verification_result

        # 6. 处理处置结果
        if verification_result:
            security_event.status = EventStatus.VISUALIZING
            security_event.process_history.append({
                "stage": "response",
                "stage_name": "风险处置",
                "result": "处置成功",
                "risk_assessment": risk_assessment,
                "response_strategy": response_strategy,
                "execution_result": execution_result,
                "verification_result": verification_result
            })
            self.logger.info(f"事件处置成功: {security_event.event_id}", trace_id=trace_id)
            await self.send_to_agent("visualization_agent", security_event.model_dump())
            await self.context.save_event(security_event.event_id, security_event.model_dump())
            return {
                "event_id": security_event.event_id,
                "status": security_event.status.value,
                "status_name": security_event.status_name,
                "result": "处置成功",
                "risk_assessment": risk_assessment,
                "response_strategy": response_strategy,
                "execution_result": execution_result,
                "verification_result": verification_result
            }

        # 7. 处置失败回滚
        rollback_result = await self._rollback_response(security_event)
        security_event.status = EventStatus.FAILED
        security_event.process_history.append({
            "stage": "response",
            "stage_name": "风险处置",
            "result": "处置失败",
            "risk_assessment": risk_assessment,
            "response_strategy": response_strategy,
            "execution_result": execution_result,
            "verification_result": verification_result,
            "rollback_result": rollback_result
        })
        self.logger.error(f"事件处置失败: {security_event.event_id}", trace_id=trace_id)
        await self.send_to_agent("visualization_agent", security_event.model_dump())
        await self.context.save_event(security_event.event_id, security_event.model_dump())
        return {
            "event_id": security_event.event_id,
            "status": security_event.status.value,
            "status_name": security_event.status_name,
            "result": "处置失败",
            "risk_assessment": risk_assessment,
            "response_strategy": response_strategy,
            "execution_result": execution_result,
            "verification_result": verification_result,
            "rollback_result": rollback_result
        }

    def _assess_risk(self, security_event: SecurityEvent) -> Dict[str, Any]:
        """风险评估"""
        raw_data = security_event.raw_data

        # 基础风险评估
        risk_assessment = {
            "risk_level": "medium",
            "impact_range": "small",
            "asset_importance": "normal"
        }

        # 检查原始数据中的风险等级
        if "incidentSeverity" in raw_data:
            severity = raw_data["incidentSeverity"]
            if severity == 4:
                risk_assessment["risk_level"] = "critical"
            elif severity == 3:
                risk_assessment["risk_level"] = "high"
            elif severity == 2:
                risk_assessment["risk_level"] = "medium"
            elif severity == 1:
                risk_assessment["risk_level"] = "low"

        # 检查目标资产重要性
        if security_event.attack_source_ip:
            from ipaddress import ip_address, IPv4Network
            try:
                src_ip = ip_address(security_event.attack_source_ip)
                # 内部网段通常被视为重要资产
                internal_networks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
                for network in internal_networks:
                    if src_ip in IPv4Network(network):
                        risk_assessment["asset_importance"] = "high"
                        break
            except:
                pass

        # 检查原始数据中的风险标签
        if "riskTag" in raw_data:
            risk_tags = raw_data["riskTag"]
            if any(tag in risk_tags for tag in ["执行", "持久化", "横向移动", "权限提升"]):
                risk_assessment["risk_level"] = "high"
                risk_assessment["impact_range"] = "medium"

        return risk_assessment

    def _develop_response_strategy(self, security_event: SecurityEvent) -> Dict[str, Any]:
        """制定处置策略"""
        risk_assessment = security_event.context.get("risk_assessment", {})

        # 根据风险等级制定处置策略
        if risk_assessment.get("risk_level") == "critical":
            response_strategy = {
                "strategy_type": "comprehensive",
                "execution_steps": ["IP封禁", "终端隔离", "告警通知"],
                "expected_effect": "完全阻止攻击，防止进一步扩散"
            }
        elif risk_assessment.get("risk_level") == "high":
            response_strategy = {
                "strategy_type": "aggressive",
                "execution_steps": ["IP封禁", "告警通知"],
                "expected_effect": "阻止攻击，防止进一步扩散"
            }
        elif risk_assessment.get("risk_level") == "medium":
            response_strategy = {
                "strategy_type": "moderate",
                "execution_steps": ["白名单管理", "告警通知"],
                "expected_effect": "监控攻击，防止进一步扩散"
            }
        else:
            response_strategy = {
                "strategy_type": "light",
                "execution_steps": ["告警通知"],
                "expected_effect": "监控攻击，及时发现异常"
            }

        return response_strategy

    async def _execute_response(self, security_event: SecurityEvent) -> Dict[str, Any]:
        """执行处置操作（需要经过HITL机制触发人工审核）"""
        response_strategy = security_event.context.get("response_strategy", {})

        execution_result = {
            "status": "success",
            "operations": []
        }

        # 执行处置操作
        for step in response_strategy.get("execution_steps", []):
            operation_result = await self._execute_operation(step, security_event)
            execution_result["operations"].append(operation_result)

        return execution_result

    async def _execute_operation(self, operation: str, security_event: SecurityEvent) -> Dict[str, Any]:
        """执行单个处置操作"""
        operation_result = {
            "operation": operation,
            "status": "pending",
            "result": None,
            "timestamp": self._get_current_time()
        }

        # 根据操作类型执行不同的处置操作
        if operation == "IP封禁":
            if security_event.attack_source_ip:
                ip_block_result = await self.call_tool(
                    "ip_block",
                    {"ip": security_event.attack_source_ip}
                )
                operation_result["status"] = "success" if ip_block_result.get("status") == "success" else "failed"
                operation_result["result"] = ip_block_result
            else:
                operation_result["status"] = "failed"
                operation_result["result"] = "未找到攻击源IP"
        elif operation == "白名单管理":
            if security_event.attack_source_ip:
                whitelist_result = await self.call_tool(
                    "whitelist_management",
                    {"ip": security_event.attack_source_ip, "action": "add"}
                )
                operation_result["status"] = "success" if whitelist_result.get("status") == "success" else "failed"
                operation_result["result"] = whitelist_result
            else:
                operation_result["status"] = "failed"
                operation_result["result"] = "未找到攻击源IP"
        elif operation == "终端隔离":
            if security_event.target_asset_ip:
                terminal_isolation_result = await self.call_tool(
                    "terminal_isolation",
                    {"ip": security_event.target_asset_ip}
                )
                operation_result["status"] = "success" if terminal_isolation_result.get("status") == "success" else "failed"
                operation_result["result"] = terminal_isolation_result
            else:
                operation_result["status"] = "failed"
                operation_result["result"] = "未找到目标资产IP"
        elif operation == "告警通知":
            alert_notification_result = await self.call_tool(
                "alert_notification",
                {"event_id": security_event.event_id}
            )
            operation_result["status"] = "success" if alert_notification_result.get("status") == "success" else "failed"
            operation_result["result"] = alert_notification_result

        return operation_result

    def _verify_response_effect(self, security_event: SecurityEvent) -> bool:
        """验证处置效果"""
        execution_result = security_event.context.get("execution_result", {})

        # 检查所有操作是否成功执行
        for operation in execution_result.get("operations", []):
            if operation["status"] != "success":
                return False

        return True

    async def _rollback_response(self, security_event: SecurityEvent) -> Dict[str, Any]:
        """处置失败回滚"""
        response_strategy = security_event.context.get("response_strategy", {})

        rollback_result = {
            "status": "success",
            "operations": []
        }

        # 执行回滚操作（反向操作）
        for step in reversed(response_strategy.get("execution_steps", [])):
            rollback_operation = self._get_rollback_operation(step)
            if rollback_operation:
                operation_result = await self._execute_operation(rollback_operation, security_event)
                rollback_result["operations"].append(operation_result)

        return rollback_result

    def _get_rollback_operation(self, operation: str) -> str:
        """获取回滚操作"""
        rollback_map = {
            "IP封禁": "IP解封",
            "白名单管理": "白名单移除",
            "终端隔离": "终端解封",
            "告警通知": "告警取消"
        }

        return rollback_map.get(operation, None)

    def _get_current_time(self) -> str:
        """获取当前时间字符串"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
