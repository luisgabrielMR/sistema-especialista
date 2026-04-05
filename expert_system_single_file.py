from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import clips


# ============================================================
# Base de conhecimento CLIPS embutida no próprio arquivo.
# O conhecimento continua separado conceitualmente da execução,
# mesmo estando fisicamente dentro deste arquivo.
# ============================================================
KB_RULES = r'''
(deftemplate alert
  (slot name (type STRING))
  (slot server (type STRING) (default "global"))
  (slot window (type STRING) (default "default"))
  (slot severity (type STRING) (default "unknown"))
  (slot scope (type STRING) (default "local")))

(deftemplate metric
  (slot name (type STRING))
  (slot server (type STRING) (default "global"))
  (slot value (type NUMBER) (default 0))
  (slot window (type STRING) (default "default"))
  (slot scope (type STRING) (default "local")))

(deftemplate switch-core
  (slot status (type STRING) (default "unknown")))

(deftemplate network-state
  (slot status (type STRING) (default "unknown")))

(deftemplate ping-status
  (slot scope (type STRING) (default "global"))
  (slot status (type STRING) (default "unknown"))
  (slot window (type STRING) (default "default"))
  (slot block (type STRING) (default "")))

(deftemplate db-status
  (slot status (type STRING) (default "unknown")))

(deftemplate api-status
  (slot status (type STRING) (default "unknown")))

(deftemplate incident-scope
  (slot scope (type STRING) (default "unknown")))

(deftemplate observation
  (slot key (type STRING))
  (slot value (type STRING))
  (slot window (type STRING) (default "default"))
  (slot target (type STRING) (default "")))

(deftemplate decision
  (slot code (type STRING))
  (slot diagnostico (type STRING))
  (slot prioridade (type STRING))
  (slot equipe (type STRING))
  (slot acao (type STRING))
  (slot status_final (type STRING))
  (slot justificativa (type STRING)))

(deftemplate rule-trace
  (slot name (type STRING))
  (slot detail (type STRING)))

(deftemplate suppressed-alert
  (slot name (type STRING))
  (slot server (type STRING))
  (slot reason (type STRING)))

(deftemplate relevant-fact
  (slot fact (type STRING)))

(defrule rule-switch-core-down
  (declare (salience 1000))
  (switch-core (status "down"))
  (not (decision))
  =>
  (assert (decision
    (code "switch_core_down")
    (diagnostico "Causa raiz física no rack central")
    (prioridade "alta")
    (equipe "infraestrutura fisica")
    (acao "Inspecionar imediatamente o rack central e restaurar o switch core")
    (status_final "resolvido_por_regra")
    (justificativa "O switch core está indisponível; por dominância de causa raiz física, os demais alertas passam a ser sintomas secundários.")))
  (assert (rule-trace (name "rule-switch-core-down") (detail "SWITCH_STATUS_DOWN ou switch_core_status=down identifica falha física dominante no rack central.")))
  (assert (relevant-fact (fact "switch_core_status=down"))))

(defrule suppress-by-switch-core
  (declare (salience 995))
  (decision (code "switch_core_down"))
  ?a <- (alert (name ?name) (server ?server))
  (test (neq ?name "SWITCH_STATUS_DOWN"))
  (not (suppressed-alert (name ?name) (server ?server)))
  =>
  (assert (suppressed-alert (name ?name) (server ?server) (reason "Falha dominante do switch core")))
  (assert (rule-trace (name "suppress-by-switch-core") (detail (str-cat "Alerta " ?name " em " ?server " foi suprimido porque o switch core caiu.")))))

(defrule rule-db-service-down
  (declare (salience 950))
  (switch-core (status "up"))
  (ping-status (scope "global") (status "ok") (window ?w))
  (observation (key "all_app_servers_db_errors") (value "true") (window ?w))
  (alert (name "DB_CONNECTION_ERROR") (window ?w))
  (not (decision))
  =>
  (assert (decision
    (code "db_service_down")
    (diagnostico "Falha critica no servico de banco de dados")
    (prioridade "alta")
    (equipe "dba")
    (acao "Acionar imediatamente a equipe de DBAs para restaurar o banco de dados")
    (status_final "resolvido_por_regra")
    (justificativa "A rede está operacional, mas todos os servidores de aplicação passaram a falhar no banco na mesma janela; isso caracteriza queda do serviço de banco como causa raiz dominante.")))
  (assert (rule-trace (name "rule-db-service-down") (detail "Rede global OK + erro de banco em todos os app servers na mesma janela indica indisponibilidade do banco.")))
  (assert (relevant-fact (fact (str-cat "ping_global=ok@" ?w))))
  (assert (relevant-fact (fact (str-cat "all_app_servers_db_errors=true@" ?w))))
  (assert (relevant-fact (fact (str-cat "DB_CONNECTION_ERROR@" ?w)))))

(defrule suppress-api-by-db-root-cause
  (declare (salience 945))
  (decision (code "db_service_down"))
  ?a <- (alert (name ?name) (server ?server))
  (test (or (eq ?name "API_TIMEOUT") (eq ?name "API_SLOW")))
  (not (suppressed-alert (name ?name) (server ?server)))
  =>
  (assert (suppressed-alert (name ?name) (server ?server) (reason "Queda do banco domina os sintomas de API")))
  (assert (rule-trace (name "suppress-api-by-db-root-cause") (detail (str-cat "Alerta " ?name " em " ?server " foi suprimido porque a queda do banco explica o sintoma na API.")))))

(defrule rule-general-network-bottleneck-high
  (declare (salience 900))
  (switch-core (status "up"))
  (network-state (status "degraded"))
  (ping-status (scope "global") (status "high_latency") (window ?w))
  (observation (key "multiple_servers_affected") (value "true") (window ?w))
  (observation (key "network_priority_hint") (value "high") (window ?w))
  (not (decision))
  =>
  (assert (decision
    (code "general_network_bottleneck")
    (diagnostico "Lentidao ou gargalo generalizado na rede")
    (prioridade "alta")
    (equipe "redes")
    (acao "Acionar equipe de redes para investigar saturacao, perda ou congestionamento")
    (status_final "resolvido_por_regra")
    (justificativa "O switch core está ligado, porém há latência alta para múltiplos servidores na mesma janela; o tráfego está comprometido de forma global.")))
  (assert (rule-trace (name "rule-general-network-bottleneck-high") (detail "Latência alta global com múltiplos servidores afetados e impacto alto indica gargalo de rede.")))
  (assert (relevant-fact (fact (str-cat "network_state=degraded@" ?w))))
  (assert (relevant-fact (fact (str-cat "ping_global=high_latency@" ?w))))
  (assert (relevant-fact (fact (str-cat "multiple_servers_affected=true@" ?w)))))

(defrule rule-general-network-bottleneck-medium
  (declare (salience 890))
  (switch-core (status "up"))
  (network-state (status "degraded"))
  (ping-status (scope "global") (status "high_latency") (window ?w))
  (observation (key "multiple_servers_affected") (value "true") (window ?w))
  (not (observation (key "network_priority_hint") (value "high") (window ?w)))
  (not (decision))
  =>
  (assert (decision
    (code "general_network_bottleneck")
    (diagnostico "Lentidao ou gargalo generalizado na rede")
    (prioridade "media")
    (equipe "redes")
    (acao "Acionar equipe de redes para investigar saturacao, perda ou congestionamento")
    (status_final "resolvido_por_regra")
    (justificativa "O switch core está operacional, mas a conectividade está degradada para múltiplos servidores; o problema é consistente com gargalo de rede, sem evidência de queda total do core.")))
  (assert (rule-trace (name "rule-general-network-bottleneck-medium") (detail "Latência alta global com múltiplos servidores afetados indica gargalo de rede com severidade intermediária.")))
  (assert (relevant-fact (fact (str-cat "network_state=degraded@" ?w))))
  (assert (relevant-fact (fact (str-cat "ping_global=high_latency@" ?w)))))

(defrule rule-block-rack-outage
  (declare (salience 850))
  (switch-core (status "up"))
  (ping-status (scope "block") (status "down") (window ?w) (block ?b))
  (observation (key "block_scope_down") (value "true") (window ?w) (target ?b))
  (not (decision))
  =>
  (assert (decision
    (code "block_rack_outage")
    (diagnostico "Falha de alimentacao eletrica ou queda de switch secundario do rack")
    (prioridade "alta")
    (equipe "infraestrutura eletrica")
    (acao "Checar alimentacao do rack e o switch Top-of-Rack do bloco afetado")
    (status_final "resolvido_por_regra")
    (justificativa "O switch core permanece funcional, mas um bloco inteiro deixou de responder ao ping no mesmo instante; isso aponta para falha setorial no rack ou na alimentacao.")))
  (assert (rule-trace (name "rule-block-rack-outage") (detail (str-cat "Bloco " ?b " caiu integralmente com switch core OK, indicando falha setorial de rack/TOR."))))
  (assert (relevant-fact (fact (str-cat "switch_core_status=up@" ?w))))
  (assert (relevant-fact (fact (str-cat "block_ping_down=" ?b "@" ?w)))))

(defrule rule-api-and-db-same-window
  (declare (salience 800))
  (alert (name "API_TIMEOUT") (server ?api-server) (window ?w))
  (alert (name "DB_CONNECTION_ERROR") (server ?db-client) (window ?w))
  (not (decision))
  =>
  (assert (decision
    (code "api_db_link_issue")
    (diagnostico "Falha na rede interna/VLAN ou no enlace entre aplicacao e banco")
    (prioridade "media")
    (equipe "infraestrutura de servidores")
    (acao "Investigar conectividade interna entre camada de aplicacao e banco de dados")
    (status_final "resolvido_por_regra")
    (justificativa "API_TIMEOUT e DB_CONNECTION_ERROR ocorreram na mesma janela, sem evidência de uma causa raiz mais ampla; a correlação sugere falha na comunicação interna entre aplicação e banco.")))
  (assert (rule-trace (name "rule-api-and-db-same-window") (detail (str-cat "API_TIMEOUT em " ?api-server " e DB_CONNECTION_ERROR em " ?db-client " ocorreram na janela " ?w "."))))
  (assert (relevant-fact (fact (str-cat "API_TIMEOUT@" ?w))))
  (assert (relevant-fact (fact (str-cat "DB_CONNECTION_ERROR@" ?w)))))

(defrule rule-local-overload-or-temperature
  (declare (salience 750))
  (or
    (alert (name "API_TIMEOUT") (server ?srv) (window ?w))
    (alert (name "API_SLOW") (server ?srv) (window ?w)))
  (or
    (metric (name "cpu_usage") (server ?srv) (window ?w) (value ?cpu&:(> ?cpu 95)))
    (metric (name "temperature_c") (server ?srv) (window ?w) (value ?temp&:(> ?temp 80))))
  (not (decision))
  =>
  (assert (decision
    (code "local_overload_or_cooling")
    (diagnostico "Sobrecarga de processamento ou falha de refrigeracao local")
    (prioridade "media")
    (equipe "infraestrutura_nuvem")
    (acao "Verificar recursos computacionais, cooling e limite de capacidade do servidor afetado")
    (status_final "resolvido_por_regra")
    (justificativa "A lentidão está localizada e coincide com uso extremo de CPU ou temperatura elevada no mesmo servidor, caracterizando sobrecarga local ou problema térmico.")))
  (assert (rule-trace (name "rule-local-overload-or-temperature") (detail (str-cat "Servidor " ?srv " apresentou lentidão/API timeout e sinal térmico ou de CPU acima do limite na janela " ?w "."))))
  (assert (relevant-fact (fact (str-cat "server=" ?srv "@" ?w)))))

(defrule rule-isolated-api-timeout
  (declare (salience 700))
  (switch-core (status "up"))
  (ping-status (scope "global") (status "ok") (window ?w))
  (incident-scope (scope "local"))
  (alert (name "API_TIMEOUT") (server ?srv) (window ?w))
  (not (alert (name "DB_CONNECTION_ERROR") (window ?w)))
  (not (alert (name "API_TIMEOUT") (server ?other&~?srv) (window ?w)))
  (not (decision))
  =>
  (assert (decision
    (code "isolated_api_timeout")
    (diagnostico "Problema na camada de aplicacao")
    (prioridade "media")
    (equipe "desenvolvimento_sustentacao")
    (acao "Acionar a equipe de desenvolvimento/sustentacao para investigar software e codigo")
    (status_final "resolvido_por_regra")
    (justificativa "O timeout é isolado, o switch core está operacional e a conectividade global está normal; portanto, a evidência aponta para falha na aplicação e não na rede.")))
  (assert (rule-trace (name "rule-isolated-api-timeout") (detail (str-cat "API_TIMEOUT isolado em " ?srv " com switch e ping globais OK."))))
  (assert (relevant-fact (fact (str-cat "ping_global=ok@" ?w))))
  (assert (relevant-fact (fact (str-cat "incident_scope=local@" ?w)))))

(defrule rule-disk-write-error
  (declare (salience 650))
  (alert (name "DISK_WRITE_ERROR") (server ?srv) (window ?w))
  (not (decision))
  =>
  (assert (decision
    (code "disk_write_error")
    (diagnostico "Problema de hardware local: disco cheio ou falhando")
    (prioridade "baixa")
    (equipe "hardware")
    (acao "Acionar equipe de hardware para verificar o disco do servidor afetado")
    (status_final "resolvido_por_regra")
    (justificativa "Existe erro de escrita em disco em um servidor específico; o problema é local e coerente com falha de hardware ou esgotamento de armazenamento.")))
  (assert (rule-trace (name "rule-disk-write-error") (detail (str-cat "Erro de escrita em disco detectado em " ?srv " na janela " ?w "."))))
  (assert (relevant-fact (fact (str-cat "DISK_WRITE_ERROR@" ?srv "@" ?w)))))

(defrule rule-false-positive
  (declare (salience 100))
  (not (decision))
  (not (alert))
  (not (observation (key "manual_review_requested") (value "true")))
  =>
  (assert (decision
    (code "false_positive")
    (diagnostico "Nenhum alerta conhecido identificado")
    (prioridade "baixa")
    (equipe "nenhuma")
    (acao "Registrar como falso positivo e manter monitoramento")
    (status_final "falso_positivo")
    (justificativa "Nenhum alerta relevante foi recebido pelo motor de inferência; a melhor classificação é falso positivo ou ruído operacional.")))
  (assert (rule-trace (name "rule-false-positive") (detail "O motor não recebeu alertas relevantes e encerrou como falso positivo."))))

(defrule rule-analysis-manual
  (declare (salience 50))
  (not (decision))
  (observation (key "manual_review_requested") (value "true") (window ?w))
  =>
  (assert (decision
    (code "manual_analysis")
    (diagnostico "Nenhum alerta conhecido identificado")
    (prioridade "media")
    (equipe "analista_n1")
    (acao "Encaminhar para analise manual")
    (status_final "analise_manual")
    (justificativa "Não houve casamento completo com cenários conhecidos, e o contexto pediu revisão humana manual.")))
  (assert (rule-trace (name "rule-analysis-manual") (detail (str-cat "A observacao manual_review_requested=true na janela " ?w " forçou encaminhamento manual.")))))

(defrule rule-unmapped-scenario
  (declare (salience 10))
  (not (decision))
  (exists (alert))
  =>
  (assert (decision
    (code "unmapped_scenario")
    (diagnostico "Cenario nao mapeado")
    (prioridade "media")
    (equipe "analise_humana_n3")
    (acao "Encaminhar logs para analise humana de nivel 3")
    (status_final "cenario_nao_mapeado")
    (justificativa "Há sinais operacionais, mas nenhuma regra de domínio mapeou o cenário de forma suficiente; o caso deve seguir para análise humana especializada.")))
  (assert (rule-trace (name "rule-unmapped-scenario") (detail "Existem alertas, porém nenhum padrão conhecido venceu as regras de decisão."))))
'''


# ============================================================
# Cenários embutidos para teste/demonstração.
# ============================================================
EXAMPLE_SCENARIOS: Dict[str, Dict[str, Any]] = {
    "01_switch_core_down": {
        "alerts": [
            {"name": "SWITCH_STATUS_DOWN", "server": "switch-core-1", "window": "w1", "severity": "critical", "scope": "global"},
            {"name": "API_TIMEOUT", "server": "app-01", "window": "w1", "severity": "high", "scope": "local"},
            {"name": "DB_CONNECTION_ERROR", "server": "app-02", "window": "w1", "severity": "high", "scope": "local"},
        ],
        "metrics": [],
        "context": {
            "switch_core_status": "down",
            "network_state": "degraded",
            "incident_scope": "global",
        },
    },
    "02_general_network_bottleneck": {
        "alerts": [
            {"name": "PING_LATENCY_HIGH", "server": "monitor-global", "window": "w2", "severity": "high", "scope": "global"}
        ],
        "metrics": [],
        "context": {
            "switch_core_status": "up",
            "network_state": "degraded",
            "incident_scope": "global",
            "ping_statuses": [{"scope": "global", "status": "high_latency", "window": "w2"}],
            "observations": [
                {"key": "multiple_servers_affected", "value": True, "window": "w2"},
                {"key": "network_priority_hint", "value": "high", "window": "w2"},
            ],
        },
    },
    "03_api_timeout_and_db_error_same_window": {
        "alerts": [
            {"name": "API_TIMEOUT", "server": "app-01", "window": "w3", "severity": "high", "scope": "local"},
            {"name": "DB_CONNECTION_ERROR", "server": "db-client-app-01", "window": "w3", "severity": "high", "scope": "local"},
        ],
        "metrics": [],
        "context": {
            "switch_core_status": "up",
            "network_state": "ok",
            "incident_scope": "local",
            "ping_statuses": [{"scope": "global", "status": "ok", "window": "w3"}],
        },
    },
    "04_isolated_api_timeout": {
        "alerts": [
            {"name": "API_TIMEOUT", "server": "app-02", "window": "w4", "severity": "medium", "scope": "local"}
        ],
        "metrics": [],
        "context": {
            "switch_core_status": "up",
            "network_state": "ok",
            "incident_scope": "local",
            "ping_statuses": [{"scope": "global", "status": "ok", "window": "w4"}],
        },
    },
    "05_disk_write_error": {
        "alerts": [
            {"name": "DISK_WRITE_ERROR", "server": "storage-01", "window": "w5", "severity": "medium", "scope": "local"}
        ],
        "metrics": [],
        "context": {
            "switch_core_status": "up",
            "network_state": "ok",
            "incident_scope": "local",
        },
    },
    "06_database_service_down": {
        "alerts": [
            {"name": "DB_CONNECTION_ERROR", "server": "app-01", "window": "w6", "severity": "critical", "scope": "global"},
            {"name": "DB_CONNECTION_ERROR", "server": "app-02", "window": "w6", "severity": "critical", "scope": "global"},
            {"name": "API_TIMEOUT", "server": "app-01", "window": "w6", "severity": "high", "scope": "local"},
        ],
        "metrics": [],
        "context": {
            "switch_core_status": "up",
            "network_state": "ok",
            "db_status": "down",
            "incident_scope": "global",
            "ping_statuses": [{"scope": "global", "status": "ok", "window": "w6"}],
            "observations": [{"key": "all_app_servers_db_errors", "value": True, "window": "w6"}],
        },
    },
    "07_local_overload_cpu": {
        "alerts": [
            {"name": "API_TIMEOUT", "server": "app-03", "window": "w7", "severity": "medium", "scope": "local"}
        ],
        "metrics": [
            {"name": "cpu_usage", "server": "app-03", "value": 98, "window": "w7", "scope": "local"}
        ],
        "context": {
            "switch_core_status": "up",
            "network_state": "ok",
            "incident_scope": "local",
            "ping_statuses": [{"scope": "global", "status": "ok", "window": "w7"}],
        },
    },
    "08_block_rack_outage": {
        "alerts": [
            {"name": "PING_DOWN", "server": "rack-b", "window": "w8", "severity": "critical", "scope": "sector"}
        ],
        "metrics": [],
        "context": {
            "switch_core_status": "up",
            "network_state": "ok",
            "incident_scope": "sector",
            "ping_statuses": [{"scope": "block", "status": "down", "window": "w8", "block": "rack-b"}],
            "observations": [{"key": "block_scope_down", "value": True, "window": "w8", "target": "rack-b"}],
        },
    },
    "09_unmapped_scenario": {
        "alerts": [
            {"name": "MEMORY_LEAK_WARNING", "server": "app-09", "window": "w9", "severity": "medium", "scope": "local"}
        ],
        "metrics": [],
        "context": {
            "switch_core_status": "up",
            "network_state": "ok",
            "incident_scope": "local",
        },
    },
    "10_false_positive": {
        "alerts": [],
        "metrics": [],
        "context": {
            "switch_core_status": "up",
            "network_state": "ok",
            "incident_scope": "unknown",
        },
    },
    "11_manual_review": {
        "alerts": [],
        "metrics": [],
        "context": {
            "switch_core_status": "up",
            "network_state": "unknown",
            "incident_scope": "unknown",
            "observations": [{"key": "manual_review_requested", "value": True, "window": "w11"}],
        },
    },
}

EXPECTED_RESULTS: Dict[str, Dict[str, str]] = {
    "01_switch_core_down": {"codigo_decisao": "switch_core_down", "status_final": "resolvido_por_regra", "prioridade": "alta"},
    "02_general_network_bottleneck": {"codigo_decisao": "general_network_bottleneck", "status_final": "resolvido_por_regra", "prioridade": "alta"},
    "03_api_timeout_and_db_error_same_window": {"codigo_decisao": "api_db_link_issue", "status_final": "resolvido_por_regra", "prioridade": "media"},
    "04_isolated_api_timeout": {"codigo_decisao": "isolated_api_timeout", "status_final": "resolvido_por_regra", "prioridade": "media"},
    "05_disk_write_error": {"codigo_decisao": "disk_write_error", "status_final": "resolvido_por_regra", "prioridade": "baixa"},
    "06_database_service_down": {"codigo_decisao": "db_service_down", "status_final": "resolvido_por_regra", "prioridade": "alta"},
    "07_local_overload_cpu": {"codigo_decisao": "local_overload_or_cooling", "status_final": "resolvido_por_regra", "prioridade": "media"},
    "08_block_rack_outage": {"codigo_decisao": "block_rack_outage", "status_final": "resolvido_por_regra", "prioridade": "alta"},
    "09_unmapped_scenario": {"codigo_decisao": "unmapped_scenario", "status_final": "cenario_nao_mapeado", "prioridade": "media"},
    "10_false_positive": {"codigo_decisao": "false_positive", "status_final": "falso_positivo", "prioridade": "baixa"},
    "11_manual_review": {"codigo_decisao": "manual_analysis", "status_final": "analise_manual", "prioridade": "media"},
}


class ExpertSystemEngine:
    """Integra JSON -> fatos -> motor CLIPS -> saída estruturada."""

    def run_from_file(self, json_path: str | Path) -> Dict[str, Any]:
        with Path(json_path).open("r", encoding="utf-8") as file:
            payload = json.load(file)
        return self.run(payload)

    def run(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        env = clips.Environment()
        self._load_embedded_knowledge_base(env)
        env.reset()

        self._assert_payload(env, payload)
        rules_fired_count = env.run()

        return self._collect_result(env, payload, rules_fired_count)

    def _load_embedded_knowledge_base(self, env: clips.Environment) -> None:
        # Mantém o projeto em um único arquivo distribuível.
        # Em tempo de execução, gravamos a KB em um arquivo temporário e o CLIPS a carrega normalmente.
        with tempfile.TemporaryDirectory(prefix="clips_kb_") as temp_dir:
            kb_path = Path(temp_dir) / "triage_rules.clp"
            kb_path.write_text(KB_RULES, encoding="utf-8")
            env.load(str(kb_path))

    def _assert_payload(self, env: clips.Environment, payload: Dict[str, Any]) -> None:
        alerts = payload.get("alerts", []) or []
        metrics = payload.get("metrics", []) or []
        context = payload.get("context", {}) or {}

        self._assert_alerts(env, alerts)
        self._assert_metrics(env, metrics)
        self._assert_context(env, context, alerts)

    def _assert_alerts(self, env: clips.Environment, alerts: Iterable[Dict[str, Any]]) -> None:
        template = env.find_template("alert")

        for alert in alerts:
            template.assert_fact(
                name=self._normalize_alert_name(alert.get("name", "")),
                server=self._normalize_text(alert.get("server", "global")),
                window=self._normalize_text(alert.get("window", "default")),
                severity=self._normalize_token(alert.get("severity", "unknown")),
                scope=self._normalize_token(alert.get("scope", "local")),
            )

    def _assert_metrics(self, env: clips.Environment, metrics: Iterable[Dict[str, Any]]) -> None:
        template = env.find_template("metric")

        for metric in metrics:
            try:
                numeric_value = float(metric.get("value", 0))
            except (TypeError, ValueError):
                numeric_value = 0.0

            template.assert_fact(
                name=self._normalize_metric_name(metric.get("name", "")),
                server=self._normalize_text(metric.get("server", "global")),
                value=numeric_value,
                window=self._normalize_text(metric.get("window", "default")),
                scope=self._normalize_token(metric.get("scope", "local")),
            )

    def _assert_context(
        self,
        env: clips.Environment,
        context: Dict[str, Any],
        alerts: Iterable[Dict[str, Any]],
    ) -> None:
        switch_template = env.find_template("switch-core")
        network_template = env.find_template("network-state")
        ping_template = env.find_template("ping-status")
        db_template = env.find_template("db-status")
        api_template = env.find_template("api-status")
        incident_scope_template = env.find_template("incident-scope")
        observation_template = env.find_template("observation")

        switch_status = context.get("switch_core_status")
        if not switch_status:
            switch_status = self._infer_switch_status_from_alerts(alerts)
        switch_template.assert_fact(status=self._normalize_token(switch_status or "unknown"))

        network_template.assert_fact(status=self._normalize_token(context.get("network_state", "unknown")))
        db_template.assert_fact(status=self._normalize_token(context.get("db_status", "unknown")))
        api_template.assert_fact(status=self._normalize_token(context.get("api_status", "unknown")))
        incident_scope_template.assert_fact(scope=self._normalize_token(context.get("incident_scope", "unknown")))

        ping_statuses = context.get("ping_statuses") or context.get("ping_status") or []
        if isinstance(ping_statuses, dict):
            ping_statuses = [ping_statuses]

        for ping in ping_statuses:
            ping_template.assert_fact(
                scope=self._normalize_token(ping.get("scope", "global")),
                status=self._normalize_token(ping.get("status", "unknown")),
                window=self._normalize_text(ping.get("window", "default")),
                block=self._normalize_text(ping.get("block", "")),
            )

        observations = list(context.get("observations") or [])
        for key, value in context.items():
            if key in {
                "switch_core_status",
                "network_state",
                "db_status",
                "api_status",
                "incident_scope",
                "ping_statuses",
                "ping_status",
                "observations",
            }:
                continue
            if isinstance(value, (str, int, float, bool)):
                observations.append({"key": key, "value": value})

        for observation in observations:
            observation_template.assert_fact(
                key=self._normalize_token(observation.get("key", "")),
                value=self._normalize_token(observation.get("value", "")),
                window=self._normalize_text(observation.get("window", "default")),
                target=self._normalize_text(observation.get("target", "")),
            )

    @staticmethod
    def _normalize_alert_name(value: Any) -> str:
        return "UNKNOWN" if value is None else str(value).strip().upper()

    @staticmethod
    def _normalize_metric_name(value: Any) -> str:
        return "unknown" if value is None else str(value).strip().lower()

    @staticmethod
    def _normalize_token(value: Any) -> str:
        return "unknown" if value is None else str(value).strip().lower()

    @staticmethod
    def _normalize_text(value: Any) -> str:
        return "" if value is None else str(value).strip().lower()

    @staticmethod
    def _infer_switch_status_from_alerts(alerts: Iterable[Dict[str, Any]]) -> Optional[str]:
        for alert in alerts:
            if str(alert.get("name", "")).strip().upper() == "SWITCH_STATUS_DOWN":
                return "down"
        return None

    def _collect_result(self, env: clips.Environment, payload: Dict[str, Any], rules_fired_count: int) -> Dict[str, Any]:
        decision_fact: Optional[Dict[str, Any]] = None
        traces: List[Dict[str, str]] = []
        suppressed_alerts: List[Dict[str, str]] = []
        relevant_facts: List[str] = []

        for fact in env.facts():
            template_name = fact.template.name
            data = dict(fact)
            if template_name == "decision":
                decision_fact = data
            elif template_name == "rule-trace":
                traces.append({"regra": data["name"], "detalhe": data["detail"]})
            elif template_name == "suppressed-alert":
                suppressed_alerts.append(
                    {"alerta": data["name"], "servidor": data["server"], "motivo": data["reason"]}
                )
            elif template_name == "relevant-fact":
                relevant_facts.append(data["fact"])

        if decision_fact is None:
            raise RuntimeError("O motor executou sem produzir uma decisão final.")

        justificativa = decision_fact["justificativa"]
        if traces:
            justificativa = (
                f"{justificativa} Regras acionadas: "
                + "; ".join(item["regra"] for item in traces)
                + "."
            )

        return {
            "diagnostico": decision_fact["diagnostico"],
            "prioridade": decision_fact["prioridade"],
            "equipe_acionada": decision_fact["equipe"],
            "acao": decision_fact["acao"],
            "alertas_suprimidos": suppressed_alerts,
            "justificativa": justificativa,
            "regras_acionadas": traces,
            "fatos_relevantes": relevant_facts,
            "status_final": decision_fact["status_final"],
            "codigo_decisao": decision_fact["code"],
            "estatisticas": {
                "regras_disparadas": rules_fired_count,
                "quantidade_alertas_entrada": len(payload.get("alerts", []) or []),
                "quantidade_metricas_entrada": len(payload.get("metrics", []) or []),
            },
        }


def list_demos() -> None:
    print("Cenários embutidos disponíveis:")
    for scenario_name in EXAMPLE_SCENARIOS:
        print(f"- {scenario_name}")


def run_demo(name: str, indent: int) -> int:
    if name not in EXAMPLE_SCENARIOS:
        print(f"Cenário '{name}' não encontrado.", file=sys.stderr)
        print("Use --list-demos para ver os nomes válidos.", file=sys.stderr)
        return 1

    engine = ExpertSystemEngine()
    result = engine.run(EXAMPLE_SCENARIOS[name])
    print(json.dumps(result, ensure_ascii=False, indent=indent))
    return 0


def run_all_demos(indent: int) -> int:
    engine = ExpertSystemEngine()
    failures: List[Dict[str, Any]] = []

    for scenario_name, payload in EXAMPLE_SCENARIOS.items():
        result = engine.run(payload)
        expected = EXPECTED_RESULTS[scenario_name]
        mismatches = {
            field: {"expected": expected_value, "actual": result.get(field)}
            for field, expected_value in expected.items()
            if result.get(field) != expected_value
        }

        if mismatches:
            failures.append({"cenario": scenario_name, "mismatches": mismatches, "resultado": result})
            print(f"[FAIL] {scenario_name}")
            print(json.dumps(mismatches, ensure_ascii=False, indent=indent))
        else:
            print(f"[OK]   {scenario_name} -> {result['codigo_decisao']}")

    if failures:
        print("\nFalhas detectadas:")
        print(json.dumps(failures, ensure_ascii=False, indent=indent))
        return 1

    print("\nTodos os cenários passaram.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Sistema especialista single-file de triagem de alertas de infraestrutura com CLIPS/clipspy."
    )
    parser.add_argument("input", nargs="?", type=Path, help="Arquivo JSON de entrada.")
    parser.add_argument("--demo", type=str, help="Executa um cenário embutido pelo nome.")
    parser.add_argument("--demo-all", action="store_true", help="Executa todos os cenários embutidos e valida os resultados.")
    parser.add_argument("--list-demos", action="store_true", help="Lista os cenários embutidos disponíveis.")
    parser.add_argument("--indent", type=int, default=2, help="Indentação do JSON de saída.")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.list_demos:
        list_demos()
        return 0

    if args.demo_all:
        return run_all_demos(args.indent)

    if args.demo:
        return run_demo(args.demo, args.indent)

    if args.input is None:
        parser.error("informe um arquivo JSON ou use --demo / --demo-all / --list-demos")

    engine = ExpertSystemEngine()
    result = engine.run_from_file(args.input)
    print(json.dumps(result, ensure_ascii=False, indent=args.indent))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
