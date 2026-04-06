import streamlit as st
import json
# Importa o motor que você já criou no outro arquivo
from expert_system_single_file import ExpertSystemEngine

# Configuração da página do Streamlit
st.set_page_config(page_title="Sistema Especialista NOC", layout="wide")

st.title("🛡️ NOC Expert - Triagem de Infraestrutura")
st.markdown("Interface interativa para o Sistema Especialista de diagnóstico de redes e servidores.")

# Inicializa o motor
@st.cache_resource # Evita recarregar a Base de Conhecimento toda hora
def load_engine():
    return ExpertSystemEngine()

engine = load_engine()

# --- SEÇÃO DE ENTRADA (SELEÇÃO DE ALERTAS) ---
st.header("1. Seleção de Alertas e Contexto")

# Usamos colunas para organizar a tela
col1, col2 = st.columns(2)

with col1:
    st.subheader("Alertas Ativos")
    # Lista de alertas comuns para o usuário selecionar
    alert_opcoes = [
        "SWITCH_STATUS_DOWN", 
        "API_TIMEOUT", 
        "API_SLOW",
        "DB_CONNECTION_ERROR", 
        "DISK_WRITE_ERROR",
        "PING_LATENCY_HIGH"
    ]
    alertas_selecionados = st.multiselect("Selecione os alertas ocorrendo agora:", alert_opcoes)
    
    # Adicionando um servidor alvo genérico para os alertas selecionados
    servidor_alvo = st.text_input("Servidor afetado (opcional):", value="app-01")

with col2:
    st.subheader("Contexto do Ambiente")
    # Controles para o contexto da rede
    switch_status = st.selectbox("Status do Switch Core:", ["up", "down", "unknown"])
    ping_global = st.selectbox("Status do Ping Global:", ["ok", "high_latency", "down", "unknown"])
    network_state = st.selectbox("Estado da Rede:", ["ok", "degraded", "unknown"])
    
st.divider()

# --- AÇÃO (PROCESSAMENTO) ---
if st.button("🚀 Processar Alertas", type="primary", use_container_width=True):
    
    if not alertas_selecionados and switch_status == "up":
        st.warning("Selecione pelo menos um alerta ou altere o status do switch para analisar.")
    else:
        with st.spinner('Motor de Inferência analisando as regras...'):
            # 1. Montar o payload no formato que o seu motor espera
            payload_alerts = [{"name": alert, "server": servidor_alvo, "window": "w_atual", "scope": "local"} for alert in alertas_selecionados]
            
            payload = {
                "alerts": payload_alerts,
                "metrics": [],
                "context": {
                    "switch_core_status": switch_status,
                    "network_state": network_state,
                    "ping_statuses": [{"scope": "global", "status": ping_global, "window": "w_atual"}],
                }
            }

            # 2. Executar o motor
            resultado = engine.run(payload)

            # --- SEÇÃO DE SAÍDA (RESULTADOS) ---
            st.header("2. Diagnóstico e Recomendações")
            
            # Definir cor baseado na prioridade
            cor_prioridade = {
                "alta": "red",
                "media": "orange",
                "baixa": "green"
            }.get(resultado["prioridade"].lower(), "gray")

            # Exibir métricas principais
            r1, r2, r3 = st.columns(3)
            r1.metric("Prioridade", resultado["prioridade"].upper())
            r2.metric("Equipe Acionada", resultado["equipe_acionada"].upper())
            r3.metric("Regras Disparadas", resultado["estatisticas"]["regras_disparadas"])

            # Exibir o Diagnóstico Principal
            st.error(f"**Diagnóstico Final:** {resultado['diagnostico']}")
            st.info(f"**Ação Recomendada:** {resultado['acao']}")

            st.divider()
            
            # --- SEÇÃO DE EXPLICAÇÃO ---
            st.header("3. Subsistema de Explicação")
            st.write(f"**Justificativa do Motor:** {resultado['justificativa']}")
            
            with st.expander("Ver rastro do motor de inferência (Regras Ativadas)"):
                if resultado['regras_acionadas']:
                    for r in resultado['regras_acionadas']:
                        st.markdown(f"- **{r['regra']}**: {r['detalhe']}")
                else:
                    st.write("Nenhuma regra de negócio específica foi disparada.")
                    
            with st.expander("Ver Alertas Suprimidos"):
                if resultado['alertas_suprimidos']:
                    st.table(resultado['alertas_suprimidos'])
                else:
                    st.write("Nenhum alerta foi suprimido pelo motor.")