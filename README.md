# 🧠 Sistema Especialista de Triagem de Alertas

Este projeto implementa um **Sistema Especialista baseado em regras de produção**, utilizando **CLIPS integrado ao Python via clipspy**, com o objetivo de diagnosticar automaticamente incidentes em infraestrutura de TI a partir de alertas e métricas.

---

## 🎯 Objetivo

Receber alertas de infraestrutura (logs, métricas e estados do sistema) e inferir automaticamente:

- Diagnóstico do problema
- Prioridade do incidente
- Ação recomendada
- Equipe responsável
- Supressão de alertas secundários
- Justificativa da decisão
- Trilha de regras acionadas

---

## 🧠 Conceitos de IA Utilizados

- Sistemas Especialistas
- Regras de Produção (IF-THEN)
- Encadeamento para frente (Forward Chaining)
- Motor de Inferência (CLIPS)
- Base de Conhecimento
- Explicabilidade (Explainable AI)

---

## 🏗️ Arquitetura

A solução segue a separação clássica de sistemas especialistas:

### 🔹 Python
Responsável por:
- Leitura do JSON de entrada
- Transformação em fatos
- Execução do motor de inferência
- Coleta e formatação dos resultados

### 🔹 CLIPS (via clipspy)
Responsável por:
- Definição de fatos (templates)
- Regras de inferência
- Priorização de regras (`salience`)
- Tomada de decisão

---

## 📦 Estrutura (versão single-file)
expert_system_single_file.py


Todo o sistema está contido em um único arquivo, incluindo:
- Base de conhecimento (CLIPS)
- Motor de inferência
- Interface de execução
- Cenários de teste embutidos

---

## ⚙️ Instalação

Requisitos:

- Python 3.10+ (recomendado 3.11 ou 3.12)
- clipspy

Instalar dependências:

python -m pip install clipspy
▶️ Execução
🔹 Rodar todos os cenários de teste
python expert_system_single_file.py --demo-all
🔹 Rodar um cenário específico
python expert_system_single_file.py --demo 01_switch_core_down
🔹 Listar cenários disponíveis
python expert_system_single_file.py --list-demos
🔹 Rodar com entrada própria (JSON)
python expert_system_single_file.py entrada.json
📥 Formato de Entrada (JSON)
{
  "alerts": [],
  "metrics": [],
  "context": {}
}
📤 Saída

O sistema retorna um objeto estruturado com:

{
  "diagnostico": "...",
  "prioridade": "...",
  "acao": "...",
  "equipe_acionada": "...",
  "alertas_suprimidos": [],
  "justificativa": "...",
  "regras_acionadas": [],
  "fatos_relevantes": [],
  "status_final": "..."
}
📊 Cenários Cobertos

O sistema possui 11 cenários de teste:

Falha no Switch Core
Gargalo generalizado de rede
API_TIMEOUT + DB_CONNECTION_ERROR
API_TIMEOUT isolado
Erro de escrita em disco
Queda do banco de dados
Sobrecarga local (CPU/temperatura)
Falha setorial (rack/switch secundário)
Cenário não mapeado
Falso positivo
Análise manual
🔍 Características do Sistema
✔️ Baseado em regras (não procedural)
✔️ Inferência automática via CLIPS
✔️ Suporte a priorização com salience
✔️ Supressão de alertas redundantes
✔️ Correlação temporal de eventos
✔️ Diferenciação entre falhas globais, setoriais e locais
✔️ Explicabilidade completa das decisões
📈 Exemplo de Execução
[OK] 06_database_service_down -> db_service_down
🧩 Possíveis Extensões
Interface gráfica (dashboard)
Integração com sistemas reais de monitoramento (Prometheus, Grafana)
Exportação de relatórios
Explicação detalhada por regra
Métricas de inferência (tempo, regras avaliadas)
Integração com IA híbrida (ML + regras)
📚 Aplicações Reais

Este tipo de sistema pode ser aplicado em:

NOC (Network Operations Center)
Monitoramento de Data Centers
Sistemas de observabilidade
Diagnóstico automatizado de falhas
Suporte técnico inteligente

Observação Final

Este sistema não utiliza estruturas procedurais como if/else para tomada de decisão.

Toda a lógica de diagnóstico é conduzida pelo motor de inferência baseado em regras, garantindo:

Transparência
Explicabilidade
Facilidade de expansão
