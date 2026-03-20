# 🔍 Análise de Campanha Sextortion — OSINT & Threat Intelligence

> **Projeto de estudo prático em análise de e-mail malicioso, OSINT e rastreamento de infraestrutura criminosa**  
> Analista: Nicollas Cavalcante Souza  
> Data do incidente: 04/03/2026  
> Status da infraestrutura: **Ativa em 19/03/2026**

---

## 🎯 Objetivo

Este projeto documenta uma investigação OSINT conduzida a partir de um e-mail de sextortion recebido, partindo dos headers do e-mail até o rastreamento da infraestrutura de servidores e do fluxo de lavagem de dinheiro em Bitcoin.

O objetivo não foi apenas identificar o golpe — foi entender como a infraestrutura funciona, como o dinheiro se move e até onde é possível rastrear usando apenas ferramentas públicas de OSINT e threat intelligence.

**Spoiler:** fui atrás de uma pena e achei uma galinha.

---

## 📖 O Golpe — Sextortion Scam

O e-mail recebido seguia o padrão clássico de **sextortion em massa**:

- Alega ter acesso a dados pessoais, senhas, arquivos e câmera do dispositivo
- Exige pagamento de **USD 600 em Bitcoin** em até 1 dia
- Usa linguagem de urgência e intimidação para pressionar a vítima
- **Nenhuma das informações alegadas é real** — é engenharia social pura

O primeiro passo foi não pagar. O segundo foi investigar.

---

## 🛠️ Ferramentas Utilizadas

| Ferramenta | Uso |
|---|---|
| **VirusTotal** | Reputação de IP, Passive DNS, Relations |
| **AbuseIPDB** | Histórico de abuse reports |
| **Shodan** | Portas abertas e serviços expostos no servidor |
| **URLScan.io** | Análise de comportamento HTTP do domínio |
| **Blockchain.com** | Rastreamento de transações Bitcoin |
| **WHOIS (ARIN)** | Atribuição do bloco IP |
| **WHOIS (ICANN)** | Registro e status do domínio |

---

## 🔎 Investigação

### 1. Ponto de partida — Headers do E-mail

Tudo começou analisando o cabeçalho do e-mail no Outlook (`Exibir origem da mensagem`). Os headers revelaram imediatamente que o e-mail era fraudulento:

```
Authentication-Results: spf=none (sender IP is 164.92.68.246)
smtp.mailfrom=api.brighterfuture.net
dkim=none (message not signed)
dmarc=fail action=none header.from=hotmail.com
compauth=fail reason=001

Return-Path: microllion@api.brighterfuture.net
X-Sender-IP: 164.92.68.246
X-MS-Exchange-Organization-SCL: 5
dest:J;OFR:SpamFilterAuthJ
```

O que cada campo revelou:
- **SPF none** — o domínio não autorizou o IP para envio → spoofing confirmado
- **DKIM none** — e-mail sem assinatura digital → não autenticado
- **DMARC fail** — falha total de autenticação → remetente forjado
- **Return-Path** diferente do `From:` → endereço real do atacante exposto: `microllion@api.brighterfuture.net`
- **SCL:5 / dest:J** — Microsoft classificou como suspeito e entregou na pasta Junk

O `From:` estava spoofado como o próprio endereço da vítima — técnica para aumentar o senso de urgência.

---

### 2. Investigando o IP — 164.92.68.246

**VirusTotal**

![VirusTotal](evidence/01_virustotal_ip.png)

- 1/94 vendors flagged — IP rotacionado para evasão de blacklists
- Passive DNS revelou todos os domínios associados ao IP

**AbuseIPDB**

![AbuseIPDB](evidence/02_abuseipdb.png)

- 2 reports de 2 fontes distintas
- Primeiro report: **27/02/2026** — apenas 5 dias antes do e-mail recebido
- Categorias: Web Spam, Email Spam, Spoofing, Exploited Host, Phishing, Hacking, Bad Web Bot
- IP **ainda ativo em 19/03/2026**

**Shodan**

![Shodan](evidence/03_shodan_ports.png)

| Porta | Serviço | Observação |
|---|---|---|
| 22 | SSH — OpenSSH 8.9p1 Ubuntu | Acesso remoto ativo |
| 80 | HTTP | Servidor web ativo |
| 443 | HTTPS | Erro TLS — mal configurado |
| **3306** | **MySQL 8.0.42** | **⚠️ Banco de dados exposto publicamente** |

A porta 3306 exposta é crítica — banco de dados sem firewall, indicando servidor comprometido ou operado negligentemente.

---

### 3. Investigando os Domínios

**`brighterfuture.net`** — domínio do servidor SMTP

![URLScan](evidence/04_urlscan_brighterfuture.png)

- Registrado: 08/09/2022 via GoDaddy
- Status: `clientDeleteProhibited`, `clientTransferProhibited`
- URLScan retornou **HTTP 502** — servidor abandonado
- Expira: 08/09/2026

**`licftluimc.quest`** — domínio no certificado TLS

- Nome gerado por algoritmo — padrão **DGA (Domain Generation Algorithm)**
- Certificado Let's Encrypt **expirado em 04/05/2023**
- Infraestrutura descartável — criada, usada e abandonada

---

### 4. Rastreamento Bitcoin

O endereço no e-mail era apenas a entrada de uma cadeia de lavagem em múltiplas camadas.

**Carteira coletora — `14id3vCsWLocRamkLqfb3J9jhpxTHPz59m`**

![Blockchain coletora](evidence/05_blockchain_coletora.png)

- Total recebido: **0.02139044 BTC ≈ R$ 7.500**
- 2 transações — vítimas confirmadas que pagaram
- Esvaziada em **16/06/2024**

---

### 5. Fluxo de Lavagem — Peel Chain

![Mixing 20 inputs](evidence/10_blockchain_mixing_flow.png)

A saída da carteira coletora consolidou **20 carteiras diferentes** em uma única transação — padrão clássico de mixing para dificultar rastreamento.

![Blockchain consolidadora](evidence/06_blockchain_consolidadora.png)
![SegWit](evidence/07_blockchain_segwit.png)

Após a consolidação, o dinheiro passou por múltiplas camadas usando a técnica de **peel chain** — o atacante divide o valor em pequenas transações e frequentemente envia para si mesmo para poluir o log e dificultar análise.

```
[Vítimas pagam]
14id3vCsWLocRamkLqfb3J9jhpxTHPz59m
R$ 7.500 — 2 transações
        |
        | 16/06/2024 — Consolidação com 19 outras carteiras
        ↓
1Gi5sqSA6NKfkaPdMu4szv1bzt3XxCyryU
R$ 84.000 consolidados (20 inputs)
        |
        | 30/06/2024 — Split em múltiplas saídas
        ↓
bc1qywz7lnh2w78...  →  bc1q3axh7dtnsq3... (peel chain — fragmenta e polui log)
1CWTFeMfPCG1Q6u...  →  bc1qqaae3hvu4l4... → 36yHeaDuLXoTnez...
        |
        | 21/08/2024 — 80 inputs consolidados → R$ 560.000
        ↓
bc1q9wvygkq7h9xgcp59mc6ghzczrqlgrj9k3ey9tz
        |
        | Migração para SegWit (Bech32 P2WPKH)
        ↓
[Exchange ou Mixer centralizado]
bc1q7cyrfmck2ffu2ud3rn5l5a8yv6f0chkp0zpemf
        |
        ↓
[Rastro público encerrado]
```

---

### 6. A Exchange — bc1q-pemf

![Exchange summary](evidence/08_blockchain_pemf_summary.png)
![Exchange saída](evidence/09_blockchain_pemf_saida.png)

A carteira `bc1q7cyrfmck2ffu...` (bc1q-pemf) é onde o rastreamento público se encerra:

- **2.839.427 transações**
- **Volume total movimentado: $2 BILHÕES**
- Saldo atual: 598 BTC ≈ $41.982

É importante entender que esta carteira **não recebe exclusivamente da nossa cadeia** — ela movimenta fundos de milhares de origens diferentes simultaneamente, comportamento típico de uma **exchange centralizada ou mixer profissional**. Nossa cadeia de lavagem chegou nela como uma das milhares de entradas, diluindo completamente a origem dos fundos no pool geral.

**O que é SegWit e por que o atacante migrou para ele?**

SegWit (Segregated Witness) é um formato moderno de endereço Bitcoin identificado pelo prefixo `bc1q`. A migração progressiva de Legacy (`1xxx`) para SegWit ao longo das camadas não é coincidência:

- **Taxas menores** — essencial ao mover dezenas de carteiras simultaneamente
- **Menor rastreabilidade** em ferramentas antigas de blockchain analytics
- **Padrão de exchanges profissionais** — facilita entrada sem levantar flags

---

## 📊 Linha do Tempo

```
Set/2022    → brighterfuture.net registrado no GoDaddy
Fev/2023    → IP alocado na DigitalOcean
              Cert licftluimc.quest emitido via Let's Encrypt
Mai/2023    → Certificado licftluimc.quest expira
16/06/2024  → 20 carteiras consolidadas → R$ 84.000 movidos
30/06/2024  → Split em múltiplas saídas — peel chain iniciado
21/08/2024  → 80 inputs consolidados → R$ 560.000
Nov/2024    → Último DNS resolution de api.brighterfuture.net
27/02/2026  → Primeiro abuse report no AbuseIPDB
04/03/2026  → E-mail de sextortion recebido
15/03/2026  → Segundo abuse report no AbuseIPDB
19/03/2026  → Investigação conduzida — IP ainda ativo
              Reportado no AbuseIPDB e DigitalOcean
```

---

## 🧠 Conclusão

O que parecia um golpe simples revelou uma operação sofisticada:

- **Infraestrutura ativa por 3+ anos** no mesmo IP sem takedown
- **Peel chain** para fragmentar e poluir rastro no blockchain
- **Migração progressiva** Legacy → SegWit ao longo das camadas
- **MySQL exposto na porta 3306** — servidor comprometido ou negligente
- **Volume estimado da operação:** dezenas de milhões de dólares
- **Destino final:** exchange com $2B em volume — rastreamento encerrado

A investigação chegou até onde as ferramentas públicas permitem. O próximo passo exigiria dados KYC de exchange via ordem judicial.

---

## 📣 Como Reportar

Se você recebeu um e-mail similar:

| Canal | Link | O que reportar |
|---|---|---|
| **AbuseIPDB** | https://www.abuseipdb.com | IP do remetente |
| **FBI IC3** | https://www.ic3.gov | Crime completo com evidências |
| **DigitalOcean Abuse** | abuse@digitalocean.com | IP e MySQL exposto |
| **GoDaddy Abuse** | https://supportcenter.godaddy.com/AbuseReport | Domínio brighterfuture.net |

---

## 🛡️ Recomendações

**Para usuários:**
- **Nunca pagar** — as informações são falsas
- Ativar **MFA** em todas as contas críticas
- Usar **senhas únicas** por serviço via gerenciador de senhas

**Para analistas / blue team:**
- Bloquear IP `164.92.68.246` e range `164.92.64.0/18`
- Blacklist de DNS: `brighterfuture.net`, `licftluimc.quest`
- Criar regra no SIEM: e-mails com SPF none + DMARC fail originados de ASN de datacenter (AS14061)
- Adicionar carteiras Bitcoin identificadas em feeds de threat intelligence

---

## 📁 Estrutura do Repositório

```
sextortion-analysis/
├── README.md
├── iocs.txt
├── email_redacted.eml
└── evidence/
    ├── 01_virustotal_ip.png
    ├── 02_abuseipdb.png
    ├── 03_shodan_ports.png
    ├── 04_urlscan_brighterfuture.png
    ├── 05_blockchain_coletora.png
    ├── 06_blockchain_consolidadora.png
    ├── 07_blockchain_segwit.png
    ├── 08_blockchain_pemf_summary.png
    ├── 09_blockchain_pemf_saida.png
    └── 10_blockchain_mixing_flow.png
```

---

## ⚠️ Disclaimer

Esta análise foi conduzida exclusivamente com ferramentas públicas de OSINT e threat intelligence para fins educacionais. Nenhum sistema foi acessado ou explorado. O objetivo é documentar TTPs de campanhas de sextortion e contribuir com a comunidade de segurança da informação.
