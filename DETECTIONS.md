# 🛡️ Regras de Detecção — Sextortion Campaign

> Regras baseadas nos IOCs identificados na análise do caso.  
> Repositório principal: [Analise-Phishing](https://github.com/SallocinAvalcante/Analise-Phishing)  
> Regra Sigma validada no [Uncoder.IO](https://tdm.socprime.com/uncoder-ai/translate).

---

## 1. Sigma Rule

Formato agnóstico — converta para qualquer SIEM usando o [Uncoder.IO](https://tdm.socprime.com/uncoder-ai/translate): cole a regra abaixo, selecione o SIEM desejado (Splunk, Elastic, QRadar, Sentinel, etc.) e clique em converter.

```yaml
title: Sextortion Campaign - Malicious Email Infrastructure
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: >
  Detects emails from known malicious infrastructure associated with sextortion campaign.
  IP 164.92.68.246 (DigitalOcean AS14061), domains brighterfuture.net and licftluimc.quest.
  SPF none and DMARC fail may be present and should be used as supporting context during investigation.
references:
    - https://github.com/SallocinAvalcante/Analise-Phishing
author: Nicollas Cavalcante Souza
date: 2026/03/19
tags:
    - attack.initial_access
    - attack.t1566
    - attack.t1566.001
logsource:
    category: email
    product: generic
detection:
    selection_ip:
        SenderIP: '164.92.68.246'
    selection_domain:
        SenderDomain|contains:
            - 'brighterfuture.net'
            - 'api.brighterfuture.net'
            - 'licftluimc.quest'
    selection_spoof:
        SPFResult: 'none'
        DMARCResult: 'fail'
        # SenderASN: 'AS14061'
        # Campo ASN raramente disponível sem enrichment — descomente se seu ambiente suportar
    condition: selection_ip or selection_domain
falsepositives:
    - Legitimate emails from misconfigured domains (SPF none / DMARC fail)
level: high
```

> ⚠️ O campo `index=*` gerado na conversão para Splunk deve ser substituído pelo índice correto do seu ambiente (ex: `index=email` ou `index=exchange`).

---

## 2. DNS Blacklist

Bloqueie os domínios maliciosos no seu servidor DNS — qualquer tentativa de resolução retorna `0.0.0.0`.

### Pi-hole
```bash
pihole --blacklist brighterfuture.net
pihole --blacklist api.brighterfuture.net
pihole --blacklist licftluimc.quest
pihole restartdns
```

### Bind9 — DNS Sinkhole
```bash
# 1. Adicionar em /etc/bind/named.conf.local
zone "brighterfuture.net" { type master; file "/etc/bind/zones/sinkhole.zone"; };
zone "licftluimc.quest"   { type master; file "/etc/bind/zones/sinkhole.zone"; };

# 2. Criar /etc/bind/zones/sinkhole.zone
$TTL 300
@   IN  SOA  localhost. root.localhost. (2026031901 3600 1800 604800 300)
    IN  NS   localhost.
*   IN  A    0.0.0.0

# 3. Reiniciar e validar
sudo systemctl restart bind9
dig brighterfuture.net @localhost   # deve retornar 0.0.0.0
```

### Windows DNS (Active Directory)
```powershell
Add-DnsServerPrimaryZone -Name "brighterfuture.net" -ZoneFile "sinkhole.dns"
Add-DnsServerPrimaryZone -Name "licftluimc.quest"   -ZoneFile "sinkhole.dns"
Add-DnsServerResourceRecordA -Name "@" -ZoneName "brighterfuture.net" -IPv4Address "0.0.0.0"
Add-DnsServerResourceRecordA -Name "@" -ZoneName "licftluimc.quest"   -IPv4Address "0.0.0.0"
```

---

## 3. Resumo dos IOCs para Bloqueio

| Tipo | Valor | Ação |
|---|---|---|
| IP | `164.92.68.246` | Bloquear no firewall e proxy |
| CIDR | `164.92.64.0/18` | Bloquear range DigitalOcean* |
| Domínio | `brighterfuture.net` | DNS sinkhole + blacklist proxy |
| Domínio | `api.brighterfuture.net` | DNS sinkhole + blacklist proxy |
| Domínio | `licftluimc.quest` | DNS sinkhole + blacklist proxy |
| ASN | `AS14061` | Monitorar e-mails originados |
| BTC Wallet | `14id3vCsWLocRamkLqfb3J9jhpxTHPz59m` | Feeds de threat intelligence |
| BTC Wallet | `1Gi5sqSA6NKfkaPdMu4szv1bzt3XxCyryU` | Feeds de threat intelligence |

> *Bloquear o range completo pode afetar serviços legítimos hospedados na DigitalOcean. Avalie o impacto antes de implementar.

---

## 🔗 Referências

- [Repositório principal](https://github.com/SallocinAvalcante/Analise-Phishing)
- [Uncoder.IO — Sigma Converter](https://tdm.socprime.com/uncoder-ai/translate)
- [MITRE ATT&CK T1566](https://attack.mitre.org/techniques/T1566/)
- [Sigma Rules — SigmaHQ](https://github.com/SigmaHQ/sigma)
