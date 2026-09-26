# OSIRIS — o que falta finalizar (backlog pós-Fase 8g)

Estado em 2026-09-19 (`master` @ `0c1fac2`+): fases 1–7 e 8a–8g concluídas, testes/clippy/fmt/lint verdes.
Este documento lista tudo que o `ARCHITECTURE.md` pede e ainda não existe, na ordem de execução.
Cada fase segue o processo do projeto: brainstorming → spec → plano → implementação (TDD, worktree) →
revisão final independente → merge → push.

## Fase 9 — Caminho de produção (segurança e comando)

### 9a. Transporte Agente→Servidor seguro (§8.3, §17)
- Hoje: o servidor lê um arquivo de spool (`LineTailer` em `osiris-server/src/ingest.rs`).
- Entregar: stream com framing + zstd sobre UDS (mesmo host) e TCP com mTLS (remoto); backpressure
  para o `DiskSpool` do agente; enrollment por certificado por agente; recusa de agente não enrolado.
- Pré-requisito de 9b e 9c.

### 9b. TLS na API/Console (§14.3, §17)
- Hoje: API em HTTP puro (`TcpListener`), depende de proxy reverso.
- Entregar: `rustls` opcional na API (cert/key por config), HSTS, cookies/tokens só sobre TLS,
  documentação de deploy.

### 9c. Canal Servidor→Agente + ações destrutivas de resposta (§13, §29 Fase 8)
- Hoje: só `CollectEvidence` executa; `TerminateProcess`, `StopService`, `QuarantineFile`,
  `BlockIndicator`, `IsolateNetwork`, `DisablePersistence` respondem 501.
- Entregar: comandos assinados Servidor→Agente sobre o transporte de 9a; execução no Agente com
  privilégio; dry-run real; auditoria pré+pós; timeout/rollback; testes com Agente falso e revisão de
  segurança dedicada (marco separado, conforme §13).

### 9d. Fleet Manager real (§21.2)
- Hoje (9d-1 entregue): `/api/v1/hosts` lê o registro de agentes real (`osiris-fleet`'s
  `HostRegistry`), alimentado pelos heartbeats `AGENT_HEALTH` no ingest — não mais uma
  listagem derivada de uma janela de eventos.
- Entregar (9d-2/9d-3): grupos de hosts; distribuição de política (nível de telemetria/config
  de sensores) via 9c; telas do Console além da lista; integração mais profunda com tenants.

## Fase 10 — Validação em Linux real
- Rodar agente + sensores em VM/container Linux reais (Ubuntu 22.04, Debian 12, RHEL 8-like).
- Cenários reais: exec, arquivo, rede/DNS, login/sudo, systemd, container, k8s (kind/minikube).
- Descobrir e corrigir diferenças entre os testes sintéticos e o kernel real.
- Verificação visual do Console no navegador (Playwright) — nunca feita até hoje.
- Primeira passada de benchmarks (§19): eventos/s, latência, memória do agente; orçamento vs. §19.2.

## Fase 11 — Backends de telemetria (§5, §10)
- **eBPF/CO-RE** (§5): loader libbpf-rs, programas para exec/fork/exit, file, net; capability probe;
  fallbacks atuais (audit/procfs) mantidos. Hoje: nenhum código eBPF.
- **ClickHouse** (§10.2): implementação do trait `Storage`, migração/benchmark vs. SQLite.

## Fase 12 — Extensibilidade e integração (§20)
- **Exporters** (§20.3): NDJSON/CSV, Syslog/CEF, OpenTelemetry (OTLP); Kafka/webhook opcionais.
- **Plugins**: regras/enriquecimento em WASM sandboxed (bounded budget por evento); sensores como
  subprocessos (futuro, §20.2).

## Fase 13 — Produto e documentação
- README, LICENSE, guia de instalação e operação, arquitetura resumida, Dockerfile(s), unit files
  systemd do agente/servidor, manifests Kubernetes (DaemonSet do agente), empacotamento (.deb/.rpm).
- ADRs em `docs/adr/` (§28), modelo de ameaças atualizado, guia de resposta a incidentes.
- Console: tela de Auditoria; paginação real nas listas; itens de UX pendentes.

## Dívidas técnicas menores (encaixar nas fases acima)
- `detect` de nuvem: com vários providers respondendo, o vencedor é o primeiro que chegar.
- Listas rolled-up (`/processes`, `/files`, `/network`, `/containers`) trabalham sobre janela limitada
  de eventos; ideal: método de rollup/distinct no trait `Storage`.
- Entidades de incidente criadas pela plataforma não são validadas (por desenho).
- WS: falha do registro de tenants mantém o conjunto anterior de hosts (logado).
- Pastas de worktree residuais bloqueadas pelo Windows: `.claude/worktrees/{followups,leftovers,phase-8e-kubernetes-context,phase-7b5-filesystem-network-containers}` — apagar manualmente.

## Definição de pronto (por fase, do `ARCHITECTURE.md` §94)
Implementação + testes + tratamento de erros + métricas + logs + docs + revisão de segurança +
consideração de performance + integração CLI/API. CI verde: `fmt`, `clippy -D warnings`, `test`,
grafo de dependências, lint/test/build do console.
