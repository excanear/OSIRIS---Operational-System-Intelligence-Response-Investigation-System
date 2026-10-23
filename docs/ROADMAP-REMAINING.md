# OSIRIS — o que falta finalizar (backlog pós-Fase 10)

Estado em 2026-10-17: fases 1–7, 8a–8g, 9 e 10 concluídas, testes/clippy/fmt/lint verdes.
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
- Hoje (9d-2 entregue): grupos de hosts (API `/api/v1/groups`, CLI, Console, filtro `?group=`
  em `/api/v1/hosts`).
- Hoje (9d-3 entregue): distribuição de política (nível de telemetria, sensores ligados/desligados,
  intervalo de heartbeat) a grupos via comandos `ApplyPolicy` assinados sobre o canal 9c; o Agente
  persiste o overlay e reporta o hash no heartbeat (status `IN_SYNC|PENDING|FAILED|UNMANAGED`).
  Ver `docs/operators-fleet-policy.md`. Com isso o Fleet Manager (§21.2) está completo.

## Fase 10 — Validação em Linux real (concluída em 2026-10-17)
- Entregue: harness real-Linux (`crates/osiris-real-linux-tests`, `tools/real-linux/{setup,run,bench}.sh`,
  workflows `real-linux.yml` e `real-linux-bench.yml`) que sobe o `osirisd` e o `osiris-server` de
  produção e verifica, via API, eventos e alertas de ações reais (exec, arquivo, sudo, unit systemd,
  conexão TCP, persistência, drop em web-root). Validado em Ubuntu 22.04 e 24.04 (GitHub Actions, com
  auditd) e Ubuntu 24.04 e Debian 13 sob WSL2 (só cenários sem auditd).
- 15 achados corrigidos, cada um com teste de regressão que roda no CI comum: distro/kernel
  "unknown", regras de shell só para `/bin/*`, linhas do spool intercaladas, separador `\x1d` do
  auditd ENRICHED, argv do processo (registro EXECVE separado), ids de alerta vs. evidência,
  `libssl-dev` no Debian, o gargalo de ingest (F1: commits por evento; WAL + `observe_batch` levou
  de ~100 para ~1000 eps armazenados, sem perda de marcadores) e o custo do lookup de arestas (F2,
  parte 1).
- Primeira passada de benchmarks contra o orçamento do §19.2: `PERFORMANCE.md`.
- Console verificado no navegador (Playwright, 17 testes em `console/e2e`, 1440x900 e 390x844): 3 bugs
  corrigidos (Origin no proxy WS, reescrita só da própria origem, arestas do grafo invisíveis).
- Detalhes e tabelas: `docs/VALIDATION.md` e `PERFORMANCE.md`.

### Dívidas da Fase 10
- **Fora de escopo, ainda por fazer**: cenários reais de container e Kubernetes (exige Docker/kind);
  distros RHEL-like (caminhos do auditd, SELinux); Debian com auditd funcionando (exige VM, o
  workflow só tem runners Ubuntu); captura real de DNS (resolvida na Fase 11a).
- **CI**: jobs de real-Linux e de Playwright seguem fora do CI (a Fase 10 manteve só `perf_smoke`
  como gate). Falta decidir quais viram gate ou job agendado; o Playwright precisa de
  `osiris-stack` em release e navegador no runner.
- **F2, fan-out do `build_chain`**: profundidade 5 com até 1000 arestas por lookup e nenhum outro
  limite; com hubs (domínio, IP, arquivo compartilhado) o custo por evento cresce com o componente
  (~75 eps no mix de 5 cenários). Precisa de decisão de desenho (teto de grau, orçamento de arestas
  por cadeia ou exclusão de hubs). Ver `PERFORMANCE.md` "Known limits".
- **M1**: o `ExecAssembler` do sensor de processo mantém um exec pendente; com registros de outros
  eventos intercalados em host ocupado o argv se perde em silêncio (o evento sai com `cmdline` vazio).
- **M3**: sem política definida o agente envia o argv completo e não há redação de segredos nos
  valores dos argumentos; só abaixo do nível STANDARD o argv é removido.
- **Bench**: o gerador de ingest só dirige cadeias de exec, então os números são um teto para mixes
  mais ricos; o forwarder é stop-and-wait (um lote de 500 em voo), o que limita a vazão por conexão.
- **Menores**: caminho de upgrade da migração de índices e aviso de fallback do WAL sem teste;
  `open_reader` do bench faz `expect` se `events.db` não existe; `free_port()` pode repetir portas.
- **Console**: itens de UX da seção "Phase 13 UX debt" de `docs/VALIDATION.md` entram na Fase 13.
  Em aberto (nunca foi especificado, não é regressão): o clique em nó do Entity Graph não faz nada,
  falta o pivô para a tela de detalhe da entidade, a definir no desenho. A Timeline não oferece hosts
  em seed só-spool.
- **Limpeza no merge**: apagar `console/vite.config.js` e `console/vite.config.d.ts` obsoletos do
  checkout principal (o Vite prefere o `.js`).

## Fase 11 — Backends de telemetria (§5, §10)
- **Fase 11a (feita)**: sensor de DNS real via AF_PACKET (dívida da Fase 10), validado em Linux real
  (run 39087535939, Ubuntu 22.04 e 24.04). Ver `docs/VALIDATION.md` e `docs/operators-dns-sensor.md`.
  Dívida: backend eBPF uprobe (11b); pontos cegos DNS sobre TCP, DoT, DoH e mDNS; o sensor não
  tenta reabrir o socket se o `initialize` falhar.
  Dívidas da revisão final da 11a:
  - Os contadores `EngineMetrics` (spec §10: pacotes, erros de parse, divergências de direção,
    timeouts, respostas sem par, despejos por overflow, duplicatas, atribuídos e não atribuídos)
    só podem ser lidos por `DnsSensor::engine_metrics()`, que nada chama. Não são exportados:
    falta uma mudança em sensor-api ou em selftelemetry.
  - O contador de descartes do kernel (`PACKET_STATISTICS`, `tp_drops`) nunca é lido. A perda
    por estouro do buffer de recepção em host ocupado passa em silêncio.
  - Tráfego encaminhado ou com NAT (Docker, roteador): a cópia de egresso (`PACKET_OUTGOING`)
    conta como local e gera um segundo evento. Se a porta colidir, esse evento pode ser atribuído
    a um processo do host sem relação. Correção futura: comparar o IP de origem com os endereços
    locais.
- **Fase 11b-1 (feita)**: motor eBPF (`crates/osiris-ebpf`, loader aya, programas C CO-RE com clang) e
  backend eBPF de exec/exit do sensor `process_exec`, com fallback para audit. Validado em Linux real
  (run 39139529617, Ubuntu 22.04 e 24.04). Ver `docs/adr/ADR-010-ebpf-loader-aya.md`,
  `docs/operators-ebpf.md` e `docs/VALIDATION.md`.
  Próximos (cada um com seu brainstorming/spec/plano): **11b-3** filesystem, **11b-4** uprobe de DNS
  em bibliotecas de resolução.
  Dívidas da 11b-1:
  - `PROCESS_FORK` não é emitido (só exec e exit).
  - Níveis de telemetria por entidade em mapas no kernel (§6): ainda não.
  - Matriz de kernels em VMs (§5.4/§26): validado só nos 2 kernels dos runners.
  - Redução de privilégios do agente a um conjunto mínimo de capabilities (§15).
  - Empacotamento do objeto BPF (.deb/.rpm, unit systemd): Fase 13.
  - Layout dos registros espelhado à mão (testes + versão de schema), sem codegen: reavaliar com a 11b-3
    (agora são três registros espelhados).
- **Fase 11b-2 (feita)**: backend eBPF TCP do sensor de rede (`bpf/net.bpf.c`: connect/accept/close,
  IPv4 e IPv6, fallback para procfs) e registro de processo v2 (identidade do executável capturada no
  kernel, uma saída por grupo de threads; resolve as saídas de thread não-líder/`pthread_exit` e a
  leitura tardia de `/proc/<pid>/exe` da 11b-1). Validado em Linux real (run 40039969622, Ubuntu 22.04
  e 24.04, kernels 6.x). Ver `docs/operators-ebpf.md`, `docs/adr/ADR-010-ebpf-loader-aya.md` e
  `docs/VALIDATION.md`.
  Dívidas da 11b-2:
  - UDP não é coberto.
  - Conexões que falham (sem conexão estabelecida) não são reportadas.
  - Accepts via io_uring não são vistos.
  - Conexões já existentes quando o agente inicia não são reportadas (nem o CLOSE delas).
  - CLOSE de conexão despejada do LRU (mais de 65 536 sockets) é perdido.
  - A checagem de identidade do executável não casa em btrfs/overlayfs (cai no resultado com `comm`).
  - O piso de kernel 5.15 é raciocinado (CO-RE), não executado: os runners atuais sobem kernels 6.x.
  - O sensor `process_exec` mostra `events_emitted_total` 0 e `last_event_at` nulo em `/status` com o
    backend eBPF (o caminho eBPF de rede conta corretamente); herdado da 11b-1.
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
