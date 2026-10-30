# Handoff — OSIRIS, Fase 11b-4 (uprobe eBPF de DNS) numa VM Ubuntu 24.04

Repo: https://github.com/excanear/OSIRIS---Operational-System-Intelligence-Response-Investigation-System
(branch `master` @ `88c4981`). Responda ao usuário em português. Quando um nome não diz o
pronome, use pronomes neutros.

## Objetivo da próxima sessão

Começar a **Fase 11b-4**: um backend eBPF de DNS com uprobes nas bibliotecas de resolução
(glibc `getaddrinfo`/libresolv, e o caminho do systemd-resolved), que captura o pid **no kernel
na hora da consulta**. Isso remove a corrida de atribuição do sensor DNS da 11a, que é feito em
espaço de usuário com AF_PACKET. Agora o host é Linux, então dá para rodar o verificador BPF e a
suíte `real_linux` localmente, sem esperar o GitHub Actions a cada iteração.

**Primeiro passo obrigatório, antes do brainstorming:** o A/B do teste
`dns_query_is_observed_and_alerts` com o sensor `filesystem` desligado e ligado. É uma condição
de aceite da revisão final da 11b-3, ver `docs/ROADMAP-REMAINING.md` ("Dívida carregada para a
11b-4") e `docs/VALIDATION.md` ("Observed flakes"). O resultado entra no spec da 11b-4.

## Situação

- **Pronto:** fases 1–10, 11a (sensor DNS AF_PACKET), 11b-1 (motor eBPF + exec/exit), 11b-2 (TCP)
  e 11b-3 (filesystem), todas com merge no master e push. Último CI real-linux verde: run
  40999372578 (22.04 com 6.8.0-1070-azure, 24.04 com 7.0.0-1017-azure). Gates no merge: clippy
  `-D warnings` limpo, 1444 testes Rust e 270 do console.
- **Remoto limpo:** os branches `real-linux/*`, `real-linux-bench/*`, `phase-11b2-net` e
  `phase-11b3-fs` foram apagados. Restam `phase-5-*`, `phase-6-*`, `phase-7-*` e `phase-9a-transport`,
  todos já mesclados no master (só apagar com OK do usuário).
- **Nada bloqueando.** A sequência que falta é 11b-4, depois 11c (ClickHouse, trait `Storage`),
  depois as Fases 12 e seguintes do `docs/ROADMAP-REMAINING.md`.

## Preparar a VM (verificar, não presumir)

- Rust stable com clippy e rustfmt (o projeto usou 1.99.1), mais `clang`, `libbpf-dev`, `bpftool`
  e `linux-headers-$(uname -r)`. Node/npm para `console/`. `python3` e `tcpdump` são usados pela
  suíte real-linux. O workflow lista o resto: `.github/workflows/real-linux.yml`.
- Os objetos BPF são gerados **só** por `tools/ebpf/build.sh`, nunca pelo cargo.
- Suíte de Linux real: `tools/real-linux/run.sh --nocapture` (precisa de root/CAP_BPF).
- Antes de confiar em `cargo test --workspace` depois de um merge que toque
  `osiris-cli`/`osiris-server`/`osiris-agent`, rode `cargo build -p osiris-cli -p osiris-server -p osiris-agent`,
  porque o e2e usa binários pré-compilados. Se `package.json` mudar, rode `npm ci` em `console/`.
- A VM é **um** kernel só. Continue usando o GH Actions (push em `real-linux/t11b4-<n>`) para a
  matriz 22.04 + 24.04 antes do merge.

## Processo (preferências do usuário)

- Ciclo completo por fase: superpowers:brainstorming → spec em `docs/superpowers/specs/` →
  superpowers:writing-plans → plano em `docs/superpowers/plans/` → superpowers:subagent-driven-development
  num worktree `.claude/worktrees/phase-11b4-<x>` → revisão final do branch inteiro (opus) → uma
  onda de correções → re-revisão com escopo → lista das linhas "Ruling:" para o usuário → merge
  ff no master → push → limpeza.
- O usuário aprova com "pode seguir com o recomendado". Siga o padrão recomendado e pare só em
  ambiguidade que bloqueia de verdade. Registre as decisões no ledger como
  `Ruling: … — costs: …`.
- O ledger do SDD (`.superpowers/sdd/<data>-<fase>/progress.md` dentro do worktree) é a fonte
  de verdade. Em toda pausa, grave uma linha RESUME exata.
- Faça push no GitHub logo depois de cada commit importante (o histórico de perda de disco do
  usuário torna isso importante). Os subagentes **não** fazem push; o controlador faz.
- Faça os despachos de implementer/reviewer com `sonnet`/`opus`, nunca `haiku`.

## Decisões em aberto para a 11b-4

- Pontos de uprobe: só glibc `getaddrinfo` ou também `gethostbyname`, `res_*` e o caminho do
  systemd-resolved (D-Bus/varlink)? E como tratar resolvers estáticos ou não glibc (Go, musl),
  que não passam pela libc?
- Relação com o backend AF_PACKET da 11a: substituir, combinar (uprobe para atribuição + pacote
  para conteúdo) ou usar como fallback? Mantenha o fallback para audit/procfs no padrão das 11b-1..3.
- Como localizar a libc em contêineres e montagens (caminho por namespace) e o que acontece com
  binários atualizados enquanto o agente roda.
- O mesmo padrão de escopo das outras fases: objeto x86_64, pontos obrigatórios/opcionais
  surfaced em `last_error`, contagem de instruções do verificador impressa no `load_*`.

## Skills a usar

- superpowers:brainstorming, superpowers:writing-plans, superpowers:subagent-driven-development
- superpowers:using-git-worktrees, superpowers:systematic-debugging (para o A/B do DNS)
- superpowers:requesting-code-review, superpowers:verification-before-completion,
  superpowers:finishing-a-development-branch

## Artefatos (leia, não copie)

- Arquitetura: `ARCHITECTURE.md` (§6 sensores, §8 bus, §26 matriz de kernels)
- Roadmap e dívidas: `docs/ROADMAP-REMAINING.md` (Fase 11, seções 11b-1..11b-3)
- Validação em Linux real e flakes: `docs/VALIDATION.md`; performance: `PERFORMANCE.md`
- eBPF: `docs/adr/ADR-010-ebpf-loader-aya.md`, `docs/operators-ebpf.md`, `bpf/*.bpf.c`,
  `crates/osiris-ebpf`, `tools/ebpf/build.sh`
- Sensor DNS atual: spec `docs/superpowers/specs/2026-10-17-phase-11a-dns-sensor-design.md`,
  plano `docs/superpowers/plans/2026-10-17-phase-11a-dns-sensor.md`
- Fase anterior, para seguir o modelo: spec
  `docs/superpowers/specs/2026-10-26-phase-11b3-ebpf-filesystem-design.md`, plano
  `docs/superpowers/plans/2026-10-26-phase-11b3-ebpf-filesystem.md`
- CI: `.github/workflows/real-linux.yml`, `real-linux-bench.yml`, `ci.yml`; harness
  `tools/real-linux/run.sh`
- Histórico: `git log --oneline 88ee9bc..88c4981` (toda a 11b-3)
