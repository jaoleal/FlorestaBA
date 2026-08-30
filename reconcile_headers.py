#!/usr/bin/env python3
"""
Reconcilia o ledger do fio (HDR-WIRE, verdade de chão) contra a crença do mapa
(HDR-MAP, projeção bugada) a partir do log do florestad.

Uso:
    ./target/release/florestad --network signet 2>&1 | tee run.log
    python3 reconcile_headers.py run.log

O ledger do fio é append-only e imune ao singleton: cada getheaders enviado e
cada headers recebido, por peer. O "inflight verdadeiro" do peer P num instante T é
    sends(P, ate T) - recvs(P, ate T)   (piso em 0)
A soma sobre os peers e o total real de getheaders pendentes. O mapa so sabe
representar 0 ou 1. O delta entre os dois e a medida direta do bug.

Correlacao e heuristica (getheaders nao tem nonce): casamos por peer + ordem
temporal, nao criptograficamente. Basta para medir "algum headers voltou daquele
peer depois do pedido".
"""
import re
import sys
from collections import defaultdict

WIRE_SEND = re.compile(r"HDR-WIRE send peer=(\d+) ts=(\d+)")
WIRE_RECV = re.compile(r"HDR-WIRE recv peer=(\d+) ts=(\d+) count=(\d+)")
MAP_SNAP = re.compile(r"HDR-MAP snapshot ts=(\d+) believes=(none|peer(\d+))")

# tempo (ms) sem resposta apos o qual um getheaders pendente e considerado morte
# silenciosa em potencial. Alinhe com o REQUEST_TIMEOUT do seu build.
SILENT_DEATH_MS = 30_000


def parse(path):
    events = []  # (ts, kind, peer, extra)
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = WIRE_SEND.search(line)
            if m:
                events.append((int(m.group(2)), "send", int(m.group(1)), None))
                continue
            m = WIRE_RECV.search(line)
            if m:
                events.append((int(m.group(2)), "recv", int(m.group(1)), int(m.group(3))))
                continue
            m = MAP_SNAP.search(line)
            if m:
                believes = None if m.group(2) == "none" else int(m.group(3))
                events.append((int(m.group(1)), "snap", believes, None))
    events.sort(key=lambda e: e[0])
    return events


def reconcile(events):
    # fila FIFO de sends pendentes por peer: guarda o ts de cada getheaders sem
    # resposta ainda. recv consome o mais antigo daquele peer.
    pending = defaultdict(list)
    rows = []
    silent_deaths = []
    total_sends = total_recvs = 0
    max_outstanding = 0

    for ts, kind, peer, extra in events:
        if kind == "send":
            pending[peer].append(ts)
            total_sends += 1
        elif kind == "recv":
            total_recvs += 1
            if pending[peer]:
                pending[peer].pop(0)  # casa o getheaders mais antigo desse peer
            # recv sem send pendente = anuncio BIP130 nao-solicitado
        elif kind == "snap":
            true_out = {p: len(q) for p, q in pending.items() if q}
            true_total = sum(true_out.values())
            max_outstanding = max(max_outstanding, true_total)
            map_count = 0 if peer is None else 1
            delta = true_total - map_count
            # flags
            flag = ""
            if peer is not None and peer not in true_out:
                flag = "MAPA-FANTASMA"        # mapa aponta peer sem request vivo no fio
            elif delta > 0 and map_count == 0:
                flag = "CEGO"                 # ha request(s) vivo(s), mapa acha que nao
            elif delta > 0:
                flag = "SUBCONTAGEM"          # mais requests vivos que o mapa cabe
            rows.append((ts, peer, dict(true_out), true_total, map_count, delta, flag))

    # varre pendentes que nunca receberam resposta dentro da janela = mortes silenciosas
    if events:
        last_ts = events[-1][0]
        for p, q in pending.items():
            for send_ts in q:
                if last_ts - send_ts > SILENT_DEATH_MS:
                    silent_deaths.append((p, send_ts, last_ts - send_ts))

    return rows, silent_deaths, total_sends, total_recvs, max_outstanding


def main():
    if len(sys.argv) < 2:
        print("uso: python3 reconcile_headers.py <run.log>")
        sys.exit(1)
    events = parse(sys.argv[1])
    if not events:
        print("nenhum evento HDR-WIRE/HDR-MAP encontrado. Rodou com RUST_LOG=debug?")
        sys.exit(0)
    rows, silent_deaths, sends, recvs, max_out = reconcile(events)

    print(f"\n{'ts':>13}  {'mapa cre':>9}  {'fio vivo (por peer)':<26}  "
          f"{'real':>4}  {'mapa':>4}  {'delta':>5}  flag")
    print("-" * 92)
    flagged = 0
    for ts, believes, true_out, true_total, map_count, delta, flag in rows:
        if not flag:
            continue  # so mostra as linhas onde ha divergencia; tire este if pra ver tudo
        flagged += 1
        bel = "none" if believes is None else f"peer{believes}"
        out = ", ".join(f"p{p}:{n}" for p, n in true_out.items()) or "-"
        print(f"{ts:>13}  {bel:>9}  {out:<26}  {true_total:>4}  {map_count:>4}  "
              f"{delta:>+5}  {flag}")

    print("\n" + "=" * 40 + " resumo " + "=" * 40)
    print(f"  getheaders enviados (fio)........ {sends}")
    print(f"  headers recebidos (fio).......... {recvs}")
    print(f"  sends sem match (potenciais)..... {sends - recvs}")
    print(f"  max requests simultaneos (fio)... {max_out}   <- o mapa so cabe 1")
    print(f"  snapshots com divergencia........ {flagged} de {len(rows)}")
    print(f"  mortes silenciosas (> {SILENT_DEATH_MS//1000}s sem resposta)... {len(silent_deaths)}")
    for p, send_ts, age in silent_deaths:
        print(f"      peer {p}: getheaders em ts={send_ts} sem resposta ha {age/1000:.1f}s")
    print()
    print("  Leitura: 'max simultaneos > 1' prova que o singleton e insuficiente.")
    print("  'CEGO' = ha request vivo e o mapa nao ve (timeout nao vai disparar).")
    print("  'MAPA-FANTASMA' = mapa rastreia peer cujo request ja nao existe no fio.")


if __name__ == "__main__":
    main()
