#!/usr/bin/env bash
# Wrapper pro florestad instrumentado (headers-singleton-instrumentation.patch).
#
# Roda o nó, mostra só os eventos HEADERS-SINGLETON ao vivo, guarda o log
# completo em arquivo e imprime um resumo das colisões quando você sair
# (Ctrl-C ou morte do processo).
#
# Uso:
#   ./run-singleton-probe.sh                     # default: --network signet
#   ./run-singleton-probe.sh --network bitcoin   # args são repassados ao florestad
#   LOG=/tmp/meu.log ./run-singleton-probe.sh    # escolhe o arquivo de log
set -u

BIN=./target/release/florestad
STAMP=$(date +%Y%m%d-%H%M%S)
LOG="${LOG:-/tmp/florestad-singleton-$STAMP.log}"

[ -x "$BIN" ] || { echo "erro: $BIN não existe — roda 'cargo build --release --bin florestad' antes"; exit 1; }
[ $# -eq 0 ] && set -- --network signet

summary() {
    echo
    echo "════════════════════════════════════════════════════════════"
    echo " HEADERS-SINGLETON — resumo da sessão"
    echo " log completo: $LOG"
    echo "════════════════════════════════════════════════════════════"

    if ! grep -q "HEADERS-SINGLETON" "$LOG" 2>/dev/null; then
        echo "(nenhum evento HEADERS-SINGLETON no log)"
        return
    fi

    echo
    echo "── contagem por tipo de evento ──"
    grep -o "HEADERS-SINGLETON [a-z-]*" "$LOG" | sort | uniq -c | sort -rn

    echo
    echo "── colisões (cada linha = um getheaders real que perdeu timeout/banscore/retry) ──"
    grep -E "HEADERS-SINGLETON (overwrite|wrong-peer-remove|orphan-request|dirty-latency|timeout-retry)" "$LOG" \
        || echo "(nenhuma colisão dura — só tráfego limpo/unsolicited)"

    echo
    echo "── removedores genéricos (antes invisíveis: disconnect/timeout/sweep) ──"
    grep -E "HEADERS-SINGLETON (disconnect-remove|timeout-remove|sweep-remove)" "$LOG" \
        || echo "(nenhum)"

    echo
    echo "── unsolicited por peer (BIP130 rotineiro ou entrada já apagada) ──"
    grep "HEADERS-SINGLETON unsolicited" "$LOG" | grep -o "peer=[0-9]*" | sort | uniq -c | sort -rn

    echo
    echo "── guard-hits (bloco novo bloqueado pelo singleton; age alta = entrada fantasma) ──"
    grep "HEADERS-SINGLETON guard-hit" "$LOG" || echo "(nenhum)"

    echo
    echo "── timeline completa dos WARNs, na ordem (procura overwrite→guard-hit e orphan→wrong-peer) ──"
    grep -E "WARN.*HEADERS-SINGLETON" "$LOG" || echo "(nenhum WARN)"

    echo
    echo "── camada 2: ledger do fio ──"
    echo "HDR-WIRE send: $(grep -c 'HDR-WIRE send' "$LOG")  |  HDR-WIRE recv: $(grep -c 'HDR-WIRE recv' "$LOG")  |  HDR-MAP snapshots: $(grep -c 'HDR-MAP snapshot' "$LOG")"
    echo "reconciliação: python3 reconcile_headers.py $LOG"
    echo "════════════════════════════════════════════════════════════"
}
trap summary EXIT

echo "log completo: $LOG"
echo "eventos ao vivo (Ctrl-C pra sair e ver o resumo):"
echo

RUST_LOG="${RUST_LOG:-info,floresta_wire=debug}" "$BIN" "$@" 2>&1 \
    | tee "$LOG" \
    | grep -E --line-buffered "HEADERS-SINGLETON|panicked"
