#!/usr/bin/env bash
set -euo pipefail

tool=$1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

printf 'mensagem original' > "$tmp/message.txt"
"$tool" keygen --scheme lamport --out "$tmp/keys"
"$tool" sign --scheme lamport --key "$tmp/keys/private.key" \
    --message "$tmp/message.txt" --out "$tmp/signature.bin"
"$tool" verify --scheme lamport --key "$tmp/keys/public.key" \
    --message "$tmp/message.txt" --signature "$tmp/signature.bin"

if "$tool" sign --scheme lamport --key "$tmp/keys/private.key" \
    --message "$tmp/message.txt" --out "$tmp/second.bin"; then
    echo 'chave reutilizada' >&2
    exit 1
fi
test ! -e "$tmp/second.bin"

printf 'mensagem alterada' > "$tmp/message.txt"
if "$tool" verify --scheme lamport --key "$tmp/keys/public.key" \
    --message "$tmp/message.txt" --signature "$tmp/signature.bin"; then
    echo 'mensagem alterada aceita' >&2
    exit 1
fi

head -c 100 "$tmp/signature.bin" > "$tmp/truncated.bin"
if "$tool" verify --scheme lamport --key "$tmp/keys/public.key" \
    --message "$tmp/message.txt" --signature "$tmp/truncated.bin"; then
    echo 'assinatura truncada aceita' >&2
    exit 1
fi

"$tool" demo lamport-reuse > "$tmp/demo.txt"
[[ $(< "$tmp/demo.txt") == *'pares expostos:'* ]]

for w in 4 16; do
    printf 'mensagem W-OTS+' > "$tmp/message.txt"
    "$tool" keygen --scheme wots+ --w "$w" --out "$tmp/wots-$w"
    "$tool" sign --scheme wots+ --w "$w" --key "$tmp/wots-$w/private.key" \
        --message "$tmp/message.txt" --out "$tmp/wots-$w.bin"
    "$tool" verify --scheme wots+ --w "$w" --key "$tmp/wots-$w/public.key" \
        --message "$tmp/message.txt" --signature "$tmp/wots-$w.bin"
    if "$tool" sign --scheme wots+ --key "$tmp/wots-$w/private.key" \
        --message "$tmp/message.txt" --out "$tmp/wots-$w-second.bin"; then
        echo 'chave W-OTS+ reutilizada' >&2
        exit 1
    fi
    printf 'mensagem modificada' > "$tmp/message.txt"
    if "$tool" verify --scheme wots+ --key "$tmp/wots-$w/public.key" \
        --message "$tmp/message.txt" --signature "$tmp/wots-$w.bin"; then
        echo 'mensagem W-OTS+ alterada aceita' >&2
        exit 1
    fi
done

# Mensagem vazia e binária, parâmetro incompatível e colisão na geração de chaves.
for scheme in lamport wots+ merkle; do
    args=(--scheme "$scheme")
    case "$scheme" in
        wots+) args+=(--w 16) ;;
        merkle) args+=(--w 16 --height 1) ;;
    esac
    for kind in empty binary; do
        dir="$tmp/edge-$scheme-$kind"
        "$tool" keygen "${args[@]}" --out "$dir"
        test "$(stat -c %a "$dir/private.key")" = 600
        cp "$dir/private.key" "$dir/before.key"
        cp "$dir/public.key" "$dir/before-public.key"
        if "$tool" keygen "${args[@]}" --out "$dir"; then
            echo 'chaves existentes sobrescritas' >&2
            exit 1
        fi
        cmp "$dir/before.key" "$dir/private.key"
        cmp "$dir/before-public.key" "$dir/public.key"
        : > "$tmp/edge-message"
        if [[ "$kind" == binary ]]; then
            printf '\000\377\001\200' > "$tmp/edge-message"
        fi
        if [[ "$scheme" == wots+ ]]; then
            if "$tool" sign --scheme wots+ --w 4 --key "$dir/private.key" \
                --message "$tmp/edge-message" --out "$dir/wrong-w.bin"; then
                echo 'parâmetro incompatível aceito' >&2
                exit 1
            fi
            cmp "$dir/before.key" "$dir/private.key"
            test ! -e "$dir/wrong-w.bin"
        fi
        "$tool" sign --scheme "$scheme" --key "$dir/private.key" \
            --message "$tmp/edge-message" --out "$dir/signature.bin"
        "$tool" verify --scheme "$scheme" --key "$dir/public.key" \
            --message "$tmp/edge-message" --signature "$dir/signature.bin"
    done
done

"$tool" keygen --scheme merkle --w 4 --height 2 --out "$tmp/merkle"
for i in 0 1 2 3; do
    printf 'mensagem Merkle %s' "$i" > "$tmp/message.txt"
    "$tool" sign --scheme merkle --key "$tmp/merkle/private.key" \
        --message "$tmp/message.txt" --out "$tmp/merkle-$i.bin"
    "$tool" verify --scheme merkle --key "$tmp/merkle/public.key" \
        --message "$tmp/message.txt" --signature "$tmp/merkle-$i.bin"
done
if "$tool" sign --scheme merkle --key "$tmp/merkle/private.key" \
    --message "$tmp/message.txt" --out "$tmp/merkle-4.bin"; then
    echo 'folha Merkle reutilizada após esgotamento' >&2
    exit 1
fi
test ! -e "$tmp/merkle-4.bin"

printf 'mensagem Merkle alterada' > "$tmp/message.txt"
if "$tool" verify --scheme merkle --key "$tmp/merkle/public.key" \
    --message "$tmp/message.txt" --signature "$tmp/merkle-3.bin"; then
    echo 'mensagem Merkle alterada aceita' >&2
    exit 1
fi

"$tool" keygen --scheme merkle --w 4 --height 1 --out "$tmp/concurrent"
printf 'mensagem concorrente' > "$tmp/message.txt"
"$tool" sign --scheme merkle --key "$tmp/concurrent/private.key" \
    --message "$tmp/message.txt" --out "$tmp/concurrent-1.bin" &
first_pid=$!
"$tool" sign --scheme merkle --key "$tmp/concurrent/private.key" \
    --message "$tmp/message.txt" --out "$tmp/concurrent-2.bin" &
second_pid=$!
wait "$first_pid"
wait "$second_pid"
! cmp -s "$tmp/concurrent-1.bin" "$tmp/concurrent-2.bin"
for i in 1 2; do
    "$tool" verify --scheme merkle --key "$tmp/concurrent/public.key" \
        --message "$tmp/message.txt" --signature "$tmp/concurrent-$i.bin"
done

# An unavailable output must not consume a key or overwrite an existing file.
for scheme in lamport wots+ merkle; do
    args=(--scheme "$scheme")
    case "$scheme" in
        wots+) args+=(--w 16) ;;
        merkle) args+=(--w 16 --height 1) ;;
    esac
    dir="$tmp/failure-$scheme"
    "$tool" keygen "${args[@]}" --out "$dir"
    cp "$dir/private.key" "$dir/before.key"
    printf 'preservar' > "$dir/existing.bin"
    for out in "$dir/existing.bin" "$dir/missing/signature.bin"; do
        if "$tool" sign --scheme "$scheme" --key "$dir/private.key" \
            --message "$tmp/message.txt" --out "$out"; then
            echo 'saída indisponível aceita' >&2
            exit 1
        fi
        cmp "$dir/before.key" "$dir/private.key"
    done
    [[ $(< "$dir/existing.bin") == preservar ]]
    "$tool" sign --scheme "$scheme" --key "$dir/private.key" \
        --message "$tmp/message.txt" --out "$dir/signature.bin"
    "$tool" verify --scheme "$scheme" --key "$dir/public.key" \
        --message "$tmp/message.txt" --signature "$dir/signature.bin"
done
