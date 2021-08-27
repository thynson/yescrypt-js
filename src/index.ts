/* eslint-disable */
// Requires the Stanford Javascript Cryptography Library (SJCL)
// https://bitwiseshiftleft.github.io/sjcl/
import sjcl from 'sjcl';

const PwxSimple = 2;
const PwxGather = 4;
const PwxRounds = 6;
const SWidth = 8;
const PwxBytes = PwxGather * PwxSimple * 8;
const PwxWords = PwxBytes / 4;
const SBytes = 3 * (1 << SWidth) * PwxSimple * 8;
const Swords = SBytes / 4;
const Smask = ((1 << SWidth) - 1) * PwxSimple * 8;
const RMin = (PwxBytes + 127) / 128;
export const YESCRYPT_RW = 2;
export const YESCRYPT_WORM = 1;
const YESCRYPT_PREHASH = 0x100000;

interface SBox {
    S: Uint32Array;
    S2: number;
    S1: number;
    S0: number;
    w: number;
}

function checkLittleEndian() {
    const u8 = new Uint8Array(2);
    u8[0] = 0;
    u8[1] = 0xff;
    const u16 = new Uint16Array(u8.buffer)[0];

    if (u16 == 0xff) {
        return false;
    } else if (u16 == 0xff00) {
        return true;
    } else {
        throw new Error('Broken execution environment: ' + typeof u16);
    }
}

const isLittleEndian = checkLittleEndian();

function swapEndian(x: number) {
    const a = x & 0xff,
        b = x & 0xff00,
        c = x & 0xff0000,
        d = x & 0xff000000;
    return (a << 24) + (b << 8) + (c >> 8) + (d >> 24);
}

export function yescrypt(
    password: Uint8Array,
    salt: Uint8Array,
    N: number,
    r: number,
    p: number,
    t: number,
    g: number,
    dkLen: number,
    flags: number = YESCRYPT_RW,
) {

    if (!isInt32(flags) || (flags & ~(YESCRYPT_RW | YESCRYPT_WORM | YESCRYPT_PREHASH)) !== 0) {
        throw Error('Unknown flags.');
    }
    if (flags === 0) {
        throw 'flags shall be either YESCRYPT_RW or YESCRYPT_WORM';
    }

    if (!isInt32(N)) {
        throw 'N is not an integer.';
    }

    if (!isInt32(r)) {
        throw 'r is not an integer.';
    }

    if (!isInt32(p)) {
        throw 'p is not an integer.';
    }

    if (!isInt32(t)) {
        throw 't is not an integer.';
    }

    if (!isInt32(g)) {
        throw 'g is not an integer.';
    }

    if (!isInt32(dkLen)) {
        throw 'dkLen is not an itneger.';
    }

    if ((N & (N - 1)) !== 0) {
        throw 'N is not a power of two.';
    }

    if (N <= 1) {
        throw 'N is too small.';
    }

    if (r < 1) {
        throw 'r is too small.';
    }

    if (p < 1) {
        throw 'p is too small.';
    }

    if (g < 0) {
        throw 'g must be non-negative.';
    }

    if (flags === 0 && t !== 0) {
        throw 'Can not use t > 0 without flags.';
    }

    if (!isInt32(p * 128 * r)) {
        throw 'Integer overflow when calculating p * 128 * r.';
    }

    if ((flags & YESCRYPT_RW) !== 0 && Math.floor(N / p) <= 1) {
        throw 'YESCRYPT_RW requires N/p >= 2.';
    }

    if ((flags & YESCRYPT_RW) !== 0 && p >= 1 && Math.floor(N / p) >= 0x100 && Math.floor(N / p) * r >= 0x20000) {
        password = yescrypt(password, salt, N >> 6, r, p, 0, 0, 32, flags | YESCRYPT_PREHASH);
    }

    let dklen_g;
    for (let i = 0; i <= g; i++) {
        if (i == g) {
            dklen_g = dkLen;
        } else {
            dklen_g = 32;
        }

        password = yescryptKdfBody(password, salt, N, r, p, t, dklen_g, flags);

        // XXX: watch for overflow on this one
        N <<= 2;
        t >>>= 1;
    }

    return password;
}

/*
 * password:    a Uint8Array.
 * salt:        a Uint8Array.
 *
 * Returns:     a Uint8Array.
 */
function yescryptKdfBody(
    password: Uint8Array,
    salt: Uint8Array,
    N: number,
    r: number,
    p: number,
    t: number,
    dkLen: number,
    flags: number = YESCRYPT_RW,
) {
    if (flags != 0) {
        let key = 'yescrypt';
        if ((flags & YESCRYPT_PREHASH) !== 0) {
            key += '-prehash';
        }
        password = hmacSha256(convertStringToUint8Array(key), password);
    }

    let bytes = pbkdf2Sha256(password, salt, 1, p * 128 * r);
    // TODO: Switch endianness here on big-endian platforms.
    // View the PBKDF2 results as an array of Uint32.
    let B = new Uint32Array(bytes.buffer);
    if (!isLittleEndian) {
        B = B.map(swapEndian);
    }

    if (flags !== 0) {
        password = bytes.slice(0, 32);
    }

    if ((flags & YESCRYPT_RW) !== 0) {
        sMix(N, r, t, p, B, flags, password);
    } else {
        for (let i = 0; i < p; i++) {
            const Bi = new Uint32Array(B.buffer, B.byteOffset + i * 2 * r * 16 * 4, 2 * r * 16);
            sMix(N, r, t, 1, Bi, flags, password);
        }
    }
    if (!isLittleEndian) {
        B = B.map(swapEndian);
        bytes = new Uint8Array(B.buffer);
    }


    const result = pbkdf2Sha256(password, bytes, 1, Math.max(dkLen, 32));

    if ((flags & (YESCRYPT_RW | YESCRYPT_WORM)) !== 0 && (flags & YESCRYPT_PREHASH) === 0) {
        const clientValue = new Uint8Array(result.buffer, result.byteOffset, 32);
        const clientKey = hmacSha256(clientValue, convertStringToUint8Array('Client Key'));
        const storedKey = sha256(clientKey);

        result.set(storedKey, 0);
    }

    // XXX we shouldn't be keeping around all that memory (gc attacks)
    return new Uint8Array(result.buffer, result.byteOffset + 0, dkLen);
}

function sMix(
    N: number,
    r: number,
    t: number,
    p: number,
    blocks: Uint32Array,
    flags: number,
    sha256?: Uint8Array,
) {
    // blocks should be p blocks (each 2*r cells).
    assert(blocks.length == p * 2 * r * 16);

    const sboxes: (SBox | null)[] = [];
    for (let i = 0; i < p; i++) {
        const sbox: SBox = {
            S: new Uint32Array(Swords),
            S2: 0,
            S1: 1024, // SWORDS / 3,
            S0: 2048, // (SWORDS / 3) * 2,
            w: 0,
        };
        sboxes.push(sbox);
    }

    let n = Math.floor(N / p);
    let Nloop_all = fNLoop(n, t, flags);
    let Nloop_rw = 0;
    if ((flags & YESCRYPT_RW) !== 0) {
        Nloop_rw = Math.floor(Nloop_all / p);
    }

    n = n - (n & 1);

    Nloop_all = Nloop_all + (Nloop_all & 1);
    Nloop_rw += 1;
    Nloop_rw = Nloop_rw - (Nloop_rw & 1);

    // Allocate N blocks.
    let V = new Uint32Array(N * 2 * r * 16);

    for (let i = 0; i < p; i++) {
        const v = i * n;
        if (i === p - 1) {
            n = N - v;
        }

        if ((flags & YESCRYPT_RW) !== 0) {
            const twoCells = new Uint32Array(blocks.buffer, blocks.byteOffset + i * 2 * r * 16 * 4, 2 * 16);
            sMix1(1, twoCells, SBytes / 128, sboxes[i]!.S, flags & ~YESCRYPT_RW, null);
            if (i == 0) {
                const for_sha256_update = new Uint8Array(
                    blocks.buffer,
                    blocks.byteOffset + (i * 2 * r * 16 + 2 * r * 16 - 16) * 4,
                    64,
                );
                const sha256_updated = hmacSha256(for_sha256_update, sha256!);
                sha256!.set(sha256_updated);
            }
        } else {
            sboxes[i] = null;
        }

        const BlockI = new Uint32Array(blocks.buffer, blocks.byteOffset + i * 2 * r * 16 * 4, 2 * r * 16);
        const VPart = new Uint32Array(V.buffer, V.byteOffset + v * 2 * r * 16 * 4, n * 2 * r * 16);
        sMix1(r, BlockI, n, VPart, flags, sboxes[i]);

        sMix2(r, BlockI, p2floor(n), Nloop_rw, VPart, flags, sboxes[i]!);
    }

    for (let i = 0; i < p; i++) {
        const BlockI = new Uint32Array(blocks.buffer, blocks.byteOffset + i * 2 * r * 16 * 4, 2 * r * 16);
        sMix2(r, BlockI, N, Nloop_all - Nloop_rw, V, flags & ~YESCRYPT_RW, sboxes[i]!);
    }
}

function sMix1(
    r: number,
    block: Uint32Array,
    N: number,
    outputBlocks: Uint32Array,
    flags: number,
    sBox: SBox | null,
) {
    shuffleBlock(2 * r, block);

    for (let i = 0; i < N; i++) {
        // OutputBlock[i] = Block
        outputBlocks.set(block, i * 2 * r * 16);

        if (false && (i & 1) !== 0) {
            // TODO: ROM support.
        } else if ((flags & YESCRYPT_RW) !== 0 && i > 1) {
            const j = wrap(integerify(r, block), i);
            // Block = Block XOR OutputBlocks[j]
            blockXor(block, 0, outputBlocks, j * 2 * r * 16, 2 * r * 16);
        }

        if (!sBox) {
            blockMixSalsa8(r, block);
        } else {
            blockMixPwxForm(r, block, sBox);
        }
    }

    unshuffleBlock(2 * r, block);
}

function sMix2(
    r: number,
    block: Uint32Array,
    N: number,
    NLoop: number,
    outputBlocks: Uint32Array,
    flags: number,
    sBox: SBox,
) {
    shuffleBlock(2 * r, block);

    for (let i = 0; i < NLoop; i++) {
        if (false && i % 2 !== 0) {
            // TODO: ROM support.
        } else {
            const j = integerify(r, block) & (N - 1);
            // Block = Block XOR OutputBlocks[j]
            blockXor(block, 0, outputBlocks, j * 2 * r * 16, 2 * r * 16);

            if ((flags & YESCRYPT_RW) !== 0) {
                outputBlocks.set(block, j * 2 * r * 16);
            }
        }

        if (sBox === null) {
            blockMixSalsa8(r, block);
        } else {
            blockMixPwxForm(r, block, sBox);
        }
    }

    unshuffleBlock(2 * r, block);
}

function blockMixPwxForm(r: number, block: Uint32Array, sBox: SBox) {
    assert(sBox !== null);

    const pwxBlocks = 2 * r; // (2 * r * 16) / PWXWORDS

    const X = block.slice(block.length - PwxWords);

    for (let i = 0; i < pwxBlocks; i++) {
        if (pwxBlocks > 1) {
            blockXor(X, 0, block, i * PwxWords, PwxWords);
        }

        pwxForm(X, sBox);

        block.set(X, i * PwxWords);
    }

    // TODO: just make sure PWXWORDS is divisible by 16
    // let i = Math.floor(((pwx_blocks - 1) * PWXWORDS) / 16);
    let i = pwxBlocks - 1;
    salsa20(new Uint32Array(block.buffer, block.byteOffset + i * 16 * 4, 16), 2);

    // TODO: check this stuff
    for (i = i + 1; i < 2 * r; i++) {
        blockXor(block, i * 16, block, (i - 1) * 16, 16);
        salsa20(new Uint32Array(block.buffer, block.byteOffset + i * 16 * 4, 16), 2);
    }
}

function multiplyUint64(a: number, b: number): [number, number] {
    let al = a & 0xffff;
    let ah = a >>> 16;
    let bl = b & 0xffff;
    let bh = b >>> 16;

    let h = ah * bh;
    let l = al * bl;
    let p = ah * bl;
    let q = al * bh;

    l += ((p & 0xffff) << 16) >>> 0;
    h += p >>> 16;
    if (l >= 2 ** 32) {
        h += 1;
        l -= 2 ** 32;
    }
    l += ((q & 0xffff) << 16) >>> 0;
    h += q >>> 16;
    if (l >= 2 ** 32) {
        h += 1;
        l -= 2 ** 32;
    }
    return [h, l];
}

function addUint64(a: [number, number], b: [number, number]) {
    a[0] += b[0];
    a[1] += b[1];
    if (a[1] >= 2 ** 32) {
        a[0] += 1;
        a[1] -= 2 ** 32;
    }
}

function blockXor(a: Uint32Array, aOffset: number, b: Uint32Array, bOffset: number, size: number) {
    for (let i = 0; i < size; i++) {
        a[aOffset + i] ^= b[bOffset + i];
    }
}

function pwxForm(pwxblock: Uint32Array, sbox: SBox) {
    assert(pwxblock.length === PwxWords);
    assert(sbox.S.length === Swords);

    const S0 = sbox.S0;
    const S1 = sbox.S1;
    const S2 = sbox.S2;

    for (let i = 0; i < PwxRounds; i++) {
        for (let j = 0; j < PwxGather; j++) {
            const x_lo = pwxblock[2 * j * PwxSimple];
            const x_hi = pwxblock[2 * j * PwxSimple + 1];

            const p0 = (x_lo & Smask) >>> 4; // (x_lo & SMASK)/ (PWXSIMPLE * 8);
            const p1 = (x_hi & Smask) >>> 4; // (x_hi & SMASK)/ (PWXSIMPLE * 8);

            for (let k = 0; k < PwxSimple; k++) {
                const lo = pwxblock[2 * (j * PwxSimple + k)];
                const hi = pwxblock[2 * (j * PwxSimple + k) + 1];

                const s0_lo = sbox.S[S0 + 2 * (p0 * PwxSimple + k)];
                const s0_hi = sbox.S[S0 + 2 * (p0 * PwxSimple + k) + 1];

                const s1_lo = sbox.S[S1 + 2 * (p1 * PwxSimple + k)];
                const s1_hi = sbox.S[S1 + 2 * (p1 * PwxSimple + k) + 1];

                let M = multiplyUint64(hi, lo);
                addUint64(M, [s0_hi, s0_lo]);
                let [mul_hi, mul_lo] = M;

                mul_lo ^= s1_lo;
                mul_hi ^= s1_hi;

                // Make them positive after bitwise op.
                mul_lo >>>= 0;
                mul_hi >>>= 0;

                pwxblock[2 * (j * PwxSimple + k)] = mul_lo;
                pwxblock[2 * (j * PwxSimple + k) + 1] = mul_hi;

                if (i != 0 && i != PwxRounds - 1) {
                    sbox.S[S2 + 2 * sbox.w] = mul_lo;
                    sbox.S[S2 + 2 * sbox.w + 1] = mul_hi;
                    sbox.w += 1;
                }
            }
        }
    }

    sbox.S0 = S2;
    sbox.S1 = S0;
    sbox.S2 = S1;
    sbox.w = sbox.w & (Smask >>> 3); // sbox.w & (SMASK / 8);
}

function blockMixSalsa8(r: number, block: Uint32Array) {
    const X = block.slice(16 * (2 * r - 1), 16 * 2 * r);
    const Y = new Uint32Array(2 * r * 16);
    for (let i = 0; i < 2 * r; i++) {
        // X = X XOR Block[i]
        blockXor(X, 0, block, i * 16, 16);
        salsa20(X, 8);
        Y.set( X, ((i & 1) * r + (i >>> 1)) * 16);
    }
    block.set(Y);
}

function salsa20(cell: Uint32Array, rounds: number) {
    unshuffleBlock(1, cell);

    const x = cell.slice(0, 16);

    // This was partially copypasted from
    // https://raw.githubusercontent.com/neoatlantis/node-salsa20/master/salsa20.js
    function R(a: number, b: number) {
        return (a << b) | (a >>> (32 - b));
    }

    for (let i = rounds; i > 0; i -= 2) {
        x[4] ^= R(x[0] + x[12], 7);
        x[8] ^= R(x[4] + x[0], 9);
        x[12] ^= R(x[8] + x[4], 13);
        x[0] ^= R(x[12] + x[8], 18);
        x[9] ^= R(x[5] + x[1], 7);
        x[13] ^= R(x[9] + x[5], 9);
        x[1] ^= R(x[13] + x[9], 13);
        x[5] ^= R(x[1] + x[13], 18);
        x[14] ^= R(x[10] + x[6], 7);
        x[2] ^= R(x[14] + x[10], 9);
        x[6] ^= R(x[2] + x[14], 13);
        x[10] ^= R(x[6] + x[2], 18);
        x[3] ^= R(x[15] + x[11], 7);
        x[7] ^= R(x[3] + x[15], 9);
        x[11] ^= R(x[7] + x[3], 13);
        x[15] ^= R(x[11] + x[7], 18);
        x[1] ^= R(x[0] + x[3], 7);
        x[2] ^= R(x[1] + x[0], 9);
        x[3] ^= R(x[2] + x[1], 13);
        x[0] ^= R(x[3] + x[2], 18);
        x[6] ^= R(x[5] + x[4], 7);
        x[7] ^= R(x[6] + x[5], 9);
        x[4] ^= R(x[7] + x[6], 13);
        x[5] ^= R(x[4] + x[7], 18);
        x[11] ^= R(x[10] + x[9], 7);
        x[8] ^= R(x[11] + x[10], 9);
        x[9] ^= R(x[8] + x[11], 13);
        x[10] ^= R(x[9] + x[8], 18);
        x[12] ^= R(x[15] + x[14], 7);
        x[13] ^= R(x[12] + x[15], 9);
        x[14] ^= R(x[13] + x[12], 13);
        x[15] ^= R(x[14] + x[13], 18);
    }

    for (let i = 0; i < 16; i++) {
        cell[i] = (x[i] + cell[i]) & 0xffffffff;
    }

    shuffleBlock(1, cell);
}

function shuffleBlock(r: number, block: Uint32Array) {
    const saved = new Uint32Array(16);
    for (let i = 0; i < r; i++) {
        for (let j = 0; j < 16; j++) {
            saved[j] = block[i * 16 + ((j * 5) % 16)];
        }
        for (let j = 0; j < 16; j++) {
            block[i * 16 + j] = saved[j];
        }
    }
}

function unshuffleBlock(r: number, block: Uint32Array) {
    const saved = new Uint32Array(16);
    for (let i = 0; i < r; i++) {
        // Saved = Block[i]
        for (let j = 0; j < 16; j++) {
            saved[j] = block[i * 16 + j];
        }
        for (let j = 0; j < 16; j++) {
            block[i * 16 + ((j * 5) % 16)] = saved[j];
        }
    }
}

function integerify(r: number, block: Uint32Array) {
    return block[(2 * r - 1) * 16];
}

function fNLoop(n: number, t: number, flags: number) {
    if ((flags & YESCRYPT_RW) !== 0) {
        if (t === 0) {
            return Math.floor((n + 2) / 3);
        } else if (t == 1) {
            return Math.floor((2 * n + 2) / 3);
        } else {
            return (t - 1) * n;
        }
    } else if ((flags & YESCRYPT_WORM) !== 0) {
        if (t === 0) {
            return n;
        } else if (t == 1) {
            return n + Math.floor((n + 1) / 2);
        } else {
            return t * n;
        }
    } else {
        return n;
    }
}

function p2floor(x: number) {
    let y;
    while ((y = x & (x - 1)) !== 0) {
        x = y;
    }
    return x;
}

function wrap(x: number, i: number) {
    let n = p2floor(i);
    return (x & (n - 1)) + (i - n);
}

function sha256(message: Uint8Array) {
    const _message = convertUint8ArrayToBitArray(message);
    const result = sjcl.hash.sha256.hash(_message);
    return convertBitArrayToUint8Array(result);
}

function hmacSha256(key: Uint8Array, message: Uint8Array) {
    const _message = convertUint8ArrayToBitArray(message);
    const _key = convertUint8ArrayToBitArray(key);
    const hmac = new sjcl.misc.hmac(_key);
    const result = hmac.mac(_message);
    return convertBitArrayToUint8Array(result);
}

function pbkdf2Sha256(password: Uint8Array, salt: Uint8Array, count: number, length: number) {
    const _password = convertUint8ArrayToBitArray(password);
    const _salt = convertUint8ArrayToBitArray(salt);
    const result = sjcl.misc.pbkdf2(_password, _salt, count, length * 8);
    return convertBitArrayToUint8Array(result);
}

function convertUint8ArrayToBitArray(uint8Array: Uint8Array) {
    // Convert to hex...
    let hex = '';
    for (let i = 0; i < uint8Array.length; i++) {
        hex += (uint8Array[i] >> 4).toString(16);
        hex += (uint8Array[i] & 0x0f).toString(16);
    }
    // ...and then to bitArray.
    return sjcl.codec.hex.toBits(hex);
}

function convertBitArrayToUint8Array(bitArray: sjcl.BitArray) {
    // Convert to hex...
    const hex = sjcl.codec.hex.fromBits(bitArray);
    // ...and then to Uint8Array.
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

function convertStringToUint8Array(asciiString: string) {
    const bytes = new Uint8Array(asciiString.length);
    for (let i = 0; i < asciiString.length; i++) {
        bytes[i] = asciiString.charCodeAt(i);
    }
    return bytes;
}

// Copied from: http://stackoverflow.com/a/3885844
function isInt32(n: number) {
    return n === +n && n === (n | 0);
}

function assert(truth_value: any, message?: string) {
    message = message || 'No message given.';
    if (!truth_value) {
        throw 'Assertion failed. Message: ' + message;
    }
}

