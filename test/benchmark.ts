import b from 'benny';
import {yescrypt, YESCRYPT_RW, YESCRYPT_WORM} from '../src';
import crypto from 'crypto';

const INPUT_16B = crypto.randomBytes(16);
const INPUT_256B = crypto.randomBytes(256);
const INPUT_4K = crypto.randomBytes(4096);
const SALT_16B = crypto.randomBytes(16);
const SALT_256B = crypto.randomBytes(256);

async function benchmarkWithParam(title: string, n: number, r: number, p: number, flags: number) {

    await b.suite(`${title} N=${n}, r=${r}, p=${p}`,
        b.add('Input 16B, Salt 16B', () => {
            yescrypt(INPUT_16B, SALT_16B, n, r, p, 0, 0, 256, flags);
        }),
        b.add('Input 256B, Salt 16B', () => {
            yescrypt(INPUT_256B, SALT_16B, n, r, p, 0, 0, 256, flags);
        }),
        b.add('Input 256B, Salt 256B', () => {
            yescrypt(INPUT_256B, SALT_256B, n, r, p, 0, 0, 256, flags);
        }),
        b.add('Input 4K, Salt 16B', () => {
            yescrypt(INPUT_4K, SALT_16B, n, r, p, 0, 0, 256, flags);
        }),
        b.add('Input 4K, Salt 256B', () => {
            yescrypt(INPUT_4K, SALT_16B, n, r, p, 0, 0, 256, flags);
        }),
        b.cycle(),
        b.complete(),
        b.save({file: `${title} RW N=${n}, r=${r}, p=${p}`}),
        b.save({file: `${title} RW N=${n}, r=${r}, p=${p}`, format: 'chart.html'}),
    );
}

Promise.resolve()
    .then(() => {
        return benchmarkWithParam('Yescrypt-Default', 2048, 8, 1, YESCRYPT_RW);
    }).then(() => {
        return benchmarkWithParam('Yescrypt-Default', 2048, 16, 1, YESCRYPT_RW);
    }).then(() => {
        return benchmarkWithParam('Yescrypt-Default', 4096, 16, 1, YESCRYPT_RW);
    }).then(() => {
        return benchmarkWithParam('Yescrypt-Default', 4096, 32, 1, YESCRYPT_RW);
    }).then(() => {
        return benchmarkWithParam('Yescrypt-WORM', 2048, 8, 1, YESCRYPT_WORM);
    }).then(() => {
        return benchmarkWithParam('Yescrypt-WORM', 2048, 16, 1, YESCRYPT_WORM);
    }).then(() => {
        return benchmarkWithParam('Yescrypt-WORM', 4096, 16, 1, YESCRYPT_WORM);
    }).then(() => {
        return benchmarkWithParam('Yescrypt-WORM', 4096, 32, 1, YESCRYPT_WORM);
    })
