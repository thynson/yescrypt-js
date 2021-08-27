import {yescrypt, YESCRYPT_RW, YESCRYPT_WORM} from '../src';

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
console.log('is little endian: ', isLittleEndian);
function convertUint8ArrayToHex(uint8Array: Uint8Array) {
    let hex = '';
    for (let i = 0; i < uint8Array.length; i++) {
        hex += (uint8Array[i]! >> 4).toString(16);
        hex += (uint8Array[i]! & 0x0f).toString(16);
    }
    return hex;
}

function strToUint8(str: string) {
    // XXX: this is not correct for unicode strings.
    const bytes = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        bytes[i] = str.charCodeAt(i);
    }
    return bytes;
}

jest.setTimeout(300000);

test('Yescrypt', () => {

    expect(convertUint8ArrayToHex(yescrypt(strToUint8('p'), strToUint8('s'), 16, 8, 1, 0, 0, 16, YESCRYPT_RW))).toBe(
        'c8c7ff1122b0b291c3f2608948782cd6',
    );
    expect(convertUint8ArrayToHex(yescrypt(strToUint8('p'), strToUint8('s'), 16, 8, 4, 0, 0, 16, YESCRYPT_RW))).toBe(
        'e2ad06a9340816659d45e0dd3d8260a6',
    );

    expect(convertUint8ArrayToHex(yescrypt(strToUint8('p'), strToUint8('s'), 16, 8, 1, 0, 0, 16, YESCRYPT_WORM))).toBe(
        '9dd636c2d0bb92345286efdaf8a68cfc',
    );

    expect(convertUint8ArrayToHex(yescrypt(strToUint8('p'), strToUint8('s'), 16, 8, 4, 0, 0, 16, YESCRYPT_WORM))).toBe(
        '28e64f65a134d187ed3b16d73973c820',
    );
    expect(convertUint8ArrayToHex(yescrypt(strToUint8('p'), strToUint8('s'), 16, 8, 1, 0, 0, 16, 0))).toBe(
        '4efe92b5bba5ee1837b4b02b67dc2dbd',
    );

    expect(convertUint8ArrayToHex(yescrypt(strToUint8('p'), strToUint8('s'), 16, 8, 4, 0, 0, 16, 0))).toBe(
        '3a84ecee9f4d433e8ef75aec28a5daa3',
    );

    expect(convertUint8ArrayToHex(yescrypt(strToUint8('p'), strToUint8('s'), 16384, 8, 1, 0, 0, 16, YESCRYPT_RW))).toBe(
        '648a7f55b1f5f083c190829860e09d37',
    );
    expect(convertUint8ArrayToHex(yescrypt(strToUint8('p'), strToUint8('s'), 16384, 8, 4, 0, 0, 16, YESCRYPT_RW))).toBe(
        'ca813c704119b47cbec20ac8faa72dfe',
    );

    expect(convertUint8ArrayToHex(yescrypt(strToUint8('p'), strToUint8('s'), 16384, 8, 1, 0, 0, 16, YESCRYPT_WORM))).toBe(
        'd44199db46046d92fb844964c099caa7',
    );

    expect(convertUint8ArrayToHex(yescrypt(strToUint8('p'), strToUint8('s'), 16384, 8, 4, 0, 0, 16, YESCRYPT_WORM))).toBe(
        '3d667b9a722cc915fbf008911c88ceca',
    );

    expect(convertUint8ArrayToHex(yescrypt(strToUint8('p'), strToUint8('s'), 16384, 8, 1, 0, 0, 16, 0))).toBe(
        '4329787752e75d1de359a05806e492d4',
    );

    expect(convertUint8ArrayToHex(yescrypt(strToUint8('p'), strToUint8('s'), 16384, 8, 4, 0, 0, 16, 0))).toBe(
        '949c1fb99e622cb8447b3b1dfd009cd2',
    );
});
