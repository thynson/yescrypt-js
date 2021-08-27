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

    // expect(convertUint8ArrayToHex(yescrypt(strToUint8('p'), strToUint8('s'), 1048576, 8, 1, 0, 0, 16, YESCRYPT_RW))).toBe(
    //     'b09179269b2b949ae6c79e45e040cd7f',
    // );
    // expect(convertUint8ArrayToHex(yescrypt(strToUint8('p'), strToUint8('s'), 1048576, 8, 4, 0, 0, 16, YESCRYPT_RW))).toBe(
    //     'fdafee4329b22265473264e3522c91d7',
    // );

    // expect(convertUint8ArrayToHex(yescrypt(strToUint8('p'), strToUint8('s'), 1048576, 8, 1, 0, 0, 16, YESCRYPT_WORM))).toBe(
    //     '270f0d216fc8d9e64357da861c0ec9ba',
    // );
    //
    // expect(convertUint8ArrayToHex(yescrypt(strToUint8('p'), strToUint8('s'), 1048576, 8, 4, 0, 0, 16, YESCRYPT_WORM))).toBe(
    //     '524a6a6ff74db4aa91e2beff86de06b1',
    // );

});
