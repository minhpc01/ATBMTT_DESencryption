class Des {

    /**
     * Des Cipher function: encrypt 'input' state with Rijndael algorithm [§5.1];
     *   applies Nr rounds (10/12/14) using key schedule w for 'add round key' stage.
     *
     * @param   {number[]}   input - 16-byte (128-bit) input state array.
     * @param   {number[][]} w - Key schedule as 2D byte-array (Nr+1 × Nb bytes).
     * @returns {number[]}   Encrypted output state array.
     */
    static cipher(input, w) {
        const Nb = 4;               // block size (in words): no of columns in state (fixed at 4 for Des)
        const Nr = w.length/Nb - 1; // no of rounds: 10/12/14 for 128/192/256-bit keys

        let state = [ [], [], [], [] ];  // initialise 4×Nb byte-array 'state' with input [§3.4]
        for (let i=0; i<4*Nb; i++) state[i%4][Math.floor(i/4)] = input[i];

        state = Des.addRoundKey(state, w, 0, Nb);

        for (let round=1; round<Nr; round++) {
            state = Des.subBytes(state, Nb);
            state = Des.shiftRows(state, Nb);
            state = Des.mixColumns(state, Nb);
            state = Des.addRoundKey(state, w, round, Nb);
        }

        state = Des.subBytes(state, Nb);
        state = Des.shiftRows(state, Nb);
        state = Des.addRoundKey(state, w, Nr, Nb);

        const output = new Array(4*Nb);  // convert state to 1-d array before returning [§3.4]
        for (let i=0; i<4*Nb; i++) output[i] = state[i%4][Math.floor(i/4)];

        return output;
    }


    /**
     * Perform key expansion to generate a key schedule from a cipher key [§5.2].
     *
     * @param   {number[]}   key - Cipher key as 16/24/32-byte array.
     * @returns {number[][]} Expanded key schedule as 2D byte-array (Nr+1 × Nb bytes).
     */
    static keyExpansion(key) {
        const Nb = 4;            // block size (in words): no of columns in state (fixed at 4 for Des)
        const Nk = key.length/4; // key length (in words): 4/6/8 for 128/192/256-bit keys
        const Nr = Nk + 6;       // no of rounds: 10/12/14 for 128/192/256-bit keys

        const w = new Array(Nb*(Nr+1));
        let temp = new Array(4);

        // initialise first Nk words of expanded key with cipher key
        for (let i=0; i<Nk; i++) {
            const r = [ key[4*i], key[4*i+1], key[4*i+2], key[4*i+3] ];
            w[i] = r;
        }

        // expand the key into the remainder of the schedule
        for (let i=Nk; i<(Nb*(Nr+1)); i++) {
            w[i] = new Array(4);
            for (let t=0; t<4; t++) temp[t] = w[i-1][t];
            // each Nk'th word has extra transformation
            if (i % Nk == 0) {
                temp = Des.subWord(Des.rotWord(temp));
                for (let t=0; t<4; t++) temp[t] ^= Des.rCon[i/Nk][t];
            }
            // 256-bit key has subWord applied every 4th word
            else if (Nk > 6 && i%Nk == 4) {
                temp = Des.subWord(temp);
            }
            // xor w[i] with w[i-1] and w[i-Nk]
            for (let t=0; t<4; t++) w[i][t] = w[i-Nk][t] ^ temp[t];
        }

        return w;
    }


    /**
     * Apply SBox to state S [§5.1.1].
     *
     * @private
     */
    static subBytes(s, Nb) {
        for (let r=0; r<4; r++) {
            for (let c=0; c<Nb; c++) s[r][c] = Des.sBox[s[r][c]];
        }
        return s;
    }


    /**
     * Shift row r of state S left by r bytes [§5.1.2].
     *
     * @private
     */
    static shiftRows(s, Nb) {
        const t = new Array(4);
        for (let r=1; r<4; r++) {
            for (let c=0; c<4; c++) t[c] = s[r][(c+r)%Nb];  // shift into temp copy
            for (let c=0; c<4; c++) s[r][c] = t[c];         // and copy back
        }          // note that this will work for Nb=4,5,6, but not 7,8 (always 4 for Des):
        return s;  // see asmDes.sourceforge.net/rijndael/rijndaelImplementation.pdf
    }


    /**
     * Combine bytes of each col of state S [§5.1.3].
     *
     * @private
     */
    static mixColumns(s, Nb) {
        for (let c=0; c<Nb; c++) {
            const a = new Array(Nb);  // 'a' is a copy of the current column from 's'
            const b = new Array(Nb);  // 'b' is a•{02} in GF(2^8)
            for (let r=0; r<4; r++) {
                a[r] = s[r][c];
                b[r] = s[r][c]&0x80 ? s[r][c]<<1 ^ 0x011b : s[r][c]<<1;
            }
            // a[n] ^ b[n] is a•{03} in GF(2^8)
            s[0][c] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3]; // {02}•a0 + {03}•a1 + a2 + a3
            s[1][c] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3]; // a0 • {02}•a1 + {03}•a2 + a3
            s[2][c] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3]; // a0 + a1 + {02}•a2 + {03}•a3
            s[3][c] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3]; // {03}•a0 + a1 + a2 + {02}•a3
        }
        return s;
    }


    /**
     * Xor Round Key into state S [§5.1.4].
     *
     * @private
     */
    static addRoundKey(state, w, rnd, Nb) {
        for (let r=0; r<4; r++) {
            for (let c=0; c<Nb; c++) state[r][c] ^= w[rnd*4+c][r];
        }
        return state;
    }


    /**
     * Apply SBox to 4-byte word w.
     *
     * @private
     */
    static subWord(w) {
        for (let i=0; i<4; i++) w[i] = Des.sBox[w[i]];
        return w;
    }


    /**
     * Rotate 4-byte word w left by one byte.
     *
     * @private
     */
    static rotWord(w) {
        const tmp = w[0];
        for (let i=0; i<3; i++) w[i] = w[i+1];
        w[3] = tmp;
        return w;
    }


}


// sBox is pre-computed multiplicative inverse in GF(2^8) used in subBytes and keyExpansion [§5.1.1]
Des.sBox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];


// rCon is Round Constant used for the Key Expansion [1st col is 2^(r-1) in GF(2^8)] [§5.2]
Des.rCon = [
    [ 0x00, 0x00, 0x00, 0x00 ],
    [ 0x01, 0x00, 0x00, 0x00 ],
    [ 0x02, 0x00, 0x00, 0x00 ],
    [ 0x04, 0x00, 0x00, 0x00 ],
    [ 0x08, 0x00, 0x00, 0x00 ],
    [ 0x10, 0x00, 0x00, 0x00 ],
    [ 0x20, 0x00, 0x00, 0x00 ],
    [ 0x40, 0x00, 0x00, 0x00 ],
    [ 0x80, 0x00, 0x00, 0x00 ],
    [ 0x1b, 0x00, 0x00, 0x00 ],
    [ 0x36, 0x00, 0x00, 0x00 ],
];


var IP_perm = new Array( -1,
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7 );

// final permutation (inverse initial permutation)
var FP_perm = new Array( -1,
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41, 9, 49, 17, 57, 25 );

// per-round expansion
var E_perm = new Array( -1,
	32, 1, 2, 3, 4, 5,
	4, 5, 6, 7, 8, 9,
	8, 9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32, 1 );

// per-round permutation
var P_perm = new Array( -1,
	16, 7, 20, 21, 29, 12, 28, 17,
	1, 15, 23, 26, 5, 18, 31, 10,
	2, 8, 24, 14, 32, 27, 3, 9,
	19, 13, 30, 6, 22, 11, 4, 25 );

// note we do use element 0 in the S-Boxes
var S1 = new Array(
	14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
	0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
	4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
	15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 );
var S2 = new Array(
	15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
	3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
	0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
	13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 );
var S3 = new Array(
	10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
	13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
	13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
	1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 );
var S4 = new Array(
	7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
	13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
	10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
	3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 );
var S5 = new Array(
	2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
	14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
	4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
	11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 );
var S6 = new Array(
	12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
	10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
	9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
	4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 );
var S7 = new Array(
	4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
	13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
	1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
	6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 );
var S8 = new Array(
	13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
	1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
	7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
	2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 );

//, first, key, permutation
var PC_1_perm = new Array( -1, 
	// C subkey bits
	57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
	10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
	// D subkey bits
	63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
	14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4 );

//, per-round, key, selection, permutation
var PC_2_perm = new Array( -1, 
	14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
	23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 );



/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

export default Des;