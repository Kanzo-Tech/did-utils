import crypto from 'crypto';
import elliptic from 'elliptic';

//first option is command-line dependant, if no argument is included the default value is 32
const size = parseInt(process.argv.slice(2)[0]) || 32;   
const randomString = crypto.randomBytes(size).toString("hex");
const key = randomString;


console.log (`Key (hex): ${key}`);

// Calculate the `secp256k1` curve and build the public key
const ec = new elliptic.ec('secp256k1');
const prv = ec.keyFromPrivate(key, 'hex');    
const pub = prv.getPublic();
console.log(`Public (hex): ${prv.getPublic('hex')}`)
console.log(`x (hex): ${pub.x.toBuffer().toString('hex')}`)
console.log(`y (hex): ${pub.y.toBuffer().toString('hex')}`)
console.log(`x (base64): ${pub.x.toBuffer().toString('base64')}`)
console.log(`y (base64): ${pub.y.toBuffer().toString('base64')}`)
console.log(`-- kty: EC, crv: secp256k1`)