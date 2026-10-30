const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const vm = require('node:vm');
const { transform } = require('../server');

const appSource=fs.readFileSync(require.resolve('../app'),'utf8');
const cipherStart=appSource.indexOf('function classicalTransform('),cipherEnd=appSource.indexOf('function renderExecutionFlow(',cipherStart);
const classroomCiphers=vm.runInNewContext(`(()=>{const matrixSelect={value:'2'};const document={querySelector:()=>matrixSelect};${appSource.slice(cipherStart,cipherEnd)};return {classicalTransform,playfairSquare,playfairTransform,hillTransform,matrixSelect}})()`,{abc:'ABCDEFGHIJKLMNOPQRSTUVWXYZ'});

test('AES block primitive matches a NIST known-answer block', () => {
  const key=Buffer.from('2b7e151628aed2a6abf7158809cf4f3c','hex');
  const plaintext=Buffer.from('6bc1bee22e409f96e93d7e117393172a','hex');
  const cipher=crypto.createCipheriv('aes-128-ecb',key,null);cipher.setAutoPadding(false);
  assert.equal(Buffer.concat([cipher.update(plaintext),cipher.final()]).toString('hex'),'3ad77bb40d7a3660a89ecaf32466ef97');
});

test('AES key sizes encrypt and decrypt independent blocks', () => {
  for (const key of ['0123456789abcdef','0123456789abcdefghijklmn','0123456789abcdefghijklmnopqrstuv']) {
    const input = { algorithm: 'aes', key, text: 'CNS laboratory input 123' };
    const encrypted = transform({ ...input, action: 'encrypt' });
    assert.match(encrypted, /^(?:[0-9a-f]{2})+$/i, `AES key length ${key.length} returns hex`);
    assert.equal(transform({ ...input, action: 'decrypt', text: encrypted }), input.text, `AES key length ${key.length} round trips`);
  }
});

test('DES encrypts and decrypts independent blocks', () => {
  const input={algorithm:'des',key:'12345678',text:'NETWORK SECURITY'};
  const encrypted=transform({...input,action:'encrypt'});
  assert.equal(transform({...input,action:'decrypt',text:encrypted}),input.text);
});

test('Double DES and EDE Triple DES encrypt with ordered DES passes', () => {
  for (const algorithm of ['2des','3des']) {
    const input={algorithm,keys:['12345678','abcdefgh','87654321'],text:'CNS demo'};
    const encrypted=transform({...input,action:'encrypt'});
    assert.equal(transform({...input,action:'decrypt',text:encrypted}),input.text,`${algorithm} round trips`);
  }
});

test('Detailed AES execution reports key size, round count and block results', () => {
  const result=transform({action:'encrypt',algorithm:'aes',key:'0123456789abcdef0123456789abcdef',text:'NETWORK SECURITY LAB',detailed:true});
  const blocks=result.steps.filter(step=>step.char.startsWith('Block '));
  assert.equal(blocks.length,2);
  assert.match(result.steps.find(step=>step.char.startsWith('AES block')).operation,/14 rounds/);
  assert.match(result.steps.find(step=>step.operation==='PKCS#7 padding').result,/^[0-9a-f]+$/);
});

test('DES rejects keys that are not eight UTF-8 bytes', () => {
  assert.throws(() => transform({ action: 'encrypt', algorithm: 'des', key: 'short', text: 'hello' }), /exactly 8 UTF-8 bytes/);
});

test('decrypt rejects malformed hex', () => {
  assert.throws(() => transform({ action: 'decrypt', algorithm: 'aes', key: '0123456789abcdef', text: 'xyz' }), /hexadecimal/);
});

test('Vigenere matches the classic ATTACKATDAWN / LEMON example', () => {
  const {classicalTransform:f}=classroomCiphers,steps=[],maps=[];
  assert.equal(f('vigenere','ATTACKATDAWN','LEMON','encrypt',steps,maps),'LXFOPVEFRNHR');
  assert.equal(f('vigenere','LXFOPVEFRNHR','LEMON','decrypt',[],[]),'ATTACKATDAWN');
});

test('Playfair encrypts and decrypts digraphs with the keyed square', () => {
  const {classicalTransform:f}=classroomCiphers;
  const cipher=f('playfair','HIDETHEGOLDINTHETREESTUMP','PLAYFAIR EXAMPLE','encrypt',[],[]);
  assert.equal(cipher,'BMODZBXDNABEKUDMUIXMMOUVIF');
  // Filler X inserted between repeated E letters is retained on decryption.
  assert.equal(f('playfair',cipher,'PLAYFAIR EXAMPLE','decrypt',[],[]),'HIDETHEGOLDINTHETREXESTUMP');
});

test('Hill cipher encrypts and decrypts with an invertible 2x2 matrix', () => {
  const {classicalTransform:f}=classroomCiphers;
  const cipher=f('hill','HELP','3,3,2,5','encrypt',[],[]);
  assert.equal(cipher,'HIAT');
  assert.equal(f('hill',cipher,'3,3,2,5','decrypt',[],[]),'HELP');
});

test('Hill cipher matches the classic 3x3 ACT / POH example', () => {
  const {classicalTransform:f}=classroomCiphers;
  classroomCiphers.matrixSelect.value='3';
  const key='6,24,1,13,16,10,20,17,15';
  assert.equal(f('hill','ACT',key,'encrypt',[],[]),'POH');
  assert.equal(f('hill','POH',key,'decrypt',[],[]),'ACT');
  classroomCiphers.matrixSelect.value='2';
});

test('Repeating polyalphabetic shifts preserve punctuation and reverse correctly', () => {
  const {classicalTransform:f}=classroomCiphers;
  const cipher=f('polyalphabetic','Meet me!','3,1,4','encrypt',[],[]);
  assert.equal(f('polyalphabetic',cipher,'3,1,4','decrypt',[],[]),'Meet me!');
});

test('Triple DES trace exposes actual EDE pass order, keys and intermediate blocks', () => {
  const r=transform({action:'encrypt',algorithm:'3des',keys:['12345678','abcdefgh','87654321'],text:'hello',detailed:true});
  const stages=r.steps.filter(s=>s.char.includes('Stage'));
  assert.deepEqual(stages.map(s=>s.operation.split(' · ')[0]),['Encrypt DES','Decrypt DES','Encrypt DES']);
  assert.match(stages[0].calculation,/key K1=3132333435363738/);
  assert.notEqual(stages[0].result,stages[1].result);
});

test('Modes of operation round-trip through both AES and DES', () => {
  const modes=['ecb','cbc','cfb','ofb','ctr'];
  for(const [algorithm,key,iv] of [['aes','0123456789abcdef0123456789abcdef','1234567890abcdef'],['des','12345678','12345678']]){
    for(const mode of modes){
      const input={algorithm,key,iv,mode,text:'Modes of operation test'};
      const encrypted=transform({...input,action:'encrypt'});
      assert.equal(transform({...input,action:'decrypt',text:encrypted}),input.text,`${algorithm}/${mode} round trip`);
    }
  }
});

test('Mode traces show CBC chaining and require a full-size IV', () => {
  const result=transform({action:'encrypt',algorithm:'aes',mode:'cbc',key:'0123456789abcdef0123456789abcdef',iv:'1234567890abcdef',text:'trace this',detailed:true});
  assert.match(result.steps.find(s=>s.char==='Block 01').calculation,/XOR/);
  assert.throws(()=>transform({action:'encrypt',algorithm:'aes',mode:'cbc',key:'0123456789abcdef0123456789abcdef',iv:'short',text:'x'}),/exactly 16 UTF-8 bytes/);
  assert.throws(()=>transform({action:'encrypt',algorithm:'2des',mode:'cbc',key:'12345678',keys:['12345678','abcdefgh'],iv:'12345678',text:'x'}),/AES or DES only/);
});

