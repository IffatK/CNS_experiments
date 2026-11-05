const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const root = __dirname;
const mime = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8', '.mp4': 'video/mp4' };
const send = (res, status, data) => { res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }); res.end(JSON.stringify(data)); };
const toHex = b => Buffer.from(b).toString('hex');
const fromHex = s => { if (!/^(?:[0-9a-f]{2})+$/i.test(s)) throw Error('Ciphertext must be even-length hexadecimal.'); return Buffer.from(s, 'hex'); };
const bytes = s => Buffer.from(s, 'utf8');
function transform({action, algorithm, text, key, keys, mode, iv, detailed=false}) {
  const decrypt=action==='decrypt';
  const trace=[];
  let blockSize,encBlock,decBlock,kb,ks,single;
  if(algorithm==='aes'){
    kb=bytes(key);if(![16,24,32].includes(kb.length))throw Error('AES key must be 16, 24, or 32 bytes.');blockSize=16;
    const raw=(input,dec)=>{const c=dec?crypto.createDecipheriv(`aes-${kb.length*8}-ecb`,kb,null):crypto.createCipheriv(`aes-${kb.length*8}-ecb`,kb,null);c.setAutoPadding(false);return Buffer.concat([c.update(input),c.final()]);};
    encBlock=b=>raw(b,false);decBlock=b=>raw(b,true);
  }else{
    const dk=x=>{const b=bytes(x||'');if(b.length!==8)throw Error('Each DES key must be exactly 8 UTF-8 bytes.');return b;};
    ks=algorithm==='des'?[dk(key)]:algorithm==='2des'?[dk(keys?.[0]||key),dk(keys?.[1])]:algorithm==='3des'?[dk(keys?.[0]||key),dk(keys?.[1]),dk(keys?.[2]||keys?.[0]||key)]:null;
    if(!ks)throw Error('Unsupported block cipher.');blockSize=8;
    single=(data,k,dec)=>{const triple=Buffer.concat([k,k,k]);const c=dec?crypto.createDecipheriv('des-ede3-ecb',triple,null):crypto.createCipheriv('des-ede3-ecb',triple,null);c.setAutoPadding(false);return Buffer.concat([c.update(data),c.final()]);};
    if(algorithm==='des'){encBlock=b=>single(b,ks[0],false);decBlock=b=>single(b,ks[0],true);}
    else if(algorithm==='2des'){encBlock=b=>single(single(b,ks[0],false),ks[1],false);decBlock=b=>single(single(b,ks[1],true),ks[0],true);}
    else{encBlock=b=>single(single(single(b,ks[0],false),ks[1],true),ks[2],false);decBlock=b=>single(single(single(b,ks[2],true),ks[1],false),ks[0],true);}
  }
  const applyPrimitive=(data, decryptBlock, blockNo) => {
    const record=(stage,input,k,out,dec,rounds=16)=>{ if(detailed) trace.push({char:`Block ${String(blockNo).padStart(2,'0')} · Stage ${stage}`,operation:`${dec?'Decrypt':'Encrypt'} DES · K${k} · ${rounds} Feistel rounds`,calculation:`Input=${toHex(input)} · key K${k}=${toHex(ks[k-1])} · ${rounds} Feistel rounds`,result:toHex(out)}); };
    if(algorithm==='aes'){const out=decryptBlock?decBlock(data):encBlock(data);if(detailed)trace.push({char:`AES block ${String(blockNo).padStart(2,'0')}`,operation:`AES-${kb.length*8} ${decryptBlock?'decryption':'encryption'} · ${kb.length===16?10:kb.length===24?12:14} rounds`,calculation:`Input=${toHex(data)} · key=${toHex(kb)} · standard key expansion and AES round transforms`,result:toHex(out)});return out;}
    const passes=algorithm==='des'?[['K1',decryptBlock]]:algorithm==='2des'?(decryptBlock?[['K2',true],['K1',true]]:[['K1',false],['K2',false]]):(decryptBlock?[['K3',true],['K2',false],['K1',true]]:[['K1',false],['K2',true],['K3',false]]);
    let out=Buffer.from(data);for(let i=0;i<passes.length;i++){const [name,dec]=passes[i],input=Buffer.from(out),keyNo=Number(name[1]);out=single(out,ks[keyNo-1],dec);record(i+1,input,keyNo,out,dec);}return out;
  };
  if(mode){if(!['aes','des'].includes(algorithm))throw Error('The modes workspace supports AES or DES only.');return transformMode({action,algorithm,text,iv,mode,blockSize,applyPrimitive,detailed,trace});}
  let input=decrypt?fromHex(text):bytes(text),output;
  const plainLength=input.length;
  if(!decrypt){const pad=blockSize-input.length%blockSize;input=Buffer.concat([input,Buffer.alloc(pad,pad)]);if(detailed)trace.push({char:'Setup',operation:'PKCS#7 padding',calculation:`${plainLength} bytes + ${pad} padding byte(s) · ${blockSize}-byte blocks`,result:toHex(input)});}
  if(input.length%blockSize)throw Error('Ciphertext length must be a multiple of the block size.');
  if(detailed)trace.push({char:'Split',operation:'Divide into blocks',calculation:`${input.length/blockSize} block(s) · ${blockSize} bytes each`,result:Array.from({length:input.length/blockSize},(_,i)=>`B${i+1}: ${toHex(input.subarray(i*blockSize,(i+1)*blockSize))}`).join('  |  ')});
  output=Buffer.alloc(input.length);
  for(let i=0;i<input.length;i+=blockSize){const index=i/blockSize+1,block=input.subarray(i,i+blockSize),result=applyPrimitive(block,decrypt,index);output.set(result,i);if(detailed)trace.push({char:`Block ${String(index).padStart(2,'0')}`,operation:`${algorithm.toUpperCase()} block result`,calculation:`${decrypt?'Decrypt':'Encrypt'} ${toHex(block)}`,result:toHex(result)});}
  if(decrypt){const pad=output[output.length-1];if(pad<1||pad>blockSize||!output.subarray(output.length-pad).every(x=>x===pad))throw Error('Invalid padding: check ciphertext and key.');output=output.subarray(0,output.length-pad);if(detailed)trace.push({char:'Finalize',operation:'Remove PKCS#7 padding',calculation:`Remove ${pad} padding byte(s)`,result:toHex(output)});}
  const value=decrypt?output.toString('utf8'):toHex(output);
  return detailed?{output:value,steps:trace}:value;
}
function transformMode({action,algorithm,text,iv,mode,blockSize,applyPrimitive,detailed,trace}) {
  const decrypt=action==='decrypt',m=String(mode).toLowerCase();
  if(!['ecb','cbc','cfb','ofb','ctr'].includes(m))throw Error('Select ECB, CBC, CFB, OFB or CTR.');
  const ivBuf=bytes(iv||'');
  if(m!=='ecb'&&ivBuf.length!==blockSize)throw Error(`${algorithm.toUpperCase()} ${m.toUpperCase()} requires an IV / initial counter of exactly ${blockSize} UTF-8 bytes.`);
  let input=decrypt?fromHex(text):bytes(text),output;
  const originalLength=input.length;
  const padded=m==='ecb'||m==='cbc';
  if(!decrypt&&padded){const pad=blockSize-input.length%blockSize;input=Buffer.concat([input,Buffer.alloc(pad,pad)]);if(detailed)trace.push({char:'Setup',operation:'PKCS#7 padding',calculation:`${originalLength} bytes + ${pad} padding byte(s)`,result:toHex(input)});}
  if(padded&&input.length%blockSize)throw Error('Ciphertext length must be a multiple of the selected cipher block size.');
  if(detailed)trace.push({char:'Mode',operation:`${m.toUpperCase()} setup`,calculation:m==='ecb'?'Independent blocks; ECB exposes repeated plaintext blocks.':`Initialize ${algorithm.toUpperCase()} ${m.toUpperCase()} with IV / counter ${toHex(ivBuf)}`,result:m==='ecb'?'No IV':toHex(ivBuf)});
  const count=padded?input.length/blockSize:Math.ceil(input.length/blockSize);
  output=Buffer.alloc(input.length);let previous=Buffer.from(ivBuf),counter=Buffer.from(ivBuf);
  for(let n=0;n<count;n++){
    const offset=n*blockSize,segment=input.subarray(offset,Math.min(offset+blockSize,input.length)),index=n+1;let result,calculation;
    if(m==='ecb') { result=applyPrimitive(segment,decrypt,index);calculation=`${decrypt?'D':'E'}_${algorithm.toUpperCase()}(${toHex(segment)})`; }
    else if(m==='cbc'){
      if(decrypt){const transformed=applyPrimitive(segment,true,index);result=Buffer.alloc(blockSize);for(let j=0;j<blockSize;j++)result[j]=transformed[j]^previous[j];calculation=`D_K(C${index})=${toHex(transformed)} XOR ${index===1?'IV':'C'+(index-1)}=${toHex(previous)}`;previous=Buffer.from(segment);}
      else{const mixed=Buffer.alloc(blockSize);for(let j=0;j<blockSize;j++)mixed[j]=segment[j]^previous[j];result=applyPrimitive(mixed,false,index);calculation=`P${index}=${toHex(segment)} XOR ${index===1?'IV':'C'+(index-1)}=${toHex(previous)} → ${toHex(mixed)} → E_K`;previous=Buffer.from(result);}
    } else if(m==='cfb'){
      const stream=applyPrimitive(previous,false,index);result=Buffer.alloc(segment.length);for(let j=0;j<segment.length;j++)result[j]=segment[j]^stream[j];calculation=`S${index}=E_K(${toHex(previous)})=${toHex(stream)} · ${decrypt?'P=C XOR S':'C=P XOR S'} · segment=${toHex(segment)}`;previous=Buffer.alloc(blockSize);previous.set(decrypt?segment:result);
    } else if(m==='ofb'){
      previous=applyPrimitive(previous,false,index);result=Buffer.alloc(segment.length);for(let j=0;j<segment.length;j++)result[j]=segment[j]^previous[j];calculation=`S${index}=E_K(S${index-1})=${toHex(previous)} · ${decrypt?'P=C XOR S':'C=P XOR S'} · segment=${toHex(segment)}`;
    } else {
      const stream=applyPrimitive(counter,false,index);result=Buffer.alloc(segment.length);for(let j=0;j<segment.length;j++)result[j]=segment[j]^stream[j];calculation=`T${index}=${toHex(counter)} · E_K(T${index})=${toHex(stream)} · ${decrypt?'P=C XOR S':'C=P XOR S'} · segment=${toHex(segment)}`;for(let j=counter.length-1;j>=0;j--){counter[j]=(counter[j]+1)&255;if(counter[j])break;}
    }
    output.set(result,offset);if(detailed)trace.push({char:`Block ${String(index).padStart(2,'0')}`,operation:`${algorithm.toUpperCase()} ${m.toUpperCase()} block`,calculation,result:toHex(result)});
  }
  if(decrypt&&padded){const pad=output[output.length-1];if(pad<1||pad>blockSize||!output.subarray(output.length-pad).every(x=>x===pad))throw Error('Invalid padding: check ciphertext, key and IV.');output=output.subarray(0,output.length-pad);if(detailed)trace.push({char:'Finalize',operation:'Remove PKCS#7 padding',calculation:`Remove ${pad} padding byte(s)`,result:toHex(output)});}
  return detailed?{output:decrypt?output.toString('utf8'):toHex(output),steps:trace}:decrypt?output.toString('utf8'):toHex(output);
}
const server = http.createServer((req,res) => {
  if (req.url.split('?')[0] === '/api/crypto' && req.method !== 'POST') { res.setHeader('allow','POST'); return send(res,405,{error:'Use POST /api/crypto. Start this project server and open the URL it prints.'}); }
  if (req.method === 'GET' && req.url.split('?')[0] === '/api/health') return send(res,200,{service:'cns-experiments',api:1});
  if (req.method === 'POST' && req.url.split('?')[0] === '/api/crypto') {
    let body=''; req.on('data', c => { body += c; if(body.length > 1e6) req.destroy(); });
    req.on('end', () => { try { const p=JSON.parse(body); if(!['aes','des','2des','3des'].includes(p.algorithm)) throw Error('Unsupported block cipher.'); if(p.mode&&(!['aes','des'].includes(p.algorithm)||!['ecb','cbc','cfb','ofb','ctr'].includes(String(p.mode).toLowerCase()))) throw Error('Modes workspace supports AES or DES only.'); send(res,200,transform({...p,detailed:true})); } catch(e) { send(res,400,{error:e.message}); } }); return;
  }
  const pathname = decodeURIComponent((req.url || '/').split('?')[0]);
  const target = path.resolve(root, pathname === '/' ? 'index.html' : `.${pathname}`);
  if (!target.startsWith(root + path.sep) && target !== path.join(root,'index.html')) { res.writeHead(403); return res.end(); }
  fs.stat(target,(err,stat)=>{
    if(err||!stat.isFile()){res.writeHead(404);return res.end('Not found');}
    const type=mime[path.extname(target)]||'application/octet-stream';
    const range=req.headers.range;
    if(range){
      const match=/^bytes=(\d*)-(\d*)$/.exec(range);
      if(!match){res.writeHead(416,{'content-range':`bytes */${stat.size}`});return res.end();}
      let start=match[1]?Number(match[1]):null,end=match[2]?Number(match[2]):null;
      if(start===null){const suffix=end; if(!suffix){res.writeHead(416,{'content-range':`bytes */${stat.size}`});return res.end();} start=Math.max(0,stat.size-suffix);end=stat.size-1;}
      else if(end===null)end=stat.size-1;
      if(start>=stat.size||start>end){res.writeHead(416,{'content-range':`bytes */${stat.size}`});return res.end();}
      end=Math.min(end,stat.size-1);
      res.writeHead(206,{'content-type':type,'accept-ranges':'bytes','content-range':`bytes ${start}-${end}/${stat.size}`,'content-length':end-start+1,'cache-control':'no-store'});
      fs.createReadStream(target,{start,end}).pipe(res);return;
    }
    res.writeHead(200,{'content-type':type,'accept-ranges':'bytes','content-length':stat.size,'cache-control':'no-store'});
    fs.createReadStream(target).pipe(res);
  });
});
const requestedPort = Number(process.env.PORT || 4173);
if (require.main === module) {
  const listen = port => { server.once('error', error => { if (error.code === 'EADDRINUSE' && !process.env.PORT) return listen(port + 1); throw error; }); server.listen(port,()=>console.log(`CNS Lab available at http://localhost:${port}`)); };
  listen(requestedPort);
}
module.exports = { transform };
