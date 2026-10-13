// DAP server: no dependencies. Serves index.html and the /api the site uses in online mode.
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const PORT=process.env.PORT||3000,ADMIN='Timbi201588',ADMIN_PW=process.env.ADMIN_PASSWORD||'';
const DIR=process.env.DATA_DIR||path.join(__dirname,'data'),FILE=path.join(DIR,'data.json');
const MONGO_URI=process.env.MONGODB_URI||'';
fs.mkdirSync(DIR,{recursive:true});
let db={users:{},posts:[],promos:{},announcement:null,version:1,sessions:{}};
if(!MONGO_URI)try{db=Object.assign(db,JSON.parse(fs.readFileSync(FILE,'utf8')))}catch{}
// Storage: MongoDB when MONGODB_URI is set (survives restarts), otherwise a local file.
let col=null,cache=new Map(),saving=false,again=false;
async function connectMongo(){const{MongoClient}=require('mongodb');const c=new MongoClient(MONGO_URI);await c.connect();col=c.db('dap').collection('items');
 const docs=await col.find({}).toArray(),posts={};let meta={};
 for(const d of docs){cache.set(d._id,d.j);const v=JSON.parse(d.j);if(d._id.startsWith('users:'))db.users[d._id.slice(6)]=v;else if(d._id.startsWith('posts:'))posts[d._id.slice(6)]=v;else if(d._id==='meta:main')meta=v}
 db.promos=meta.promos||{};db.announcement=meta.announcement||null;db.sessions=meta.sessions||{};db.version=meta.version||1;
 const ord=meta.order||[];db.posts=ord.filter(i=>posts[i]).map(i=>posts[i]).concat(Object.keys(posts).filter(i=>!ord.includes(i)).map(i=>posts[i]))}
async function persist(){if(saving){again=true;return}saving=true;
 try{const items=new Map();for(const n in db.users)items.set('users:'+n,JSON.stringify(db.users[n]));for(const p of db.posts)items.set('posts:'+p.id,JSON.stringify(p));
  items.set('meta:main',JSON.stringify({promos:db.promos,announcement:db.announcement,sessions:db.sessions,order:db.posts.map(p=>String(p.id)),version:db.version}));
  const ops=[];for(const[k,v]of items)if(cache.get(k)!==v)ops.push({replaceOne:{filter:{_id:k},replacement:{_id:k,j:v},upsert:true}});
  for(const k of cache.keys())if(!items.has(k))ops.push({deleteOne:{filter:{_id:k}}});
  if(ops.length){await col.bulkWrite(ops);for(const[k,v]of items)cache.set(k,v);for(const k of[...cache.keys()])if(!items.has(k))cache.delete(k)}}
 catch(e){console.error('Save failed:',e.message)}
 saving=false;if(again){again=false;persist()}}
let tm;const save=()=>{db.version++;clearTimeout(tm);tm=setTimeout(()=>MONGO_URI?persist():fs.writeFile(FILE,JSON.stringify(db),()=>{}),400)};
const PRIV=['notifications','saved','txs','postAlerts','settings'],LOCK=['droplets','txs','unlockedFrames','banned'];
const hash=(pw,salt)=>crypto.scryptSync(pw,salt,32).toString('hex');
const find=n=>Object.keys(db.users).find(k=>k.toLowerCase()===String(n||'').toLowerCase());
const fail=(status,message)=>{throw{status,message}};
const hits={};const limited=ip=>{const h=hits[ip]=(hits[ip]&&Date.now()-hits[ip].t<6e5)?hits[ip]:{n:0,t:Date.now()};return ++h.n>30};
function state(me){const admin=me===ADMIN,fol={},users={};
 for(const n in db.users)for(const t of db.users[n].following||[])(fol[t]=fol[t]||[]).push(n);
 for(const n in db.users){const o={};for(const k in db.users[n]){if(k==='_pw'||(!admin&&n!==me&&PRIV.includes(k)))continue;o[k]=db.users[n][k]}o.followers=fol[n]||[];users[n]=o}
 return{users,posts:db.posts,promos:admin?db.promos:{},announcement:db.announcement,me,version:db.version}}
function drops(n,amt,tx){const u=db.users[n];u.droplets=Math.max(0,(u.droplets||0)+amt);u.txs=[Object.assign({t:Date.now(),amt},tx)].concat(u.txs||[]).slice(0,40)}
function notif(n,x){const u=db.users[n];if(u.settings&&u.settings.notificationsEnabled===false)return;u.notifications=[Object.assign({id:Date.now()+Math.random(),createdAt:Date.now(),read:false},x)].concat(u.notifications||[]).slice(0,60)}
function login(me){const t=crypto.randomBytes(24).toString('hex');db.sessions[t]=me;save();return{token:t}}
const routes={
 'POST /api/signup':(me,b,ip)=>{if(limited(ip))fail(429,'Too many tries. Wait a few minutes.');const name=String(b.name||'').trim(),pw=String(b.password||'');
  if(!/^[a-zA-Z0-9_]{3,20}$/.test(name))fail(400,'Username: 3–20 letters, numbers, or underscores.');if(pw.length<4)fail(400,'Password needs at least 4 characters.');
  if(find(name))fail(400,'That username is taken.');if(name.toLowerCase()===ADMIN.toLowerCase()&&(!ADMIN_PW||pw!==ADMIN_PW))fail(403,'Admin signup needs the ADMIN_PASSWORD from your server settings.');
  const salt=crypto.randomBytes(16).toString('hex');db.users[name]={_pw:{salt,hash:hash(pw,salt)},bio:'',following:[],followers:[],postAlerts:{},notifications:[],settings:{notificationsEnabled:true},saved:[],unlockedFrames:[],droplets:0,txs:[]};return login(name)},
 'POST /api/login':(me,b,ip)=>{if(limited(ip))fail(429,'Too many tries. Wait a few minutes.');const n=find(b.name),u=n&&db.users[n];
  if(!u||!u._pw||hash(String(b.password||''),u._pw.salt)!==u._pw.hash)fail(401,'Username or password is incorrect.');if(u.banned)fail(403,'This account has been banned.');return login(n)},
 'POST /api/logout':(me,b,ip,tok)=>{delete db.sessions[tok];save();return{ok:1}},
 'GET /api/state':(me,b,ip,tok,q)=>q.get('v')==db.version?{same:true}:state(me),
 'POST /api/sync':(me,d)=>{const admin=me===ADMIN;
  for(const n in d.users||{}){const u=db.users[n];if(!u||(n!==me&&!admin))continue;for(const k in d.users[n]){if(k==='_pw'||k==='password'||k==='followers'||(!admin&&LOCK.includes(k)))continue;u[k]=d.users[n][k]}}
  if(admin)for(const n of d.deleteUsers||[])if(n!==ADMIN){delete db.users[n];for(const t in db.sessions)if(db.sessions[t]===n)delete db.sessions[t]}
  for(const id in d.posts||{}){const v=d.posts[id],i=db.posts.findIndex(p=>String(p.id)===id);
   if(v===null){if(i>=0&&(admin||db.posts[i].user===me))db.posts.splice(i,1)}
   else if(i>=0){v.user=db.posts[i].user;db.posts[i]=v}else{if(!admin)v.user=me;db.posts.unshift(v)}}
  if(admin){if(d.promos)db.promos=d.promos;if('announcement'in d)db.announcement=d.announcement}
  save();return state(me)},
 'POST /api/send':(me,b)=>{const to=find(b.to),amt=Math.floor(Number(b.amount)),u=db.users[me];
  if(!to)fail(400,'No such user.');if(to===me)fail(400,"You can't send droplets to yourself.");if(db.users[to].banned)fail(400,'That account is banned.');
  if(!(amt>0))fail(400,'Enter an amount of 1 or more.');if(me!==ADMIN&&(u.droplets||0)<amt)fail(400,'Not enough droplets.');
  if(me===ADMIN)u.txs=[{t:Date.now(),amt:0,type:'sent',with:to,sent:amt}].concat(u.txs||[]);else drops(me,-amt,{type:'sent',with:to});
  drops(to,amt,{type:'received',with:me});notif(to,{type:'droplets',from:me,amt});save();return{state:state(me),to,amt}},
 'POST /api/redeem':(me,b)=>{const code=String(b.code||'').trim().toUpperCase(),pr=db.promos[code],u=db.users[me];
  if(!code||!pr)fail(400,"That code isn't valid.");pr.used=pr.used||[];if(pr.used.includes(me))fail(400,'You already used that code.');if(pr.max&&pr.used.length>=pr.max)fail(400,'That code has run out.');
  const got=[];if(pr.frame&&pr.frame!=='none'){u.unlockedFrames=u.unlockedFrames||[];if(!u.unlockedFrames.includes(pr.frame))u.unlockedFrames.push(pr.frame);u.frame=pr.frame;got.push('the '+pr.frame+' frame')}
  if(pr.droplets>0){drops(me,pr.droplets,{type:'promo',note:code});got.push(pr.droplets+' 💧')}pr.used.push(me);save();
  return{state:state(me),message:'You got '+(got.join(' and ')||'a reward')+'!'}}};
const open=new Set(['POST /api/signup','POST /api/login']);
(async()=>{if(MONGO_URI){await connectMongo();console.log('Using MongoDB storage')}
http.createServer((req,res)=>{const url=new URL(req.url,'http://x'),ip=req.headers['x-forwarded-for']||req.socket.remoteAddress||'',key=req.method+' '+url.pathname;
 const out=(s,o,t)=>{res.writeHead(s,{'Content-Type':t||'application/json','Cache-Control':'no-store'});res.end(t?o:JSON.stringify(o))};
 if(url.pathname==='/api/ping')return out(200,{online:true});
 if(req.method==='GET'&&(url.pathname==='/'||url.pathname==='/index.html'))return fs.readFile(path.join(__dirname,'index.html'),(e,d)=>e?out(404,'Not found','text/plain'):out(200,d,'text/html; charset=utf-8'));
 const h=routes[key];if(!h)return out(404,{error:'Not found'});
 let size=0;const ch=[];req.on('data',c=>{size+=c.length;if(size>4e7){out(413,{error:'Too large'});req.destroy()}else ch.push(c)});
 req.on('end',()=>{try{let b={};try{b=JSON.parse(Buffer.concat(ch).toString()||'{}')}catch{}
  const tok=(req.headers.authorization||'').replace('Bearer ',''),me=db.sessions[tok];
  if(!open.has(key)){if(!me||!db.users[me])fail(401,'Please log in again.');if(db.users[me].banned)fail(403,'This account has been banned.')}
  out(200,h(me,b,ip,tok,url.searchParams))}catch(e){out(e.status||500,{error:e.message||'Server error'})}})
}).listen(PORT,()=>console.log('DAP running on '+PORT))})().catch(e=>{console.error('Startup failed:',e.message);process.exit(1)});
