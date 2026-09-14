const http = require("http");
const crypto = require("crypto");
const { URL } = require("url");
const cloudbase = require("@cloudbase/node-sdk");

const PORT = Number(process.env.PORT || 9000);
const EDIT_PASSWORD = String(process.env.TIMELINE_EDIT_PASSWORD || "");
const XIAOQINGER_EDIT_PASSWORD = String(process.env.XIAOQINGER_EDIT_PASSWORD || "");
const BACKUP_PASSWORD = String(process.env.TIMELINE_BACKUP_PASSWORD || "");
const TOKEN_TTL_MS = 12 * 60 * 60 * 1000;
const MAX_BODY_BYTES = 5.5 * 1024 * 1024;
const DEFAULT_EVENT_LIMIT = 4;
const MAX_EVENT_LIMIT = 5;
const SAFE_RESPONSE_BYTES = 5 * 1024 * 1024;
const LEGACY_ROOM_ID = "07201218";

const app = cloudbase.init({
  env: cloudbase.SYMBOL_CURRENT_ENV,
  accessKey: process.env.CLOUDBASE_APIKEY
});
const db = app.database();

const COLLECTIONS = {
  events: "timeline_events",
  connections: "timeline_connections",
  tags: "timeline_tags",
  bgm: "timeline_bgm",
  activityLogs: "timeline_activity_logs",
  meta: "timeline_meta",
  editorIdentities: "timeline_editor_identities"
};

function normalizeRoom(value) {
  const s = String(value || "").trim();
  return (s || "default").slice(0, 120);
}
function requestRoomFromUrl(urlObj) { return normalizeRoom(urlObj?.searchParams?.get("room")); }
function requestRoomFromBody(body) { return normalizeRoom(body?.room); }
function roomHash(room) { return crypto.createHash("sha256").update(normalizeRoom(room)).digest("hex").slice(0, 24); }
function metaDocId(kind, room) {
  room = normalizeRoom(room);
  if (room === LEGACY_ROOM_ID) return kind; // keep migrated production data compatible
  return `${kind}_${roomHash(room)}`;
}
function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Max-Age", "86400");
}
function sendJson(res, statusCode, payload) {
  const body = JSON.stringify(payload);
  setCors(res);
  res.statusCode = statusCode;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Length", Buffer.byteLength(body));
  res.end(body);
}
function cleanDoc(doc) {
  if (!doc || typeof doc !== "object") return doc;
  const { _id, roomId, ...rest } = doc;
  if (rest.data && typeof rest.data === "object" && !Array.isArray(rest.data)) {
    const ownKeys = Object.keys(rest).filter(k => k !== "data");
    if (ownKeys.length === 0) return rest.data;
  }
  return rest;
}
function unwrapStoredRow(row) {
  if (!row || typeof row !== "object") return row;
  if (row.data && typeof row.data === "object" && !Array.isArray(row.data)) {
    const keys = Object.keys(row).filter(k => k !== "_id" && k !== "roomId" && k !== "data");
    if (keys.length === 0) return row.data;
  }
  return row;
}
function parseNonNegativeInt(value, fallback = 0) {
  const n = Number(value); return Number.isFinite(n) && n >= 0 ? Math.floor(n) : fallback;
}
function parsePositiveInt(value, fallback = 1) {
  const n = Number(value); return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}
function safeJsonClone(value) { return JSON.parse(JSON.stringify(value)); }
function base64url(input) { return Buffer.from(input).toString("base64url"); }
function hmacKey() { return String(process.env.CLOUDBASE_APIKEY || "timeline-api-fallback-key"); }
function signTokenPayload(payloadB64) { return crypto.createHmac("sha256", hmacKey()).update(payloadB64).digest("base64url"); }
function createScopedToken(scope, room) {
  const payload = { scope, room: normalizeRoom(room), exp: Date.now() + TOKEN_TTL_MS, nonce: crypto.randomBytes(12).toString("hex") };
  const p = base64url(JSON.stringify(payload));
  return `${p}.${signTokenPayload(p)}`;
}
function verifyScopedToken(token, scope, room) {
  if (!token || !token.includes(".")) return { ok:false, error:"unauthorized" };
  const [p, sig] = token.split(".");
  const expected = signTokenPayload(p);
  const a = Buffer.from(sig || ""); const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return { ok:false, error:"unauthorized" };
  try {
    const payload = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
    if (payload.scope !== scope) return { ok:false, error:"unauthorized" };
    if (normalizeRoom(payload.room) !== normalizeRoom(room)) return { ok:false, error:"wrong_room" };
    if (!Number.isFinite(Number(payload.exp)) || Date.now() > Number(payload.exp)) return { ok:false, error:"token_expired" };
    return { ok:true, payload };
  } catch (_) { return { ok:false, error:"unauthorized" }; }
}
function bearerToken(req) {
  const header = String(req.headers.authorization || "");
  return header.startsWith("Bearer ") ? header.slice(7).trim() : "";
}
function requireScopedAuth(req, res, scope, room, message) {
  const verified = verifyScopedToken(bearerToken(req), scope, room);
  if (!verified.ok) {
    sendJson(res, 401, { ok:false, error:verified.error, message:message || "授权无效或已过期" });
    return false;
  }
  return true;
}
function securePasswordMatch(supplied, expected) {
  const exactA = Buffer.from(String(supplied || ""));
  const exactB = Buffer.from(String(expected || ""));
  if (exactA.length === exactB.length && crypto.timingSafeEqual(exactA, exactB)) return true;

  // 兼容控制台环境变量或复制输入意外带上的首尾空白；不改变密码中间的字符。
  const trimmedA = Buffer.from(String(supplied || "").trim());
  const trimmedB = Buffer.from(String(expected || "").trim());
  return trimmedA.length === trimmedB.length && crypto.timingSafeEqual(trimmedA, trimmedB);
}
async function readBodyJson(req) {
  return await new Promise((resolve, reject) => {
    const chunks=[]; let size=0;
    req.on("data", chunk => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) { reject(Object.assign(new Error("request_too_large"), {code:"request_too_large"})); req.destroy(); return; }
      chunks.push(chunk);
    });
    req.on("end", () => { try { const raw=Buffer.concat(chunks).toString("utf8"); resolve(raw ? JSON.parse(raw) : {}); } catch (_) { reject(Object.assign(new Error("invalid_json"), {code:"invalid_json"})); } });
    req.on("error", reject);
  });
}

let legacyMigrationPromise = null;
async function getLightRows(collectionName, batchSize=200) {
  const rows=[]; let offset=0;
  while (true) {
    const result = await db.collection(collectionName).orderBy("_id","asc").skip(offset).limit(batchSize).field({_id:true, roomId:true}).get();
    const batch = Array.isArray(result?.data) ? result.data : [];
    rows.push(...batch);
    if (batch.length < batchSize) break;
    offset += batch.length;
  }
  return rows;
}
async function ensureLegacyRoomMigration() {
  if (legacyMigrationPromise) return legacyMigrationPromise;
  legacyMigrationPromise = (async () => {
    const markerRef = db.collection(COLLECTIONS.meta).doc("room_migration_v2");
    try {
      const got = await markerRef.get();
      const row = Array.isArray(got?.data) ? got.data[0] : got?.data;
      if (row?.done) return;
    } catch (_) {}
    const names = [COLLECTIONS.events, COLLECTIONS.connections, COLLECTIONS.tags, COLLECTIONS.bgm, COLLECTIONS.activityLogs, COLLECTIONS.editorIdentities];
    for (const name of names) {
      const rows = await getLightRows(name);
      const missing = rows.filter(r => r?._id && !String(r?.roomId || "").trim());
      for (let i=0;i<missing.length;i+=12) {
        await Promise.all(missing.slice(i,i+12).map(r => db.collection(name).doc(r._id).update({roomId:LEGACY_ROOM_ID})));
      }
    }
    await markerRef.set({done:true, legacyRoomId:LEGACY_ROOM_ID, updatedAt:Date.now()});
  })().catch(err => { legacyMigrationPromise = null; throw err; });
  return legacyMigrationPromise;
}

function roomQuery(collectionName, room) { return db.collection(collectionName).where({ roomId: normalizeRoom(room) }); }
async function getCount(collectionName, room) {
  const result = await roomQuery(collectionName, room).count();
  return Number(result?.total || 0);
}
async function getCounts(room) {
  const [events,connections,tags,bgm,activityLogs] = await Promise.all([
    getCount(COLLECTIONS.events,room), getCount(COLLECTIONS.connections,room), getCount(COLLECTIONS.tags,room), getCount(COLLECTIONS.bgm,room), getCount(COLLECTIONS.activityLogs,room)
  ]);
  return {events,connections,tags,bgm,activityLogs,total:events+connections+tags+bgm+activityLogs};
}
async function readMetaVersion(room) {
  try {
    const result = await db.collection(COLLECTIONS.meta).doc(metaDocId("current",room)).get();
    const raw = Array.isArray(result?.data) ? result.data[0] : result?.data;
    const row = unwrapStoredRow(raw);
    if (row?.version) return String(row.version);
  } catch (_) {}
  const counts = await getCounts(room);
  return `initial:${counts.events}:${counts.connections}:${counts.tags}:${counts.bgm}:${counts.activityLogs}`;
}
async function bumpVersion(room, kind="write") {
  const version = `${Date.now().toString(36)}-${crypto.randomBytes(4).toString("hex")}`;
  await db.collection(COLLECTIONS.meta).doc(metaDocId("current",room)).set({roomId:normalizeRoom(room), version, updatedAt:Date.now(), kind});
  return version;
}
async function getMetaPayload(room) {
  const [counts,version] = await Promise.all([getCounts(room), readMetaVersion(room)]);
  return {ok:true, room:normalizeRoom(room), version, counts, documentCount:counts.total};
}
async function readXiaoqingerConfig(room) {
  try {
    const result = await db.collection(COLLECTIONS.meta).doc(metaDocId("xiaoqinger",room)).get();
    const raw = Array.isArray(result?.data) ? result.data[0] : result?.data;
    const row = unwrapStoredRow(raw);
    return row?.config && typeof row.config === "object" ? row.config : null;
  } catch (_) { return null; }
}
async function readAllSmallCollection(collectionName, room, batchSize=100) {
  const items=[]; let offset=0;
  while (true) {
    const result = await roomQuery(collectionName,room).orderBy("_id","asc").skip(offset).limit(batchSize).get();
    const batch = Array.isArray(result?.data) ? result.data : [];
    items.push(...batch.map(cleanDoc));
    if (batch.length < batchSize) break;
    offset += batch.length;
  }
  return items;
}
async function readRawRoomCollection(collectionName, room, batchSize=100) {
  const rows=[]; let offset=0;
  while (true) {
    const result = await roomQuery(collectionName,room).orderBy("_id","asc").skip(offset).limit(batchSize).get();
    const batch = Array.isArray(result?.data) ? result.data : [];
    rows.push(...batch);
    if (batch.length < batchSize) break;
    offset += batch.length;
  }
  return rows;
}
async function readEventsChunk(room, offset, requestedLimit) {
  const total = await getCount(COLLECTIONS.events,room);
  const limit = Math.min(Math.max(parsePositiveInt(requestedLimit,DEFAULT_EVENT_LIMIT),1),MAX_EVENT_LIMIT);
  if (offset >= total) return {ok:true,type:"events",room:normalizeRoom(room),total,offset,requestedLimit:limit,returned:0,nextOffset:null,hasMore:false,items:[]};
  const result = await roomQuery(COLLECTIONS.events,room).orderBy("_id","asc").skip(offset).limit(limit).get();
  let items=(Array.isArray(result?.data)?result.data:[]).map(cleanDoc);
  while (items.length>1 && Buffer.byteLength(JSON.stringify({items}))>SAFE_RESPONSE_BYTES) items.pop();
  if (items.length===1) {
    const bytes=Buffer.byteLength(JSON.stringify({items}));
    if (bytes>SAFE_RESPONSE_BYTES) return {ok:false,error:"single_event_too_large",message:"单个事件响应超过安全大小，请把 Base64 媒体迁移到云存储。",offset,approximateBytes:bytes};
  }
  const returned=items.length, nextOffset=offset+returned;
  return {ok:true,type:"events",room:normalizeRoom(room),total,offset,requestedLimit:limit,returned,nextOffset:nextOffset<total?nextOffset:null,hasMore:nextOffset<total,items};
}
async function findByLogicalId(collectionName, logicalId, room) {
  const result = await db.collection(collectionName).where({id:logicalId, roomId:normalizeRoom(room)}).limit(1).get();
  const rows=Array.isArray(result?.data)?result.data:[];
  if (rows[0]) return rows[0];
  const allRows=await readRawRoomCollection(collectionName,room);
  return allRows.find(row => String(unwrapStoredRow(row)?.id)===String(logicalId)) || null;
}
async function upsertByLogicalId(collectionName, logicalId, data, room) {
  const existing=await findByLogicalId(collectionName,logicalId,room);
  const clean=safeJsonClone(data); clean.id=logicalId; clean.roomId=normalizeRoom(room);
  if (existing?._id) { await db.collection(collectionName).doc(existing._id).set(clean); return existing._id; }
  const added=await db.collection(collectionName).add(clean); return added?.id || added?._id || "";
}
async function deleteByLogicalId(collectionName, logicalId, room) {
  const rows=await readRawRoomCollection(collectionName,room);
  const matches=rows.filter(row => String(unwrapStoredRow(row)?.id)===String(logicalId));
  for (const row of matches) if (row?._id) await db.collection(collectionName).doc(row._id).remove();
  return matches.length;
}



function publicIdentityProfileId(room,ownerToken) {
  return crypto.createHash("sha256")
    .update(`${normalizeRoom(room)}\0${String(ownerToken||"")}`)
    .digest("hex")
    .slice(0,32);
}

function normalizeIdentityHistory(values) {
  const out=[];
  const seen=new Set();
  for(const raw of Array.isArray(values)?values:[]){
    const name=normalizeIdentityName(
      typeof raw==="string" ? raw : (raw?.handle || raw?.name || "")
    );
    if(!name || seen.has(name)) continue;
    seen.add(name);
    out.push(name);
  }
  return out.slice(-50);
}

async function findIdentityByPublicProfileId(room,profileId) {
  const wanted=String(profileId||"");
  if(!wanted) return null;
  const rows=await readRawRoomCollection(COLLECTIONS.editorIdentities,room);
  let best=null;
  for(const row of rows){
    const data=unwrapStoredRow(row);
    if(!data?.ownerToken) continue;
    if(publicIdentityProfileId(room,data.ownerToken)!==wanted) continue;
    if(!best || (Number(data.updatedAt)||0)>(Number(best.updatedAt)||0)) best=data;
  }
  return best;
}

function identityProfilePayload(room,identity) {
  if(!identity) return {profileId:"",currentHandle:"",history:[]};
  const current=normalizeIdentityName(identity.displayName||"");
  const history=normalizeIdentityHistory(identity.history||[])
    .map(handle=>({handle,current:handle===current}));
  return {
    profileId:publicIdentityProfileId(room,identity.ownerToken),
    currentHandle:current,
    history
  };
}

async function findIdentityByOwnerToken(room, ownerToken) {
  const token=String(ownerToken||"");
  if(!token) return null;
  const rows=await readRawRoomCollection(COLLECTIONS.editorIdentities,room);
  let best=null;
  for(const row of rows){
    const data=unwrapStoredRow(row);
    if(!data || String(data.ownerToken||"")!==token) continue;
    if(!best || (Number(data.updatedAt)||0)>(Number(best.updatedAt)||0)) best=data;
  }
  return best;
}

function commentsMetaDocId(room,eventId) {
  const eventHash=crypto.createHash("sha256").update(String(eventId||"")).digest("hex").slice(0,28);
  return metaDocId(`comments_${eventHash}`,room);
}

async function readCommentDoc(room,eventId) {
  const ref=db.collection(COLLECTIONS.meta).doc(commentsMetaDocId(room,eventId));
  try{
    const result=await ref.get();
    const raw=Array.isArray(result?.data)?result.data[0]:result?.data;
    const row=unwrapStoredRow(raw);
    const items=Array.isArray(row?.items)?row.items:[];
    return {ref,items};
  }catch(_){
    return {ref,items:[]};
  }
}

async function writeCommentDoc(room,eventId,items) {
  const ref=db.collection(COLLECTIONS.meta).doc(commentsMetaDocId(room,eventId));
  await ref.set({
    roomId:normalizeRoom(room),
    eventId:String(eventId||""),
    items:safeJsonClone(Array.isArray(items)?items:[]),
    updatedAt:Date.now(),
    kind:"comments"
  });
}

async function readCommentsForEvent(room,eventId) {
  const {items}=await readCommentDoc(room,eventId);
  const sorted=items.slice().sort((a,b)=>(Number(a?.createdAt)||0)-(Number(b?.createdAt)||0));
  const identityCache=new Map();
  const messages=[];
  for(const data of sorted){
    const anonymous=data?.anonymous===true;
    const token=String(data?.authorOwnerToken||"");
    let displayName="一枚小鱼丁";
    if(!anonymous){
      if(!identityCache.has(token)) identityCache.set(token,await findIdentityByOwnerToken(room,token));
      const identity=identityCache.get(token);
      displayName=normalizeIdentityName(identity?.displayName || data?.authorName || "") || "未知用户";
    }
    messages.push({
      id:String(data?.id||""),
      eventId:String(data?.eventId||""),
      parentId:data?.parentId ? String(data.parentId) : null,
      content:String(data?.content||""),
      createdAt:Number(data?.createdAt)||0,
      author:{displayName,anonymous,profileId:anonymous||!token?"":publicIdentityProfileId(room,token)}
    });
  }
  return messages;
}

async function handleTimelineGet(urlObj,res,room) {
  const type=(urlObj.searchParams.get("type")||"meta").trim();
  if (type==="meta") return sendJson(res,200,await getMetaPayload(room));
  if (type==="events") {
    const payload=await readEventsChunk(room,parseNonNegativeInt(urlObj.searchParams.get("offset"),0),urlObj.searchParams.get("limit"));
    return sendJson(res,payload.ok?200:413,payload);
  }
  if (type==="connections") { const items=await readAllSmallCollection(COLLECTIONS.connections,room); return sendJson(res,200,{ok:true,type,room,total:items.length,items}); }
  if (type==="tags") {
    const raw=await readAllSmallCollection(COLLECTIONS.tags,room);
    const items=raw.map(item=>typeof item==="string"?item:(typeof item?.name==="string"?item.name:(typeof item?.id==="string"?item.id:String(item??""))));
    return sendJson(res,200,{ok:true,type,room,total:items.length,items});
  }
  if (type==="bgm") { const items=await readAllSmallCollection(COLLECTIONS.bgm,room); return sendJson(res,200,{ok:true,type,room,total:items.length,items}); }
  if (type==="comments") {
    const eventId=String(urlObj.searchParams.get("eventId")||"").slice(0,200);
    if(!eventId) return sendJson(res,400,{ok:false,error:"invalid_event_id"});
    const messages=await readCommentsForEvent(room,eventId);
    return sendJson(res,200,{ok:true,type,room,eventId,messages});
  }
  if (type==="identityHistory") {
    const profileId=String(urlObj.searchParams.get("profileId")||"").slice(0,80);
    if(!profileId) return sendJson(res,400,{ok:false,error:"bad_profile_id"});
    const identity=await findIdentityByPublicProfileId(room,profileId);
    return sendJson(res,200,{ok:true,type,room,profile:identityProfilePayload(room,identity)});
  }
  if (type==="activityLogs") {
    const rows=await readRawRoomCollection(COLLECTIONS.activityLogs,room);
    const items=rows.map(row=>({...cleanDoc(row),_logId:String(row?._id||"")}));
    return sendJson(res,200,{ok:true,type,room,total:items.length,items});
  }
  if (type==="xiaoqinger") return sendJson(res,200,{ok:true,type,room,config:await readXiaoqingerConfig(room)});
  return sendJson(res,400,{ok:false,error:"bad_type",message:"type 不正确"});
}
function normalizeIdentityName(value){return String(value||"").normalize("NFKC").trim().replace(/\s+/g," ").slice(0,80);}
function identityDocKey(name,room){
  const normalized=normalizeIdentityName(name);
  if (normalizeRoom(room)===LEGACY_ROOM_ID) return crypto.createHash("sha256").update(normalized).digest("hex");
  return crypto.createHash("sha256").update(`${normalizeRoom(room)}\0${normalized}`).digest("hex");
}
async function handleWriteAction(req,res,body,room) {
  const action=String(body?.action||"");
  if (action==="auth") {
    if (!EDIT_PASSWORD) return sendJson(res,503,{ok:false,error:"edit_password_not_configured",message:"服务端尚未配置 TIMELINE_EDIT_PASSWORD"});
    if (!securePasswordMatch(body?.password,EDIT_PASSWORD)) return sendJson(res,401,{ok:false,error:"bad_password",message:"密码错误"});
    return sendJson(res,200,{ok:true,token:createScopedToken("timeline-edit",room),expiresInMs:TOKEN_TTL_MS});
  }
  if (action==="xiaoqingerAuth") {
    if (!XIAOQINGER_EDIT_PASSWORD) return sendJson(res,503,{ok:false,error:"xiaoqinger_password_not_configured",message:"服务端尚未配置 XIAOQINGER_EDIT_PASSWORD"});
    if (!securePasswordMatch(body?.password,XIAOQINGER_EDIT_PASSWORD)) return sendJson(res,401,{ok:false,error:"bad_password",message:"密码错误"});
    return sendJson(res,200,{ok:true,token:createScopedToken("xiaoqinger-edit",room),expiresInMs:TOKEN_TTL_MS});
  }
  if (action==="backupAuth") {
    if (!BACKUP_PASSWORD) return sendJson(res,503,{ok:false,error:"backup_password_not_configured",message:"服务端尚未配置 TIMELINE_BACKUP_PASSWORD"});
    if (!securePasswordMatch(body?.password,BACKUP_PASSWORD)) return sendJson(res,401,{ok:false,error:"bad_password",message:"密码错误"});
    return sendJson(res,200,{ok:true});
  }

  if (action==="updateXiaoqinger") {
    if (!requireScopedAuth(req,res,"xiaoqinger-edit",room,"小晴儿台词编辑授权无效或已过期")) return;
    const config=body?.config;
    if (!config || typeof config!=="object" || !Array.isArray(config.lines) || !config.lines.length) return sendJson(res,400,{ok:false,error:"bad_xiaoqinger_config"});
    const clean=safeJsonClone(config);
    await db.collection(COLLECTIONS.meta).doc(metaDocId("xiaoqinger",room)).set({roomId:normalizeRoom(room),config:clean,updatedAt:Date.now()});
    return sendJson(res,200,{ok:true,version:await bumpVersion(room,"xiaoqinger_update")});
  }


  // 用户 ID 属于云端身份系统，不要求处于编辑模式；ownerToken 用于证明同一浏览器对该 ID 的所有权。
  if (action==="checkIdentityOwnership") {
    const name=normalizeIdentityName(body?.name);
    const ownerToken=String(body?.ownerToken||"").slice(0,200);
    if(!name||!ownerToken) return sendJson(res,400,{ok:false,error:"bad_identity"});
    try{
      const ref=db.collection(COLLECTIONS.editorIdentities).doc(identityDocKey(name,room));
      const result=await ref.get();
      const raw=Array.isArray(result?.data)?result.data[0]:result?.data;
      const row=unwrapStoredRow(raw);
      const owned=!!row && normalizeRoom(row.roomId)===normalizeRoom(room) && String(row.ownerToken||"")===ownerToken;
      return sendJson(res,200,{ok:true,owned,name:owned?normalizeIdentityName(row.displayName||name):name});
    }catch(_){
      return sendJson(res,200,{ok:true,owned:false,name});
    }
  }

  if (action==="claimIdentity") {
    const name=normalizeIdentityName(body?.name);
    const oldName=normalizeIdentityName(body?.oldName);
    const ownerToken=String(body?.ownerToken||"").slice(0,200);
    if(!name||!ownerToken) return sendJson(res,400,{ok:false,error:"bad_identity"});

    const nextRef=db.collection(COLLECTIONS.editorIdentities).doc(identityDocKey(name,room));
    const nextResult=await nextRef.get();
    const nextRaw=Array.isArray(nextResult?.data)?nextResult.data[0]:nextResult?.data;
    const nextRow=unwrapStoredRow(nextRaw);
    if(nextRow && normalizeRoom(nextRow.roomId)!==normalizeRoom(room))
      return sendJson(res,409,{ok:false,error:"identity_taken"});
    if(nextRow && String(nextRow.ownerToken||"")!==ownerToken)
      return sendJson(res,409,{ok:false,error:"identity_taken",message:"该 ID 已被其他用户使用"});

    const inheritedHistory=normalizeIdentityHistory([
      ...(Array.isArray(nextRow?.history)?nextRow.history:[]),
      oldName,
      name
    ]);
    await nextRef.set({
      roomId:normalizeRoom(room),
      displayName:name,
      ownerToken,
      history:inheritedHistory,
      updatedAt:Date.now()
    });

    // 主身份写入已经成功后，旧记录清理和版本号更新都只做附加处理。
    // 附加处理失败不能让前端误以为 ID 保存失败。
    if(oldName && oldName!==name){
      try{
        const oldRef=db.collection(COLLECTIONS.editorIdentities).doc(identityDocKey(oldName,room));
        const oldResult=await oldRef.get();
        const raw=Array.isArray(oldResult?.data)?oldResult.data[0]:oldResult?.data;
        const oldRow=unwrapStoredRow(raw);
        if(oldRow && normalizeRoom(oldRow.roomId)===normalizeRoom(room) && String(oldRow.ownerToken||"")===ownerToken)
          await oldRef.remove();
      }catch(err){ console.warn("identity old-record cleanup failed",err); }
    }
    let version="";
    try{ version=await bumpVersion(room,"identity_claim"); }catch(err){ console.warn("identity version bump failed",err); }
    return sendJson(res,200,{ok:true,name,version});

  }

  if (action==="renameIdentity") {
    const name=normalizeIdentityName(body?.name);
    const oldName=normalizeIdentityName(body?.oldName);
    const ownerToken=String(body?.ownerToken||"").slice(0,200);
    if(!name||!oldName||!ownerToken) return sendJson(res,400,{ok:false,error:"bad_identity"});
    if(name===oldName) return sendJson(res,200,{ok:true,name,version:await bumpVersion(room,"identity_rename_noop")});

    // 必须先证明旧 ID 属于当前 ownerToken。
    const oldRef=db.collection(COLLECTIONS.editorIdentities).doc(identityDocKey(oldName,room));
    const oldResult=await oldRef.get();
    const oldRaw=Array.isArray(oldResult?.data)?oldResult.data[0]:oldResult?.data;
    const oldRow=unwrapStoredRow(oldRaw);
    if(!oldRow || normalizeRoom(oldRow.roomId)!==normalizeRoom(room) || String(oldRow.ownerToken||"")!==ownerToken)
      return sendJson(res,403,{ok:false,error:"identity_not_owned",message:"无法确认旧 ID 的所有权"});

    // 新 ID 若已被别的 owner 使用则拒绝。
    const nextRef=db.collection(COLLECTIONS.editorIdentities).doc(identityDocKey(name,room));
    const nextResult=await nextRef.get();
    const nextRaw=Array.isArray(nextResult?.data)?nextResult.data[0]:nextResult?.data;
    const nextRow=unwrapStoredRow(nextRaw);
    if(nextRow && String(nextRow.ownerToken||"")!==ownerToken)
      return sendJson(res,409,{ok:false,error:"identity_taken",message:"该 ID 已被其他用户使用"});

    const inheritedHistory=normalizeIdentityHistory([
      ...(Array.isArray(oldRow?.history)?oldRow.history:[]),
      ...(Array.isArray(nextRow?.history)?nextRow.history:[]),
      oldName,
      name
    ]);
    await nextRef.set({
      roomId:normalizeRoom(room),
      displayName:name,
      ownerToken,
      history:inheritedHistory,
      updatedAt:Date.now()
    });

    // 主身份已经写入成功。下面都属于附加同步，任何一项失败都不能把保存判定为失败。
    try{
      const logs=await readRawRoomCollection(COLLECTIONS.activityLogs,room);
      for(const row of logs){
        if(!row?._id) continue;
        const data=unwrapStoredRow(row);
        if(!data) continue;
        const current=normalizeIdentityName(
          data.userName || data.username || data.displayName || data.userId || ""
        );
        const isAnonymous =
          data.anonymous===true ||
          current==="不知名的小鱼丁" ||
          current==="一枚小鱼丁";
        if(isAnonymous || current!==oldName) continue;

        try{
          await db.collection(COLLECTIONS.activityLogs).doc(row._id).update({
            userId:name,
            userName:name,
            username:name,
            displayName:name,
            updatedAt:Date.now()
          });
        }catch(err){ console.warn("activity identity sync failed",err); }
      }
    }catch(err){ console.warn("activity identity scan failed",err); }

    try { await oldRef.remove(); } catch(err){ console.warn("old identity cleanup failed",err); }
    let version="";
    try{ version=await bumpVersion(room,"identity_rename"); }catch(err){ console.warn("identity version bump failed",err); }
    return sendJson(res,200,{ok:true,name,version});
  }


  if (action==="getOwnIdentityHistory") {
    const ownerToken=String(body?.ownerToken||"").slice(0,200);
    if(!ownerToken) return sendJson(res,400,{ok:false,error:"bad_identity"});
    const identity=await findIdentityByOwnerToken(room,ownerToken);
    return sendJson(res,200,{ok:true,profile:identityProfilePayload(room,identity)});
  }

  if (action==="commentAdd") {
    const eventId=String(body?.eventId||"").slice(0,200);
    const content=String(body?.content||"").trim();
    const parentId=body?.parentId ? String(body.parentId).slice(0,200) : null;
    const ownerToken=String(body?.ownerToken||"").slice(0,200);
    const identityName=normalizeIdentityName(body?.identityName||"");
    const anonymous=body?.anonymous===true;
    if(!eventId) return sendJson(res,400,{ok:false,error:"invalid_event_id"});
    if(!content || content.length>500) return sendJson(res,400,{ok:false,error:"invalid_content"});
    if(!ownerToken) return sendJson(res,400,{ok:false,error:"bad_identity"});

    let identity=null;
    if(!anonymous){
      if(!identityName)
        return sendJson(res,400,{ok:false,error:"identity_required",message:"请先在用户设置中填写 ID"});
      const ref=db.collection(COLLECTIONS.editorIdentities).doc(identityDocKey(identityName,room));
      const result=await ref.get();
      const raw=Array.isArray(result?.data)?result.data[0]:result?.data;
      identity=unwrapStoredRow(raw);
      if(!identity || String(identity.ownerToken||"")!==ownerToken)
        return sendJson(res,409,{ok:false,error:"identity_mismatch",message:"当前用户 ID 与身份凭证不匹配"});
    }

    const {items}=await readCommentDoc(room,eventId);
    if(parentId && !items.some(x=>String(x?.id||"")===parentId))
      return sendJson(res,404,{ok:false,error:"parent_not_found"});

    const id=`c_${Date.now().toString(36)}_${crypto.randomBytes(5).toString("hex")}`;
    items.push({
      id,
      eventId,
      parentId,
      content,
      createdAt:Date.now(),
      authorOwnerToken:ownerToken,
      authorName:anonymous ? "" : identityName,
      anonymous
    });
    await writeCommentDoc(room,eventId,items);
    return sendJson(res,200,{ok:true,id});
  }

  if (action==="commentDelete") {
    const id=String(body?.id||"").slice(0,200);
    const ownerToken=String(body?.ownerToken||"").slice(0,200);
    if(!id || !ownerToken) return sendJson(res,400,{ok:false,error:"bad_comment_delete"});

    // 评论存在于对应事件的 meta 文档中；逐个 comments_* 文档扫描代价很高，
    // 所以前端同时传 eventId。
    const eventId=String(body?.eventId||"").slice(0,200);
    if(!eventId) return sendJson(res,400,{ok:false,error:"invalid_event_id"});
    const {items}=await readCommentDoc(room,eventId);
    const idx=items.findIndex(x=>String(x?.id||"")===id);
    if(idx<0) return sendJson(res,404,{ok:false,error:"comment_not_found"});
    if(String(items[idx]?.authorOwnerToken||"")!==ownerToken)
      return sendJson(res,403,{ok:false,error:"not_owner"});
    items.splice(idx,1);
    await writeCommentDoc(room,eventId,items);
    return sendJson(res,200,{ok:true});
  }

  if (!requireScopedAuth(req,res,"timeline-edit",room,"编辑授权无效或已过期")) return;

  if (action==="upsertEvent") {
    const event=body?.event; if(!event || (typeof event.id!=="string" && typeof event.id!=="number")) return sendJson(res,400,{ok:false,error:"bad_event"});
    await upsertByLogicalId(COLLECTIONS.events,event.id,event,room); return sendJson(res,200,{ok:true,version:await bumpVersion(room,"event_upsert")});
  }
  if (action==="deleteEvent") {
    const eventId=body?.eventId; await deleteByLogicalId(COLLECTIONS.events,eventId,room);
    const connections=await readAllSmallCollection(COLLECTIONS.connections,room);
    for(const c of connections) if(String(c.sourceId)===String(eventId)||String(c.targetId)===String(eventId)) await deleteByLogicalId(COLLECTIONS.connections,c.id,room);
    return sendJson(res,200,{ok:true,version:await bumpVersion(room,"event_delete")});
  }
  if (action==="upsertConnection") { const c=body?.connection; if(!c||!c.id)return sendJson(res,400,{ok:false,error:"bad_connection"}); await upsertByLogicalId(COLLECTIONS.connections,c.id,c,room); return sendJson(res,200,{ok:true,version:await bumpVersion(room,"connection_upsert")}); }
  if (action==="deleteConnection") { await deleteByLogicalId(COLLECTIONS.connections,body?.connectionId,room); return sendJson(res,200,{ok:true,version:await bumpVersion(room,"connection_delete")}); }
  if (action==="upsertTag") { const tag=String(body?.tag||"").trim(); if(!tag)return sendJson(res,400,{ok:false,error:"bad_tag"}); await upsertByLogicalId(COLLECTIONS.tags,tag,{id:tag,name:tag},room); return sendJson(res,200,{ok:true,version:await bumpVersion(room,"tag_upsert")}); }
  if (action==="deleteTag") { const tag=String(body?.tag||"").trim(); await deleteByLogicalId(COLLECTIONS.tags,tag,room); return sendJson(res,200,{ok:true,version:await bumpVersion(room,"tag_delete")}); }
  if (action==="upsertBgm") { const bgm=body?.bgm; if(!bgm||!bgm.id)return sendJson(res,400,{ok:false,error:"bad_bgm"}); await upsertByLogicalId(COLLECTIONS.bgm,bgm.id,bgm,room); return sendJson(res,200,{ok:true,version:await bumpVersion(room,"bgm_upsert")}); }
  if (action==="deleteBgm") { await deleteByLogicalId(COLLECTIONS.bgm,body?.bgmId,room); return sendJson(res,200,{ok:true,version:await bumpVersion(room,"bgm_delete")}); }
  if (action==="activityLog") {
    const log=safeJsonClone(body?.log||{});
    log.timestamp=Number(log.timestamp)||Date.now();
    log.roomId=normalizeRoom(room);
    log.anonymous=log.anonymous===true;

    if(log.anonymous){
      log.userId="不知名的小鱼丁";
      log.userName="不知名的小鱼丁";
      log.username="不知名的小鱼丁";
      log.displayName="不知名的小鱼丁";
    }else{
      const identityName=normalizeIdentityName(body?.identityName || log.userName || log.username || log.displayName || log.userId);
      if(identityName){
        log.userId=identityName;
        log.userName=identityName;
        log.username=identityName;
        log.displayName=identityName;
      }
    }

    await db.collection(COLLECTIONS.activityLogs).add(log);
    return sendJson(res,200,{ok:true,version:await bumpVersion(room,"activity_log")});
  }
  return sendJson(res,400,{ok:false,error:"bad_action",message:"未知写入动作"});
}

const server=http.createServer(async(req,res)=>{
  setCors(res);
  if(req.method==="OPTIONS"){res.statusCode=204;return res.end();}
  try{
    await ensureLegacyRoomMigration();
    const urlObj=new URL(req.url,`http://${req.headers.host||"localhost"}`);
    const path=urlObj.pathname.replace(/\/+$/,"") || "/";
    if(path==="/health"&&req.method==="GET") return sendJson(res,200,{ok:true,service:"timeline-api",mode:"cloudbase-multi-room-v8",editPasswordConfigured:!!EDIT_PASSWORD,xiaoqingerPasswordConfigured:!!XIAOQINGER_EDIT_PASSWORD,backupPasswordConfigured:!!BACKUP_PASSWORD,timestamp:new Date().toISOString()});
    if(path==="/timeline/version"&&req.method==="GET"){const room=requestRoomFromUrl(urlObj);return sendJson(res,200,await getMetaPayload(room));}
    if(path==="/timeline"&&req.method==="GET"){const room=requestRoomFromUrl(urlObj);return await handleTimelineGet(urlObj,res,room);}
    if(path==="/timeline"&&req.method==="POST"){const body=await readBodyJson(req);const room=requestRoomFromBody(body);return await handleWriteAction(req,res,body,room);}
    if(path==="/timeline") return sendJson(res,405,{ok:false,error:"method_not_allowed"});
    return sendJson(res,404,{ok:false,error:"not_found",path});
  }catch(error){
    console.error("timeline-api error:",error);
    if(error?.code==="request_too_large")return sendJson(res,413,{ok:false,error:"request_too_large"});
    if(error?.code==="invalid_json")return sendJson(res,400,{ok:false,error:"invalid_json"});
    return sendJson(res,500,{ok:false,error:"internal_error",message:error?.message||"Unknown error"});
  }
});
server.listen(PORT,()=>console.log(`timeline-api listening on port ${PORT}`));
