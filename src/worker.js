// Cloudflare Worker: KV short link subscription + access token protection
// Requires:
// - KV namespace binding: SUB_STORE
// - Secret/Variable: SUB_ACCESS_TOKEN
// Optional:
// - Secret/Variable: SUB_LINK_SECRET (legacy long-token compatibility)

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'GET,POST,OPTIONS',
      'access-control-allow-headers': 'content-type',
    },
  });
}

function text(body, status = 200, contentType = 'text/plain; charset=utf-8') {
  return new Response(body, {
    status,
    headers: {
      'content-type': contentType,
      'access-control-allow-origin': '*',
    },
  });
}

function b64EncodeUtf8(str) {
  return btoa(unescape(encodeURIComponent(str)));
}

function b64DecodeUtf8(str) {
  return decodeURIComponent(escape(atob(str)));
}

function escapeYaml(str = '') {
  return String(str)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, ' ');
}

function parsePreferredEndpoints(input) {
  return String(input || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [raw, remark = ''] = line.split('#');
      const value = raw.trim();
      const hashRemark = remark.trim();
      const match = value.match(/^(.*?)(?::(\d+))?$/);
      return {
        server: match?.[1] || value,
        port: match?.[2] ? Number(match[2]) : undefined,
        remark: hashRemark,
      };
    });
}

function parseVmess(link) {
  const raw = link.slice('vmess://'.length).trim();
  const obj = JSON.parse(b64DecodeUtf8(raw));
  return {
    type: 'vmess',
    name: obj.ps || 'vmess',
    server: obj.add,
    port: Number(obj.port || 443),
    uuid: obj.id,
    cipher: obj.scy || 'auto',
    network: obj.net || 'ws',
    tls: obj.tls === 'tls',
    host: obj.host || '',
    path: obj.path || '/',
    sni: obj.sni || obj.host || '',
    alpn: obj.alpn || '',
    fp: obj.fp || '',
  };
}

function parseUrlLike(link, type) {
  const u = new URL(link);
  return {
    type,
    name: decodeURIComponent(u.hash.replace(/^#/, '')) || type,
    server: u.hostname,
    port: Number(u.port || 443),
    password: type === 'trojan' ? decodeURIComponent(u.username) : undefined,
    uuid: type === 'vless' ? decodeURIComponent(u.username) : undefined,
    network: u.searchParams.get('type') || 'tcp',
    tls: (u.searchParams.get('security') || '').toLowerCase() === 'tls',
    host: u.searchParams.get('host') || u.searchParams.get('sni') || '',
    path: u.searchParams.get('path') || '/',
    sni: u.searchParams.get('sni') || u.searchParams.get('host') || '',
    fp: u.searchParams.get('fp') || '',
    alpn: u.searchParams.get('alpn') || '',
    flow: u.searchParams.get('flow') || '',
  };
}

function parseRawLinks(input) {
  const lines = String(input || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  const result = [];
  for (const line of lines) {
    if (line.startsWith('vmess://')) {
      result.push(parseVmess(line));
      continue;
    }
    if (line.startsWith('vless://')) {
      result.push(parseUrlLike(line, 'vless'));
      continue;
    }
    if (line.startsWith('trojan://')) {
      result.push(parseUrlLike(line, 'trojan'));
      continue;
    }
    try {
      const decoded = b64DecodeUtf8(line);
      if (/^(vmess|vless|trojan):\/\//m.test(decoded)) {
        result.push(...parseRawLinks(decoded));
      }
    } catch {}
  }
  return result;
}

function buildNodes(baseNodes, preferredEndpoints, options = {}) {
  const output = [];
  const prefix = (options.namePrefix || '').trim();
  let counter = 0;
  for (const node of baseNodes) {
    for (const ep of preferredEndpoints) {
      counter += 1;
      const nameParts = [];
      if (node.name) nameParts.push(node.name);
      if (prefix) nameParts.push(prefix);
      if (ep.remark) nameParts.push(ep.remark);
      else nameParts.push(String(counter));
      output.push({
        ...node,
        name: nameParts.join(' | '),
        server: ep.server,
        port: ep.port || node.port,
        host: options.keepOriginalHost ? node.host : '',
        sni: options.keepOriginalHost ? node.sni : '',
      });
    }
  }
  return output;
}

function encodeVmess(node) {
  const obj = {
    v: '2',
    ps: node.name,
    add: node.server,
    port: String(node.port),
    id: node.uuid,
    aid: '0',
    scy: node.cipher || 'auto',
    net: node.network || 'ws',
    type: 'none',
    host: node.host || '',
    path: node.path || '/',
    tls: node.tls ? 'tls' : '',
    sni: node.sni || '',
    alpn: node.alpn || '',
    fp: node.fp || '',
  };
  return 'vmess://' + b64EncodeUtf8(JSON.stringify(obj));
}

function encodeVless(node) {
  const url = new URL(`vless://${encodeURIComponent(node.uuid)}@${node.server}:${node.port}`);
  url.searchParams.set('type', node.network || 'ws');
  if (node.tls) url.searchParams.set('security', 'tls');
  if (node.host) url.searchParams.set('host', node.host);
  if (node.sni) url.searchParams.set('sni', node.sni);
  if (node.path) url.searchParams.set('path', node.path);
  if (node.alpn) url.searchParams.set('alpn', node.alpn);
  if (node.fp) url.searchParams.set('fp', node.fp);
  if (node.flow) url.searchParams.set('flow', node.flow);
  url.hash = node.name;
  return url.toString();
}

function encodeTrojan(node) {
  const url = new URL(`trojan://${encodeURIComponent(node.password)}@${node.server}:${node.port}`);
  if (node.network) url.searchParams.set('type', node.network);
  if (node.tls) url.searchParams.set('security', 'tls');
  if (node.host) url.searchParams.set('host', node.host);
  if (node.sni) url.searchParams.set('sni', node.sni);
  if (node.path) url.searchParams.set('path', node.path);
  if (node.alpn) url.searchParams.set('alpn', node.alpn);
  if (node.fp) url.searchParams.set('fp', node.fp);
  url.hash = node.name;
  return url.toString();
}

function renderRaw(nodes) {
  const lines = nodes
    .map((node) => {
      if (node.type === 'vmess') return encodeVmess(node);
      if (node.type === 'vless') return encodeVless(node);
      if (node.type === 'trojan') return encodeTrojan(node);
      return '';
    })
    .filter(Boolean);
  return b64EncodeUtf8(lines.join('\n'));
}

function renderClash(nodes) {
  const proxies = nodes
    .map((node) => {
      if (node.type === 'vmess') {
        const lines = [
          `  - name: "${escapeYaml(node.name)}"`,
          `    type: vmess`,
          `    server: ${node.server}`,
          `    port: ${node.port}`,
          `    uuid: ${node.uuid}`,
          `    alterId: 0`,
          `    cipher: ${node.cipher || 'auto'}`,
          `    udp: true`,
          `    tls: ${node.tls ? 'true' : 'false'}`,
          `    network: ${node.network || 'ws'}`,
        ];

        if (node.sni) {
          lines.push(`    servername: "${escapeYaml(node.sni)}"`);
        }

        if ((node.network || 'ws') === 'ws') {
          lines.push(
            `    ws-opts:`,
            `      path: "${escapeYaml(node.path || '/')}"`,
            `      headers:`,
            `        Host: "${escapeYaml(node.host || node.sni || '')}"`
          );
        }

        return lines.join('\n');
      }

      if (node.type === 'vless') {
        const lines = [
          `  - name: "${escapeYaml(node.name)}"`,
          `    type: vless`,
          `    server: ${node.server}`,
          `    port: ${node.port}`,
          `    uuid: ${node.uuid}`,
          `    udp: true`,
          `    tls: ${node.tls ? 'true' : 'false'}`,
          `    network: ${node.network || 'ws'}`,
        ];

        if (node.sni) {
          lines.push(`    servername: "${escapeYaml(node.sni)}"`);
        }

        if ((node.network || 'ws') === 'ws') {
          lines.push(
            `    ws-opts:`,
            `      path: "${escapeYaml(node.path || '/')}"`,
            `      headers:`,
            `        Host: "${escapeYaml(node.host || node.sni || '')}"`
          );
        }

        return lines.join('\n');
      }

      if (node.type === 'trojan') {
        const lines = [
          `  - name: "${escapeYaml(node.name)}"`,
          `    type: trojan`,
          `    server: ${node.server}`,
          `    port: ${node.port}`,
          `    password: "${escapeYaml(node.password || '')}"`,
          `    udp: true`,
        ];

        if (node.sni) {
          lines.push(`    sni: "${escapeYaml(node.sni)}"`);
        }

        if (node.tls !== false) {
          lines.push(`    tls: true`);
        }

        if (node.network) {
          lines.push(`    network: ${node.network}`);
        }

        if (node.network === 'ws') {
          lines.push(
            `    ws-opts:`,
            `      path: "${escapeYaml(node.path || '/')}"`,
            `      headers:`,
            `        Host: "${escapeYaml(node.host || node.sni || '')}"`
          );
        }

        return lines.join('\n');
      }

      return '';
    })
    .filter(Boolean);

  const proxyNames = nodes.map(
    (node) => `      - "${escapeYaml(node.name)}"`
  );

  const allGroupMembers = [
    `      - "自动选择"`,
    ...proxyNames,
    `      - DIRECT`,
  ];

  const autoGroupMembers = proxyNames.length ? proxyNames : [`      - DIRECT`];

  return [
    `mixed-port: 7890`,
    `allow-lan: false`,
    `mode: rule`,
    `log-level: info`,
    `ipv6: true`,
    ``,
    `proxies:`,
    ...(proxies.length ? proxies : []),
    ``,
    `proxy-groups:`,
    `  - name: "自动选择"`,
    `    type: url-test`,
    `    url: "http://www.gstatic.com/generate_204"`,
    `    interval: 300`,
    `    tolerance: 50`,
    `    proxies:`,
    ...autoGroupMembers,
    ``,
    `  - name: "节点选择"`,
    `    type: select`,
    `    proxies:`,
    ...allGroupMembers,
    ``,
    `rules:`,
    `  - MATCH,节点选择`,
  ].join('\n');
}

function renderSurge(nodes, baseUrl, accessToken) {
  const proxies = nodes
    .filter((node) => node.type === 'vmess' || node.type === 'trojan')
    .map((node) => {
      if (node.type === 'vmess') {
        return `${node.name} = vmess, ${node.server}, ${node.port}, username=${node.uuid}, ws=true, ws-path=${node.path || '/'}, ws-headers=Host:${node.host || ''}, tls=${node.tls ? 'true' : 'false'}, sni=${node.sni || ''}`;
      }
      return `${node.name} = trojan, ${node.server}, ${node.port}, password=${node.password || ''}, sni=${node.sni || ''}`;
    });

  return [
    '[General]',
    'skip-proxy = 127.0.0.1, localhost',
    '',
    '[Proxy]',
    ...proxies,
    '',
    '[Proxy Group]',
    'Proxy = select, ' +
      nodes
        .filter((n) => n.type === 'vmess' || n.type === 'trojan')
        .map((n) => n.name)
        .join(', '),
    '',
    '[Rule]',
    'FINAL,Proxy',
    '',
    '; token-protected subscription',
    `; ${baseUrl}?token=${accessToken}`,
  ].join('\n');
}

function createShortId(length = 10) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  let out = '';
  for (let i = 0; i < length; i++) {
    out += chars[bytes[i] % chars.length];
  }
  return out;
}

async function createUniqueShortId(env, tries = 8) {
  for (let i = 0; i < tries; i++) {
    const id = createShortId(10);
    const exists = await env.SUB_STORE.get(`sub:${id}`);
    if (!exists) return id;
  }
  throw new Error('无法生成唯一短链接，请稍后再试');
}

function normalizeLines(value = '') {
  return String(value)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .sort()
    .join('\n');
}

async function sha256Hex(input) {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function buildDedupHash(body) {
  const normalized = {
    nodeLinks: normalizeLines(body.nodeLinks || ''),
    preferredIps: normalizeLines(body.preferredIps || ''),
    namePrefix: String(body.namePrefix || '').trim(),
    keepOriginalHost: body.keepOriginalHost !== false,
  };
  return sha256Hex(JSON.stringify(normalized));
}


// Persistent subscriptions: source inputs stay private in KV, never in Git.
function sourceUrl(value) {
  const u = new URL(value);
  if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password) throw new Error('源订阅 URL 无效');
  const h = u.hostname.toLowerCase();
  if (!h.includes('.') || h.includes(':') || /(^|\.)(localhost|local|internal)$/.test(h)) throw new Error('源订阅需要公网地址');
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) {
    const [a,b] = h.split('.').map(Number);
    if (a===0 || a===10 || a===127 || a>=224 || (a===100 && b>=64 && b<=127) || (a===169 && b===254) || (a===172 && b>=16 && b<=31) || (a===192 && b===168) || (a===198 && (b===18 || b===19))) throw new Error('Cloudflare 无法读取内网源订阅');
  }
  return u;
}
async function readSource(value) {
  let u = sourceUrl(value);
  for (let attempt=0; attempt<4; attempt++) {
    const response = await fetch(u.toString(), {redirect:'manual', signal:AbortSignal.timeout(12000), headers:{'User-Agent':'v2rayN/7.0','Accept':'text/plain'}});
    if ([301,302,303,307,308].includes(response.status)) {
      const location = response.headers.get('location');
      if (!location) throw new Error('源订阅重定向无效');
      u = sourceUrl(new URL(location,u).toString());
      continue;
    }
    if (!response.ok) { const body = await response.text(); const kind = response.headers.get('cf-mitigated') === 'challenge' ? 'Cloudflare 验证' : /error code: 1010/i.test(body) ? 'Cloudflare 1010' : /error code: 1020/i.test(body) ? 'Cloudflare 1020' : /cloudflare/i.test(body) ? 'Cloudflare 返回' : '源服务返回'; throw new Error('源订阅读取失败（HTTP '+response.status+'，'+kind+'）'); }
    if (Number(response.headers.get('content-length')||0)>2097152) throw new Error('源订阅超过 2 MB');
    const reader = response.body.getReader();
    const chunks=[]; let size=0;
    while (true) { const {done,value}=await reader.read(); if(done) break; size+=value.length; if(size>2097152){await reader.cancel();throw new Error('源订阅超过 2 MB');} chunks.push(value); }
    const bytes=new Uint8Array(size); let offset=0; for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
    return new TextDecoder().decode(bytes);
  }
  throw new Error('源订阅重定向过多');
}
async function resolveNodes(input) {
  const lines=String(input||'').split(/\r?\n/).map(v=>v.trim()).filter(Boolean);
  if(lines.length>200) throw new Error('最多输入 200 行');
  const urls=lines.filter(v=>/^https?:\/\//i.test(v));
  if(urls.length>5) throw new Error('最多输入 5 个源订阅');
  const nodes=[];
  for(const line of lines) {
    const content=/^https?:\/\//i.test(line) ? await readSource(line) : line;
    nodes.push(...parseRawLinks(content));
  }
  const eligible=nodes.filter(n=>n.network==='ws' && n.tls && n.host && n.sni);
  const unique=[...new Map(eligible.map(n=>[JSON.stringify(n),n])).values()];
  if(!unique.length) throw new Error('没有识别到可优选的 WS + TLS 节点；请使用原始/Base64订阅，保留 Host/SNI');
  return {nodes:unique, skipped:nodes.length-eligible.length};
}
function accessAllowed(provided,env) {
  return Boolean(env.SUB_ACCESS_TOKEN && provided && provided===env.SUB_ACCESS_TOKEN);
}
async function handleGenerate(request, env, url) {
  if(!env.SUB_STORE) return json({ok:false,error:'请绑定 SUB_STORE KV'},503);
  if(!env.SUB_ACCESS_TOKEN) return json({ok:false,error:'请先在 Cloudflare 设置 SUB_ACCESS_TOKEN Secret'},503);
  let body; try {body=await request.json();} catch {return json({ok:false,error:'请求体不是合法 JSON'},400);}
  if(!accessAllowed(body.accessToken,env)) return json({ok:false,error:'访问令牌错误'},403);
  try {
    const nodeLinks=String(body.nodeLinks||'').trim();
    const preferredIps=String(body.preferredIps||'').trim();
    if(nodeLinks.length>2097152 || preferredIps.length>20000) throw new Error('输入过大');
    const resolved=await resolveNodes(nodeLinks);
    const preferredEndpoints=parsePreferredEndpoints(preferredIps);
    if(!preferredEndpoints.length || preferredEndpoints.length>50) throw new Error('请填写 1 至 50 个优选地址');
    for(const ep of preferredEndpoints) {
      if(!/^[a-zA-Z0-9.-]+$/.test(ep.server) || (ep.port && ![443,2053,2083,2087,2096,8443].includes(ep.port))) throw new Error('优选地址格式错误，端口需为 Cloudflare HTTPS 代理端口');
    }
    if(resolved.nodes.length*preferredEndpoints.length>500) throw new Error('生成节点数量最多 500');
    const options={namePrefix:String(body.namePrefix||'').slice(0,100),keepOriginalHost:body.keepOriginalHost!==false};
    const normalized={nodeLinks,preferredIps,...options};
    const hash=await sha256Hex(JSON.stringify(normalized));
    const dedupKey='persistent:'+hash;
    let id=await env.SUB_STORE.get(dedupKey);
    if(id && !(await env.SUB_STORE.get('sub:'+id))) id=null;
    if(!id) {
      id=createShortId(32);
      await env.SUB_STORE.put('sub:'+id,JSON.stringify({version:2,createdAt:new Date().toISOString(),nodeLinks,preferredIps,options}));
      await env.SUB_STORE.put(dedupKey,id);
    }
    const nodes=buildNodes(resolved.nodes,preferredEndpoints,options);
    const makeUrl=target=>url.origin+'/sub/'+id+'?target='+target+'&token='+encodeURIComponent(body.accessToken);
    return json({ok:true,storage:'kv',shortId:id,urls:{auto:makeUrl('raw'),raw:makeUrl('raw'),clash:makeUrl('clash'),surge:makeUrl('surge')},counts:{inputNodes:resolved.nodes.length,preferredEndpoints:preferredEndpoints.length,outputNodes:nodes.length},preview:nodes.slice(0,50).map(n=>({name:n.name,server:n.server,port:n.port,host:n.host,sni:n.sni,type:n.type})),warnings:resolved.skipped?['已跳过 '+resolved.skipped+' 个非 WS + TLS 节点']:[],persistent:true});
  } catch (error) { const msg = String(error?.message || '未知错误'); const known = /^(源订阅|没有识别到|最多输入|请填写|优选地址|生成节点|Cloudflare 无法|输入过大)/.test(msg); return json({ok:false,error:known ? msg : '源订阅读取或处理失败：' + String(error?.name || 'Error')},400); }
}
async function handleSub(url,env) {
  if(!accessAllowed(url.searchParams.get('token'),env)) return text('Forbidden',403);
  const id=url.pathname.split('/').pop();
  if(!id) return text('missing id',400);
  const raw=await env.SUB_STORE.get('sub:'+id);
  if(!raw) return text('not found',404);
  try {
    const record=JSON.parse(raw);
    const nodes=record.version===2 ? buildNodes((await resolveNodes(record.nodeLinks)).nodes,parsePreferredEndpoints(record.preferredIps),record.options) : record.nodes;
    const target=(url.searchParams.get('target')||'raw').toLowerCase();
    let response;
    if(target==='clash') response=text(renderClash(nodes),200,'text/yaml; charset=utf-8');
    else if(target==='surge') response=text(renderSurge(nodes,url.origin+url.pathname,url.searchParams.get('token')));
    else if(target==='raw') response=text(renderRaw(nodes));
    else return text('supported targets: raw, clash',400);
    response.headers.set('cache-control','private, no-store');
    response.headers.set('referrer-policy','no-referrer');
    response.headers.set('profile-update-interval','6');
    return response;
  } catch { return text('源订阅读取失败，请稍后更新订阅',502); }
}
export default {
  async fetch(request,env) {
    const url=new URL(request.url);
    if(request.method==='POST' && url.pathname==='/api/generate') return handleGenerate(request,env,url);
    if(request.method==='GET' && url.pathname.startsWith('/sub/')) return handleSub(url,env);
    return env.ASSETS.fetch(request);
  }
};
